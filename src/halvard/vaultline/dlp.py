"""Data-handling rules (F084): what may leave through which door.

A rule says: for data carrying this label (or this sensitivity), on this channel, to this kind of destination, do this.
Actions, mildest to strictest: allow, warn, justify (the person gives a reason, time-boxed, recorded), block.
The strictest matching rule wins. `justifiable: false` on a block means no reason can unlock it (secrets). Rules live in the signed
policy bundle, so they work with no connection. Messages are written for the person who hit the rule: what happened, why, what to do.
"""
from dataclasses import dataclass, field

ORDER = {"allow": 0, "warn": 1, "justify": 2, "block": 3}
RANK = {"public": 0, "internal": 1, "confidential": 2, "regulated": 3}
SECRETS = ["secret_key", "secret_generic"]

DEFAULT_RULES = [
    {"id": "usb-regulated-unprotected", "sensitivity": "regulated", "channel": "usb", "dest": ["unapproved", "approved_plain"], "action": "block",
     "message": "This file contains regulated data (such as card or national ID numbers). It cannot be copied to this drive. Use an approved encrypted drive or the shared drive."},
    {"id": "usb-regulated-encrypted", "sensitivity": "regulated", "channel": "usb", "dest": ["approved_encrypted"], "action": "allow", "message": "Copied to an approved encrypted drive. This is recorded."},
    {"id": "usb-confidential-unapproved", "sensitivity": "confidential", "channel": "usb", "dest": ["unapproved", "approved_plain"], "action": "justify",
     "message": "This file is marked confidential. Tell us why it needs to go on this drive, and it will be allowed for an hour."},
    {"id": "email-regulated-external", "sensitivity": "regulated", "channel": "email_external", "dest": ["external"], "action": "block",
     "message": "This message contains regulated data and is addressed outside the company. It was held, not sent. Remove the data, or ask a data owner to approve sending."},
    {"id": "email-regulated-partner", "sensitivity": "regulated", "channel": "email_external", "dest": ["partner"], "action": "justify",
     "message": "This message contains regulated data and goes to a partner. Tell us why it needs to be sent this way."},
    {"id": "email-confidential-external", "sensitivity": "confidential", "channel": "email_external", "dest": ["external", "partner"], "action": "warn",
     "message": "This message contains confidential data and goes outside the company. It was sent, and this is recorded."},
    {"id": "upload-regulated-unsanctioned", "sensitivity": "regulated", "channel": "upload", "dest": ["unsanctioned", "personal"], "action": "block",
     "message": "Regulated data cannot be uploaded to this service. Use the company's approved storage."},
    {"id": "upload-confidential-unsanctioned", "sensitivity": "confidential", "channel": "upload", "dest": ["unsanctioned", "personal"], "action": "justify",
     "message": "This file is confidential and this service is not approved. Tell us why it needs to go there."},
    {"id": "print-regulated", "sensitivity": "regulated", "channel": "print", "dest": ["*"], "action": "justify",
     "message": "This document contains regulated data. Tell us why it needs to be printed."},
    {"id": "share-regulated-public", "sensitivity": "regulated", "channel": "cloud_share_public", "dest": ["*"], "action": "block",
     "message": "Regulated data cannot be shared with a public link."},
    {"id": "ai-regulated-shadow", "sensitivity": "regulated", "channel": "ai_prompt", "dest": ["ai_shadow", "ai_standard"], "action": "block",
     "message": "This contains regulated data (such as card or national ID numbers). It cannot be sent to this AI tool. Remove the data, or use the approved enterprise AI workspace if your role allows."},
    {"id": "ai-regulated-enterprise", "sensitivity": "regulated", "channel": "ai_prompt", "dest": ["ai_enterprise"], "action": "justify",
     "message": "This contains regulated data. The approved AI workspace may be used for it only with a reason. Tell us why, and it will be allowed for an hour."},
    {"id": "ai-confidential-shadow", "sensitivity": "confidential", "channel": "ai_prompt", "dest": ["ai_shadow"], "action": "block",
     "message": "This is confidential and this AI tool is not approved by IT. Use the approved AI workspace, or ask IT to review this tool."},
    {"id": "ai-confidential-standard", "sensitivity": "confidential", "channel": "ai_prompt", "dest": ["ai_standard"], "action": "justify",
     "message": "This is confidential and this AI tool is approved for general use only. Tell us why it needs to go there."},
    {"id": "ai-internal-shadow", "sensitivity": "internal", "channel": "ai_prompt", "dest": ["ai_shadow"], "action": "warn",
     "message": "This AI tool is not approved by IT. What you sent was allowed, and this is recorded."},
    {"id": "secrets-anywhere", "labels": SECRETS, "channel": "*", "dest": ["*"], "action": "block", "justifiable": False,
     "message": "This file contains a password, key or token. It cannot leave this computer this way. Store secrets in the company's secret manager."},
]


@dataclass
class Decision:
    action: str = "allow"
    rule: str | None = None
    labels: dict = field(default_factory=dict)
    message: str = ""
    justifiable: bool = True
    inspected: bool = True


UNREAD_BLOCK = {("usb", "unapproved"), ("usb", "approved_plain"), ("email_external", "external")}


def decide(classification, channel, dest_class, rules=None, min_conf=0.7) -> Decision:
    """classification may be None when inspection is off; then only content-independent rules (none by default) can apply."""
    rules = DEFAULT_RULES if rules is None else rules
    best = Decision(inspected=classification is not None)
    if classification is None: return best
    labels = {k: v["count"] for k, v in classification.labels.items() if v["confidence"] >= min_conf}
    best.labels = labels
    for r in rules:
        if r["channel"] not in ("*", channel) or not ("*" in r["dest"] or dest_class in r["dest"]): continue
        hit = (r.get("labels") and any(l in labels for l in r["labels"])) or (r.get("sensitivity") and (labels or classification.unscannable) and RANK[classification.sensitivity] >= RANK[r["sensitivity"]])
        if hit and (ORDER[r["action"]] > ORDER[best.action] or best.rule is None or (r["action"] == best.action and best.justifiable and not r.get("justifiable", True))):
            best = Decision(r["action"], r["id"], labels, r["message"] + (f" (Halvard could not read this file: {classification.unscannable}, so it is treated as regulated.)" if classification.unscannable and not labels else ""), r.get("justifiable", True), True)
    if classification.unscannable and (channel, dest_class) in UNREAD_BLOCK and not (best.action == "block" and not best.justifiable):
        best = Decision("block", "unread-regulated", labels,
                        f"Halvard could not read this file ({classification.unscannable}). It is regulated, so a reason cannot copy it to an unapproved drive or an external address. Residual: file not read.",
                        False, True)
    return best
