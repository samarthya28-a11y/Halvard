"""Vaultline service (tenant side): scans sanctioned stores, controls outbound mail, collects device catalogs, joins sensitivity with exposure (F083-F085).

Everything that reads content goes through an Inspector, so the same gate applies here as on a device: off by default, scoped, purposed, noticed.
"""
import json

from ..ledger.audit import opaque
from ..signet.detectors import Finding
from . import dlp as dlpmod
from .classifiers import Classifier, Classification
from .inspection import InspectionPolicy, Inspector, InspectionNotAllowed

RANK = {"public": 0, "internal": 1, "confidential": 2, "regulated": 3}


class VaultlineService:
    def __init__(self, store, ctx, clock, aws, mail, own_domains, partners=(), policy: InspectionPolicy | None = None, rules=None, audit=None, atlas=None):
        self.store, self.ctx, self.clock, self.aws, self.mail, self.audit, self.atlas = store, ctx, clock, aws, mail, audit, atlas
        self.own, self.partners = {d.lower() for d in own_domains}, {d.lower() for d in partners}
        self.policy = policy or InspectionPolicy()
        self.inspector = Inspector(self.policy, clock, Classifier(), audit, source="tenant")
        self.rules, self.held_just = rules, {}
        self._n = 0; self.findings = []
        if mail is not None: mail.outbound_hook = self.outbound_decision

    # ---------------- sanctioned cloud stores ----------------
    def scan_bucket(self, bucket, max_objects=500):
        rid = f"s3:{bucket}"; b = self.aws.buckets[bucket]; labels, hits, unread, n = {}, 0, 0, 0; sens = "internal"
        for key, data in list(b.objects.items())[:max_objects]:
            c = self.inspector.inspect(f"s3:{bucket}/{key}", key, data, who="vaultline"); n += 1
            if c.unscannable: unread += 1
            if c.labels:
                hits += 1
                for l, v in c.labels.items(): labels[l] = labels.get(l, 0) + v["count"]
            if RANK[c.sensitivity] > RANK[sens]: sens = c.sensitivity
        if self.store.has_entity(self.ctx, rid):
            self.store.update_entity(self.ctx, rid, self.clock.now(), suggested_sensitivity=sens, suggestion_evidence=[f"vaultline:scan:{n}:{hits}"])
        if self.audit:
            self.audit.append("vaultline.store_scanned", "halvard:vaultline", "system", opaque(rid), {"objects": n, "objects_with_hits": hits, "labels": labels, "sensitivity": sens, "unreadable": unread}, controls=("VAULTLINE.CLASSIFICATION",))
        return {"bucket": bucket, "objects": n, "objects_with_hits": hits, "labels": labels, "suggested_sensitivity": sens, "unreadable": unread}

    def exposed_sensitive(self):
        """Stores that are both exposed and sensitive: the combination that matters (F085)."""
        out = []
        for e in self.store.entities(self.ctx):
            if e["kind"] != "data_store": continue
            sens = e["sensitivity"] or e["suggested_sensitivity"]
            pub = e["attrs"].get("public")
            if pub and sens in ("regulated", "confidential"):
                out.append({"store": e["entity_id"], "sensitivity": sens, "customer_set": bool(e["sensitivity"]), "severity": "critical" if sens == "regulated" else "high",
                            "why": f"{e['display_name']} is readable by anyone and holds {sens} data" + ("" if e["sensitivity"] else " (Halvard's suggestion from scanning; confirm or correct it)")})
        return out

    def unprotected_sensitive_stores(self):
        """Sensitive stores without encryption or versioning (not public, but weakly protected)."""
        out = []
        for n, b in self.aws.buckets.items():
            sens = self.atlas.sensitivity_of(f"s3:{n}") if self.atlas else None
            if sens in ("regulated", "confidential") and (not b.encryption or not b.versioning):
                out.append({"store": f"s3:{n}", "sensitivity": sens, "gaps": [g for g, bad in (("not encrypted", not b.encryption), ("no versioning", not b.versioning)) if bad]})
        return out

    # ---------------- device catalogs ----------------
    def ingest_catalog(self, device_id, entries):
        """Device sent labels and counts only. Record on the device entity that it holds sensitive data, and how much, never what or where in readable form."""
        if not entries or not self.store.has_entity(self.ctx, device_id): return None
        sens = max((e.sensitivity for e in entries), key=RANK.get); counts = {}
        for e in entries:
            for l, c in e.labels.items(): counts[l] = counts.get(l, 0) + c
        self.store.update_entity(self.ctx, device_id, self.clock.now(), suggested_sensitivity=sens, suggestion_evidence=[f"vaultline:device-catalog:{len(entries)}"], attrs={"data_labels": counts, "files_with_labels": sum(1 for e in entries if e.labels)})
        return {"device": device_id, "files": len(entries), "labels": counts, "sensitivity": sens}

    # ---------------- outbound mail ----------------
    def _external(self, msg): return [r for r in msg.to if r.rsplit("@", 1)[-1].lower() not in self.own]

    def outbound_decision(self, msg):
        ext = self._external(msg)
        if not ext: return {"action": "allow", "inspected": False}
        dest = "partner" if all(r.rsplit("@", 1)[-1].lower() in self.partners for r in ext) else "external"
        merged, sens = {}, "internal"
        try:
            parts = [("body.txt", msg.body.encode())] + [(a.name, a.data) for a in msg.attachments]
            for name, data in parts:
                c = self.inspector.inspect("mail:outbound", name, data, who="vaultline")
                for l, v in c.labels.items():
                    if l not in merged or v["confidence"] > merged[l]["confidence"]: merged[l] = {**v, "count": v["count"] + merged.get(l, {}).get("count", 0)}
                if RANK[c.sensitivity] > RANK[sens]: sens = c.sensitivity
            cls = Classification(merged, sens)
        except InspectionNotAllowed:
            return {"action": "allow", "inspected": False}
        d = dlpmod.decide(cls, "email_external", dest, self.rules)
        just = d.action == "justify" and self.held_just.get(msg.id, 0) > self.clock.now()
        if self.audit:
            self.audit.append("vaultline.outbound_decision", msg.sender, "end_user", opaque(msg.sender), {"decision": "allow" if just else d.action, "rule": d.rule, "labels": d.labels, "dest_class": dest, "recipients": len(ext), "email": msg.sender},
                              controls=("VAULTLINE.EMAIL_CONTROL",))
        return {"action": "allow" if just else d.action, "rule": d.rule, "message": d.message, "labels": d.labels, "justifiable": d.justifiable, "inspected": True}

    def justify_outbound(self, sender, msg_id, text):
        """The sender gives a reason for a held message whose rule allows one. Blocked messages (and secrets) need a second person via release_outbound_message."""
        text = (text or "").strip()
        if not 10 <= len(text) <= 200: raise ValueError("Please give a reason of 10 to 200 characters.")
        msg = self.mail.messages[msg_id]; self.held_just[msg_id] = self.clock.now() + 3600
        d = self.outbound_decision(msg)
        if d["action"] != "allow": self.held_just.pop(msg_id, None); raise PermissionError(d.get("message") or "A reason cannot unlock this message; ask a data owner to approve it.")
        if self.audit: self.audit.append("vaultline.outbound_justified", sender, "end_user", opaque(sender), {"justification": text, "email": sender}, controls=("VAULTLINE.EMAIL_CONTROL",))
        return self.mail.release_held(sender, msg_id)
