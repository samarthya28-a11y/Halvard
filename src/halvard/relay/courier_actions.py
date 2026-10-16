"""Courier actions (F065, F066, F070): pull mail back, hold it recoverably, release it with an audit trail, remove mailbox tampering.

Clawback moves copies to a recoverable quarantine; it never deletes. Purging is a separate, approval-gated, irreversible action.
The result always lists what clawback could NOT undo: messages already opened, clicked, replied to, forwarded or saved to a device.
"""
from .authority import Requirement
from .matrix_def import BY_KEY


def _copies(eng, key):
    """All (mailbox, msg_id) copies for an attachment hash, message id or campaign key (including forwards)."""
    mail, courier = eng.adapters.mail, eng.adapters.courier
    keys = {key} | {r.msg_id for r in courier.records.values() if r.campaign == key}
    seen, out = set(), []
    for k in keys:
        for a, mid, folder in mail.copies(k):
            if (a, mid) not in seen: seen.add((a, mid)); out.append((a, mid, folder))
    return out


class ClawbackMessage:
    def preview(self, eng, req):
        mail, copies = eng.adapters.mail, []
        for k in req.targets: copies += _copies(eng, k)
        live = [c for c in copies if c[2] != "quarantine"]
        risky = [c for c in live if mail.mailboxes[c[0]].state.get(c[1], set()) & {"attachment_opened", "clicked", "replied", "forwarded"}]
        return {"summary": f"Move {len(live)} copy(ies) in {len({c[0] for c in live})} mailbox(es) to a recoverable quarantine. Nothing is deleted. "
                           + (f"{len(risky)} were already opened, clicked, answered or forwarded; moving them does not undo that." if risky else "None have been opened, clicked or forwarded."),
                "cannot_undo": BY_KEY["clawback_message"]["cannot_undo"] + ["what recipients already did with a message before it was pulled"], "copies": len(live), "at_risk": len(risky)}

    def apply(self, eng, req, plan):
        mail, moved, risky = eng.adapters.mail, [], []
        for k in req.targets:
            for a, mid, folder in _copies(eng, k):
                if folder == "quarantine": continue
                st = sorted(mail.mailboxes[a].state.get(mid, set()))
                if mail.quarantine(a, mid): moved.append((a, mid)); 
                if set(st) & {"attachment_opened", "clicked", "replied", "forwarded"}: risky.append({"mailbox": a, "msg_id": mid, "state": st})
        for a, mid in moved:
            rec = eng.adapters.courier.records.get((a, mid))
            if rec: rec.auto_quarantined = True
        return {"summary": f"Pulled {len(moved)} copy(ies) from {len({a for a, _ in moved})} mailbox(es). " + (f"{len(risky)} had already been used by the recipient: " + ", ".join(f"{r['mailbox']} ({'/'.join(r['state'])})" for r in risky) + "." if risky else "None had been opened."),
                "undo": {"moved": moved}, "detail": {"moved": moved, "at_risk": risky}, "audit": {"copies": len(moved), "mailboxes": len({a for a, _ in moved}), "at_risk": len(risky), "email": [a for a, _ in moved][:50], "key": req.targets[0]}}

    def undo(self, eng, r, d, ureq):
        n = sum(1 for a, mid in d["moved"] if eng.adapters.mail.restore(a, mid)); return {"summary": f"Returned {n} message(s) to their mailboxes."}


class ReleaseMessage:
    def _parse(self, t): return t.split("|", 1)

    def extra_requirements(self, eng, req):
        out = []
        for t in req.targets:
            a, mid = self._parse(t); rec = eng.adapters.courier.records.get((a, mid))
            if rec and rec.verdict == "malicious": out.append(Requirement("approve", ["it_admin", "analyst"], 1))     # a harmful message needs a second pair of eyes
        return out

    def preview(self, eng, req):
        if not req.params.get("reason_text"): return {"summary": "A reason is required to release a message.", "invalid": True, "cannot_undo": []}
        lines = []
        for t in req.targets:
            a, mid = self._parse(t); rec = eng.adapters.courier.records.get((a, mid))
            lines.append(f"{rec.sender if rec else mid}: {rec.verdict if rec else 'not analysed'}" + (f" ({'; '.join(rec.reasons[:2])})" if rec and rec.reasons else ""))
        return {"summary": "Return to the mailbox: " + " | ".join(lines), "cannot_undo": ["anything the recipient does with the message once it is back"]}

    def apply(self, eng, req, plan):
        n = 0
        for t in req.targets:
            a, mid = self._parse(t); n += bool(eng.adapters.mail.restore(a, mid))
        return {"summary": f"Released {n} message(s).", "undo": {"targets": list(req.targets)}, "audit": {"released": n, "email": [self._parse(t)[0] for t in req.targets][:50]}}

    def undo(self, eng, r, d, ureq):
        for t in d["targets"]:
            a, mid = self._parse(t); eng.adapters.mail.quarantine(a, mid)
        return {"summary": "Messages quarantined again."}


class PurgeMessage:
    def preview(self, eng, req):
        if req.case_id and eng.holds.get(req.case_id): return {"summary": "This case is under legal hold; quarantined mail is evidence and cannot be deleted.", "invalid": True, "cannot_undo": []}
        return {"summary": f"Permanently delete {len(req.targets)} quarantined message(s). This cannot be undone.", "cannot_undo": BY_KEY["purge_message"]["cannot_undo"]}

    def apply(self, eng, req, plan):
        n = sum(bool(eng.adapters.mail.purge(*t.split("|", 1))) for t in req.targets); return {"summary": f"Deleted {n} message(s).", "undo": {}, "audit": {"purged": n}}


class RemoveMailboxRule:
    def preview(self, eng, req): return {"summary": f"Remove {len(req.targets)} mailbox rule(s). The rule is kept so it can be restored.", "cannot_undo": []}

    def apply(self, eng, req, plan):
        done = [t for t in req.targets if eng.adapters.mail.remove_rule(*t.split("|", 1))]; return {"summary": f"Removed {len(done)} rule(s).", "undo": {"rules": done}, "audit": {"rules": len(done)}}

    def undo(self, eng, r, d, ureq):
        for t in d["rules"]: eng.adapters.mail.restore_rule(*t.split("|", 1))
        return {"summary": "Rules restored."}


class DisableForwarding:
    def preview(self, eng, req): return {"summary": "Stop forwarding to outside addresses for " + ", ".join(req.targets) + ". Mail already forwarded stays with whoever received it.", "cannot_undo": BY_KEY["disable_forwarding"]["cannot_undo"]}

    def apply(self, eng, req, plan):
        prev = {}
        for a in req.targets:
            mb = eng.adapters.mail.mailboxes[a]; prev[a] = mb.forwarding; mb.forwarding = None
        return {"summary": f"Forwarding turned off on {len(prev)} mailbox(es).", "undo": {"prev": prev}, "audit": {"mailboxes": len(prev), "email": list(prev)}}

    def undo(self, eng, r, d, ureq):
        for a, to in d["prev"].items(): eng.adapters.mail.mailboxes[a].forwarding = to
        return {"summary": "Forwarding settings restored."}


class BlockSender:
    def preview(self, eng, req): return {"summary": "Stop all future mail from " + ", ".join(req.targets) + " for everyone. Mail already delivered is not touched.", "cannot_undo": []}

    def apply(self, eng, req, plan):
        for d in req.targets: eng.adapters.mail.block_sender(d)
        return {"summary": f"Blocked {len(req.targets)} sender domain(s).", "undo": {"domains": list(req.targets)}, "audit": {"domains": len(req.targets)}}

    def undo(self, eng, r, d, ureq):
        for x in d["domains"]: eng.adapters.mail.unblock_sender(x)
        return {"summary": "Sender domains unblocked."}


def register_courier(engine):
    engine.handlers.update({"clawback_message": ClawbackMessage(), "release_message": ReleaseMessage(), "purge_message": PurgeMessage(),
                            "remove_mailbox_rule": RemoveMailboxRule(), "disable_forwarding": DisableForwarding(), "block_sender": BlockSender()})
