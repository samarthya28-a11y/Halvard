"""Atlas actions (F079) and the outbound-hold release (F084). Each previews who or what stops working before it runs, and keeps what is needed to undo."""
from .matrix_def import BY_KEY


class BlockPublicAccess:
    def preview(self, eng, req):
        aws, notes = eng.adapters.aws, []
        for t in req.targets:
            b = aws.buckets[t.split(":", 1)[1]]
            notes.append(f"{b.name}: anonymous reads stop at once" + ("; THIS BUCKET IS TAGGED AS A WEBSITE, so the site will stop working" if b.tags.get("website") else "") + ("" if b.effective_public else " (it is not public now)"))
        return {"summary": "Block all public access. " + " | ".join(notes), "cannot_undo": BY_KEY["block_public_access"]["cannot_undo"]}

    def apply(self, eng, req, plan):
        prev = {t: eng.adapters.aws.block_public_access(t.split(":", 1)[1]) for t in req.targets}
        return {"summary": f"Public access blocked on {len(prev)} bucket(s).", "undo": {"prev": prev}, "audit": {"buckets": len(prev), "key": req.targets[0]}}

    def undo(self, eng, r, d, ureq):
        for t, prev in d["prev"].items(): eng.adapters.aws.restore_public_access(t.split(":", 1)[1], prev)
        return {"summary": "The earlier public-access settings were restored. The data is exposed again if it was before."}


class RestrictSecurityGroupRule:
    def _parse(self, t): sg, port, cidr = t.split("|"); return sg, int(port), cidr

    def preview(self, eng, req):
        aws, lines = eng.adapters.aws, []
        for t in req.targets:
            sg, port, cidr = self._parse(t); users = [i for i, x in aws.instances.items() if sg in x.sg_ids]
            lines.append(f"close port {port} from {cidr} on {sg}; affects {', '.join(users) or 'no instances'}")
        return {"summary": "; ".join(lines) + ". Anyone relying on that access from outside loses it.", "cannot_undo": []}

    def apply(self, eng, req, plan):
        done = []
        for t in req.targets:
            sg, port, cidr = self._parse(t); eng.adapters.aws.revoke_sg_rule(sg, {"port": port, "cidr": cidr}); done.append((sg, port, cidr))
        return {"summary": f"Closed {len(done)} firewall rule(s).", "undo": {"rules": done}, "audit": {"rules": len(done)}}

    def undo(self, eng, r, d, ureq):
        for sg, port, cidr in d["rules"]: eng.adapters.aws.authorize_sg_rule(sg, {"port": port, "cidr": cidr, "proto": "tcp"})
        return {"summary": "Firewall rules reopened."}


class DisableAccessKey:
    def preview(self, eng, req):
        aws, lines = eng.adapters.aws, []
        for t in req.targets:
            u, k = t.split("|"); key = next(x for x in aws.users[u].keys if x["id"] == k); idle = (aws.clock.now() - (key["last_used"] or key["created"])) / 86400
            lines.append(f"{u}'s key {k[:8]}... (idle {int(idle)} days)")
        return {"summary": "Turn off " + ", ".join(lines) + ". Anything still using it will fail.", "cannot_undo": BY_KEY["disable_access_key"]["cannot_undo"]}

    def apply(self, eng, req, plan):
        for t in req.targets: u, k = t.split("|"); eng.adapters.aws.set_key_active(u, k, False)
        return {"summary": f"Turned off {len(req.targets)} key(s).", "undo": {"keys": list(req.targets)}, "audit": {"keys": len(req.targets)}}

    def undo(self, eng, r, d, ureq):
        for t in d["keys"]: u, k = t.split("|"); eng.adapters.aws.set_key_active(u, k, True)
        return {"summary": "Keys turned back on."}


class EnforceImdsv2:
    def preview(self, eng, req): return {"summary": f"Require the safer metadata service on {', '.join(req.targets)}. Software that only speaks the old one fails until updated.", "cannot_undo": BY_KEY["enforce_imdsv2"]["cannot_undo"]}

    def apply(self, eng, req, plan):
        prev = {t: eng.adapters.aws.require_imds_v2(t) for t in req.targets}; return {"summary": f"Safer metadata service required on {len(prev)} instance(s).", "undo": {"prev": prev}}

    def undo(self, eng, r, d, ureq):
        for t, was in d["prev"].items(): eng.adapters.aws.instances[t].imds_v2_required = was
        return {"summary": "Metadata service setting restored."}


class ReleaseOutbound:
    def preview(self, eng, req):
        if not req.params.get("reason_text"): return {"summary": "A reason is required to release a held message.", "invalid": True, "cannot_undo": []}
        return {"summary": f"Send {len(req.targets)} held message(s) as written. Once sent, a message cannot be recalled.", "cannot_undo": BY_KEY["release_outbound_message"]["cannot_undo"]}

    def apply(self, eng, req, plan):
        n = sum(bool(eng.adapters.mail.release_held(*t.split("|", 1))) for t in req.targets)
        return {"summary": f"Sent {n} held message(s).", "undo": {}, "audit": {"released": n, "email": [t.split("|")[0] for t in req.targets][:50]}}


def register_atlas(engine):
    engine.handlers.update({"block_public_access": BlockPublicAccess(), "restrict_security_group_rule": RestrictSecurityGroupRule(), "disable_access_key": DisableAccessKey(),
                            "enforce_imdsv2": EnforceImdsv2(), "release_outbound_message": ReleaseOutbound()})
