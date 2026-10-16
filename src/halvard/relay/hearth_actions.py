"""Hearth actions: placing tripwires on devices and creating decoy identities. Both are reversible and previewed; neither touches an existing file or a real account."""
from .matrix_def import BY_KEY


class PlaceTripwires:
    def preview(self, eng, req):
        specs = req.params.get("specs") or []
        if not specs: return {"summary": "Name at least one tripwire.", "invalid": True, "cannot_undo": []}
        lines = [f"{d}: " + ", ".join(f"{s['path']} ({s['kind'].replace('_', ' ')})" for s in specs) for d in req.targets]
        return {"summary": "Create generated filler files that nothing should touch: " + "; ".join(lines) + ". A file that already exists at a path is left alone. A program changing an encryption tripwire is stopped on the spot.", "cannot_undo": []}

    def apply(self, eng, req, plan):
        h, res, ids = eng.adapters.hearth, {}, []
        specs = [{**s, "id": s.get("id") or h.new_id()} for s in req.params["specs"]]; ids = [s["id"] for s in specs]
        for d in req.targets: res[d] = h.set_specs(d, specs)
        return {"summary": f"Tripwires sent to {len(req.targets)} device(s)" + (f" ({sum(1 for v in res.values() if v == 'queued')} waiting for the device to come online)" if "queued" in res.values() else "") + ".",
                "undo": {"devices": list(req.targets), "ids": ids}, "audit": {"devices": len(req.targets), "tripwires": len(ids)}}

    def undo(self, eng, r, d, ureq):
        for dev in d["devices"]: eng.adapters.hearth.remove_specs(dev, d["ids"])
        return {"summary": "Tripwires removed; the files Halvard created are deleted if nobody has changed them."}


class CreateDecoyIdentity:
    def preview(self, eng, req):
        k = req.params.get("kind")
        if k not in ("idp_user", "ad_user", "aws_key"): return {"summary": "Choose idp_user, ad_user or aws_key.", "invalid": True, "cannot_undo": []}
        return {"summary": f"Create a decoy {k.replace('_', ' ')} named {req.targets[0]}. It gets no roles, no groups and no permissions, and exists only to be tried; any use raises an alarm.", "cannot_undo": []}

    def apply(self, eng, req, plan):
        d = eng.adapters.hearth.create_decoy_identity(req.params["kind"], req.targets[0], req.actor.id)
        return {"summary": f"Decoy created ({d.id}).", "undo": {"decoy": d.id}, "detail": {"decoy": d.id}, "audit": {"decoy": d.id, "kind": d.kind}}

    def undo(self, eng, r, d, ureq):
        eng.adapters.hearth.remove_decoy(d["decoy"], ureq.actor.id); return {"summary": "Decoy removed."}


def register_hearth(eng): eng.handlers["place_tripwires"], eng.handlers["create_decoy_identity"] = PlaceTripwires(), CreateDecoyIdentity()
