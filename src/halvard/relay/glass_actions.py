"""Glass actions (F094, F095): patching through signed device commands, rolling back, and temporary protections that expire.
Each previews what restarts or stops working before it runs and keeps what is needed to undo."""
from .atlas_actions import RestrictSecurityGroupRule
from .matrix_def import BY_KEY


class InstallUpdates:
    def preview(self, eng, req):
        p = req.params
        if not p.get("product") or not p.get("version"): return {"summary": "An update needs a product and a version.", "invalid": True, "cannot_undo": []}
        lines = []
        for d in req.targets:
            a = eng.adapters.fleet.agents.get(d)
            lines.append(f"{d}: {a.host.software.get(p['product'], 'not installed')} -> {p['version']}" + ("" if a.online else " (offline: the command waits until it returns)") if a else f"{d}: not enrolled")
        return {"summary": f"Install {p['product']} {p['version']} on {len(req.targets)} device(s), restarting the program on each: " + "; ".join(lines), "cannot_undo": []}

    def apply(self, eng, req, plan):
        a, results = eng.adapters, {}
        rule = req._reqmt.level if getattr(req, "_reqmt", None) else "approve"
        for d in req.targets:
            r = a.fleet.send(d, "install_update", {"product": req.params["product"], "version": req.params["version"]}, req.reason, req.case_id, req._approvals, rule, issuer=req.actor.id)
            det = r.get("detail") or {}
            results[d] = {"status": r["status"], "previous": det.get("previous"), "healthy": det.get("healthy"), "message": r.get("message", "")}
        done = [d for d, r in results.items() if r["status"] == "executed"]
        return {"summary": f"{len(done)} of {len(req.targets)} device(s) updated" + (f"; {sum(1 for r in results.values() if r['status'] == 'queued')} waiting for the device to come online" if any(r["status"] == "queued" for r in results.values()) else "") + ".",
                "undo": {"product": req.params["product"], "prev": {d: results[d]["previous"] for d in done}}, "detail": {"results": results},
                "audit": {"product": req.params["product"], "to_version": req.params["version"], "devices": len(req.targets), "updated": len(done), "unhealthy": sum(1 for r in results.values() if r["healthy"] is False)}}

    def undo(self, eng, r, d, ureq):
        n = 0
        for dev, was in d["prev"].items():
            if was is None: continue
            res = eng.adapters.fleet.send(dev, "rollback_update", {"product": d["product"], "to_version": was}, f"undo update on {dev}", None, getattr(ureq, "_approvals", []), getattr(ureq, "_reqmt", None).level if getattr(ureq, "_reqmt", None) else "approve", issuer=ureq.actor.id)
            n += res["status"] == "executed"
        return {"summary": f"{d['product']} put back on {n} device(s)."}


class RollbackUpdates:
    def preview(self, eng, req):
        p = req.params
        if not p.get("product") or not p.get("to"): return {"summary": "A rollback needs a product and the version for each device.", "invalid": True, "cannot_undo": []}
        return {"summary": f"Put {p['product']} back on {len(p['to'])} device(s): " + "; ".join(f"{d} -> {v}" for d, v in sorted(p["to"].items())) + ". The program restarts.", "cannot_undo": BY_KEY["rollback_update"]["cannot_undo"]}

    def apply(self, eng, req, plan):
        res, rule = {}, (req._reqmt.level if getattr(req, "_reqmt", None) else "approve")
        for d, v in req.params["to"].items():
            r = eng.adapters.fleet.send(d, "rollback_update", {"product": req.params["product"], "to_version": v}, req.reason, req.case_id, req._approvals, rule, issuer=req.actor.id)
            res[d] = {"status": r["status"], "healthy": (r.get("detail") or {}).get("healthy")}
        ok = [d for d, r in res.items() if r["status"] == "executed"]
        return {"summary": f"{req.params['product']} rolled back on {len(ok)} of {len(res)} device(s).", "undo": {}, "detail": {"results": res}, "audit": {"product": req.params["product"], "devices": len(res), "rolled_back": len(ok)}}


class ApplyCompensatingControl:
    def preview(self, eng, req):
        p = req.params
        if p.get("kind") == "restrict_exposure":
            s = RestrictSecurityGroupRule().preview(eng, req)["summary"]
        elif p.get("kind") == "block_application":
            s = f"Switch off {p.get('app')} on {', '.join(req.targets)}; people cannot start it until the protection is removed."
        else: return {"summary": "Unknown kind of temporary protection.", "invalid": True, "cannot_undo": []}
        return {"summary": f"{s} This protection expires; the update is still needed.", "cannot_undo": BY_KEY["apply_compensating_control"]["cannot_undo"]}

    def apply(self, eng, req, plan):
        p = req.params; g = eng.adapters.glass
        if p["kind"] == "restrict_exposure": out = RestrictSecurityGroupRule().apply(eng, req, plan); undo = {"kind": "restrict_exposure", **out["undo"], "control": p["control_id"]}
        else:
            states = g.pusher(req.targets, p["app"], p["why"], p["control_id"]); out = {"summary": f"{p['app']} switched off on {len(req.targets)} device(s)" + (f" ({sum(1 for s in states.values() if s != 'applied')} waiting for the device to come online)" if any(s != 'applied' for s in states.values()) else "") + "."}
            undo = {"kind": "block_application", "devices": list(req.targets), "control": p["control_id"]}
        g.register_control(p, req.targets)
        return {"summary": out["summary"], "undo": undo, "detail": {"control": p["control_id"]}, "audit": {"control": p["control_id"], "kind": p["kind"], "targets": len(req.targets), "expires_at": p["expires_at"]}}

    def undo(self, eng, r, d, ureq):
        if d["kind"] == "restrict_exposure": RestrictSecurityGroupRule().undo(eng, r, d, ureq)
        else: eng.adapters.glass.pusher(d["devices"], None, None, d["control"], remove=True)
        eng.adapters.glass.unregister_control(d["control"])
        return {"summary": "The temporary protection was removed."}


def register_glass(eng):
    eng.handlers["install_update"], eng.handlers["rollback_update"] = InstallUpdates(), RollbackUpdates()
    eng.handlers["apply_compensating_control"] = ApplyCompensatingControl()
