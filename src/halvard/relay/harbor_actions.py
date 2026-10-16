"""Harbor action (F076): file a change request in the customer's own network tool. Halvard never edits the network."""
from .matrix_def import BY_KEY


class RequestNetworkChange:
    def preview(self, eng, req):
        cr = req.params.get("change_request")
        if not cr or not cr.get("changes"): return {"summary": "There is nothing to submit.", "invalid": True, "cannot_undo": []}
        return {"summary": f"File a change request with {len(cr['changes'])} proposed rule change(s) for site {cr['site']} in your network tool. Halvard does not apply them; your network team does. " + "; ".join(f"{c['op']} {c['rule'][0]}->{c['rule'][1]}:{c['rule'][2]} ({c['why']})" for c in cr["changes"][:3]), "cannot_undo": BY_KEY["request_network_change"]["cannot_undo"]}

    def apply(self, eng, req, plan):
        tid = eng.adapters.change_tool.submit(req.params["change_request"]); return {"summary": f"Filed as {tid}. Nobody's network changed.", "undo": {"ticket": tid}, "detail": {"ticket": tid}, "audit": {"ticket": tid, "changes": len(req.params["change_request"]["changes"])}}

    def undo(self, eng, r, d, ureq): eng.adapters.change_tool.withdraw(d["ticket"]); return {"summary": f"{d['ticket']} withdrawn."}


def register_harbor(eng): eng.handlers["request_network_change"] = RequestNetworkChange()
