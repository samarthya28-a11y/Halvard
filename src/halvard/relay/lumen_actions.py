"""Lumen actions (F106). Suspending an agent stops every tool call it makes; the gateway refuses them, and pending requests are dropped."""
from .matrix_def import BY_KEY


class SuspendAgent:
    def preview(self, eng, req):
        reg = eng.adapters.lumen.registry; names = []
        for t in req.targets:
            a = reg.agents.get(t.removeprefix("ai:"))
            if a is None: return {"summary": f"{t} is not on the AI agent inventory.", "invalid": True, "cannot_undo": []}
            names.append(f"{a.name} (owner {a.owner or 'unknown'})")
        return {"summary": "Suspend " + ", ".join(names) + ". Every tool call they make is refused and their waiting requests are dropped until someone resumes them.", "cannot_undo": BY_KEY["suspend_ai_agent"]["cannot_undo"]}

    def apply(self, eng, req, plan):
        g = eng.adapters.lumen.gateway; ids = [t.removeprefix("ai:") for t in req.targets]
        for i in ids: g.suspend(i, by=req.actor.id)
        return {"summary": f"Suspended {len(ids)} AI agent(s).", "undo": {"agents": ids}, "audit": {"agents": len(ids)}}

    def undo(self, eng, r, d, ureq):
        for i in d["agents"]: eng.adapters.lumen.gateway.resume(i, by=ureq.actor.id)
        return {"summary": "The AI agent(s) can make tool calls again."}


def register_lumen(eng): eng.handlers["suspend_ai_agent"] = SuspendAgent()
