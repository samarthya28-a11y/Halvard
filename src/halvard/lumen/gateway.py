"""The agent gateway: allow, ask or block every tool call an AI agent makes, by what it is doing and what data is in it (F106), and record
enough to explain an incident afterwards (F107).

Enforcement is real, not advisory: tools in the reference build execute only with a grant the gateway signed for that exact call (agent, tool,
action, a digest of the arguments, 60 seconds, once). A call that goes around the gateway reaches a tool with no grant and is refused.

Decisions, strictest rule wins:
  block  never runs; the agent is told why in plain words
  ask    waits for a named person; the approval is for this exact call (its digest), once, and expires; an agent cannot approve anything
  allow  runs, and is recorded

Data type: the payload is classified only if the customer's content-inspection gate allows it (purpose, notice, scope, same as Vaultline). If it is
off, Halvard says the data type is UNKNOWN and treats an unknown payload leaving the company as needing a person.
The record keeps: agent, session, step, tool, action, decision, rule, data labels and counts, argument digest, whether untrusted content had been read,
approver role. Targets (paths, addresses) go to private audit fields. Payload content is never kept.
"""
import fnmatch, hashlib, hmac, json, secrets
from dataclasses import dataclass, field

from ..addr import domain_of
from ..cases import CaseFinding
from ..vaultline.inspection import InspectionNotAllowed
from ..vaultline.dlp import RANK, SECRETS

ACTION_CLASS = {"read": "read_internal", "list": "read_internal", "query": "read_internal", "write": "write_internal", "fetch_url": "read_external", "read_mail": "read_external",
                "send": "send_external", "send_mail": "send_external", "upload": "send_external", "delete": "delete", "execute": "execute_code", "grant": "change_permissions", "pay": "spend"}
DESTRUCTIVE = {"delete", "execute_code", "change_permissions", "spend"}
LEAVING = {"send_external"}
TAINT_SENSITIVE = {"send_external", "execute_code", "change_permissions", "delete", "spend"}
ORDER = {"allow": 0, "ask": 1, "block": 2}
APPROVERS = ("it_admin", "analyst")
GRANT_TTL, ASK_TTL, RATE_WINDOW, RATE_LIMIT = 60.0, 900.0, 60.0, 30


@dataclass
class Decision:
    action: str = "allow"
    rule: str = "allowed-by-default"
    message: str = ""
    labels: dict = field(default_factory=dict)
    data_known: bool = False
    askable: bool = True
    also: list = field(default_factory=list)       # every rule that applied, strictest first; the person approving sees all of them


@dataclass
class Session:
    id: str
    agent: str
    step: int = 0
    taint: dict = field(default_factory=dict)         # source kind -> count; set when the agent read content nobody here wrote
    calls: list = field(default_factory=list)
    blocks: int = 0


class ReferenceTools:
    """Tools an agent can call. They run only with a gateway grant. `effects` is what really happened, for tests and for the incident page."""
    def __init__(self, key, clock):
        self.key, self.clock, self.used, self.effects = key, clock, set(), []
        self.files, self.pages, self.rows = {}, {}, {}
        self.mail_sent = []

    @staticmethod
    def _canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()

    def mint(self, agent, tool, action, digest):
        body = {"agent": agent, "tool": tool, "action": action, "digest": digest, "exp": self.clock.now() + GRANT_TTL, "nonce": secrets.token_hex(8)}
        return {**body, "sig": hmac.new(self.key, self._canon(body), "sha256").hexdigest()}

    def run(self, grant, tool, action, params):
        body = {k: v for k, v in (grant or {}).items() if k != "sig"}
        if not grant or not hmac.compare_digest(hmac.new(self.key, self._canon(body), "sha256").hexdigest(), grant.get("sig", "")): raise PermissionError("no valid grant from the gateway")
        if body["nonce"] in self.used: raise PermissionError("grant already used")
        if self.clock.now() > body["exp"]: raise PermissionError("grant expired")
        if (body["tool"], body["action"]) != (tool, action) or body["digest"] != digest_of(tool, action, params): raise PermissionError("grant is for a different call")
        self.used.add(body["nonce"]); return self._do(tool, action, params)

    def _do(self, tool, action, p):
        t = p.get("target")
        if tool == "files":
            if action in ("read", "list"): self.effects.append(("files", action, t)); return {"data": self.files.get(t, b""), "untrusted": False}
            if action == "write": self.files[t] = p.get("data", b""); self.effects.append(("files", "write", t)); return {"ok": True}
            if action == "delete": self.files.pop(t, None); self.effects.append(("files", "delete", t)); return {"ok": True}
        if tool == "web" and action == "fetch_url": self.effects.append(("web", "fetch", t)); return {"data": self.pages.get(t, b""), "untrusted": True, "source": "web"}
        if tool == "mail":
            if action == "send_mail": self.mail_sent.append((t, p.get("data", b""))); self.effects.append(("mail", "send", t)); return {"ok": True}
            if action == "read_mail": self.effects.append(("mail", "read", t)); return {"data": b"", "untrusted": True, "source": "email"}
        if tool == "db" and action == "query": self.effects.append(("db", "query", t)); return {"data": self.rows.get(t, b""), "untrusted": False}
        if tool == "shell" and action == "execute": self.effects.append(("shell", "execute", t)); return {"ok": True}
        raise NotImplementedError(f"{tool}.{action}")


def digest_of(tool, action, p):
    return hashlib.sha256(json.dumps([tool, action, p.get("target"), hashlib.sha256(_b(p.get("data"))).hexdigest()], sort_keys=True).encode()).hexdigest()


def _b(x): return x if isinstance(x, bytes) else (x or "").encode() if isinstance(x, str) else b""


class AgentGateway:
    def __init__(self, registry, tools, clock, audit=None, inspector=None, rate_limit=RATE_LIMIT, internal_domains=()):
        self.registry, self.tools, self.clock, self.audit = registry, tools, clock, audit
        self.inspector, self.rate_limit, self.internal_domains = inspector, rate_limit, {d.lower() for d in internal_domains}
        self.sessions, self.pending, self.findings, self._cursor, self._n, self._pn = {}, {}, [], 0, 0, 0

    def _log(self, kind, subject, data, controls=("LUMEN.AGENT_GATEWAY",)):
        if self.audit: self.audit.append(kind, "halvard:lumen", "system", subject, data, controls=controls)

    # ---------------- sessions and untrusted context ----------------
    def session(self, agent_id, sid=None):
        sid = sid or f"s-{agent_id}-{len([s for s in self.sessions.values() if s.agent == agent_id]) + 1}"
        return self.sessions.setdefault(sid, Session(sid, agent_id))

    def ingest(self, session, source, trusted=False):
        """Context the agent took in outside a tool call (a user attachment, a pasted web page). Untrusted content taints the session."""
        if not trusted: session.taint[source] = session.taint.get(source, 0) + 1

    # ---------------- the rules ----------------
    def _classify(self, agent, tool, name, data):
        """(classification, known). Nothing is read unless the customer's inspection gate allows it; then the answer is 'unknown', not 'clean'."""
        if data is None or data == b"": return None, True
        if self.inspector is None: return None, False
        try: return self.inspector.inspect(f"ai:{agent.id}:{tool}", name, _b(data), who=agent.id), True
        except InspectionNotAllowed: return None, False

    def action_class(self, action, params):
        ac = ACTION_CLASS.get(action)
        if action == "send_mail" and domain_of(str(params.get("target", ""))) in self.internal_domains: return "write_internal"       # mail to a colleague is not leaving
        return ac

    def evaluate(self, agent, session, tool, action, params, cls, known):
        ac = self.action_class(action, params)
        labels = {k: v["count"] for k, v in cls.labels.items() if v["confidence"] >= 0.7} if cls else {}
        best = Decision(labels=labels, data_known=known)
        if ac is None: return Decision("block", "agent-unknown-action", f"'{action}' is not an action Halvard knows how to judge, so it is not allowed.", labels, known, False)
        if agent.status == "suspended": return Decision("block", "agent-suspended", "This agent is suspended. Ask its owner or IT.", labels, known, False)
        spec = agent.tools.get(tool)
        if not spec or action not in spec["actions"]: return Decision("block", "agent-undeclared-tool", f"This agent is not registered to use {tool} to {action}. Register that tool for it first.", labels, known, False)
        tgt = str(params.get("target", ""))
        if not any(fnmatch.fnmatch(tgt, g) for g in spec["resources"]): return Decision("block", "agent-outside-resources", f"{tgt or 'that resource'} is outside what this agent is registered to use.", labels, known, False)
        sens = cls.sensitivity if cls else None
        also = []
        def hit(a, rule, msg, askable=True):
            nonlocal best
            also.append(rule)
            if ORDER[a] > ORDER[best.action]: best = Decision(a, rule, msg, labels, known, askable and a != "block", also)
        if set(labels) & set(SECRETS) and ac != "read_internal": hit("block", "agent-secrets", "Credentials and keys may not be moved by an agent.")
        if ac in LEAVING and sens == "regulated": hit("block", "agent-regulated-external", "Regulated data (such as card or national ID numbers) may not be sent outside the company by an agent.")
        if ac in LEAVING and sens == "confidential": hit("ask", "agent-confidential-external", "This carries confidential data outside the company. A person must approve it.")
        if ac in LEAVING and not known and params.get("data"): hit("ask", "agent-unknown-data-external", "Content inspection is off, so Halvard cannot tell what data this is. A person must approve sending it outside.")
        if ac in DESTRUCTIVE: hit("block" if agent.tier != "reviewed" else "ask", "agent-destructive", "This can delete, run code, change access or spend money. " + ("The agent has not been reviewed, so it is refused." if agent.tier != "reviewed" else "A person must approve it."))
        if session.taint and ac in TAINT_SENSITIVE:
            srcs = ", ".join(sorted(session.taint)); hit("ask", "agent-untrusted-context", f"The agent read untrusted content ({srcs}) earlier in this session, and is now asked to do something that could be a response to instructions hidden in it. A person must approve.")
            if sens in ("regulated", "confidential") and ac in LEAVING: hit("block", "agent-untrusted-context", f"After reading untrusted content ({srcs}) the agent tried to send protected data out.")
        if agent.tier != "reviewed" and ac in ("write_internal", "send_external"): hit("ask", "agent-unreviewed-write", "This agent has not been reviewed. A person must approve what it writes or sends.")
        now = self.clock.now(); recent = [t for t in session.calls if now - t <= RATE_WINDOW]
        if len(recent) >= self.rate_limit: hit("ask", "agent-runaway", f"{len(recent)} tool calls in the last minute. This looks like a loop; a person must say it should continue.")
        best.also = [best.rule] + [r for r in also if r != best.rule] if best.action != "allow" else []
        return best

    # ---------------- the call ----------------
    def call(self, agent_id, session, tool, action, params):
        """Returns {'decision','rule','message', ...}. On allow the tool has run and `result` holds what it returned."""
        agent = self.registry.agents.get(agent_id) or self.registry.observe(agent_id)
        session.step += 1; params = dict(params)
        name = str(params.get("target", "payload")).rsplit("/", 1)[-1] or "payload"
        cls, known = self._classify(agent, tool, name, params.get("data"))
        d = self.evaluate(agent, session, tool, action, params, cls, known)
        if agent.source == "observed" and d.rule == "agent-undeclared-tool": d = Decision("block", "agent-unregistered", "This agent is not on the inventory. Nothing it asks for will run until a person registers it.", d.labels, known, False)
        dig = digest_of(tool, action, params); out = {"decision": d.action, "rule": d.rule, "message": d.message, "labels": d.labels, "data_known": known, "step": session.step, "digest": dig, "rules": d.also}
        session.calls.append(self.clock.now())
        if d.action == "allow": out["result"] = self._run(agent, session, tool, action, params, dig)
        elif d.action == "ask":
            self._pn += 1; pid = f"ask-{self._pn}"; self.pending[pid] = {"agent": agent_id, "session": session.id, "tool": tool, "action": action, "params": params, "digest": dig, "step": session.step, "exp": self.clock.now() + ASK_TTL, "rule": d.rule}
            out["pending_id"] = pid
        else: session.blocks += 1
        self._record(agent, session, tool, action, params, d, dig, out)
        return out

    def _run(self, agent, session, tool, action, params, dig):
        g = self.tools.mint(agent.id, tool, action, dig); r = self.tools.run(g, tool, action, params)
        if r.get("untrusted"): self.ingest(session, r.get("source", tool))
        return {k: v for k, v in r.items() if k != "data"} | ({"data": r["data"]} if "data" in r else {})

    def _record(self, agent, session, tool, action, params, d, dig, out, extra=None):
        ac = self.action_class(action, params) or "unknown"
        data = {"agent": agent.id, "session": session.id, "step": session.step, "tool": tool, "action": action, "action_class": ac, "decision": d.action, "rule": d.rule, "labels": d.labels, "data_known": d.data_known,
                "tainted": bool(session.taint), "taint_sources": sorted(session.taint), "digest": dig, "rules": d.also, "dst": str(params.get("target", "")), "owner": agent.owner, **(extra or {})}
        self._log("lumen.tool_call", agent.id, data)
        self._find(agent, session, d, tool, action, params)

    def _find(self, agent, session, d, tool, action, params):
        spec = {"agent-regulated-external": (0.8, "tried to send regulated data outside the company"), "agent-secrets": (0.8, "tried to move credentials"), "agent-untrusted-context": (0.6, "was asked to take a sensitive action after reading untrusted content, which can mean hidden instructions"),
                "agent-unregistered": (0.5, "is not on the inventory and tried to use a tool"), "agent-runaway": (0.5, "made an unusual burst of tool calls"), "agent-destructive": (0.5, "tried a destructive action")}.get(d.rule)
        if not spec or (d.action == "allow"): return
        conf, what = spec
        if d.rule == "agent-destructive" and agent.tier == "reviewed": return
        self.findings.append(CaseFinding(f"lumen-{agent.id}-{session.id}-{session.step}", "lumen", "ai_agent_misuse", f"ai:{agent.id}", conf, f"AI agent {agent.name} {what}.", d.message, self.clock.now(), None,
                                         {"detector": d.rule, "agent": agent.id, "session": session.id, "step": session.step, "blocked": d.action == "block", "tool": tool, "action": action}))

    def poll(self):
        out, self.findings = self.findings, []
        now = self.clock.now()
        for pid in [p for p, v in self.pending.items() if v["exp"] < now]:
            v = self.pending.pop(pid); self._log("lumen.ask_expired", v["agent"], {"agent": v["agent"], "pending": pid, "tool": v["tool"], "action": v["action"]})
        return out

    # ---------------- people decide ----------------
    def approve(self, pid, approver, note=""):
        v = self.pending.get(pid)
        if v is None: return {"status": "unknown", "message": "No such request, or it expired and was refused."}
        agent = self.registry.agents[v["agent"]]
        if approver.role not in APPROVERS and approver.id != agent.owner: raise PermissionError("Only IT, an analyst or the agent's owner can approve an agent's request. An agent cannot approve anything.")
        if approver.id == agent.identity.get("ref"): raise PermissionError("An agent cannot approve its own request.")
        if self.clock.now() > v["exp"]:
            self.pending.pop(pid); return {"status": "expired", "message": "This request expired and was refused."}
        if agent.status == "suspended": return {"status": "blocked", "message": "The agent is suspended."}
        self.pending.pop(pid); session = self.sessions[v["session"]]
        r = self._run(agent, session, v["tool"], v["action"], v["params"], v["digest"])
        self._log("lumen.ask_approved", v["agent"], {"agent": v["agent"], "session": v["session"], "step": v["step"], "tool": v["tool"], "action": v["action"], "rule": v["rule"], "approver_role": approver.role, "approver": approver.id, "digest": v["digest"], "justification": note})
        return {"status": "executed", "result": r}

    def deny(self, pid, approver, note=""):
        v = self.pending.pop(pid, None)
        if v is None: return {"status": "unknown"}
        agent = self.registry.agents[v["agent"]]
        if approver.role not in APPROVERS and approver.id != agent.owner: raise PermissionError("Only IT, an analyst or the agent's owner can answer an agent's request.")
        self._log("lumen.ask_denied", v["agent"], {"agent": v["agent"], "session": v["session"], "step": v["step"], "tool": v["tool"], "action": v["action"], "rule": v["rule"], "approver_role": approver.role, "justification": note})
        return {"status": "denied"}

    # ---------------- suspend / resume (the action engine calls these) ----------------
    def suspend(self, agent_id, by="system"):
        a = self.registry.agents[agent_id]; a.status = "suspended"
        for pid in [p for p, v in self.pending.items() if v["agent"] == agent_id]: self.pending.pop(pid)
        self._log("lumen.agent_suspended", agent_id, {"agent": agent_id, "by": by})

    def resume(self, agent_id, by="system"):
        self.registry.agents[agent_id].status = "active"; self._log("lumen.agent_resumed", agent_id, {"agent": agent_id, "by": by})

    # ---------------- F107: explain an incident from the record ----------------
    def explain(self, ledger, agent_id, session_id=None):
        rows = [r for r in ledger.entries() if r["kind"] in ("lumen.tool_call", "lumen.ask_approved", "lumen.ask_denied", "lumen.agent_suspended", "lumen.agent_resumed") and r["public"].get("agent") == agent_id and (session_id is None or r["public"].get("session") in (session_id, None))]
        agent = self.registry.agents.get(agent_id); L = [f"AI agent {agent.name if agent else agent_id} (owner {agent.owner if agent else '?'}, {agent.tier if agent else '?'})" + (f", session {session_id}" if session_id else "")]
        left, blocked = [], 0
        for r in rows:
            p = r["public"]; t = int(r["ts"])
            if r["kind"] == "lumen.tool_call":
                lab = (" carrying " + ", ".join(f"{k} x{v}" for k, v in p["labels"].items())) if p["labels"] else (" (data type unknown)" if not p["data_known"] and p["action_class"] == "send_external" else "")
                L.append(f"  step {p['step']:>2}  t={t}  {p['tool']}.{p['action']} -> {p['decision'].upper()} [{p['rule']}]{lab}" + (f"; after reading untrusted {', '.join(p['taint_sources'])}" if p["tainted"] and p["action_class"] in TAINT_SENSITIVE else ""))
                if p["decision"] == "allow" and p["action_class"] == "send_external": left.append(p["step"])
                if p["decision"] == "block": blocked += 1
            elif r["kind"] == "lumen.ask_approved": L.append(f"  step {p['step']:>2}  t={t}  approved by {p['approver_role']} ({p['rule']})"); left.append(p["step"]) if p["action"] in ("send", "send_mail", "upload") else None
            elif r["kind"] == "lumen.ask_denied": L.append(f"  step {p['step']:>2}  t={t}  refused by {p['approver_role']}")
            else: L.append(f"  t={t}  {r['kind'].split('.')[1].replace('_', ' ')}")
        L.append(f"Summary: {len([r for r in rows if r['kind'] == 'lumen.tool_call'])} tool call(s), {blocked} blocked, {len(left)} sent something outside the company (steps {left or 'none'}). Payload contents are not kept; the digests identify exactly what was approved.")
        return "\n".join(L)
