"""Inventory of AI agents (F105): who runs them, which identity they act as, which tools they may call, and what that identity could REACH.

An agent is software that decides on its own which tools to call. Three ways one gets on the list: a person registers it, the gateway sees an
unknown agent call a tool (it is listed as unreviewed and its calls are refused), or an identity the customer tagged as an AI agent's is found
in the identity provider or the cloud. 'Effective permissions' are computed from what the identity can really do in those systems, not from what
the agent says it needs. A gap between the two is shown: that gap is the blast radius if the agent is manipulated.
"""
from dataclasses import dataclass, field
import fnmatch

from ..signet.service import idp_id

REGISTRARS = ("it_admin", "analyst")
REVIEWERS = ("it_admin",)


@dataclass
class AgentRecord:
    id: str
    name: str
    owner: str | None                       # a person id; every agent should have one
    identity: dict                          # {"kind": "idp_user"|"aws_role", "ref": "..."}
    tools: dict = field(default_factory=dict)      # tool -> {"actions": [...], "resources": [glob, ...]}
    tier: str = "unreviewed"                # unreviewed | reviewed
    status: str = "active"                  # active | suspended
    source: str = "registered"              # registered | observed | identity_tag
    first_seen: float = 0.0
    reviewed_by: str | None = None
    reviewed_at: float | None = None


class AgentRegistry:
    def __init__(self, clock, audit=None, idp=None, aws=None, signet=None):
        self.clock, self.audit, self.idp, self.aws, self.signet = clock, audit, idp, aws, signet
        self.agents = {}

    def _log(self, kind, subject, data):
        if self.audit: self.audit.append(kind, "halvard:lumen", "system", subject, data, controls=("LUMEN.AGENT_INVENTORY",))

    def register(self, principal, agent_id, name, owner, identity, tools):
        if principal.role not in REGISTRARS: raise PermissionError("Registering an AI agent needs it_admin or analyst")
        if not owner: raise ValueError("every AI agent needs a named owner")
        for t, spec in tools.items():
            if not spec.get("actions"): raise ValueError(f"tool {t} lists no actions")
        a = self.agents.get(agent_id)
        rec = AgentRecord(agent_id, name, owner, identity, {t: {"actions": sorted(s["actions"]), "resources": list(s.get("resources", ["*"])), "stores": list(s.get("stores", []))} for t, s in tools.items()}, "unreviewed", a.status if a else "active", "registered", self.clock.now())
        self.agents[agent_id] = rec
        self._log("lumen.agent_registered", agent_id, {"agent": agent_id, "owner": owner, "tools": sorted(tools), "identity_kind": identity["kind"], "by": principal.id}); return rec

    def review(self, principal, agent_id):
        """A review says a named person looked at the owner, the tools and the effective permissions and accepts them. Excess permission blocks it."""
        if principal.role not in REVIEWERS: raise PermissionError("Reviewing an AI agent needs it_admin")
        a = self.agents[agent_id]
        if not a.tools: raise ValueError("an agent with no declared tools cannot be reviewed")
        ex = self.excess(a)
        if ex["admin"] or ex["extra_stores"]:
            raise ValueError("its identity can reach more than its tools need: " + self.describe_excess(ex) + " Reduce the identity's access first.")
        a.tier, a.reviewed_by, a.reviewed_at = "reviewed", principal.id, self.clock.now()
        self._log("lumen.agent_reviewed", agent_id, {"agent": agent_id, "by": principal.id}); return a

    def observe(self, agent_id):
        """An unknown agent called a tool. List it, unreviewed, with no tools: it can do nothing until a person registers it."""
        if agent_id in self.agents: return self.agents[agent_id]
        a = self.agents[agent_id] = AgentRecord(agent_id, agent_id, None, {"kind": "unknown", "ref": ""}, {}, "unreviewed", "active", "observed", self.clock.now())
        self._log("lumen.agent_observed", agent_id, {"agent": agent_id}); return a

    def discover_identities(self):
        """Identities the customer tagged as AI agents' that nobody registered."""
        found = []
        if self.idp:
            for upn, u in self.idp.users.items():
                aid = f"idp:{upn}"
                if u.ai_agent and not any(a.identity == {"kind": "idp_user", "ref": upn} for a in self.agents.values()):
                    self.agents[aid] = AgentRecord(aid, u.display, None, {"kind": "idp_user", "ref": upn}, {}, "unreviewed", "active", "identity_tag", self.clock.now()); found.append(aid); self._log("lumen.agent_found_by_identity", aid, {"agent": aid})
        if self.aws:
            for n, r in self.aws.roles.items():
                aid = f"aws:{n}"
                if r.ai_agent and not any(a.identity == {"kind": "aws_role", "ref": n} for a in self.agents.values()):
                    self.agents[aid] = AgentRecord(aid, n, None, {"kind": "aws_role", "ref": n}, {}, "unreviewed", "active", "identity_tag", self.clock.now()); found.append(aid); self._log("lumen.agent_found_by_identity", aid, {"agent": aid})
        return found

    # ---- effective permissions ----
    def effective(self, a: AgentRecord):
        k, ref = a.identity.get("kind"), a.identity.get("ref")
        if k == "aws_role" and self.aws and ref in self.aws.roles:
            r = self.aws.roles[ref]; return {"admin": r.admin, "stores": sorted([f"s3:{b}" for b in r.buckets] + [f"rds:{d}" for d in r.dbs]), "roles": [], "reaches_crown_jewel": False}
        if k == "idp_user" and self.idp and ref in self.idp.users:
            u = self.idp.users[ref]; paths = self.signet.access_paths(idp_id(ref)) if self.signet else []
            stores = sorted({p.split()[-1] for p in paths})
            return {"admin": bool(set(u.roles) & {"Global Administrator", "Privileged Role Administrator"}), "stores": stores, "roles": sorted(u.roles), "reaches_crown_jewel": bool(paths)}
        return {"admin": False, "stores": [], "roles": [], "reaches_crown_jewel": False}

    def needed(self, a: AgentRecord):
        return sorted({r for spec in a.tools.values() for r in spec.get("stores", [])})     # data stores its tools legitimately need; 'resources' only limits which targets a call may name

    def excess(self, a: AgentRecord):
        eff, need = self.effective(a), self.needed(a)
        extra = [s for s in eff["stores"] if not any(fnmatch.fnmatch(s, g) for g in need)]
        return {"admin": eff["admin"], "extra_stores": extra, "reaches_crown_jewel": eff["reaches_crown_jewel"], "roles": eff["roles"]}

    @staticmethod
    def describe_excess(ex):
        bits = (["it is an administrator"] if ex["admin"] else []) + ([f"it can also reach {', '.join(ex['extra_stores'])}"] if ex["extra_stores"] else [])
        return "; ".join(bits) + "."

    def report(self):
        out = []
        for a in self.agents.values():
            ex = self.excess(a)
            out.append({"id": a.id, "name": a.name, "owner": a.owner, "tier": a.tier, "status": a.status, "source": a.source, "identity": a.identity, "tools": {t: s["actions"] for t, s in a.tools.items()},
                        "admin": ex["admin"], "extra_stores": ex["extra_stores"], "reaches_crown_jewel": ex["reaches_crown_jewel"],
                        "problems": ([] if a.owner else ["no owner"]) + (["no tools declared, so every call is refused"] if not a.tools else []) + ([self.describe_excess(ex)] if ex["admin"] or ex["extra_stores"] else []) + ([] if a.tier == "reviewed" else ["not reviewed"])})
        return sorted(out, key=lambda x: (x["tier"] == "reviewed", x["id"]))
