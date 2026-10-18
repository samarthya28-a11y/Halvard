"""Keeper (F120): a crew that works for many companies from one desk, and for each one only inside a written list of what it may do.

What bounds the crew, in the order it is checked:
  1. the crew member is assigned to the company
  2. the company opened a standing grant to Keeper (scopes cases and act), recorded in its Ledger; the customer can revoke it at once
  3. the crew member's region is allowed by the company's residency; the deployment profile allows remote crews at all
  4. the crew member has a just-in-time elevation for THAT company (minutes, not days), recorded
  5. the company's charter lists the action; in out-of-hours mode the action falls outside the company's business hours
  6. the authority matrix: Keeper may do 'within_auto' actions only where the cell is auto/notify, may only PROPOSE 'propose_only' ones (a customer approver runs them), and may never do 'never' ones
Crew see case summaries with people's names replaced by stable pseudonyms unless the charter says otherwise. Raw telemetry and hunting are not part of the desk at all.
Nothing a crew member does in one company is visible from another. The customer's report is read from its own Ledger.
"""
import re, time
from dataclasses import dataclass, field

from ..ledger.audit import opaque
from ..relay.actions import ActionRequest, Principal
from ..relay.matrix_def import BY_KEY

MAX_ELEVATION_MIN = 120


@dataclass
class Charter:
    tenant: str
    actions: frozenset
    mode: str                     # always | out_of_hours
    business_hours: tuple         # (start_hour, end_hour) UTC; the customer's own staff cover this window
    contact: str                  # who Keeper escalates to
    see_people: bool
    signed_by: str


@dataclass
class Crew:
    id: str
    home_region: str
    tenants: set = field(default_factory=set)
    elevated: dict = field(default_factory=dict)       # tenant -> until


class KeeperDesk:
    def __init__(self, platform):
        self.p, self.charters, self.crew = platform, {}, {}

    def hire(self, crew_id, home_region): self.crew[crew_id] = Crew(crew_id, home_region); return self.crew[crew_id]
    def assign(self, crew_id, tenant): self.crew[crew_id].tenants.add(tenant)

    # ---------------- the customer's side ----------------
    def set_charter(self, owner, actions, mode="always", business_hours=(8, 18), contact="", see_people=False, days=365):
        self.p._auth(owner)
        if owner.role not in ("owner", "it_admin"): raise PermissionError("Only the company's owner or IT admin can set Keeper's charter.")
        actions = frozenset(actions)
        for a in actions:
            if a not in BY_KEY: raise ValueError(f"{a} is not an action in the authority matrix")
            if BY_KEY[a]["keeper"] == "never": raise ValueError(f"{a} can never be done by Keeper; the matrix forbids it")
        if mode not in ("always", "out_of_hours"): raise ValueError("mode must be always or out_of_hours")
        rec = self.p.tenants[owner.tenant]
        self.charters[owner.tenant] = Charter(owner.tenant, actions, mode, business_hours, contact, see_people, owner.id)
        g = self.p.open_access(owner, "keeper", "keeper_crew", "*", {"cases", "act"}, days * 1440, standing=True)
        rec.cp.ledger.append("fabric.keeper_charter", owner.id, owner.role, "keeper", {"actions": sorted(actions), "mode": mode, "see_people": see_people, "grant": g.id}, controls=("KEEPER.CHARTER",))
        return g

    def report(self, owner):
        """What Keeper did in this company, read from the company's own Ledger."""
        self.p._auth(owner)
        if owner.role not in ("owner", "it_admin", "auditor"): raise PermissionError("Keeper's activity report is for the company's owner, IT admin or auditor.")
        led = self.p.tenants[owner.tenant].cp.ledger
        return [{"ts": r["ts"], "kind": r["kind"], **{k: v for k, v in r["public"].items() if k in ("crew", "action", "status", "case", "reason_class", "why", "minutes")}} for r in led.entries() if r["kind"].startswith("fabric.keeper_") and r["kind"] != "fabric.keeper_charter"]

    # ---------------- the crew's side ----------------
    def _gate(self, crew, tenant, scope):
        c = self.crew.get(crew)
        if c is None or tenant not in c.tenants: self.p._refuse(tenant, crew, "this crew member is not assigned to this company")
        ch = self.charters.get(tenant)
        if ch is None: self.p._refuse(tenant, crew, "this company has no Keeper charter")
        # the platform checks grant, region, deployment, key state and records the access
        g = self.p.delegations.find(tenant, "keeper", "keeper_crew", scope)
        if g is None: self.p._refuse(tenant, crew, "Keeper has no open access to this company")
        if g.region not in ("*", c.home_region): self.p._refuse(tenant, crew, "Keeper's access was granted for a different region than this crew member works from")
        rec = self.p.tenants[tenant]
        ok, why = rec.residency.check("staff_access", c.home_region)
        if not ok: self.p._refuse(tenant, crew, why)
        from .deployment import PROFILES
        if not PROFILES[rec.deployment]["remote_staff"] or not PROFILES[rec.deployment]["keeper"]: self.p._refuse(tenant, crew, f"this is a {rec.deployment} deployment; Keeper cannot operate it remotely")
        self.p.refresh_key(tenant)
        if self.p.locked(tenant): self.p._refuse(tenant, crew, "the company's key service has locked its data")
        return c, ch, rec

    def elevate(self, crew, tenant, minutes, reason):
        c, ch, rec = self._gate(crew, tenant, "act")
        if not reason.strip(): raise ValueError("a reason is required")
        if not 0 < minutes <= MAX_ELEVATION_MIN: raise ValueError(f"elevation lasts at most {MAX_ELEVATION_MIN} minutes")
        c.elevated[tenant] = self.p.clock.now() + minutes * 60
        rec.cp.ledger.append("fabric.keeper_elevated", crew, "keeper_crew", tenant, {"crew": crew, "minutes": minutes, "why": "recorded"}, controls=("KEEPER.JIT",)); return c.elevated[tenant]

    def _redact(self, text, rec, ch):
        if ch.see_people: return text
        for r in rec.cp.hr.records.values():
            tag = f"[person {opaque(r.person)[2:6]}]"
            whole = [x for x in (r.name, r.email, r.upn, r.sam, r.person) if x]
            parts = [t for t in re.split(r"[\s,.\-_'’]+", r.name or "") if len(t) >= 3]       # a first or family name on its own is still a person
            for n in sorted(set(whole + parts), key=len, reverse=True):
                # whole words only: "Ann" must not turn "Annual" into "[person]ual". Very short names match only as written (case-sensitive) so ordinary words survive.
                text = re.sub(r"(?<!\w)" + re.escape(n) + r"(?!\w)", tag, text, flags=re.IGNORECASE if len(n) >= 4 else 0)
        return text

    def queue(self, crew):
        """Open cases across the companies this crew member is assigned to, most urgent first. Each entry belongs to one company and carries no other company's data."""
        out = []
        for t in sorted(self.crew[crew].tenants):
            try: c, ch, rec = self._gate(crew, t, "cases")
            except PermissionError: continue
            rec.cp.ledger.append("fabric.keeper_viewed", crew, "keeper_crew", t, {"crew": crew}, controls=("KEEPER.CHARTER",))
            for case in rec.cp.cases.cases.values():
                if case.status == "closed": continue
                conf, _ = rec.cp.cases.confidence(case); f0 = case.findings[0]
                out.append({"tenant": t, "case": case.id, "headline": self._redact(f0.summary, rec, ch), "confidence": round(conf, 2), "status": case.status, "needs_a_person": len(case.pending), "done": len(case.actions)})
        return sorted(out, key=lambda x: (-x["confidence"], x["tenant"], x["case"]))

    def case_view(self, crew, tenant, case_id):
        c, ch, rec = self._gate(crew, tenant, "cases"); case = rec.cp.cases.cases[case_id]
        return self._redact(rec.cp.cases.page(case), rec, ch)

    def _hours_ok(self, ch):
        if ch.mode == "always": return True
        h = time.gmtime(self.p.clock.now()).tm_hour; return not (ch.business_hours[0] <= h < ch.business_hours[1])

    def act(self, crew, tenant, action, targets, reason, case_id=None, params=None):
        c, ch, rec = self._gate(crew, tenant, "act")
        until = c.elevated.get(tenant, 0)
        if until <= self.p.clock.now():
            rec.cp.ledger.append("fabric.keeper_refused", crew, "keeper_crew", tenant, {"crew": crew, "action": action, "why": "no elevation"}, controls=("KEEPER.JIT",))
            raise PermissionError("elevation required for this company: ask for just-in-time access first")
        if action not in ch.actions:
            rec.cp.ledger.append("fabric.keeper_refused", crew, "keeper_crew", tenant, {"crew": crew, "action": action, "why": "not in the charter"}, controls=("KEEPER.CHARTER",))
            raise PermissionError(f"{action} is not on this company's Keeper charter")
        if not self._hours_ok(ch):
            rec.cp.ledger.append("fabric.keeper_refused", crew, "keeper_crew", tenant, {"crew": crew, "action": action, "why": "inside business hours"}, controls=("KEEPER.CHARTER",))
            raise PermissionError("this charter lets Keeper act only out of hours; the company's own team covers business hours")
        res = rec.cp.engine.request(ActionRequest(action, Principal(crew, "keeper_crew", elevated_until=until), list(targets), reason, case_id, params or {}))
        rec.cp.ledger.append("fabric.keeper_action", crew, "keeper_crew", tenant, {"crew": crew, "action": action, "status": res.status, "case": case_id}, controls=("KEEPER.CHARTER",))
        return res
