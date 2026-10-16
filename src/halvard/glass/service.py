"""Glass: what is open, in what order, what holds it shut until a patch lands, and whether the patch is safe to roll out.

State kept here (controls, rings, plans, exceptions, accepted risks) is in memory in the reference build; the Ledger holds the history of
every change. A production build stores them in the assurance graph beside the entity they concern.
"""
from dataclasses import dataclass, field

from ..relay.actions import ActionRequest, Principal
from . import baseline as B
from .exposure import Exposure, make, value_weight, SEV_W, DEFAULT_SLA_DAYS
from .feed import vkey

RING_ORDER = ("pilot", "early", "broad", "critical")
ROLE_OPS = {
    "view_exposures": {"it_admin", "analyst", "owner"},
    "compensate": {"it_admin", "analyst"},
    "extend_control": {"it_admin"},
    "accept_risk": {"owner"},
    "grant_exception": {"it_admin"},
    "manage_rings": {"it_admin"},
    "view_board": {"owner", "it_admin", "analyst", "auditor"},
}
MAX_CONTROL_DAYS, MAX_EXTENSIONS, MAX_EXTENSION_DAYS, MAX_RISK_DAYS, MAX_EXCEPTION_DAYS = 30, 2, 14, 90, 90
SYSTEM = Principal("halvard:auto", "system")


@dataclass
class Control:
    id: str
    exposure: str
    advisory: str | None
    entity: str
    kind: str
    targets: list
    app: str | None
    applied_at: float
    expires_at: float
    reason: str
    extensions: int = 0
    status: str = "active"        # active | expired | retired | removed
    warned: set = field(default_factory=set)


@dataclass
class RingState:
    ring: str
    devices: list
    status: str = "pending"       # pending | awaiting_approval | soaking | passed | halted
    started: float | None = None
    pending_id: str | None = None
    previous: dict = field(default_factory=dict)
    note: str = ""


@dataclass
class Plan:
    id: str
    product: str
    version: str
    soak_s: int
    rings: list
    actor: Principal
    status: str = "running"       # running | complete | halted
    reason: str = ""


class GlassService:
    def __init__(self, store, ctx, clock, audit, feed, aws, atlas, fleet, engine, surface=None, sla=None, signet=None):
        self.store, self.ctx, self.clock, self.audit, self.feed, self.aws, self.atlas, self.fleet, self.engine = store, ctx, clock, audit, feed, aws, atlas, fleet, engine
        self.surface, self.sla, self.signet = surface, dict(sla or DEFAULT_SLA_DAYS), signet
        self.controls, self.plans, self.rings, self.exceptions, self.risks, self.first_seen, self._open = {}, {}, {}, {}, {}, {}, set()
        self._n = self._pn = 0; self._cache = {}; self.baseline = B.DEFAULT_BASELINE; self.blocked = {}     # device -> {app: {why, control}}
        self.pusher = None                                                                   # set by the control plane: pushes a signed bundle with the blocked list

    # ---------------- authorization and records ----------------
    def require(self, principal, op):
        if principal.role not in ROLE_OPS[op]:
            self._log("glass.denied", principal.id, {"op": op, "role": principal.role}, ("GLASS.AUTHORIZATION",))
            raise PermissionError(f"{op.replace('_', ' ')} needs one of: {', '.join(sorted(ROLE_OPS[op]))}")

    def _log(self, kind, subject, data, controls=("GLASS.EXPOSURE_RANKING",)):
        if self.audit: self.audit.append(kind, "halvard:glass", "system", subject, data, controls=controls)

    # ---------------- inventory ----------------
    def reports(self):
        """Latest inventory per device. An offline device cannot report, so its last report is used and marked stale."""
        for d, a in self.fleet.agents.items():
            if a.online: self._cache[d] = {**a.inventory(), "stale": False}
            elif d in self._cache: self._cache[d] = {**self._cache[d], "stale": True}
            else: self._cache[d] = {"software": {}, "settings": {}, "broken_services": [], "ts": None, "stale": True}
        return dict(self._cache)

    def _ent(self, eid): return next((e for e in self.store.entities(self.ctx) if e["entity_id"] == eid), None)

    def _value(self, eid):
        e = self._ent(eid)
        if not e: return value_weight(None, None, "standard")
        return value_weight(e["criticality"], e["sensitivity"] or e["suggested_sensitivity"], e["asset_class"])

    def _name(self, eid):
        e = self._ent(eid); return e["display_name"] if e else eid

    # ---------------- F093: the ranked list ----------------
    def _first(self, xid):
        return self.first_seen.setdefault(xid, self.clock.now())

    def _control_for(self, exposure_id):
        return next((c for c in self.controls.values() if c.exposure == exposure_id and c.status in ("active", "expired")), None)

    def _finish(self, x):
        c = self._control_for(x.id)
        if c: x.status = "compensated" if c.status == "active" else "compensation_expired"; x.note = f"Temporary protection {c.id} " + ("holds until patched" if c.status == "active" else "has passed its expiry and is still in force; a person must extend it, patch, or sign a risk acceptance")
        r = self.risks.get(x.id)
        if r and r["until"] > self.clock.now(): x.status, x.note = "accepted_risk", f"Risk accepted by {r['by']} for another {int((r['until'] - self.clock.now()) // 86400) + 1} day(s): {r['reason']}"
        return x

    def evaluate(self, principal=None):
        if principal is not None: self.require(principal, "view_exposures")
        now, out = self.clock.now(), []
        reps = self.reports()
        for d, rep in reps.items():
            reach_ports = self.aws.reachable_from_internet(d) if d in self.aws.instances else []
            for product, version in sorted(rep["software"].items()):
                for a in self.feed.matching(product, version):
                    reach = "local" if a.surface == "local" else ("internet" if reach_ports and (a.port is None or a.port in reach_ports) else "network")
                    xid = f"{a.id}@{d}"; sev = max(0.3, a.base_severity / 10)
                    comp = self._control_for(xid) is not None and self._control_for(xid).status == "active"
                    x = make(xid, "vulnerability", d, self._name(d), f"{product} {version}: {a.summary}", a.exploit, reach, self._value(d), sev, self._first(xid), now, self.sla, comp,
                             advisory=a.id, product=product, version=version, fixed_in=a.affected_below, workaround=a.workaround,
                             fix=f"Update {product} to {a.affected_below} or later.", why=[f"{a.id}: affects {product} below {a.affected_below}"])
                    if a.workaround == "restrict_exposure" and reach == "internet" and d in self.aws.instances:
                        x.fix_params = {"targets": [f"{sg}|{p}|0.0.0.0/0" for sg in self.aws.instances[d].sg_ids for p in reach_ports if any(r["port"] == p and r["cidr"] == "0.0.0.0/0" for r in self.aws.sgs[sg].rules) and (a.port is None or p == a.port)]}
                    elif a.workaround == "block_application": x.fix_params = {"targets": [d], "app": product}
                    out.append(self._finish(x))
            for dr in B.check(d, rep["settings"], self.baseline, self.exceptions, now):
                xid = f"baseline:{dr.key}@{d}"
                out.append(self._finish(make(xid, "misconfiguration", d, self._name(d), f"{dr.label} is off baseline (expected {dr.expected}, found {dr.observed})", "none", "local", self._value(d), SEV_W[dr.severity],
                                             self._first(xid), now, self.sla, fix=dr.fix, why=["configuration baseline"])))
        for f in self.atlas.posture_findings or []:
            xid = f"{f.check_id}@{f.resource}"; reach = {"internet": "internet", "internal": "network"}.get(f.exposure, "local")
            out.append(self._finish(make(xid, "misconfiguration", f.resource, self._name(f.resource), f.title, "none", reach, self._value(f.resource), SEV_W[f.severity], self._first(xid), now, self.sla,
                                         fix=f"Run {f.fix_action}." if f.fix_action else "Review and correct this setting.", why=[f.why])))
        if self.surface:
            known = {i.public_ip for i in self.aws.instances.values() if i.public_ip}
            for f in self.surface.findings(known):
                xid = f"{f['kind']}@{f['ip']}:{f['port']}"; eid = next((i for i, x in self.aws.instances.items() if x.public_ip == f["ip"]), f"ext:{f['ip']}")
                a = f.get("advisory")
                twin = next((x for x in out if a and x.id == f"{a.id}@{eid}"), None)
                if twin: twin.why.append("also confirmed from the internet side"); continue
                out.append(self._finish(make(xid, "vulnerability" if a else "misconfiguration", eid, self._name(eid) if eid != f"ext:{f['ip']}" else f["ip"], f["title"], a.exploit if a else "none", "internet",
                                             self._value(eid), SEV_W[f["severity"]], self._first(xid), now, self.sla, advisory=a.id if a else None, product=f.get("product"), version=f.get("version"),
                                             fixed_in=a.affected_below if a else None, fix="Close or restrict the port, or update the service." if not a else f"Update {f['product']} to {a.affected_below} or later.", why=f["why"])))
        out.sort(key=lambda x: (["now", "soon", "scheduled"].index(x.tier), -x.score, x.id))
        cur = {x.id for x in out}
        for x in out:
            if x.id not in self._open: self._log("glass.exposure_opened", x.id, {"exposure": x.id, "tier": x.tier, "kind": x.kind, "entity": x.entity, "ordering_number": x.score})
        for gone in sorted(self._open - cur):
            self._log("glass.exposure_closed", gone, {"exposure": gone, "age_days": round((now - self.first_seen.get(gone, now)) / 86400, 1)})
        self._open = cur
        return out

    def get(self, xid): return next((x for x in self.evaluate() if x.id == xid), None)

    # ---------------- F094: temporary protection with an expiry ----------------
    def compensate(self, principal, xid, days, reason, kind=None):
        self.require(principal, "compensate")
        if not reason.strip(): raise ValueError("a reason is required")
        if not 0 < days <= MAX_CONTROL_DAYS: raise ValueError(f"a temporary protection lasts at most {MAX_CONTROL_DAYS} days; patch or sign a risk acceptance for longer")
        x = self.get(xid)
        if x is None: raise KeyError(f"{xid} is not an open item")
        if self._control_for(xid): raise ValueError(f"{xid} already has a temporary protection")
        kind = kind or x.workaround
        if kind not in ("restrict_exposure", "block_application") or not x.fix_params.get("targets"): raise ValueError(f"no temporary protection is available for {xid}")
        self._n += 1; cid = f"cc-{self._n}"
        res = self.engine.request(ActionRequest("apply_compensating_control", principal, list(x.fix_params["targets"]), f"{reason} ({x.advisory or x.id})", None,
                                                {"kind": kind, "control_id": cid, "exposure": xid, "advisory": x.advisory, "app": x.fix_params.get("app"), "entity": x.entity,
                                                 "expires_at": self.clock.now() + days * 86400, "why": f"{x.advisory or 'a known flaw'} is open and the update is not available yet"}))
        return res

    def register_control(self, p, targets):
        c = Control(p["control_id"], p["exposure"], p.get("advisory"), p["entity"], p["kind"], list(targets), p.get("app"), self.clock.now(), p["expires_at"], p["why"])
        self.controls[c.id] = c
        self._log("glass.control_applied", c.id, {"control": c.id, "exposure": c.exposure, "kind": c.kind, "expires_in_days": round((c.expires_at - c.applied_at) / 86400, 1), "targets": len(c.targets)}, ("GLASS.COMPENSATING_CONTROL",))
        return c

    def unregister_control(self, cid):
        c = self.controls.get(cid)
        if c: c.status = "removed"; self._log("glass.control_removed", cid, {"control": cid}, ("GLASS.COMPENSATING_CONTROL",))

    def action_of(self, cid):
        return next((a for a, ex in self.engine.executed.items() if ex["req"].params.get("control_id") == cid and not ex["undone"] and ex["req"].action == "apply_compensating_control"), None)

    def review_controls(self):
        """Run every cycle. Warn before expiry; on expiry keep the protection and escalate; when the patch has landed, say the protection can come off."""
        now, notes = self.clock.now(), []
        live = {x.id for x in self.evaluate()}
        for c in self.controls.values():
            if c.status not in ("active", "expired"): continue
            if c.exposure not in live:
                c.status = "retired"; notes.append((c.id, "retired")); self._log("glass.control_retired", c.id, {"control": c.id, "why": "the patch landed"}, ("GLASS.COMPENSATING_CONTROL",)); continue
            left = (c.expires_at - now) / 86400
            for d in (3, 1):
                if 0 < left <= d and d not in c.warned: c.warned.add(d); notes.append((c.id, f"expires in {d} day(s)")); self._log("glass.control_expiring", c.id, {"control": c.id, "days_left": round(left, 1)}, ("GLASS.COMPENSATING_CONTROL",))
            if left <= 0 and c.status == "active":
                c.status = "expired"; notes.append((c.id, "expired")); self._log("glass.control_expired", c.id, {"control": c.id, "exposure": c.exposure, "still_in_force": True}, ("GLASS.COMPENSATING_CONTROL",))
        return notes

    def extend_control(self, principal, cid, days, reason):
        self.require(principal, "extend_control"); c = self.controls[cid]
        if c.status not in ("active", "expired"): raise ValueError(f"{cid} is {c.status}")
        if not reason.strip(): raise ValueError("a reason is required")
        if not 0 < days <= MAX_EXTENSION_DAYS: raise ValueError(f"an extension lasts at most {MAX_EXTENSION_DAYS} days")
        if c.extensions >= MAX_EXTENSIONS: raise ValueError(f"{cid} was already extended {MAX_EXTENSIONS} times. Patch it, or have the owner sign a risk acceptance.")
        c.extensions += 1; c.expires_at = max(c.expires_at, self.clock.now()) + days * 86400; c.status = "active"; c.warned = set()
        self._log("glass.control_extended", cid, {"control": cid, "days": days, "justification": reason, "by": principal.id, "extensions": c.extensions}, ("GLASS.COMPENSATING_CONTROL",))
        return c

    def accept_risk(self, principal, xid, days, reason):
        self.require(principal, "accept_risk")
        if not reason.strip(): raise ValueError("a reason is required")
        if not 0 < days <= MAX_RISK_DAYS: raise ValueError(f"a risk acceptance lasts at most {MAX_RISK_DAYS} days")
        self.risks[xid] = {"by": principal.id, "reason": reason, "until": self.clock.now() + days * 86400}
        self._log("glass.risk_accepted", xid, {"exposure": xid, "days": days, "justification": reason, "by": principal.id}, ("GLASS.RISK_ACCEPTANCE",))

    def release_control(self, principal, cid):
        """Take a retired or no-longer-needed protection off. Goes through the same approval rules as putting it on."""
        a = self.action_of(cid)
        if a is None: raise KeyError(cid)
        return self.engine.undo(a, principal)

    # ---------------- baselines (F098) ----------------
    def grant_exception(self, principal, device, key, days, reason):
        self.require(principal, "grant_exception")
        if key not in self.baseline: raise KeyError(key)
        if not reason.strip(): raise ValueError("a reason is required")
        if not 0 < days <= MAX_EXCEPTION_DAYS: raise ValueError(f"an exception lasts at most {MAX_EXCEPTION_DAYS} days")
        self.exceptions[(device, key)] = {"until": self.clock.now() + days * 86400, "reason": reason, "by": principal.id}
        self._log("glass.baseline_exception", device, {"device": device, "key": key, "days": days, "justification": reason, "by": principal.id}, ("GLASS.BASELINE",))

    # ---------------- F095: patch rings ----------------
    def ring_of(self, device):
        if device in self.rings: return self.rings[device]
        e = self._ent(device)
        if e and (e["criticality"] == "crown_jewel" or e["asset_class"] in ("production", "clinical", "privileged")): return "critical"
        return "broad"

    def assign_ring(self, principal, device, ring):
        self.require(principal, "manage_rings")
        if ring not in RING_ORDER: raise ValueError(f"ring must be one of {RING_ORDER}")
        e = self._ent(device)
        if ring in ("pilot", "early") and e and (e["criticality"] == "crown_jewel" or e["asset_class"] in ("production", "clinical", "privileged")):
            raise ValueError(f"{device} is a crown jewel or a {e['asset_class']} host; it may not be in the {ring} ring")
        self.rings[device] = ring; self._log("glass.ring_assigned", device, {"device": device, "ring": ring, "by": principal.id}, ("GLASS.PATCH_RINGS",))

    def rollout(self, principal, product, version, soak_s=3600):
        self.require(principal, "manage_rings")
        by = {}
        for d, rep in self.reports().items():
            v = rep["software"].get(product)
            if v is not None and vkey(v) < vkey(version): by.setdefault(self.ring_of(d), []).append(d)
        if not by: raise ValueError(f"nothing needs {product} {version}")
        self._pn += 1; plan = Plan(f"plan-{self._pn}", product, version, soak_s, [RingState(r, sorted(by[r])) for r in RING_ORDER if r in by], principal)
        self.plans[plan.id] = plan
        self._log("glass.rollout_started", plan.id, {"plan": plan.id, "product": product, "version": version, "rings": {r.ring: len(r.devices) for r in plan.rings}, "by": principal.id}, ("GLASS.PATCH_RINGS",))
        return self.advance(plan.id)

    def _run_ring(self, plan, rs):
        res = self.engine.request(ActionRequest("install_update", plan.actor, list(rs.devices), f"patch ring {rs.ring}: {plan.product} {plan.version}", None, {"product": plan.product, "version": plan.version, "plan": plan.id, "ring": rs.ring}))
        return self._after_install(plan, rs, res)

    def _after_install(self, plan, rs, res):
        if res.status == "executed":
            rs.previous = {d: r.get("previous") for d, r in res.detail.get("results", {}).items()}; rs.status, rs.started = "soaking", self.clock.now()
            self._log("glass.ring_installed", plan.id, {"plan": plan.id, "ring": rs.ring, "devices": len(rs.devices), "queued": sum(1 for r in res.detail.get("results", {}).values() if r.get("status") == "queued")}, ("GLASS.PATCH_RINGS",))
        elif res.status in ("pending_approval", "pending_pattern_acceptance"): rs.status, rs.pending_id, rs.note = "awaiting_approval", res.action_id, res.message
        else: rs.status, rs.note = "halted", res.message; plan.status, plan.reason = "halted", res.message
        return res

    def approve_ring(self, plan_id, approver):
        plan = self.plans[plan_id]; rs = next(r for r in plan.rings if r.status == "awaiting_approval")
        res = self.engine.approve(rs.pending_id, approver)
        if res.status == "executed": rs.pending_id = None; self._after_install(plan, rs, res)
        return res

    def _unhealthy(self, rs, plan):
        reps = self.reports(); return sorted(d for d in rs.devices if reps[d]["broken_services"])

    def _halt(self, plan, rs, bad):
        rs.status, plan.status = "halted", "halted"
        plan.reason = f"{plan.product} {plan.version} broke things on {', '.join(bad)}; later rings were not touched."
        self._log("glass.rollout_halted", plan.id, {"plan": plan.id, "ring": rs.ring, "devices_broken": len(bad), "product": plan.product, "version": plan.version}, ("GLASS.PATCH_RINGS",))
        if all(rs.previous.get(d) for d in bad):
            res = self.engine.request(ActionRequest("rollback_update", SYSTEM, bad, plan.reason, None, {"product": plan.product, "to": {d: rs.previous[d] for d in bad}}, automatic=True, pattern="patch_failure_rollback"))
            rs.note = res.message if res.status != "executed" else "Rolled back automatically."
            return res

    def advance(self, plan_id):
        """Move a rollout forward one step. Returns plain text for the console."""
        plan = self.plans[plan_id]
        if plan.status != "running": return f"{plan.status}: {plan.reason}"
        for rs in plan.rings:
            if rs.status == "passed": continue
            if rs.status == "pending": self._run_ring(plan, rs)
            if rs.status == "awaiting_approval": return f"Waiting for an approver before {rs.ring} ring ({len(rs.devices)} device(s)): {rs.note}"
            if rs.status == "halted": return f"halted: {plan.reason or rs.note}"
            bad = self._unhealthy(rs, plan)
            if bad: self._halt(plan, rs, bad); return f"halted: {plan.reason}"
            left = rs.started + plan.soak_s - self.clock.now()
            if left > 0: return f"{rs.ring} ring updated; watching it for {int(left // 60) + 1} more minute(s) before the next ring."
            reps = self.reports(); waiting = sorted(d for d in rs.devices if reps[d]["software"].get(plan.product) != plan.version)
            if waiting: return f"{rs.ring} ring: waiting for {', '.join(waiting)} to come online and install before moving on."
            rs.status = "passed"; self._log("glass.ring_passed", plan.id, {"plan": plan.id, "ring": rs.ring, "devices": len(rs.devices)}, ("GLASS.PATCH_RINGS",))
        plan.status = "complete"; self._log("glass.rollout_complete", plan.id, {"plan": plan.id}, ("GLASS.PATCH_RINGS",))
        return "complete"
