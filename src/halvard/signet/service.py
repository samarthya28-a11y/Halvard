"""Signet service: connectors -> assurance graph -> detections -> findings, plus access paths (F061) and device-health push (F055)."""
import json
from collections import deque

from .idp import PRIVILEGED_ROLES
from .ad import PRIVILEGED_GROUPS

CRIT_ORDER = {None: 0, "low": 1, "normal": 2, "high": 3, "crown_jewel": 4}


def idp_id(upn): return f"id:idp:{upn}"
def ad_id(sam): return f"id:ad:{sam}"
def group_id(name): return f"grp:{name}"
def person_id(p): return p


def entity_of_finding(f):
    """Map a finding's entity string to its graph entity id (None for things like source addresses)."""
    e = f.entity
    if e.startswith("ip:"): return None
    return ad_id(e[3:]) if e.startswith("ad:") else idp_id(e)


class SignetService:
    def __init__(self, store, ctx, clock, idp, ad, detector, hr, audit=None, resource_acl=None, crown_jewels=(), service_accounts=()):
        self.store, self.ctx, self.clock, self.idp, self.ad, self.det, self.hr, self.audit = store, ctx, clock, idp, ad, detector, hr, audit
        self.resource_acl = resource_acl or {}           # group name -> [resource entity ids]
        self.cursors = {"idp": 0, "ad": 0}; self.last_poll = {}
        self.findings = []

    # ---------------- graph ----------------
    def sync_graph(self):
        now, S, c = self.clock.now(), self.store, self.ctx
        for r in self.hr.records.values():
            S.put_entity(c, r.person, "person", r.name, now, attrs={"dept": r.dept, "status": r.status})
        priv_cloud = {u for u, x in self.idp.users.items() if set(x.roles) & PRIVILEGED_ROLES}
        for upn, u in self.idp.users.items():
            S.put_entity(c, idp_id(upn), "identity", upn, now, asset_class="privileged" if upn in priv_cloud else "standard",
                         attrs={"type": "service" if u.is_service else "user", "source": "idp", "enabled": u.enabled, "roles": dict(u.roles), "mfa": u.mfa_enrolled})
            hr = self.hr.by_upn(upn)
            if hr: S.put_edge(c, idp_id(upn), "acts_for", hr.person, now)
        priv_ad = set(self.ad.privileged_members())
        for sam, u in self.ad.users.items():
            if u.is_computer: continue
            S.put_entity(c, ad_id(sam), "identity", sam, now, asset_class="privileged" if sam in priv_ad else "standard",
                         attrs={"type": "service" if u.is_service else "user", "source": "ad", "enabled": u.enabled, "groups": sorted(u.groups), "spns": u.spns})
            hr = self.hr.by_sam(sam)
            if hr: S.put_edge(c, ad_id(sam), "acts_for", hr.person, now)
        for g in set(self.ad.groups) | {g for gs in self.resource_acl for g in [gs]}:
            S.put_entity(c, group_id(g), "identity", g, now, asset_class="privileged" if g in PRIVILEGED_GROUPS else "standard", criticality="high" if g in PRIVILEGED_GROUPS else None, attrs={"type": "group"})
        for sam, u in self.ad.users.items():
            for g in u.groups:
                if group_id(g) in {e["entity_id"] for e in S.entities(c)}: S.put_edge(c, ad_id(sam), "member_of", group_id(g), now)
        for g, res in self.resource_acl.items():
            for rid in res: S.put_edge(c, group_id(g), "can_access", rid, now)
        for did, d in self.idp.devices.items():
            if did in {e["entity_id"] for e in S.entities(c)}:
                owner = self.hr.by_upn(d["owner"])
                if owner: S.put_edge(c, owner.person, "uses", did, now)
        return len(S.entities(c))

    def link_device(self, person, device_id, now=None):
        self.store.put_edge(self.ctx, person, "uses", device_id, now or self.clock.now())

    # ---------------- connectors ----------------
    def poll(self):
        out = []
        for src, conn in (("idp", self.idp), ("ad", self.ad)):
            evs, self.cursors[src] = conn.events_since(self.cursors[src]); self.last_poll[src] = self.clock.now()
            for ev in evs:
                for f in self.det.ingest(ev):
                    eid = entity_of_finding(f)
                    if eid and eid in {e["entity_id"] for e in self.store.entities(self.ctx)}:
                        self.store.add_finding(self.ctx, f.id, eid, f.detector, "Signet", f.confidence, f.evidence, f.ts)
                        self.store.set_finding_case(self.ctx, f.id, None, f.technique)
                    out.append(f)
                    if self.audit:
                        from ..ledger.audit import opaque
                        self.audit.append("signet.finding", "halvard:signet", "system", opaque(f.entity),
                                          {"detector": f.detector, "technique": f.technique, "confidence": f.confidence, "why": f.why, "user": f.entity}, controls=("SIGNET.DETECTION",))
        self.findings += out; return out

    def connector_health(self, max_lag_s=900):
        """Connector gaps are coverage gaps (F121): a silent IdP feed means identity attacks are invisible."""
        now = self.clock.now(); gaps = []
        for src in ("idp", "ad"):
            last = self.last_poll.get(src)
            if last is None or now - last > max_lag_s: gaps.append({"connector": src, "reason": "never polled" if last is None else f"last poll {int((now - last) // 60)} minutes ago"})
        return gaps

    # ---------------- access paths (F061) ----------------
    def access_paths(self, identity_entity, max_depth=5):
        """Every route from an identity to anything marked crown_jewel, over member_of / can_access / delegates_to / acts_for / uses."""
        ents = {e["entity_id"]: e for e in self.store.entities(self.ctx)}
        adj = {}
        for s, r, d, _ in self.store.edges(self.ctx):
            if r in ("member_of", "can_access", "delegates_to", "acts_for", "uses", "runs_on"): adj.setdefault(s, []).append((r, d))
            if r == "acts_for": adj.setdefault(d, []).append(("has_account", s))      # a person reaches whatever any of their accounts reaches
        paths, q = [], deque([(identity_entity, [identity_entity])])
        seen = {identity_entity: 0}
        while q:
            n, p = q.popleft()
            if (len(p) - 1) // 2 >= max_depth: continue       # p alternates node, relation, node ...; count hops, not tokens
            for r, d in adj.get(n, []):
                if d in p: continue
                np_ = p + [f"-{r}->", d]
                if ents.get(d, {}).get("criticality") == "crown_jewel": paths.append(np_)
                q.append((d, p + [f"-{r}->", d]))          # keep walking: a crown jewel can also be a stepping stone to another
        return [" ".join(x) for x in paths]

    # ---------------- device health into the IdP (F055) ----------------
    @staticmethod
    def device_health(agent):
        """Compliant means: agent not tampered with, not isolated, no unresolved incident, and recently heard from."""
        reasons = []
        if agent.host.isolated: reasons.append("isolated")
        if not agent.host.encryption_status()["system"]: reasons.append("disk not encrypted")
        if any(i["mode"] == "enforce" and any(r[1] != "executed" for r in i["results"]) for i in agent.incidents): reasons.append("open incident awaiting response")
        if any(e["kind"] == "ward.tamper_detected" for e in agent.spool.entries()): reasons.append("agent tampering detected")
        return {"compliant": not reasons, "reasons": reasons}

    def push_device_health(self, agent):
        h = self.device_health(agent); self.idp.set_device_compliance(agent.device_id, h["compliant"], "; ".join(h["reasons"])); return h
