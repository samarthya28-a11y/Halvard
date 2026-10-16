"""Delegated access: how anyone outside a tenant (a service provider, Halvard's crew, a parent company) gets to touch it. There is no other way.

A grant is made BY the tenant (its owner or IT admin), names ONE grantee, ONE role, a set of scopes and an expiry, and can be revoked at once.
Every use is recorded in the TENANT's own Ledger with the grantee's identity, so the customer can always see who looked at what.
Scopes: summary (headline numbers only), cases (case summaries, people redacted unless the charter allows), act (request actions; the authority matrix still decides).
Parent-ness gives nothing: a holding company sees a child only through a grant the child made.
"""
from dataclasses import dataclass, field

SCOPES = {"summary", "cases", "act"}
MAX_MINUTES = 30 * 24 * 60
MAX_STANDING_MINUTES = 365 * 24 * 60            # Keeper charters only
OPENERS = ("owner", "it_admin")


@dataclass
class Grant:
    id: str
    tenant: str
    grantee: str
    role: str
    region: str
    scopes: frozenset
    opened_by: str
    expires: float
    standing: bool = False
    revoked: bool = False


class Delegations:
    def __init__(self, clock): self.clock, self.grants, self._n = clock, {}, 0

    def open(self, tenant, opener, grantee, role, region, scopes, minutes, ledger, standing=False):
        if opener.tenant != tenant or opener.role not in OPENERS: raise PermissionError("Only the company's own owner or IT admin can open access to it.")
        if not scopes or not set(scopes) <= SCOPES: raise ValueError(f"scopes must be a non-empty subset of {sorted(SCOPES)}")
        if role not in ("service_provider", "keeper_crew", "group_admin"): raise ValueError("role must be service_provider, keeper_crew or group_admin")
        cap = MAX_STANDING_MINUTES if (standing and role == "keeper_crew") else MAX_MINUTES
        if not 0 < minutes <= cap: raise ValueError(f"access lasts at most {cap // 1440} days")
        self._n += 1; g = Grant(f"dg-{self._n}", tenant, grantee, role, region, frozenset(scopes), opener.id, self.clock.now() + minutes * 60, standing and role == "keeper_crew")
        self.grants[g.id] = g
        ledger.append("fabric.access_granted", opener.id, opener.role, grantee, {"grant": g.id, "grantee": grantee, "role": role, "scopes": sorted(g.scopes), "region": region, "days": round(minutes / 1440, 1)}, controls=("FABRIC.DELEGATION",))
        return g

    def revoke(self, tenant, opener, grant_id, ledger):
        g = self.grants[grant_id]
        if opener.tenant != tenant or g.tenant != tenant or opener.role not in OPENERS: raise PermissionError("Only the company's own owner or IT admin can revoke its access grants.")
        g.revoked = True; ledger.append("fabric.access_revoked", opener.id, opener.role, g.grantee, {"grant": g.id}, controls=("FABRIC.DELEGATION",))

    def find(self, tenant, grantee, role, scope):
        for g in self.grants.values():
            if g.tenant == tenant and g.grantee == grantee and g.role == role and scope in g.scopes and not g.revoked and g.expires > self.clock.now(): return g
        return None
