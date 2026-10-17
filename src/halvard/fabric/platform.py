"""The platform: many companies on one deployment with hard walls (F116), regional residency and customer-managed keys (F117), deployment profiles (F118).

The walls, from the bottom up:
  * one shared tenant database where every row and every foreign key carries the tenant id (the schema refuses a cross-tenant edge), every query binds the tenant from a
    context that the platform hands out only to that tenant's own people, and object storage resolves under t/<tenant>/ and refuses anything that escapes
  * a separate Ledger, seal key and device-policy key per tenant, derived from a platform secret that no tenant ever sees
  * encrypted objects under a per-tenant data key wrapped by the customer's own master key where they choose one
  * the only way in from outside a tenant is a delegation the tenant opened (fabric/delegation.py); each use is logged in THAT tenant's Ledger
Every refusal is recorded in the target tenant's Ledger. Every public method that acts for a company first checks that the caller is one of that company's enrolled members (or holds a grant the company opened); an id alone reaches nothing.
In-process code that already holds a ControlPlane object is outside this wall by design: the real wall is a service boundary (see docs/12, item 29).
"""
import hashlib, hmac, os
from dataclasses import dataclass, field
from pathlib import Path

from ..controlplane import ControlPlane
from ..ledger.audit import AuditLog
from ..relay.actions import Principal
from ..tenancy import TenantStore, SupportGrants
from .crypto import ReferenceKMS, TenantKeys, KeyUnavailable
from .delegation import Delegations
from .deployment import PROFILES, EgressPolicy, dependencies, read_bundle, BundleError
from .residency import ResidencyPolicy, REGIONS


class AccessRefused(PermissionError):
    pass


@dataclass(frozen=True)
class Member:
    """A person of a company, as that company's own staff. Only a Member of tenant T gets T's control plane."""
    tenant: str
    id: str
    role: str


@dataclass
class TenantRec:
    id: str
    cp: ControlPlane
    region: str
    deployment: str
    operated_by: str
    parent: str | None
    keys: TenantKeys
    key_owner: str
    residency: ResidencyPolicy
    egress: EgressPolicy
    bundle_version: int = 0
    was_locked: bool = False


class RoutingAudit:
    """TenantStore calls audit.append(kind, actor, role, subject=<tenant id>, ...). Route the record to that tenant's own Ledger."""
    def __init__(self, platform): self.p = platform

    def append(self, kind, actor, role, subject, data=None, controls=()):
        rec = self.p.tenants.get(subject)
        return (rec.cp.ledger if rec else self.p.ledger).append(kind, actor, role, subject, data, controls=controls)


class Platform:
    def __init__(self, root, clock, secret=b"platform-secret-0123456789abcdefgh"):
        self.root, self.clock, self.secret = Path(root), clock, secret
        self.root.mkdir(parents=True, exist_ok=True)
        self.ledger = AuditLog(str(self.root / "platform-ledger.log"), "platform", self._derive("platform-ledger"), clock)
        self.store = TenantStore(objects_root=self.root / "objects", grants=SupportGrants(clock), audit=RoutingAudit(self))
        self.tenants, self.delegations, self.members = {}, Delegations(clock), set()

    def _derive(self, label, tenant=""): return hmac.new(self.secret, f"{label}:{tenant}".encode(), "sha256").digest()

    # ---------------- tenants ----------------
    def create_tenant(self, tenant, name, region="eu-west", deployment="cloud", operated_by="customer", parent=None, kms=None, allowed_regions=None, allow_staff_from=None, egress_allow=(), **cp_kw):
        if tenant in self.tenants: raise ValueError(f"{tenant} exists")
        if deployment not in PROFILES: raise ValueError(f"deployment must be one of {sorted(PROFILES)}")
        if parent and parent not in self.tenants: raise ValueError("parent company is not on this platform")
        res = ResidencyPolicy(region, allowed_regions, allow_staff_from)
        cp = ControlPlane(str(self.root / "tenants" / tenant), self.clock, self._derive("policy", tenant), tenant=tenant, store=self.store, region=region, deployment=deployment, operated_by=operated_by,
                          ledger_key=self._derive("ledger", tenant), **cp_kw)
        keys = TenantKeys(kms or ReferenceKMS(self.clock, f"halvard-managed-{tenant}")); self.store.ciphers[tenant] = keys.unlock()
        rec = TenantRec(tenant, cp, region, deployment, operated_by, parent, keys, "customer" if kms else "halvard", res, EgressPolicy(deployment, egress_allow, cp.ledger, tenant))
        self.tenants[tenant] = rec
        if parent: self.store.db.execute("UPDATE tenant SET parent_tenant=? WHERE tenant_id=?", (parent, tenant)); self.store.db.commit()
        cp.ledger.append("fabric.tenant_created", "halvard:fabric", "system", tenant, {"region": region, "deployment": deployment, "operated_by": operated_by, "key_owner": rec.key_owner, "parent": parent}, controls=("FABRIC.DEPLOYMENT",))
        return rec

    def refresh_key(self, tenant):
        """Re-ask the customer's key service. Revoked or destroyed: the tenant's store goes to a locked cipher and every object read and write fails closed."""
        rec = self.tenants[tenant]; self.store.ciphers[tenant] = rec.keys.unlock()
        locked = not hasattr(rec.keys.cipher, "_k")
        if locked != rec.was_locked:        # record each change of state once
            rec.was_locked = locked
            rec.cp.ledger.append("fabric.key_state", "halvard:fabric", "system", tenant, {"locked": locked, "key_owner": rec.key_owner}, controls=("FABRIC.CUSTOMER_KEYS",))
        return not locked

    def locked(self, tenant): return not hasattr(self.store.ciphers.get(tenant), "_k")

    # ---------------- the company's own people ----------------
    def enroll_member(self, member: Member):
        """The company's staff are enrolled by the platform when the company is set up (in production: its identity provider). A Member that was not enrolled is a forgery."""
        self.members.add((member.tenant, member.id, member.role)); return member

    def _auth(self, member: Member):
        if not isinstance(member, Member):
            self.ledger.append("fabric.access_refused", "unknown", "outsider", "platform", {"why": "no company member was named"}, controls=("FABRIC.DELEGATION",)); raise AccessRefused("a company member must be named")
        if (member.tenant, member.id, member.role) not in self.members: self._refuse(member.tenant, member.id, "not a recognised member of this company")

    def customer(self, member: Member):
        self._auth(member)
        rec = self.tenants.get(member.tenant)
        if rec is None: raise AccessRefused("unknown company")
        self.refresh_key(member.tenant)
        if self.locked(member.tenant): self._refuse(member.tenant, member.id, "your key service has locked this company's data")
        return rec.cp

    def _refuse(self, tenant, who, why, kind="fabric.access_refused"):
        rec = self.tenants.get(tenant)
        (rec.cp.ledger if rec else self.ledger).append(kind, who, "outsider", tenant, {"why": why}, controls=("FABRIC.DELEGATION",))
        raise AccessRefused(why)

    # ---------------- everyone else: delegated access only ----------------
    def open_access(self, opener: Member, grantee, role, region, scopes, minutes, standing=False):
        self._auth(opener); rec = self.tenants[opener.tenant]
        return self.delegations.open(opener.tenant, opener, grantee, role, region, scopes, minutes, rec.cp.ledger, standing)

    def allow_access_from(self, opener: Member, region):
        """The company explicitly allows people in another region to be granted access (follow-the-sun support, a foreign parent company). Off by default."""
        self._auth(opener)
        if opener.role not in ("owner", "it_admin"): raise PermissionError("Only the company's owner or IT admin can change where its data may be accessed from.")
        if region not in REGIONS: raise ValueError(f"unknown region {region}")
        rec = self.tenants[opener.tenant]; rec.residency.allow_staff_from.add(region)
        rec.cp.ledger.append("fabric.region_allowed", opener.id, opener.role, region, {"region": region}, controls=("FABRIC.RESIDENCY",))

    def revoke_access(self, opener: Member, grant_id):
        self._auth(opener); self.delegations.revoke(opener.tenant, opener, grant_id, self.tenants[opener.tenant].cp.ledger)

    def delegated(self, tenant, grantee, role, region, scope):
        """Return the grant if (and only if) every wall allows it. Otherwise refuse, in plain words, and record why in the tenant's Ledger."""
        rec = self.tenants.get(tenant)
        if rec is None: self._refuse(tenant, grantee, "unknown company", "fabric.access_refused")
        g = self.delegations.find(tenant, grantee, role, scope)
        if g is None: self._refuse(tenant, grantee, f"{grantee} has no open '{scope}' access to this company (none was granted, it expired, or it was revoked)")
        if g.region != region: self._refuse(tenant, grantee, "the grant was made for a different region than the caller is in")
        ok, why = rec.residency.check("staff_access" if role == "keeper_crew" else "provider_access", region)
        if not ok: self._refuse(tenant, grantee, why)
        if not PROFILES[rec.deployment]["remote_staff"] and role in ("keeper_crew", "service_provider"):
            self._refuse(tenant, grantee, f"this is a {rec.deployment} deployment; remote crews and providers cannot reach it")
        self.refresh_key(tenant)
        if self.locked(tenant): self._refuse(tenant, grantee, "the company's key service has locked its data")
        rec.cp.ledger.append("fabric.delegated_access", grantee, role, tenant, {"grant": g.id, "scope": scope, "region": region}, controls=("FABRIC.DELEGATION",))
        return g

    def summary(self, tenant, grantee, role, region):
        """Headline numbers only: score, band, per-outcome scores, how many items are open. No item titles, names or paths."""
        self.delegated(tenant, grantee, role, region, "summary"); s = self.tenants[tenant].cp.board.score(Principal("fabric", "auditor"))
        items = self.tenants[tenant].cp.glass.evaluate()
        return {"tenant": tenant, "overall": s["overall"], "band": s["band"], "outcomes": {k: v["score"] for k, v in s["outcomes"].items()}, "open_items": len(items), "fix_now": sum(1 for x in items if x.tier == "now")}

    def portfolio(self, member: Member):
        """A holding company's view of its subsidiaries: only those that granted it 'summary'. Being the parent gives nothing."""
        self._auth(member); out = {}
        for t, rec in self.tenants.items():
            if rec.parent != member.tenant: continue
            try: out[t] = self.summary(t, member.id, "group_admin", self.tenants[member.tenant].region)
            except AccessRefused as e: out[t] = {"tenant": t, "access": "none", "why": str(e)}
        return out

    # ---------------- deployment ----------------
    def external_call(self, member: Member, dest, purpose, fn):
        """An outbound call made on a company's behalf. Only that company's own enrolled people can cause one."""
        self._auth(member); self.tenants[member.tenant].egress.check(dest, purpose); return fn()

    def dependency_report(self, member: Member):
        """What this company's deployment calls out to (or does instead). Only that company's own enrolled people can read it."""
        self._auth(member); return dependencies(self.tenants[member.tenant].deployment)

    def import_bundle(self, member: Member, path, vendor_key):
        """Apply a signed offline bundle (advisories, AI tool catalog, known-bad file hashes) to the member's own company. Who is asking is checked first,
        then the signature, every part's hash and the version; it applies whole or not at all."""
        self._auth(member)
        if member.role not in ("owner", "it_admin"): self._refuse(member.tenant, member.id, "only the company's owner or IT admin can apply an update bundle")
        tenant = member.tenant
        from ..glass.feed import feed_from_dict
        from ..lumen.inventory import AITool
        rec = self.tenants[tenant]
        try: man, parts = read_bundle(path, vendor_key, rec.bundle_version)
        except BundleError as e:
            rec.cp.ledger.append("fabric.bundle_refused", "halvard:fabric", "system", tenant, {"why": str(e)}, controls=("FABRIC.DEPLOYMENT",)); raise
        cp = rec.cp
        if "advisories" in parts: cp.glass.feed = cp.surface.feed = feed_from_dict(parts["advisories"])
        if "ai_catalog" in parts: cp.lumen.inventory.catalog = [AITool(**t) for t in parts["ai_catalog"]["tools"]]
        if "iocs" in parts and parts["iocs"]: cp.push_ioc(list(parts["iocs"]))
        rec.bundle_version = man["version"]
        cp.ledger.append("fabric.bundle_applied", "halvard:fabric", "system", tenant, {"version": man["version"], "parts": sorted(man["parts"])}, controls=("FABRIC.DEPLOYMENT",)); return man

    # ---------------- support and export ----------------
    def open_support_grant(self, opener: Member, staff_principal, minutes, staff_region):
        """Halvard staff reach a tenant only through this, only if the profile allows remote staff, and only from a region the tenant's residency allows."""
        self._auth(opener); rec = self.tenants[opener.tenant]
        if opener.role not in ("owner", "it_admin"): raise PermissionError("Only the company's owner or IT admin can open a support grant.")
        if not PROFILES[rec.deployment]["remote_staff"]: self._refuse(opener.tenant, staff_principal, f"{rec.deployment} deployments do not accept remote Halvard staff", "fabric.support_refused")
        ok, why = rec.residency.check("staff_access", staff_region)
        if not ok: self._refuse(opener.tenant, staff_principal, why, "fabric.support_refused")
        gid = self.store.grants.open(opener.tenant, staff_principal, minutes, opener.id)
        rec.cp.ledger.append("fabric.support_grant", opener.id, opener.role, staff_principal, {"grant": gid, "minutes": minutes, "region": staff_region}, controls=("FABRIC.DELEGATION",)); return gid

    def export(self, member: Member, destination_region):
        """The customer's data export (F128 in spirit): refused if the destination region is outside the tenant's residency. Only the company's own owner or IT admin can ask."""
        self._auth(member)
        if member.role not in ("owner", "it_admin"): self._refuse(member.tenant, member.id, "only the company's owner or IT admin can export its data", "fabric.export_refused")
        tenant = member.tenant
        rec = self.tenants[tenant]; self.refresh_key(tenant)
        if self.locked(tenant): self._refuse(tenant, "halvard:fabric", "the company's key service has locked its data; nothing can be exported", "fabric.export_refused")
        ok, why = rec.residency.check("export", destination_region)
        rec.cp.ledger.append("fabric.export_" + ("allowed" if ok else "refused"), "halvard:fabric", "system", tenant, {"to_region": destination_region}, controls=("FABRIC.RESIDENCY",))
        if not ok: raise AccessRefused(why)
        return True
