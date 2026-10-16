"""Tenant isolation. Every read and write takes a TenantContext; there is no unscoped query path.

Isolation is enforced three ways: (1) SQL always binds tenant_id from the context, never from caller input;
(2) the schema's composite foreign keys refuse cross-tenant edges; (3) object storage resolves paths under
t/<tenant>/ and refuses anything that escapes. Support staff see a tenant only through a time-boxed grant.
Failures are closed (raise) and recorded.
"""
import json, sqlite3
from dataclasses import dataclass
from pathlib import Path

SCHEMA = (Path(__file__).parent / "graph" / "schema.sql").read_text(encoding="utf-8")


class TenantIsolationError(PermissionError):
    pass


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    principal: str
    role: str
    support_grant: str | None = None   # grant id when acting as Halvard support


class SupportGrants:
    def __init__(self, clock):
        self.clock, self._g = clock, {}

    def open(self, tenant_id, staff_principal, minutes, opened_by_customer: str):
        gid = f"grant-{len(self._g)+1}"
        self._g[gid] = (tenant_id, staff_principal, self.clock.now() + minutes * 60, opened_by_customer)
        return gid

    def valid(self, ctx: TenantContext):
        g = self._g.get(ctx.support_grant)
        return bool(g and g[0] == ctx.tenant_id and g[1] == ctx.principal and self.clock.now() < g[2])


class TenantStore:
    def __init__(self, db_path=":memory:", objects_root=None, grants: SupportGrants | None = None, audit=None):
        self.db = sqlite3.connect(db_path)
        self.db.executescript(SCHEMA)
        self.objects_root = Path(objects_root) if objects_root else None
        self.grants, self.audit = grants, audit
        self.registered = set()
        self.ciphers = {}          # tenant -> object cipher (customer-managed or Halvard-managed key); see fabric/crypto.py

    # -- guards --
    def _guard(self, ctx: TenantContext):
        if ctx.tenant_id not in self.registered:
            self._deny(ctx, "unknown tenant")
        if ctx.role in ("halvard_support",):
            if not (self.grants and self.grants.valid(ctx)):
                self._deny(ctx, "no open support grant")

    def _deny(self, ctx, why):
        if self.audit:
            self.audit.append("tenant.access_denied", ctx.principal, ctx.role, ctx.tenant_id, {"why": why},
                              controls=("TENANCY.ISOLATION",))
        raise TenantIsolationError(why)

    def create_tenant(self, tenant_id, name, region="eu-west", deployment="cloud", operated_by="customer"):
        self.db.execute("INSERT INTO tenant(tenant_id,name,region,deployment,operated_by) VALUES(?,?,?,?,?)",
                        (tenant_id, name, region, deployment, operated_by))
        self.registered.add(tenant_id); self.db.commit()

    # -- entities --
    def put_entity(self, ctx, entity_id, kind, display_name, now, **kw):
        self._guard(ctx)
        cols = {"criticality": None, "sensitivity": None, "asset_class": "standard", "should_be_protected": 1,
                "site_id": None, "attrs": "{}"}
        cols.update(kw)
        cols["attrs"] = cols["attrs"] if isinstance(cols["attrs"], str) else json.dumps(cols["attrs"])
        self.db.execute("""INSERT OR REPLACE INTO entity(tenant_id,entity_id,kind,display_name,site_id,criticality,
            sensitivity,asset_class,should_be_protected,attrs,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (ctx.tenant_id, entity_id, kind, display_name, cols["site_id"], cols["criticality"],
                         cols["sensitivity"], cols["asset_class"], cols["should_be_protected"], cols["attrs"], now, now))
        self.db.commit()

    def get_entity(self, ctx, entity_id):
        self._guard(ctx)
        cur = self.db.execute("SELECT * FROM entity WHERE tenant_id=? AND entity_id=?", (ctx.tenant_id, entity_id))
        row = cur.fetchone()
        if not row:
            raise KeyError(entity_id)   # same answer whether it exists in another tenant or nowhere
        return dict(zip([c[0] for c in cur.description], row))

    def list_entities(self, ctx, kind=None):
        self._guard(ctx)
        q, a = "SELECT entity_id FROM entity WHERE tenant_id=?", [ctx.tenant_id]
        if kind:
            q += " AND kind=?"; a.append(kind)
        return [r[0] for r in self.db.execute(q, a)]

    def add_edge(self, ctx, src, rel, dst, now):
        self._guard(ctx)
        self.db.execute("INSERT INTO edge(tenant_id,src,rel,dst,observed_at) VALUES(?,?,?,?,?)",
                        (ctx.tenant_id, src, rel, dst, now)); self.db.commit()

    def add_edge_raw(self, tenant_id, src, rel, dst, dst_tenant, now):
        """Test hook for the cross-tenant edge attempt: the schema must refuse it."""
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("INSERT INTO edge(tenant_id,src,rel,dst,observed_at) VALUES(?,?,?,?,?)", (tenant_id, src, rel, dst, now))

    # -- object storage --
    def object_path(self, ctx, key):
        self._guard(ctx)
        base = (self.objects_root / "t" / ctx.tenant_id).resolve()
        p = (base / key).resolve()
        if base != p and base not in p.parents:
            self._deny(ctx, "object path escapes tenant prefix")
        return p

    def put_object(self, ctx, key, data: bytes):
        p = self.object_path(ctx, key); p.parent.mkdir(parents=True, exist_ok=True)
        c = self.ciphers.get(ctx.tenant_id); p.write_bytes(c.seal(data) if c else data)

    def get_object(self, ctx, key):
        p = self.object_path(ctx, key)
        if not p.exists():
            raise KeyError(key)
        c = self.ciphers.get(ctx.tenant_id); raw = p.read_bytes()
        return c.unseal(raw) if c else raw


# ---- sensors, findings (kept here so every query goes through the tenant guard) ----
def _put_sensor(self, ctx, sensor_id, entity_id, kind, now, promised_interval_s=900, version="0.1"):
    self._guard(ctx)
    self.db.execute("INSERT OR REPLACE INTO sensor(tenant_id,sensor_id,entity_id,kind,version,last_heartbeat,promised_interval_s)"
                    " VALUES(?,?,?,?,?,?,?)", (ctx.tenant_id, sensor_id, entity_id, kind, version, now, promised_interval_s))
    self.db.commit()


def _heartbeat(self, ctx, sensor_id, now):
    self._guard(ctx)
    self.db.execute("UPDATE sensor SET last_heartbeat=? WHERE tenant_id=? AND sensor_id=?", (now, ctx.tenant_id, sensor_id))
    self.db.commit()


def _protected_entities(self, ctx):
    """Entities that should be protected, with their sensor heartbeat state."""
    self._guard(ctx)
    cur = self.db.execute("""SELECT e.entity_id,e.display_name,e.criticality,e.kind,s.sensor_id,s.last_heartbeat,s.promised_interval_s
        FROM entity e LEFT JOIN sensor s ON s.tenant_id=e.tenant_id AND s.entity_id=e.entity_id AND s.kind='ward'
        WHERE e.tenant_id=? AND e.should_be_protected=1 AND e.kind IN ('device','workload')""", (ctx.tenant_id,))
    return [dict(zip([c[0] for c in cur.description], r)) for r in cur]


def _add_finding(self, ctx, finding_id, entity_id, kind, module, confidence, evidence, now):
    self._guard(ctx)
    self.db.execute("INSERT OR REPLACE INTO finding(tenant_id,finding_id,entity_id,kind,module,confidence,evidence,created_at)"
                    " VALUES(?,?,?,?,?,?,?,?)", (ctx.tenant_id, finding_id, entity_id, kind, module, confidence,
                                                  json.dumps(evidence), now))
    self.db.commit()


def _findings(self, ctx, kind=None):
    self._guard(ctx)
    q, a = "SELECT finding_id,entity_id,kind,confidence,evidence FROM finding WHERE tenant_id=?", [ctx.tenant_id]
    if kind: q += " AND kind=?"; a.append(kind)
    return self.db.execute(q, a).fetchall()


TenantStore.put_sensor, TenantStore.heartbeat, TenantStore.protected_entities = _put_sensor, _heartbeat, _protected_entities
TenantStore.add_finding, TenantStore.findings = _add_finding, _findings


def _entities(self, ctx):
    self._guard(ctx)
    cur = self.db.execute("SELECT * FROM entity WHERE tenant_id=?", (ctx.tenant_id,))
    names = [c[0] for c in cur.description]; out = []
    for r in cur.fetchall():
        d = dict(zip(names, r)); d["attrs"] = json.loads(d["attrs"] or "{}"); out.append(d)
    return out


def _edges(self, ctx, rel=None):
    self._guard(ctx)
    q, a = "SELECT src,rel,dst,attrs FROM edge WHERE tenant_id=?", [ctx.tenant_id]
    if rel: q += " AND rel=?"; a.append(rel)
    return [(s, r, d, json.loads(at or "{}")) for s, r, d, at in self.db.execute(q, a)]


def _put_edge(self, ctx, src, rel, dst, now, **attrs):
    self._guard(ctx)
    self.db.execute("INSERT OR REPLACE INTO edge(tenant_id,src,rel,dst,attrs,observed_at) VALUES(?,?,?,?,?,?)",
                    (ctx.tenant_id, src, rel, dst, json.dumps(attrs), now)); self.db.commit()


def _set_finding_case(self, ctx, finding_id, case_id, technique=None):
    self._guard(ctx)
    self.db.execute("UPDATE finding SET case_id=?, technique=COALESCE(?,technique) WHERE tenant_id=? AND finding_id=?", (case_id, technique, ctx.tenant_id, finding_id)); self.db.commit()


TenantStore.entities, TenantStore.edges, TenantStore.put_edge, TenantStore.set_finding_case = _entities, _edges, _put_edge, _set_finding_case


_ENTITY_UPDATABLE = {"display_name", "criticality", "sensitivity", "asset_class", "should_be_protected", "suggested_criticality", "suggested_sensitivity", "suggestion_evidence", "attrs", "site_id"}


def _update_entity(self, ctx, entity_id, now=None, **fields):
    """Change named columns only. Column names come from a fixed list, never from callers' strings."""
    self._guard(ctx)
    bad = set(fields) - _ENTITY_UPDATABLE
    if bad: raise ValueError(f"cannot update {sorted(bad)}")
    if "attrs" in fields and not isinstance(fields["attrs"], str): fields["attrs"] = json.dumps(fields["attrs"])
    if "suggestion_evidence" in fields and not isinstance(fields["suggestion_evidence"], str): fields["suggestion_evidence"] = json.dumps(fields["suggestion_evidence"])
    sets = ", ".join(f"{k}=?" for k in fields) + (", last_seen=?" if now is not None else "")
    cur = self.db.execute(f"UPDATE entity SET {sets} WHERE tenant_id=? AND entity_id=?", (*fields.values(), *( [now] if now is not None else []), ctx.tenant_id, entity_id))
    self.db.commit(); return cur.rowcount


def _has_entity(self, ctx, entity_id):
    self._guard(ctx)
    return self.db.execute("SELECT 1 FROM entity WHERE tenant_id=? AND entity_id=?", (ctx.tenant_id, entity_id)).fetchone() is not None


TenantStore.update_entity, TenantStore.has_entity = _update_entity, _has_entity
