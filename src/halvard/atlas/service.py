"""Atlas service: cloud account -> assurance graph -> posture findings, config-change detections, workload coverage and policy consistency.

What Atlas will not do: it does not overwrite what the customer set. Criticality and sensitivity written by a person are never replaced by
a sync or a scan; Halvard's own view is stored beside them as a suggestion with its evidence.
"""
import json

from ..signet.detectors import Finding
from ..ledger.audit import opaque
from . import posture as P
from .aws import ADMIN_PORTS, DB_PORTS

WORLD = ("0.0.0.0/0", "::/0")


def bucket_id(n): return f"s3:{n}"
def user_id(n): return f"cloud:user:{n}"
def role_id(n): return f"cloud:role:{n}"
INTERNET = "cloud:internet"


class AtlasService:
    def __init__(self, store, ctx, clock, aws, audit=None, ip_flagged=None):
        self.store, self.ctx, self.clock, self.aws, self.audit = store, ctx, clock, aws, audit
        self.ip_flagged = ip_flagged or (lambda ip: False)
        self.cursor, self.findings, self._n = 0, [], 0
        self.posture_findings = []
        self.suppressed = set()      # resources that are decoys (Hearth); they are meant to look weak and must not show as posture problems

    # ---------------- context from the graph (customer value first, Halvard's suggestion second) ----------------
    def _ent(self, rid):
        return next((e for e in self.store.entities(self.ctx) if e["entity_id"] == rid), None)

    def sensitivity_of(self, rid):
        e = self._ent(rid); return (e["sensitivity"] or e["suggested_sensitivity"]) if e else None

    def criticality_of(self, rid):
        e = self._ent(rid); return e["criticality"] if e else None

    # ---------------- graph ----------------
    def sync_graph(self):
        now, S, c, aws = self.clock.now(), self.store, self.ctx, self.aws
        def put(eid, kind, name, tags=None, **attrs):
            tags = tags or {}
            if S.has_entity(c, eid): S.update_entity(c, eid, now, attrs={**attrs, "tags": tags}); return
            S.put_entity(c, eid, kind, name, now, asset_class="production" if tags.get("env") == "prod" else "standard", criticality=tags.get("criticality") if tags.get("criticality") in ("high", "crown_jewel") else None,
                         sensitivity=None, should_be_protected=1 if kind == "workload" else 0, attrs={**attrs, "tags": tags})
        put(INTERNET, "application", "The internet", type="internet"); put(f"aws:{aws.account_id}", "application", f"AWS account {aws.account_id}", type="cloud_account")
        for n, b in aws.buckets.items(): put(bucket_id(n), "data_store", n, b.tags, type="bucket", public=b.effective_public)
        for d, db in aws.dbs.items(): put(f"rds:{d}", "data_store", d, db.tags, type="database", public=db.public)
        for n, r in aws.roles.items(): put(role_id(n), "identity", n, type="role", admin=r.admin)
        for n, u in aws.users.items(): put(user_id(n), "identity", n, type="user", source="cloud", mfa=u.mfa, admin=u.admin)
        for i, x in aws.instances.items(): put(i, "workload", x.tags.get("name", i), x.tags, type="instance", public_ip=x.public_ip, agent=x.agent_installed)
        for eid_, tags_ in [(bucket_id(n), b.tags) for n, b in aws.buckets.items()] + [(f"rds:{d}", db.tags) for d, db in aws.dbs.items()] + [(i, x.tags) for i, x in aws.instances.items()]:
            if tags_.get("owner") and S.has_entity(c, tags_["owner"]): S.put_edge(c, tags_["owner"], "owns", eid_, now)        # the tag says who answers for it
        for i, x in aws.instances.items():
            ports = aws.reachable_from_internet(i)
            if ports: S.put_edge(c, INTERNET, "can_access", i, now, ports=ports)
            if x.role: S.put_edge(c, i, "uses", role_id(x.role), now)
        for n, r in aws.roles.items():
            for b in r.buckets: S.put_edge(c, role_id(n), "can_access", bucket_id(b), now)
            for d in r.dbs: S.put_edge(c, role_id(n), "can_access", f"rds:{d}", now)
        return len(S.entities(c))

    # ---------------- posture ----------------
    def run_posture(self):
        fs = self.visible(P.run_checks(self.aws, self.sensitivity_of, self.criticality_of)); self.posture_findings = fs
        known = {e["entity_id"] for e in self.store.entities(self.ctx)}
        for f in fs:
            if f.resource in known: self.store.add_finding(self.ctx, f"posture-{f.check_id}-{f.resource}", f.resource, "posture", "Atlas", 1.0, f.evidence, self.clock.now())
        if self.audit:
            from collections import Counter
            self.audit.append("atlas.posture_run", "halvard:atlas", "system", opaque(self.aws.account_id), {"findings": len(fs), "by_severity": dict(Counter(f.severity for f in fs))}, controls=("ATLAS.POSTURE",))
        return fs

    def visible(self, fs): return [f for f in fs if f.resource not in self.suppressed]

    def paths(self): return P.internet_paths(self.aws, self.sensitivity_of, self.criticality_of)

    # ---------------- change detections ----------------
    def _f(self, ev, detector, family, entity, technique, conf, why, summary, **details):
        self._n += 1
        f = Finding(f"F-{detector}-{self._n}", detector, family, entity, technique, round(conf, 2), why, summary, [f"aws:{detector}"], ev["ts"], "aws", {"actor": ev.get("actor"), "ip": ev.get("ip"), **details})
        self.findings.append(f)
        if self.audit:
            self.audit.append("atlas.finding", "halvard:atlas", "system", opaque(entity), {"detector": detector, "technique": technique, "confidence": f.confidence, "why": why, "user": ev.get("actor"), "ip": ev.get("ip")}, controls=("ATLAS.DETECTION",))
        return f

    def poll(self):
        evs, self.cursor = self.aws.events_since(self.cursor); out = []
        for e in evs:
            k, flagged = e["kind"], bool(e.get("ip") and self.ip_flagged(e["ip"]))
            extra = "; made from an address already flagged for attacking an account here" if flagged else ""
            if k == "bucket_made_public":
                rid = bucket_id(e["bucket"]); sens = self.sensitivity_of(rid)
                out.append(self._f(e, "bucket_made_public", "cloud_exposure", rid, "T1530", 0.98 if sens == "regulated" else 0.9 if not flagged else 0.95,
                                   "public-access protections were switched off and anonymous reads now succeed" + (" on a bucket holding regulated data" if sens == "regulated" else "") + extra,
                                   f"Bucket {e['bucket']} was opened to the whole internet.", bucket=e["bucket"], sensitivity=sens))
            elif k == "sg_rule_added" and e["cidr"] in WORLD and (e["port"] in ADMIN_PORTS or e["port"] in DB_PORTS):
                kind = "remote administration" if e["port"] in ADMIN_PORTS else "database"
                out.append(self._f(e, "world_open_port", "cloud_exposure", e["sg"] if self._ent(e["sg"]) else f"aws:{self.aws.account_id}", "T1562.007", 0.9 if flagged else 0.85,
                                   f"a {kind} port ({e['port']}) was opened to anyone" + extra, f"Port {e['port']} was opened to the internet on {e['sg']}.", sg=e["sg"], port=e["port"], cidr=e["cidr"]))
            elif k == "access_key_created" and (e["actor"] != e["user"] or flagged):
                out.append(self._f(e, "foreign_access_key", "cloud_abuse", user_id(e["user"]), "T1098.001", 0.95 if flagged else 0.8,
                                   f"an access key was created for {e['user']} by someone else" + extra, f"A new access key was created for {e['user']}.", user=e["user"]))
            elif k == "admin_policy_attached":
                out.append(self._f(e, "admin_attached", "cloud_abuse", user_id(e["user"]), "T1098.003", 0.9 if flagged else 0.8, "full administrator rights were attached to an account" + extra, f"{e['user']} was given administrator rights.", user=e["user"]))
        return out

    # ---------------- workloads ----------------
    def enroll_workload(self, instance_id, agent):
        """The same agent and the same policy mechanism as a laptop (F002/F080). Registers the sensor that coverage checks."""
        self.aws.instances[instance_id].agent_installed = True
        self.store.put_sensor(self.ctx, f"ward-{instance_id}", instance_id, "ward", self.clock.now())

    def heartbeat(self, instance_id): self.store.heartbeat(self.ctx, f"ward-{instance_id}", self.clock.now())

    def workload_policy_findings(self, fleet):
        """Is every cloud workload under the same prevention policy as the rest of the estate? Production workloads must be enforcing."""
        out, ref = [], max([a.bundle.version for a in fleet.agents.values()] or [0])
        for iid, inst in self.aws.instances.items():
            a = fleet.agents.get(iid)
            if not a: continue
            if any(m != "enforce" for m in (a.bundle.prevention.get("bulk_encryption"), a.bundle.prevention.get("known_bad"))) and inst.tags.get("env") == "prod":
                out.append({"workload": iid, "kind": "prevention_not_enforcing", "severity": "high", "why": f"{iid} is a production workload and Ward is not set to block on it ({a.bundle.prevention})."})
            if a.bundle.version < ref: out.append({"workload": iid, "kind": "policy_out_of_date", "severity": "medium", "why": f"{iid} runs policy version {a.bundle.version}; the newest in the fleet is {ref}."})
        return out
