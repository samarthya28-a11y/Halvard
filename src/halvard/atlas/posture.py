"""Cloud posture checks (F079, F092-style hygiene). Each check states the configuration fact it rests on, the exposure, and a fix Relay can run.
They are Halvard's own checks, informed by common benchmark themes. This is NOT a claim of conformance with CIS or any other benchmark.

Severity is raised by context (is it reachable from the internet; does it hold regulated data; does the instance carry an admin role),
and the reason is written next to it. Ordering is by that severity, then exposure, then asset value. No numeric risk score is invented.
"""
from dataclasses import dataclass, field

from .aws import ADMIN_PORTS, DB_PORTS

SEV = {"low": 1, "medium": 2, "high": 3, "critical": 4}
EXP = {"none": 0, "internal": 1, "internet": 2}
DAY = 86400.0


@dataclass
class PostureFinding:
    check_id: str
    title: str
    resource: str                 # graph entity id, e.g. s3:bucket, i-123, rds:db
    severity: str
    exposure: str
    why: str
    evidence: list = field(default_factory=list)
    fix_action: str | None = None
    fix_params: dict = field(default_factory=dict)
    sensitivity: str | None = None


def _raise(sev, to): return to if SEV[to] > SEV[sev] else sev


def run_checks(aws, sensitivity_of=lambda rid: None, criticality_of=lambda rid: None, key_max_age_days=90):
    out, now = [], aws.clock.now()
    # ---- storage ----
    for n, b in aws.buckets.items():
        rid, sens = f"s3:{n}", sensitivity_of(f"s3:{n}")
        if b.effective_public:
            sev = "critical" if sens in ("regulated",) else "high"
            out.append(PostureFinding("S3_PUBLIC", f"Bucket {n} can be read by anyone on the internet", rid, sev, "internet",
                                      "anonymous reads succeed" + (" and the bucket holds regulated data" if sens == "regulated" else ""),
                                      [f"public access block: acls={b.block_public_acls}/{b.ignore_public_acls} policy={b.block_public_policy}/{b.restrict_public_buckets}", f"acl_public_read={b.acl_public_read} policy_public_read={b.policy_public_read}"],
                                      "block_public_access", {"bucket": n}, sens))
        if not b.encryption: out.append(PostureFinding("S3_NO_ENCRYPTION", f"Bucket {n} is not encrypted at rest", rid, _raise("medium", "high") if sens == "regulated" else "medium", "none", "default encryption is off", ["encryption=None"], None, {}, sens))
        if not b.versioning and sens in ("regulated", "confidential"): out.append(PostureFinding("S3_NO_VERSIONING", f"Bucket {n} holds {sens} data without versioning", rid, "low", "none", "overwritten or deleted objects cannot be recovered", ["versioning=False"], None, {}, sens))
    # ---- network and compute ----
    for iid, i in aws.instances.items():
        ports = aws.reachable_from_internet(iid); role = aws.roles.get(i.role)
        reach_sensitive = bool(role and any(sensitivity_of(f"s3:{b}") == "regulated" or criticality_of(f"s3:{b}") == "crown_jewel" for b in role.buckets))
        for p in ports:
            if p in ADMIN_PORTS:
                sev = "critical" if (role and role.admin) or reach_sensitive else "high"
                out.append(PostureFinding("SG_WORLD_ADMIN", f"Instance {iid} accepts remote administration (port {p}) from anywhere", iid, sev, "internet",
                                          "anyone can try to log in" + ("; the instance's role is an administrator" if role and role.admin else "") + ("; its role can read regulated or crown-jewel data" if reach_sensitive else ""),
                                          [f"public ip {i.public_ip}", f"port {p} open to 0.0.0.0/0"], "restrict_security_group_rule", {"sg": _sg_for(aws, i, p), "port": p, "cidr": "0.0.0.0/0"}))
            elif p in DB_PORTS:
                out.append(PostureFinding("SG_WORLD_DB", f"Instance {iid} exposes a database port ({p}) to the internet", iid, "high", "internet", "databases should not be reachable from anywhere",
                                          [f"public ip {i.public_ip}", f"port {p} open to 0.0.0.0/0"], "restrict_security_group_rule", {"sg": _sg_for(aws, i, p), "port": p, "cidr": "0.0.0.0/0"}))
        if role and role.admin and i.public_ip: out.append(PostureFinding("EC2_PUBLIC_ADMIN_ROLE", f"Public instance {iid} carries an administrator role", iid, "critical" if ports else "high", "internet" if ports else "internal",
                                                                          "if the instance is taken over, so is the whole account", [f"role {role.name} admin", f"public ip {i.public_ip}"]))
        if not i.imds_v2_required: out.append(PostureFinding("EC2_IMDSV1", f"Instance {iid} allows the old metadata service", iid, "high" if (ports and role) else "medium", "internet" if ports else "internal",
                                                              "a server-side request forgery can steal the role's credentials" + ("; the instance is reachable from the internet and has a role" if ports and role else ""),
                                                              ["imds_v2_required=False"], "enforce_imdsv2", {"instance": iid}))
        if not i.volumes_encrypted: out.append(PostureFinding("EC2_UNENCRYPTED_VOLUME", f"Instance {iid} has an unencrypted disk", iid, "medium", "none", "snapshots and detached disks are readable", ["volumes_encrypted=False"]))
    for did, d in aws.dbs.items():
        if d.public: out.append(PostureFinding("RDS_PUBLIC", f"Database {did} is publicly reachable", f"rds:{did}", "critical" if not d.encrypted else "high", "internet", "the database accepts connections from the internet" + ("" if d.encrypted else " and is not encrypted"), [f"public={d.public}", f"encrypted={d.encrypted}"]))
        if not d.encrypted: out.append(PostureFinding("RDS_UNENCRYPTED", f"Database {did} is not encrypted", f"rds:{did}", "medium", "none", "storage and backups are unencrypted", ["encrypted=False"]))
        if d.backup_days < 1: out.append(PostureFinding("RDS_NO_BACKUP", f"Database {did} has no automatic backups", f"rds:{did}", "medium", "none", "recovery after loss or ransomware depends on manual copies", [f"backup_days={d.backup_days}"]))
    # ---- identity ----
    for n, u in aws.users.items():
        if u.console and not u.mfa: out.append(PostureFinding("IAM_NO_MFA", f"User {n} signs in to the console without a second factor", f"cloud:user:{n}", "critical" if u.admin else "high", "internet", "a stolen password is enough" + ("; the user is an administrator" if u.admin else ""), ["console=True", "mfa=False"]))
        for k in u.keys:
            age = (now - k["created"]) / DAY; idle = (now - (k["last_used"] or k["created"])) / DAY
            if k["active"] and age > key_max_age_days: out.append(PostureFinding("IAM_OLD_KEY", f"User {n} has an access key {int(age)} days old", f"cloud:user:{n}", "medium", "none", f"keys older than {key_max_age_days} days should be rotated", [f"key age {int(age)} days"], "disable_access_key", {"user": n, "key": k["id"]}))
            if k["active"] and idle > key_max_age_days: out.append(PostureFinding("IAM_UNUSED_KEY", f"User {n} has an access key unused for {int(idle)} days", f"cloud:user:{n}", "high" if u.admin else "medium", "none", "an unused key is risk with no benefit", [f"idle {int(idle)} days"], "disable_access_key", {"user": n, "key": k["id"]}))
        if u.admin and not u.mfa: pass
    if not aws.trail_enabled: out.append(PostureFinding("TRAIL_OFF", "Account activity logging is off", f"aws:{aws.account_id}", "high", "none", "changes to the account leave no record", ["trail_enabled=False"]))
    out.sort(key=lambda f: (-SEV[f.severity], -EXP[f.exposure], f.check_id, f.resource))
    return out


def _sg_for(aws, inst, port):
    return next((sg for sg in inst.sg_ids if any(r["port"] == port and r["cidr"] in ("0.0.0.0/0", "::/0") for r in aws.sgs[sg].rules)), inst.sg_ids[0] if inst.sg_ids else None)


def internet_paths(aws, sensitivity_of=lambda rid: None, criticality_of=lambda rid: None):
    """Routes from the internet to data: open port -> instance -> its role -> a bucket or database. Marks routes that end at regulated or crown-jewel data."""
    out = []
    for iid, i in aws.instances.items():
        ports = aws.reachable_from_internet(iid); role = aws.roles.get(i.role)
        if not ports or not role: continue
        ends = [f"s3:{b}" for b in sorted(role.buckets)] + [f"rds:{d}" for d in sorted(role.dbs)] + (["the whole account (administrator role)"] if role.admin else [])
        for e in ends:
            out.append({"path": f"internet -> port {','.join(map(str, ports))} -> {iid} -> role {role.name} -> {e}", "end": e,
                        "critical": e.startswith("the whole") or sensitivity_of(e) == "regulated" or criticality_of(e) == "crown_jewel"})
    return sorted(out, key=lambda p: (not p["critical"], not p["end"].startswith("the whole")))
