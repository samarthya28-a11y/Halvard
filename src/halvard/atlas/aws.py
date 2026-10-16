"""Reference AWS account: the contract Atlas codes against. It models the parts that decide exposure, and ENFORCES them:
an anonymous request to a bucket succeeds or fails according to the public-access block, ACL and policy, as in the real service
(simplified); security groups decide what the internet can reach; keys and roles decide who can read what. Config changes are
written to an event log (a CloudTrail stand-in) with the actor and source address.
"""
import secrets
from dataclasses import dataclass, field

ADMIN_PORTS = {22, 3389, 5985, 5986}
DB_PORTS = {3306, 5432, 1433, 27017, 6379, 9200, 1521}


@dataclass
class Bucket:
    name: str
    tags: dict = field(default_factory=dict)
    block_public_acls: bool = True
    ignore_public_acls: bool = True
    block_public_policy: bool = True
    restrict_public_buckets: bool = True
    acl_public_read: bool = False
    policy_public_read: bool = False
    encryption: str | None = "AES256"
    versioning: bool = True
    logging: bool = True
    objects: dict = field(default_factory=dict)

    @property
    def effective_public(self):
        return (self.acl_public_read and not self.ignore_public_acls) or (self.policy_public_read and not self.restrict_public_buckets)


@dataclass
class Instance:
    id: str
    tags: dict
    sg_ids: list
    public_ip: str | None = None
    role: str | None = None
    imds_v2_required: bool = True
    volumes_encrypted: bool = True
    state: str = "running"
    agent_installed: bool = False


@dataclass
class SecurityGroup:
    id: str
    rules: list = field(default_factory=list)       # {"port": 22, "cidr": "0.0.0.0/0", "proto": "tcp"}


@dataclass
class IAMUser:
    name: str
    mfa: bool = False
    console: bool = False
    keys: list = field(default_factory=list)        # {"id","created","last_used","active"}
    admin: bool = False
    permissions: set = field(default_factory=set)    # API actions the user's key may call (admin = all)


@dataclass
class Role:
    name: str
    admin: bool = False
    buckets: set = field(default_factory=set)       # buckets the role can read
    dbs: set = field(default_factory=set)
    ai_agent: bool = False          # tagged by the customer as the identity an AI agent runs as


@dataclass
class DB:
    id: str
    tags: dict
    public: bool = False
    encrypted: bool = True
    backup_days: int = 7
    sg_ids: list = field(default_factory=list)


class ReferenceAWS:
    def __init__(self, account_id, clock):
        self.account_id, self.clock = account_id, clock
        self.buckets, self.instances, self.sgs, self.users, self.roles, self.dbs = {}, {}, {}, {}, {}, {}
        self.trail_enabled = True; self.log = []

    def _ev(self, kind, actor, ip=None, **extra):
        e = {"ts": self.clock.now(), "source": "aws", "kind": kind, "actor": actor, "ip": ip, "account": self.account_id, **extra}; self.log.append(e); return e

    def events_since(self, cursor): return self.log[cursor:], len(self.log)

    # ---------------- provisioning ----------------
    def add_bucket(self, name, **kw): self.buckets[name] = Bucket(name, **kw); return self.buckets[name]
    def add_sg(self, sid, rules=()): self.sgs[sid] = SecurityGroup(sid, list(rules)); return self.sgs[sid]
    def add_instance(self, iid, tags, sg_ids, **kw): self.instances[iid] = Instance(iid, tags, list(sg_ids), **kw); return self.instances[iid]
    def add_role(self, name, **kw): self.roles[name] = Role(name, **kw); return self.roles[name]
    def add_user(self, name, **kw): self.users[name] = IAMUser(name, **kw); return self.users[name]
    def add_db(self, did, tags, **kw): self.dbs[did] = DB(did, tags, **kw); return self.dbs[did]
    def put_object(self, bucket, key, data: bytes): self.buckets[bucket].objects[key] = data

    # ---------------- things people do (logged) ----------------
    def make_bucket_public(self, bucket, actor, ip=None):
        b = self.buckets[bucket]; b.block_public_acls = b.ignore_public_acls = b.block_public_policy = b.restrict_public_buckets = False; b.policy_public_read = True
        self._ev("bucket_made_public", actor, ip, bucket=bucket)

    def open_sg(self, sg, port, cidr, actor, ip=None):
        self.sgs[sg].rules.append({"port": port, "cidr": cidr, "proto": "tcp"}); self._ev("sg_rule_added", actor, ip, sg=sg, port=port, cidr=cidr)

    def create_key(self, user, actor, ip=None):
        k = {"id": "AKIA" + secrets.token_hex(8).upper(), "created": self.clock.now(), "last_used": None, "active": True}; self.users[user].keys.append(k)
        self._ev("access_key_created", actor, ip, user=user, key=k["id"]); return k

    def attach_admin(self, user, actor, ip=None): self.users[user].admin = True; self._ev("admin_policy_attached", actor, ip, user=user)

    # ---------------- API calls with a key (logged; denied unless the user may do it) ----------------
    def api_call(self, key_id, action, ip=None):
        for u in self.users.values():
            for k in u.keys:
                if k["id"] != key_id: continue
                if not k["active"]: self._ev("api_call_denied", u.name, ip, key=key_id, action=action, reason="key disabled"); raise PermissionError("InvalidClientTokenId")
                k["last_used"] = self.clock.now(); ok = u.admin or action in u.permissions
                self._ev("api_call" if ok else "api_call_denied", u.name, ip, key=key_id, action=action)
                if not ok: raise PermissionError("AccessDenied")
                return True
        self._ev("api_call_denied", "unknown", ip, key=key_id, action=action, reason="unknown key"); raise PermissionError("InvalidClientTokenId")

    # ---------------- enforcement the model really does ----------------
    def anonymous_read(self, bucket, key):
        b = self.buckets[bucket]
        if not b.effective_public: raise PermissionError("AccessDenied")
        return b.objects[key]

    def reachable_from_internet(self, instance_id):
        i = self.instances[instance_id]
        if not i.public_ip: return []
        return sorted({r["port"] for sg in i.sg_ids for r in self.sgs[sg].rules if r["cidr"] in ("0.0.0.0/0", "::/0")})

    # ---------------- admin surface used by Atlas actions ----------------
    def block_public_access(self, bucket):
        b = self.buckets[bucket]; prev = (b.block_public_acls, b.ignore_public_acls, b.block_public_policy, b.restrict_public_buckets)
        b.block_public_acls = b.ignore_public_acls = b.block_public_policy = b.restrict_public_buckets = True
        self._ev("public_access_blocked", "atlas", bucket=bucket); return prev

    def restore_public_access(self, bucket, prev):
        b = self.buckets[bucket]; b.block_public_acls, b.ignore_public_acls, b.block_public_policy, b.restrict_public_buckets = prev

    def revoke_sg_rule(self, sg, rule):
        self.sgs[sg].rules = [r for r in self.sgs[sg].rules if not (r["port"] == rule["port"] and r["cidr"] == rule["cidr"])]; self._ev("sg_rule_revoked", "atlas", sg=sg, port=rule["port"])

    def authorize_sg_rule(self, sg, rule): self.sgs[sg].rules.append(dict(rule))

    def set_key_active(self, user, key_id, active):
        for k in self.users[user].keys:
            if k["id"] == key_id: k["active"] = active; self._ev("access_key_disabled" if not active else "access_key_enabled", "atlas", user=user)

    def require_imds_v2(self, instance_id): i = self.instances[instance_id]; prev = i.imds_v2_required; i.imds_v2_required = True; return prev
