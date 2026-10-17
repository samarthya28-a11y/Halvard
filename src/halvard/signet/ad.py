"""Reference Active Directory: users, groups, SPNs, domain controllers, and the Windows security events a DC writes.

Event ids follow Windows: 4624 logon, 4625 failed logon, 4768 TGT request, 4769 service-ticket request, 4771 pre-auth failure,
4720 account created, 4724 password reset, 4725 account disabled, 4728/4732/4756 member added to a global/local/universal
security group, 4662 object operation (here: directory replication). Encryption type 0x17 is RC4-HMAC.
"""
from dataclasses import dataclass, field

from ..fabric.connector_auth import seal

DS_REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
DS_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
PRIVILEGED_GROUPS = {"Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Backup Operators"}


@dataclass
class ADUser:
    sam: str
    enabled: bool = True
    spns: list = field(default_factory=list)
    groups: set = field(default_factory=set)
    preauth_required: bool = True
    is_service: bool = False
    is_computer: bool = False
    pwd_last_set: float = 0.0
    manager: str | None = None
    cloud_upn: str | None = None            # hybrid link: the cloud identity synced from this account
    last_logon: float = 0.0
    interactive_logon_seen: bool = False
    description: str = ""


class ReferenceAD:
    def __init__(self, domain, clock, dcs=("DC01",)):
        self.domain, self.clock, self.dcs = domain, clock, set(dcs)
        self.users, self.groups, self.log = {}, {g: set() for g in PRIVILEGED_GROUPS}, []
        for dc in dcs: self.add_user(dc + "$", is_computer=True)

    def add_user(self, sam, **kw):
        u = ADUser(sam, pwd_last_set=self.clock.now(), **kw); self.users[sam] = u; return u

    def _ev(self, eid, dc="DC01", **fields):
        e = {"ts": self.clock.now(), "source": "ad", "event_id": eid, "dc": dc, **fields}; self.log.append(seal(e)); return e

    def events_since(self, cursor): return self.log[cursor:], len(self.log)

    # ---------------- things that happen on a domain ----------------
    def logon(self, sam, ok, src_ip, workstation, logon_type=3, kerberos=True):
        if not ok:
            return self._ev(4771 if kerberos else 4625, account=sam, src_ip=src_ip, workstation=workstation, failure="bad password")
        u = self.users[sam]; u.last_logon = self.clock.now(); u.interactive_logon_seen |= logon_type in (2, 10)
        return self._ev(4624, account=sam, src_ip=src_ip, workstation=workstation, logon_type=logon_type)

    def tgt_request(self, sam, src_ip, preauth_type=2):
        return self._ev(4768, account=sam, src_ip=src_ip, preauth_type=preauth_type)       # 0 = no pre-authentication (AS-REP roastable)

    def tgs_request(self, sam, spn, enc_type, src_ip):
        return self._ev(4769, account=sam, service=spn, enc_type=hex(enc_type), src_ip=src_ip)

    def create_user(self, by, sam, **kw):
        self.add_user(sam, **kw); return self._ev(4720, account=sam, by=by)

    def add_member(self, by, group, member):
        self.groups.setdefault(group, set()).add(member)
        if member in self.users: self.users[member].groups.add(group)
        eid = 4756 if group in ("Enterprise Admins", "Schema Admins") else 4732 if group in ("Administrators", "Account Operators", "Backup Operators") else 4728
        return self._ev(eid, group=group, member=member, by=by)

    def replicate(self, account, src_host, src_ip):
        return self._ev(4662, account=account, src_host=src_host, src_ip=src_ip, properties=[DS_REPL_GET_CHANGES, DS_REPL_GET_CHANGES_ALL])

    # ---------------- admin surface used by Signet actions ----------------
    def disable(self, sam, by="signet"):
        self.users[sam].enabled = False; self._ev(4725, account=sam, by=by)

    def enable(self, sam, by="signet"): self.users[sam].enabled = True

    def reset_password(self, sam, by="signet"):
        self.users[sam].pwd_last_set = self.clock.now(); self._ev(4724, account=sam, by=by)

    def remove_member(self, group, member):
        self.groups.get(group, set()).discard(member)
        if member in self.users: self.users[member].groups.discard(group)

    def privileged_members(self):
        out = {}
        for g in PRIVILEGED_GROUPS:
            for m in self.groups.get(g, ()): out.setdefault(m, set()).add(g)
        return out
