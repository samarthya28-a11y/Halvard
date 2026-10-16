import os, tempfile
from helpers import *
from halvard.fabric.platform import Platform, Member, AccessRefused
from halvard.fabric.keeper import KeeperDesk
from halvard.fabric.crypto import ReferenceKMS, KeyUnavailable
from halvard.fabric.deployment import EgressDenied, build_bundle
from halvard.relay.actions import Principal, ActionRequest
from halvard.signet.hr import HRRecord

DAY = 86400
VENDOR_KEY = b"halvard-release-signing-key-0123"


class World8:
    """A platform with: acme (EU, cloud), globex (US, cloud), holdco (EU parent of acme and globex), bank (EU, private deployment)."""
    def __init__(self, bank_kms=None, acme_kms=None):
        self.tmp = tempfile.mkdtemp(); self.clock = ManualClock(); self.p = Platform(os.path.join(self.tmp, "platform"), self.clock)
        p = self.p
        self.holdco = p.create_tenant("holdco", "Holdco", region="eu-west")
        self.acme = p.create_tenant("acme", "Acme", region="eu-west", parent="holdco", kms=acme_kms)
        self.globex = p.create_tenant("globex", "Globex", region="us-east", parent="holdco")
        self.bank = p.create_tenant("bank", "Bank", region="eu-central", deployment="private", operated_by="customer", kms=bank_kms)
        self.M = {}
        for t in ("holdco", "acme", "globex", "bank"):
            for r in ("owner", "it_admin", "analyst"): self.M[(t, r)] = p.enroll_member(Member(t, f"{t}-{r}", r))
        for t, name in (("acme", "Alice Kim"), ("globex", "Gary Stone")):
            cp = p.tenants[t].cp; first = name.split()[0].lower()
            cp.hr.add(HRRecord(f"p:{first}", name, f"{first}@{t}.com", first, "active", "Finance", None, 0, email=f"{first}@{t}.com"))
            cp.store.put_entity(cp.ctx, f"p:{first}", "person", name, self.clock.now())
            cp.store.put_entity(cp.ctx, "srv-fin", "data_store", "Finance database", self.clock.now(), criticality="crown_jewel")      # the SAME entity id in two companies
            self.add_laptop(t, "LT-1", first)

    def add_laptop(self, tenant, device, owner_first):
        cp = self.p.tenants[tenant].cp; a, h, _, fs = make_agent(os.path.join(self.tmp, tenant, device)); a.clock = self.clock; a.engine.clock = self.clock; a.spool.clock = self.clock; a.journal.clock = self.clock
        a.device_id = device; a.bundle = a.bundle.__class__(**{**a.bundle.__dict__, "tenant": tenant}).sign(cp.fleet.key)
        cp.idp.add_user(f"{owner_first}@{tenant}.com"); cp.enroll_device(a, f"{owner_first}@{tenant}.com"); return a, h, fs

    def m(self, tenant, role="it_admin"): return self.M[(tenant, role)]
