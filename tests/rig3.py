import os, tempfile
from helpers import *
from halvard.controlplane import ControlPlane
from halvard.signet.hr import HRRecord
from halvard.signet.idp import ResourceServer, App
from halvard.signet.notify import Channel
from halvard.ward import simulate as sim
from halvard.detect.library import DetectionLibrary
from halvard.relay.actions import Principal

LON, MOW = dict(country="GB", lat=51.5, lon=-0.12), dict(country="RU", lat=55.7, lon=37.6)
KEY = b"content-key" * 3
STEALER_RULE = dict(name="Browser session store copied", description="A process other than the browser created a copy of a cookie database",
                    query='kind=file AND op=create AND path contains "cookies" AND NOT proc~"chrome*"', techniques=["T1539"], severity="high", confidence=0.7,
                    tests={"positive": [dict(kind="file", op="create", path="/tmp/x/Cookies.copy", proc="stealer.exe")], "negative": [dict(kind="file", op="create", path="/home/a/Cookies", proc="chrome.exe")]})


class World:
    """acme: alice (standard, laptop LT-17, hybrid AD account), bob (Domain Admin), manager Maria, finance server marked crown_jewel."""
    def __init__(self, auto=True, device_class="standard", channels=None, alice_class_priv=False):
        self.tmp = tempfile.mkdtemp(); self.clock = ManualClock()
        self.ch = channels if channels is not None else [Channel("email")]
        self.cp = ControlPlane(self.tmp, self.clock, POLICY_KEY, accepted_patterns=("identity_takeover_containment",) if auto else (), channels=self.ch)
        cp = self.cp; idp, ad = cp.idp, cp.ad
        idp.add_app("mail", "Mail", cae=True); idp.add_app("crm", "CRM", cae=True); idp.add_app("wiki", "Team Wiki", cae=False)
        for u in ("alice", "bob", "maria"): idp.add_user(f"{u}@acme.com")
        for s in ("alice", "bob", "maria"): ad.add_user(s)
        ad.add_member("admin-ops", "Domain Admins", "bob"); cp.detector.change_approvers.add("admin-ops")
        cp.hr.add(HRRecord("p:maria", "Maria Lopez", "maria@acme.com", "maria", "active", "Finance", None, 0, email="maria@acme.com"))
        cp.hr.add(HRRecord("p:alice", "Alice Kim", "alice@acme.com", "alice", "active", "Finance", "p:maria", 0, email="alice@acme.com"))
        cp.hr.add(HRRecord("p:bob", "Bob Ng", "bob@acme.com", "bob", "active", "IT", "p:maria", 0, email="bob@acme.com"))
        cp.store.put_entity(cp.ctx, "srv-fin", "data_store", "Finance database", self.clock.now(), criticality="crown_jewel")
        cp.signet.resource_acl = {"Finance-Users": ["srv-fin"], "Domain Admins": ["srv-fin"]}
        ad.groups["Finance-Users"] = set(); ad.add_member("admin-ops", "Finance-Users", "alice")
        idp.assign_role("bob@acme.com", "Global Administrator", "admin-ops", mode="jit", via_jit_request="REQ-1"); cp.detector.approved_jit.add("REQ-1")
        # alice's laptop
        self.agent, self.host, _, self.fs = make_agent(os.path.join(self.tmp, "lt17"), asset_class=device_class)
        self.agent.clock = self.clock; self.agent.engine.clock = self.clock; self.agent.spool.clock = self.clock
        self.agent.journal.clock = self.clock
        self.agent.device_id = "LT-17"
        cp.enroll_device(self.agent, "alice@acme.com")
        lib = DetectionLibrary(self.clock); au, rv = Principal("u-a", "analyst"), Principal("u-r", "analyst")
        r = lib.create(au, dict(STEALER_RULE, expires_at=self.clock.now() + 90 * 86400)); lib.submit(r, au); lib.approve(r, rv); self.agent.apply_content(lib.build_pack(KEY), KEY)
        cp.signet.sync_graph(); cp.signet.link_device("p:alice", "LT-17")
        self.mail, self.crm, self.wiki = ResourceServer(idp, "mail"), ResourceServer(idp, "crm"), ResourceServer(idp, "wiki")

    def alice_signs_in(self):
        idp = self.cp.idp
        self.sess = idp.sign_in("alice@acme.com", "correct-horse", "198.51.100.4", LON, device_id="LT-17", mfa="approve", app="mail")
        self.crm_t = idp.refresh_grant(self.sess["refresh_token"], "198.51.100.4", LON, device_id="LT-17", app="crm")
        self.wiki_t = idp.refresh_grant(self.crm_t["refresh_token"], "198.51.100.4", LON, device_id="LT-17", app="wiki")
        self.refresh = self.wiki_t["refresh_token"]
        return self

    def stealer_runs(self):
        """Infostealer on LT-17 copies the browser session store (Ward sees file activity, not contents)."""
        self.host.spawn(666, "stealer.exe", exe_sha256="de" * 32)
        self.fs.create(666, os.path.join(self.tmp, "stolen", "Cookies.copy"), b"opaque-bytes" * 20)
        self.clock.advance(120)

    def attacker_replays(self):
        """The attacker, elsewhere, renews the stolen session and uses it."""
        idp = self.cp.idp
        self.stolen = idp.refresh_grant(self.refresh, "203.0.113.7", MOW, device_id=None, app="wiki")
        self.stolen_mail = idp.refresh_grant(self.stolen["refresh_token"], "203.0.113.7", MOW, device_id=None, app="mail")
        return self
