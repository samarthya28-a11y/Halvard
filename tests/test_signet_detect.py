import unittest
from helpers import *
from halvard.signet.idp import ReferenceIdP, AuthError, App
from halvard.signet.ad import ReferenceAD
from halvard.signet.detectors import IdentityDetector, Thresholds, haversine_km
from halvard.detect.library import ATTACK

LON, NYC, MOW = dict(country="GB", lat=51.5, lon=-0.12), dict(country="US", lat=40.7, lon=-74.0), dict(country="RU", lat=55.7, lon=37.6)
GOOD = "correct-horse"


class Rig:
    def __init__(self, **kw):
        self.clock = ManualClock(); self.idp = ReferenceIdP("acme", self.clock); self.ad = ReferenceAD("acme.local", self.clock)
        self.det = IdentityDetector(self.clock, domain_controllers=["DC01"], **kw); self.ci = self.ca = 0; self.found = []
        for u in ("alice", "bob", "carol"): self.idp.add_user(f"{u}@acme.com")
        self.idp.add_app("portal", "Portal"); self.idp.add_app("evil", "Shiny Mail Tool", publisher_verified=False, created_at=self.clock.now() - 2 * 86400)

    def pump(self):
        evs, self.ci = self.idp.events_since(self.ci); evs2, self.ca = self.ad.events_since(self.ca); out = []
        for e in evs + evs2: out += self.det.ingest(e)
        self.found += out; return out


def names(fs): return sorted(f.detector for f in fs)


class CloudDetectionTests(unittest.TestCase):
    def test_password_spray_and_the_account_that_fell(self):
        r = Rig()
        for i in range(12):
            r.idp.add_user(f"u{i}@acme.com")
            try: r.idp.sign_in(f"u{i}@acme.com", "Summer2026!", "203.0.113.9", MOW)
            except AuthError: pass
            r.clock.advance(20)
        f = [x for x in r.pump() if x.detector == "password_spray"]; self.assertEqual(len(f), 1)
        self.assertEqual((f[0].technique, f[0].family, f[0].confidence), ("T1110.003", "credential_attack", 0.8)); self.assertEqual(len(f[0].details["accounts"]), 10)
        r.idp.users["u3@acme.com"].password = "Summer2026!"; r.idp.users["u3@acme.com"].mfa_enrolled = False
        r.idp.sign_in("u3@acme.com", "Summer2026!", "203.0.113.9", MOW)
        self.assertIn("spray_success", names(r.pump()))

    def test_ordinary_failures_do_not_look_like_a_spray(self):
        r = Rig()
        for i in range(30):      # one user mistyping repeatedly, and a slow trickle from an office address
            try: r.idp.sign_in("alice@acme.com", "typo", "198.51.100.4", LON)
            except AuthError: pass
        for i in range(12):
            try: r.idp.sign_in(f"alice@acme.com", "typo", f"198.51.100.{i}", LON)
            except AuthError: pass
            r.clock.advance(3600)
        self.assertNotIn("password_spray", names(r.pump()))

    def test_mfa_fatigue_flood_then_approval(self):
        r = Rig()
        r.idp.sign_in("alice@acme.com", GOOD, "203.0.113.9", MOW, mfa="approve", prompts=7)
        f = [x for x in r.pump() if x.detector == "mfa_fatigue"]; self.assertEqual(len(f), 1); self.assertEqual((f[0].technique, f[0].confidence), ("T1621", 0.92))
        self.assertIn("then one was approved", f[0].why)

    def test_one_forgotten_mfa_approval_is_not_fatigue(self):
        r = Rig(); r.idp.sign_in("alice@acme.com", GOOD, "198.51.100.4", LON, mfa="approve", prompts=2); self.assertNotIn("mfa_fatigue", names(r.pump()))

    def test_impossible_travel_and_its_exclusions(self):
        r = Rig(); r.idp.sign_in("alice@acme.com", GOOD, "198.51.100.4", LON, device_id=None, mfa="approve"); r.clock.advance(600)
        r.idp.sign_in("alice@acme.com", GOOD, "192.0.2.50", NYC, device_id=None, mfa="approve")
        f = [x for x in r.pump() if x.detector == "impossible_travel"]; self.assertEqual(len(f), 1); self.assertGreater(f[0].details["kmh"], 900)
        r2 = Rig(); r2.idp.sign_in("alice@acme.com", GOOD, "198.51.100.4", LON, mfa="approve"); r2.clock.advance(9 * 3600)
        r2.idp.sign_in("alice@acme.com", GOOD, "192.0.2.50", NYC, mfa="approve"); self.assertNotIn("impossible_travel", names(r2.pump()))     # nine hours is enough
        r3 = Rig(trusted_egress=["198.51.100.4"]); r3.idp.sign_in("alice@acme.com", GOOD, "198.51.100.4", LON, mfa="approve"); r3.clock.advance(600)
        r3.idp.sign_in("alice@acme.com", GOOD, "192.0.2.50", NYC, mfa="approve"); self.assertNotIn("impossible_travel", names(r3.pump()))        # corporate VPN egress
        self.assertAlmostEqual(haversine_km(LON, NYC), 5570, delta=60)

    def test_same_device_travel_is_lower_confidence_than_new_device(self):
        r = Rig(); r.idp.register_device("LT-1", "alice@acme.com"); r.idp.sign_in("alice@acme.com", GOOD, "198.51.100.4", LON, device_id="LT-1", mfa="approve"); r.clock.advance(600)
        r.idp.sign_in("alice@acme.com", GOOD, "192.0.2.50", NYC, device_id="LT-1", mfa="approve")
        self.assertEqual([x.confidence for x in r.pump() if x.detector == "impossible_travel"], [0.6])

    def test_stolen_session_is_seen_as_token_replay(self):
        r = Rig(); r.idp.register_device("LT-17", "alice@acme.com"); t = r.idp.sign_in("alice@acme.com", GOOD, "198.51.100.4", LON, device_id="LT-17", mfa="approve")
        r.clock.advance(300); r.idp.refresh_grant(t["refresh_token"], "203.0.113.7", MOW, device_id=None)
        f = [x for x in r.pump() if x.detector == "token_replay"]; self.assertEqual(len(f), 1); self.assertEqual((f[0].technique, f[0].confidence), ("T1550.001", 0.9))
        self.assertIn("another country", f[0].why)

    def test_legitimate_refresh_from_the_home_device_is_quiet(self):
        r = Rig(); r.idp.register_device("LT-17", "alice@acme.com"); t = r.idp.sign_in("alice@acme.com", GOOD, "198.51.100.4", LON, device_id="LT-17", mfa="approve")
        for _ in range(5): r.clock.advance(1800); t = r.idp.refresh_grant(t["refresh_token"], "198.51.100.4", LON, device_id="LT-17")
        self.assertEqual([x for x in r.pump() if x.family == "identity_takeover"], [])

    def test_refresh_token_reuse_means_two_holders_and_ends_the_family(self):
        r = Rig(); t = r.idp.sign_in("alice@acme.com", GOOD, "198.51.100.4", LON, mfa="approve"); t2 = r.idp.refresh_grant(t["refresh_token"], "198.51.100.4", LON)
        with self.assertRaises(AuthError): r.idp.refresh_grant(t["refresh_token"], "203.0.113.7", MOW)          # old token replayed
        f = [x for x in r.pump() if x.detector == "refresh_reuse"]; self.assertEqual(len(f), 1); self.assertEqual(f[0].confidence, 0.95)
        with self.assertRaises(AuthError): r.idp.refresh_grant(t2["refresh_token"], "198.51.100.4", LON)       # even the legitimate copy is dead: user signs in again

    def test_illicit_consent(self):
        r = Rig(); r.idp.grant_consent("alice@acme.com", "evil", ["Mail.Read", "offline_access"])
        f = [x for x in r.pump() if x.detector == "illicit_consent"]; self.assertEqual(len(f), 1); self.assertEqual(f[0].confidence, 0.85)
        r2 = Rig(); r2.idp.grant_consent("alice@acme.com", "portal", ["User.Read"]); r2.idp.grant_consent("alice@acme.com", "evil", ["User.Read"]); self.assertEqual(r2.pump(), [])

    def test_privileged_role_outside_the_approved_process(self):
        r = Rig(approved_jit=["REQ-7"]); r.idp.assign_role("bob@acme.com", "Global Administrator", assigned_by="carol@acme.com", mode="permanent")
        r.idp.assign_role("carol@acme.com", "Exchange Administrator", assigned_by="carol@acme.com", mode="permanent")
        r.idp.assign_role("alice@acme.com", "Global Administrator", assigned_by="carol@acme.com", mode="jit", via_jit_request="REQ-7")
        r.idp.assign_role("alice@acme.com", "Reports Reader", assigned_by="bob@acme.com", mode="permanent")
        f = r.pump(); self.assertEqual([(x.entity, x.confidence) for x in f], [("bob@acme.com", 0.85), ("carol@acme.com", 0.95)])

    def test_legacy_authentication_is_flagged_when_allowed(self):
        r = Rig(); r.idp.legacy_auth_allowed = True; r.idp.users["alice@acme.com"].mfa_enrolled = False
        r.idp.sign_in("alice@acme.com", GOOD, "198.51.100.4", LON, protocol="legacy"); self.assertIn("legacy_auth", names(r.pump()))


class DirectoryDetectionTests(unittest.TestCase):
    def test_kerberoasting(self):
        r = Rig(); r.ad.add_user("jdoe")
        for i in range(6): r.ad.tgs_request("jdoe", f"MSSQLSvc/db{i}.acme.local", 0x17, "10.0.0.50"); r.clock.advance(5)
        f = r.pump(); self.assertEqual(names(f), ["kerberoasting"]); self.assertEqual((f[0].technique, f[0].entity), ("T1558.003", "ad:jdoe"))

    def test_normal_ticket_traffic_is_not_kerberoasting(self):
        r = Rig()
        for i in range(40): r.ad.tgs_request("jdoe", f"cifs/fs{i % 3}.acme.local", 0x12, "10.0.0.50")           # AES
        for i in range(12): r.ad.tgs_request("mlee", f"http/app{i}.acme.local", 0x12, "10.0.0.51")              # many services, but strong encryption
        for i in range(40): r.ad.tgs_request("jdoe", "cifs/fs1.acme.local", 0x17, "10.0.0.50")                    # one service, RC4
        for i in range(10): r.ad.tgs_request("WS01$", f"host/x{i}", 0x17, "10.0.0.60")                            # computer account
        self.assertEqual(r.pump(), [])

    def test_asrep_roasting(self):
        r = Rig(allowed_asrep=["legacyapp"]); r.ad.tgt_request("legacyapp", "10.0.0.5", 0); self.assertEqual(r.pump(), [])
        for a in ("a", "b", "c"): r.ad.tgt_request(a, "10.0.0.77", 0)
        f = r.pump(); self.assertEqual(len(f), 3); self.assertEqual(f[-1].confidence, 0.85)

    def test_dcsync_only_for_non_domain_controllers(self):
        r = Rig(); r.ad.replicate("DC01$", "DC01", "10.0.0.2"); self.assertEqual(r.pump(), [])
        r.ad.replicate("svc-backup", "WS09", "10.0.0.99"); f = r.pump(); self.assertEqual((names(f), f[0].confidence, f[0].technique), (["dcsync"], 0.97, "T1003.006"))

    def test_privileged_group_changes_and_new_admin_accounts(self):
        r = Rig(change_approvers=["admin-ops"]); r.ad.add_member("admin-ops", "Domain Admins", "jane"); self.assertEqual(r.pump(), [])        # approved change
        r.ad.create_user("jdoe", "tmp-admin"); r.ad.add_member("jdoe", "Domain Admins", "tmp-admin")
        f = r.pump(); self.assertEqual(names(f), ["privilege_escalation"]); self.assertEqual(f[0].confidence, 0.95); self.assertIn("less than an hour", f[0].why)
        r.ad.add_member("jdoe", "Enterprise Admins", "jdoe"); self.assertEqual(r.ad.log[-1]["event_id"], 4756)
        r.ad.add_member("jdoe", "Marketing", "jdoe"); self.assertEqual(len([x for x in r.pump() if x.detector == "privilege_escalation"]), 1)    # only the privileged group

    def test_directory_password_spray(self):
        r = Rig()
        for i in range(12): r.ad.logon(f"user{i}", False, "10.0.0.88", "WS88"); r.clock.advance(10)
        self.assertEqual(names(r.pump()), ["password_spray"])

    def test_service_account_used_interactively(self):
        r = Rig(service_accounts=["svc-sql"]); r.ad.add_user("svc-sql", is_service=True); r.ad.logon("svc-sql", True, "10.0.0.5", "SQL1", logon_type=5); self.assertEqual(r.pump(), [])
        r.ad.logon("svc-sql", True, "10.0.0.5", "SQL1", logon_type=10); self.assertEqual(names(r.pump()), ["service_account_interactive"])


class HonestyTests(unittest.TestCase):
    def test_every_technique_tag_exists_in_the_bundled_list_and_findings_explain_themselves(self):
        r = Rig(); r.idp.register_device("D", "alice@acme.com"); t = r.idp.sign_in("alice@acme.com", GOOD, "198.51.100.4", LON, device_id="D", mfa="approve", prompts=7)
        r.idp.refresh_grant(t["refresh_token"], "203.0.113.7", MOW); r.idp.grant_consent("bob@acme.com", "evil", ["Mail.Read"]); r.idp.assign_role("carol@acme.com", "Global Administrator", "carol@acme.com")
        r.ad.replicate("x", "h", "1.1.1.1"); r.ad.tgt_request("q", "1.1.1.1", 0)
        for i in range(6): r.ad.tgs_request("k", f"s{i}", 0x17, "1.1.1.1")
        r.ad.add_member("z", "Domain Admins", "z")
        fs = r.pump(); self.assertGreaterEqual(len(fs), 7)
        for f in fs:
            self.assertIn(f.technique, ATTACK["techniques"], f.detector); self.assertTrue(f.why and f.summary and f.evidence); self.assertTrue(0 < f.confidence <= 1)
            self.assertFalse(any(k in f.details for k in ("password", "token", "refresh_token", "access_token")))     # never carry secrets into findings


if __name__ == "__main__":
    unittest.main()
