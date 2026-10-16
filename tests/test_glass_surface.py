import unittest
from helpers import *
from rig6 import *
from halvard.glass.surface import ScopeError, PROBE_PORTS


class ScopeTests(unittest.TestCase):
    def test_nothing_is_probed_outside_what_the_customer_owns_and_the_refusal_is_recorded(self):
        w = World6(); s = w.cp.surface
        with self.assertRaises(ScopeError): s.probe("192.0.2.99", 22)                                       # someone else's server
        self.assertNotIn(("192.0.2.99", 22), w.net.probes)
        r = next(r for r in w.cp.ledger.entries() if r["kind"] == "glass.probe_refused"); self.assertEqual(r["private"]["ip"], "192.0.2.99")
        self.assertEqual(s.scope(), {"198.51.100.80", "198.51.100.81"})                                      # the company's own cloud addresses only

    def test_a_domain_only_nominates_addresses_and_a_person_confirms_each_before_anything_is_probed(self):
        w = World6(); s = w.cp.surface; w.net.point("acme.com", "203.0.113.50", "192.0.2.99")
        with self.assertRaises(PermissionError): s.declare_domain(AN, "acme.com")
        rec = s.declare_domain(ADM, "acme.com"); self.assertEqual(s.candidates(), set())                      # declared is not verified
        self.assertFalse(s.verify_domain(ADM, "acme.com")); w.net.txt[rec["record"]] = ["halvard-verify=wrong"]; self.assertFalse(s.verify_domain(ADM, "acme.com"))
        w.net.txt[rec["record"]] = [rec["value"]]; self.assertTrue(s.verify_domain(ADM, "acme.com"))
        self.assertEqual(s.candidates(), {"203.0.113.50", "192.0.2.99"}); self.assertNotIn("203.0.113.50", s.scope())          # verified is not confirmed
        with self.assertRaises(ScopeError): s.probe("192.0.2.99", 22)                                       # a vendor's shared server is never probed on DNS alone
        with self.assertRaises(PermissionError): s.confirm_address(AN, "203.0.113.50", "ours")
        with self.assertRaises(ValueError): s.confirm_address(ADM, "203.0.113.50", " ")
        with self.assertRaises(ValueError): s.confirm_address(ADM, "198.18.0.1", "an address no domain points to")
        s.confirm_address(ADM, "203.0.113.50", "our colocation rack"); self.assertIn("203.0.113.50", s.scope()); self.assertNotIn("192.0.2.99", s.scope())
        self.assertEqual(sum(1 for r in w.cp.ledger.entries() if r["kind"] == "glass.domain_verification_failed"), 2)
        with self.assertRaises(PermissionError): s.scan(SD)
        s.scan(ADM); self.assertTrue(any(ip == "203.0.113.50" for ip, _ in w.net.probes)); self.assertFalse(any(ip == "192.0.2.99" for ip, _ in w.net.probes))
        s.remove_address(ADM, "203.0.113.50"); self.assertNotIn("203.0.113.50", s.scope()); self.assertFalse(any(k[0] == "203.0.113.50" for k in s.observed))

    def test_the_scan_only_makes_plain_connections_to_the_fixed_port_list(self):
        w = World6(); w.verify_scope()
        self.assertTrue(w.net.probes); self.assertTrue(all(p in PROBE_PORTS for _, p in w.net.probes)); self.assertTrue(all(ip in w.cp.surface.scope() for ip, _ in w.net.probes))


class SurfaceFindingTests(unittest.TestCase):
    def test_what_the_internet_sees_joins_the_same_ranked_list(self):
        w = World6(); w.verify_scope(); g = w.cp.glass; xs = {x.id: x for x in g.evaluate()}
        self.assertTrue(any(k.startswith("admin_exposed@198.51.100.81:22") for k in xs))                      # ssh open to the world at the bastion
        unk = xs["unknown_asset@203.0.113.50:8443"]; self.assertEqual((unk.kind, unk.reach), ("misconfiguration", "internet")); self.assertIn("not in your inventory", unk.title)
        twin = xs["HLV-SAMPLE-0001@i-web"]; self.assertIn("also confirmed from the internet side", twin.why)          # one item, not two
        self.assertFalse(any(k.startswith("vulnerable_service@198.51.100.80") for k in xs))

    def test_an_unknown_server_with_a_known_flaw_is_ranked_as_what_it_is(self):
        w = World6(); w.net.add_host("203.0.113.60", {443: {"service": "https", "product": "webserver", "version": "2.4.40"}}); w.net.point("shop.acme.com", "203.0.113.60"); w.net.point("acme.com", "203.0.113.60"); w.verify_scope()
        x = next(x for x in w.cp.glass.evaluate() if x.id == "vulnerable_service@203.0.113.60:443"); self.assertEqual((x.exploit, x.reach, x.tier), ("exploited_in_wild", "internet", "now")); self.assertEqual(x.advisory, "HLV-SAMPLE-0001")

    def test_closing_the_port_closes_the_finding_after_the_next_scan(self):
        w = World6(); w.verify_scope(); g = w.cp.glass
        self.assertTrue(any(x.id.startswith("admin_exposed@198.51.100.81") for x in g.evaluate()))
        r = w.cp.engine.request(ActionRequest("restrict_security_group_rule", AN, ["sg-admin|22|0.0.0.0/0"], "ssh from anywhere", None, {})); self.assertEqual(r.status, "executed")
        w.net.hosts["198.51.100.81"]["services"].clear(); w.cp.glass_cycle()
        self.assertFalse(any(x.id.startswith("admin_exposed@198.51.100.81") for x in g.evaluate()))


class ExpiryTests(unittest.TestCase):
    def test_certificates_warn_as_they_approach_and_each_level_is_recorded_once(self):
        w = World6(); w.verify_scope(); s = w.cp.surface
        e = s.expiries(); self.assertEqual([(x["kind"], x["name"], x["level"]) for x in e], [("certificate", "old.acme.com", "soon")]); self.assertEqual(s.expiries()[0]["days_left"], 20.0)
        w.clock.advance(14 * DAY); self.assertEqual(s.expiries()[0]["level"], "urgent")
        w.clock.advance(10 * DAY); self.assertEqual(s.expiries()[0]["level"], "expired")
        s.expiries(); logged = [r["public"]["level"] for r in w.cp.ledger.entries() if r["kind"] == "glass.expiry_warning"]; self.assertEqual(logged, ["soon", "urgent", "expired"])

    def test_a_time_boxed_admin_exposure_is_quiet_until_its_window_ends_then_it_is_a_critical_finding(self):
        w = World6(); w.verify_scope(); s = w.cp.surface
        with self.assertRaises(PermissionError): s.approve_temporary_exposure(AN, "198.51.100.81", 22, 7, "contractor")
        with self.assertRaises(ValueError): s.approve_temporary_exposure(ADM, "198.51.100.81", 22, 31, "x")
        with self.assertRaises(ValueError): s.approve_temporary_exposure(ADM, "198.51.100.81", 22, 7, "")
        s.approve_temporary_exposure(ADM, "198.51.100.81", 22, 7, "contractor migration")
        has = lambda: [f for f in s.findings({"198.51.100.80", "198.51.100.81"}) if f["kind"] == "admin_exposed"]
        self.assertEqual(has(), []); w.clock.advance(5 * DAY); self.assertEqual([x["kind"] for x in s.expiries() if x["kind"] == "temporary_exposure"], ["temporary_exposure"])
        w.clock.advance(3 * DAY); f = has(); self.assertEqual((len(f), f[0]["severity"]), (1, "critical")); self.assertIn("after its approved window ended", f[0]["title"])


if __name__ == "__main__":
    unittest.main()
