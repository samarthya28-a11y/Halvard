"""Independent cross-check, phase 6. Free-text reasons and the external-scan scope."""
import json, unittest
from helpers import *
from rig6 import *
from halvard.glass.surface import ExternalSurface, ReferenceInternet, ScopeError
from halvard.relay.actions import Principal

PDF = "HLV-SAMPLE-0002@LT-17"
AN = Principal("u-an", "analyst")
OWNER = Principal("u-own", "owner")
ADM = Principal("u-adm", "it_admin")


class FreeTextTests(unittest.TestCase):
    def test_a_persons_name_in_a_protection_reason_is_absent_from_every_public_audit_field(self):
        w = World6()
        w.cp.glass.compensate(AN, PDF, 7, "ask Dana Whitfield about the vendor")
        public = "\n".join(json.dumps(e["public"]) for e in w.cp.ledger.entries())
        self.assertNotIn("Dana", public)
        self.assertNotIn("Whitfield", public)


class SurfaceScopeTests(unittest.TestCase):
    def test_a_probe_to_an_address_that_was_not_confirmed_sends_nothing(self):
        clock = ManualClock(); net = ReferenceInternet(clock)
        net.add_host("203.0.113.50", {443: {"service": "https", "product": "web", "version": "1"}})
        net.add_host("192.0.2.99", {22: {"service": "ssh", "product": "sshd", "version": "9"}})
        net.point("old.acme.com", "203.0.113.50"); net.point("vendor.example", "192.0.2.99")
        surf = ExternalSurface(net, clock, None, lambda: {"198.51.100.10"}, None)
        ch = surf.declare_domain(ADM, "old.acme.com")
        net.txt["_halvard-challenge.old.acme.com"] = [ch["value"]]
        self.assertTrue(surf.verify_domain(ADM, "old.acme.com"))
        with self.assertRaises(ScopeError):
            surf.probe("203.0.113.50", 443)
        with self.assertRaises(ScopeError):
            surf.probe("192.0.2.99", 22)
        self.assertEqual(net.probes, [])
        surf.confirm_address(ADM, "203.0.113.50", "this is the old portal we still run")
        self.assertIsNotNone(surf.probe("203.0.113.50", 443))
        with self.assertRaises(ScopeError):
            surf.probe("192.0.2.99", 22)

    def test_an_expired_temporary_protection_is_not_lifted_by_review(self):
        from halvard.ward.agent import Blocked
        w = World6()
        w.cp.glass.compensate(AN, PDF, 3, "update not packaged yet")
        w.clock.advance(4 * 86400)
        notes = w.cp.glass.review_controls()
        self.assertIn(("cc-1", "expired"), notes)
        with self.assertRaises(Blocked):
            w.agent.pre_execute("/apps/pdfviewer.exe", b"MZ x")

    def test_an_analyst_cannot_accept_a_risk_and_an_extension_cannot_exceed_the_cap(self):
        w = World6(); g = w.cp.glass
        g.compensate(AN, PDF, 3, "update not packaged yet")
        w.clock.advance(4 * 86400); g.review_controls()
        with self.assertRaises(PermissionError):
            g.accept_risk(AN, PDF, 30, "we will live with it")
        g.extend_control(ADM, "cc-1", 7, "vendor patch due next week")
        g.extend_control(ADM, "cc-1", 7, "vendor slipped again")
        with self.assertRaises(ValueError):
            g.extend_control(ADM, "cc-1", 7, "a third extension")

    def test_the_board_leaves_an_unmeasured_restore_test_out_of_a_full_mark(self):
        w = World6()
        page = w.cp.board.page(OWNER)
        self.assertIn("not measured", page.lower())
        self.assertNotIn("100 / 100", page)
