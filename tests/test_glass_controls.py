import unittest
from helpers import *
from rig6 import *
from halvard.ward.agent import Blocked

PDF = "HLV-SAMPLE-0002@LT-17"; WEB = "HLV-SAMPLE-0001@i-web"


class CompensatingControlTests(unittest.TestCase):
    def block_pdf(self, w, days=7):
        return w.cp.glass.compensate(AN, PDF, days, "update not packaged yet")

    def test_a_program_is_switched_off_on_the_device_itself_with_an_expiry_and_a_record(self):
        w = World6(); g = w.cp.glass; r = self.block_pdf(w)
        self.assertEqual(r.status, "executed"); self.assertIn("pdfviewer", r.preview["summary"]); self.assertIn("expires", r.preview["summary"])
        with self.assertRaises(Blocked) as cm: w.agent.pre_execute("/apps/pdfviewer.exe", b"MZ ordinary program")
        self.assertIn("switched off on this device", str(cm.exception))
        w.agent.pre_execute("/apps/notepad.exe", b"MZ other program")                                      # only the named program
        x = g.get(PDF); self.assertEqual(x.status, "compensated"); c = next(iter(g.controls.values())); self.assertEqual(c.expires_at - c.applied_at, 7 * DAY)
        e = next(r for r in w.cp.ledger.entries() if r["kind"] == "glass.control_applied"); self.assertEqual(e["public"]["expires_in_days"], 7.0)
        self.assertTrue(any(r["kind"] == "ward.exec_blocked_by_temporary_protection" for r in w.agent.spool.entries()))

    def test_it_works_with_no_network_and_a_device_that_was_offline_gets_it_on_return(self):
        w = World6(); w.agent.set_online(False)
        r = self.block_pdf(w); self.assertEqual(r.status, "executed"); self.assertIn("waiting for the device", r.message)
        w.agent.pre_execute("/apps/pdfviewer.exe", b"MZ x")                                                # not yet enforced: it was offline when asked
        w.cp.fleet.reconnect("LT-17")
        with self.assertRaises(Blocked): w.agent.pre_execute("/apps/pdfviewer.exe", b"MZ x")
        w.agent.set_online(False)
        with self.assertRaises(Blocked): w.agent.pre_execute("/apps/pdfviewer.exe", b"MZ x")               # and keeps blocking while offline

    def test_a_queued_protection_is_not_lost_when_another_policy_push_follows(self):
        w = World6(); w.agent.set_online(False); self.block_pdf(w)
        w.cp.push_ioc(["ab" * 32]); w.cp.fleet.reconnect("LT-17")
        with self.assertRaises(Blocked): w.agent.pre_execute("/apps/pdfviewer.exe", b"MZ x")
        self.assertIn("ab" * 32, w.agent.bundle.known_bad_sha256)

    def test_a_production_host_waits_for_an_approver_and_the_preview_says_what_stops(self):
        w = World6(); g = w.cp.glass
        r = g.compensate(AN, WEB, 5, "update needs a change window")
        self.assertEqual(r.status, "pending_approval"); self.assertIn("close port 443", r.preview["summary"]); self.assertEqual(w.cp.aws.reachable_from_internet("i-web"), [443])        # nothing changed yet
        done = w.cp.engine.approve(r.action_id, ADM); self.assertEqual(done.status, "executed")
        self.assertEqual(w.cp.aws.reachable_from_internet("i-web"), []); x = g.get(WEB); self.assertEqual(x.status, "compensated"); self.assertEqual(x.tier, "soon")      # 'now' steps down while held

    def test_limits_reasons_and_roles_are_enforced(self):
        w = World6(); g = w.cp.glass
        with self.assertRaises(PermissionError): g.compensate(SD, PDF, 7, "x")
        with self.assertRaises(ValueError): g.compensate(AN, PDF, 31, "too long")
        with self.assertRaises(ValueError): g.compensate(AN, PDF, 7, "  ")
        with self.assertRaises(KeyError): g.compensate(AN, "HLV-SAMPLE-0002@nowhere", 7, "x")
        self.assertEqual(self.block_pdf(w).status, "executed")
        with self.assertRaises(ValueError): self.block_pdf(w)
        w.host.settings["firewall_enabled"] = False
        with self.assertRaises(ValueError): g.compensate(AN, "baseline:firewall_enabled@LT-17", 7, "no workaround exists")

    def test_expiry_keeps_the_protection_in_force_and_puts_the_item_back_at_the_top(self):
        w = World6(); g = w.cp.glass; self.block_pdf(w, 5); w.clock.advance(2.5 * DAY + 1)
        self.assertIn(("cc-1", "expires in 3 day(s)"), g.review_controls()); self.assertEqual(g.review_controls(), [])                      # warned once
        w.clock.advance(1.6 * DAY); self.assertIn(("cc-1", "expires in 1 day(s)"), g.review_controls())
        w.clock.advance(1 * DAY); self.assertIn(("cc-1", "expired"), g.review_controls())
        with self.assertRaises(Blocked): w.agent.pre_execute("/apps/pdfviewer.exe", b"MZ x")               # nothing was silently lifted
        x = g.get(PDF); self.assertEqual(x.status, "compensation_expired"); self.assertIn("a person must extend it", x.note)
        self.assertTrue(any(r["kind"] == "glass.control_expired" and r["public"]["still_in_force"] for r in w.cp.ledger.entries()))

    def test_extension_is_limited_reasoned_and_capped_then_only_the_owner_can_accept_the_risk(self):
        w = World6(); g = w.cp.glass; self.block_pdf(w, 3); w.clock.advance(4 * DAY); g.review_controls()
        with self.assertRaises(PermissionError): g.extend_control(AN, "cc-1", 7, "x")
        with self.assertRaises(ValueError): g.extend_control(ADM, "cc-1", 7, "")
        with self.assertRaises(ValueError): g.extend_control(ADM, "cc-1", 15, "too long")
        c = g.extend_control(ADM, "cc-1", 7, "vendor patch due next week"); self.assertEqual((c.status, c.extensions), ("active", 1))
        self.assertEqual(g.get(PDF).status, "compensated")
        g.extend_control(ADM, "cc-1", 7, "vendor slipped"); 
        with self.assertRaises(ValueError) as cm: g.extend_control(ADM, "cc-1", 7, "again")
        self.assertIn("risk acceptance", str(cm.exception))
        g.accept_risk(OWNER, PDF, 30, "vendor has no fix; program is used by one person"); self.assertEqual(g.get(PDF).status, "accepted_risk")

    def test_free_text_reasons_go_to_the_private_part_of_the_record_never_the_public_part(self):
        w = World6(); g = w.cp.glass; self.block_pdf(w, 3); w.clock.advance(4 * DAY); g.review_controls(); g.extend_control(ADM, "cc-1", 7, "ask Dana Whitfield about the vendor")
        g.accept_risk(OWNER, WEB, 10, "Dana's call"); e = next(r for r in w.cp.ledger.entries() if r["kind"] == "glass.control_extended")
        self.assertNotIn("Dana", str(e["public"])); self.assertIn("Dana", str(e["private"]))
        r = next(r for r in w.cp.ledger.entries() if r["kind"] == "glass.risk_accepted"); self.assertNotIn("Dana", str(r["public"]))

    def test_when_the_patch_lands_the_protection_is_retired_and_can_be_taken_off(self):
        w = World6(); g = w.cp.glass; self.block_pdf(w)
        w.host.software["pdfviewer"] = "11.2"; self.assertIn(("cc-1", "retired"), g.review_controls())
        with self.assertRaises(Blocked): w.agent.pre_execute("/apps/pdfviewer.exe", b"MZ x")               # still on until a person removes it: removing is a change too
        r = g.release_control(ADM, "cc-1"); self.assertEqual(r.status, "executed")
        w.agent.pre_execute("/apps/pdfviewer.exe", b"MZ x"); self.assertEqual(g.controls["cc-1"].status, "removed")

    def test_undoing_the_action_removes_the_protection_on_the_device_and_in_the_record(self):
        w = World6(); g = w.cp.glass; r = self.block_pdf(w); u = w.cp.engine.undo(r.action_id, ADM)
        self.assertEqual(u.status, "executed"); w.agent.pre_execute("/apps/pdfviewer.exe", b"MZ x"); self.assertEqual(g.get(PDF).status, "open")

    def test_restricting_exposure_can_be_undone_and_reopens_the_port(self):
        w = World6(); g = w.cp.glass; r = g.compensate(AN, WEB, 5, "window"); w.cp.engine.approve(r.action_id, ADM)
        u = w.cp.engine.undo(w.cp.glass.action_of("cc-1"), ADM)
        if u.status == "pending_approval": u = w.cp.engine.approve(u.action_id, ADM2)
        self.assertEqual(u.status, "executed"); self.assertEqual(w.cp.aws.reachable_from_internet("i-web"), [443])


if __name__ == "__main__":
    unittest.main()
