import unittest
from helpers import *
from rig6 import *
from halvard.relay.actions import ActionRequest


def versions(w, product="pdfviewer"): return {d: r["software"].get(product) for d, r in w.cp.glass.reports().items() if r["software"].get(product)}


class PatchRingTests(unittest.TestCase):
    def test_a_good_update_goes_pilot_first_then_the_rest_only_after_the_soak_and_every_step_is_recorded(self):
        w = World6(); g = w.cp.glass; msg = g.rollout(ADM, "pdfviewer", "11.2", soak_s=3600)
        self.assertIn("pilot ring updated", msg); self.assertEqual(versions(w), {"LT-17": "11.1", "LT-22": "11.2"})        # the broad ring has not been touched
        w.clock.advance(1800); self.assertIn("watching", g.advance("plan-1")); self.assertEqual(versions(w)["LT-17"], "11.1")
        w.clock.advance(1900); g.advance("plan-1"); self.assertEqual(versions(w), {"LT-17": "11.2", "LT-22": "11.2"})
        w.clock.advance(3700); self.assertEqual(g.advance("plan-1"), "complete")
        kinds = [r["kind"] for r in w.cp.ledger.entries() if r["kind"].startswith("glass.ring_") and r["kind"] != "glass.ring_assigned" or r["kind"].startswith("glass.rollout")]
        self.assertEqual(kinds, ["glass.rollout_started", "glass.ring_installed", "glass.ring_passed", "glass.ring_installed", "glass.ring_passed", "glass.rollout_complete"])

    def test_a_bad_update_stops_at_the_pilot_rolls_back_there_and_never_reaches_anyone_else(self):
        w = World6(); g = w.cp.glass; w.host2.update_defects[("pdfviewer", "11.2")] = ["document-preview"]
        msg = g.rollout(ADM, "pdfviewer", "11.2"); self.assertTrue(msg.startswith("halted")); self.assertIn("LT-22", msg)
        self.assertEqual(versions(w), {"LT-17": "11.1", "LT-22": "11.1"}); self.assertEqual(w.host2.broken_services(), [])        # pilot is back as it was; the rest never changed
        self.assertEqual(g.plans["plan-1"].status, "halted"); self.assertEqual(g.advance("plan-1")[:6], "halted")
        h = next(r for r in w.cp.ledger.entries() if r["kind"] == "glass.rollout_halted"); self.assertEqual((h["public"]["ring"], h["public"]["devices_broken"]), ("pilot", 1))
        self.assertTrue(any(r["kind"] == "relay.action_executed" and r["public"].get("pattern") == "patch_failure_rollback" for r in w.cp.ledger.entries()))

    def test_without_the_accepted_pattern_the_rollback_waits_for_a_person_and_says_so(self):
        w = World6(); w.cp.engine.auth.policy.accepted_patterns.discard("patch_failure_rollback"); w.host2.update_defects[("pdfviewer", "11.2")] = ["document-preview"]
        w.cp.glass.rollout(ADM, "pdfviewer", "11.2"); self.assertEqual(versions(w)["LT-22"], "11.2"); self.assertEqual(w.host2.broken_services(), ["document-preview"])
        self.assertTrue(any(p for p in w.cp.engine.pending.values() if p["req"].action == "rollback_update"))

    def test_production_and_crown_jewel_hosts_go_last_and_wait_for_an_approver(self):
        w = World6(); g = w.cp.glass; self.assertEqual((g.ring_of("i-web"), g.ring_of("i-bastion"), g.ring_of("LT-22")), ("critical", "broad", "pilot"))
        g.rollout(ADM, "sshd", "9.4", soak_s=0); w.clock.advance(1); msg = g.advance("plan-1")
        self.assertEqual(versions(w, "sshd"), {"i-web": "9.3", "i-bastion": "9.4"}); self.assertIn("Waiting for an approver before critical", msg)
        r = g.approve_ring("plan-1", ADM2); self.assertEqual(r.status, "executed"); self.assertEqual(versions(w, "sshd")["i-web"], "9.4")
        w.clock.advance(1); self.assertEqual(g.advance("plan-1"), "complete")

    def test_a_bad_update_on_a_production_host_is_never_rolled_back_without_an_approver(self):
        w = World6(); g = w.cp.glass; w.web.host.update_defects[("sshd", "9.4")] = ["remote-admin"]
        g.rollout(ADM, "sshd", "9.4", soak_s=0); w.clock.advance(1); g.advance("plan-1"); g.approve_ring("plan-1", ADM2); w.clock.advance(1); g.advance("plan-1")
        self.assertEqual(g.plans["plan-1"].status, "halted"); self.assertEqual(versions(w, "sshd")["i-web"], "9.4")           # still broken: the rollback needs a person
        rb = [p for p in w.cp.engine.pending.values() if p["req"].action == "rollback_update"]; self.assertEqual(len(rb), 1)
        done = w.cp.engine.approve(next(iter(w.cp.engine.pending)), ADM2); self.assertEqual(done.status, "executed"); self.assertEqual(versions(w, "sshd")["i-web"], "9.3")

    def test_an_offline_device_blocks_the_ring_from_passing_until_it_has_actually_installed(self):
        w = World6(); g = w.cp.glass; w.agent.set_online(False); g.rollout(ADM, "pdfviewer", "11.2", soak_s=0); w.clock.advance(1); g.advance("plan-1")
        self.assertIn("waiting for LT-17", g.advance("plan-1")); self.assertEqual(g.plans["plan-1"].status, "running")
        w.cp.fleet.reconnect("LT-17"); w.clock.advance(1); self.assertEqual(versions(w)["LT-17"], "11.2"); self.assertEqual(g.advance("plan-1"), "complete")

    def test_rings_have_rules_roles_and_records(self):
        w = World6(); g = w.cp.glass
        with self.assertRaises(ValueError): g.assign_ring(ADM, "i-web", "pilot")
        with self.assertRaises(ValueError): g.assign_ring(ADM, "LT-17", "nonsense")
        with self.assertRaises(PermissionError): g.assign_ring(AN, "LT-17", "early")
        with self.assertRaises(PermissionError): g.rollout(SD, "pdfviewer", "11.2")
        with self.assertRaises(ValueError): g.rollout(ADM, "pdfviewer", "11.0")
        g.assign_ring(ADM, "LT-17", "early"); self.assertTrue(any(r["kind"] == "glass.ring_assigned" and r["public"]["ring"] == "early" for r in w.cp.ledger.entries()))

    def test_the_device_itself_refuses_an_update_command_that_carries_too_little_approval(self):
        w = World6(); r = w.cp.fleet.send("i-web", "install_update", {"product": "sshd", "version": "9.4"}, "forged", None, [], "notify")
        self.assertEqual(r["status"], "rejected"); self.assertIn("requires", r["message"]); self.assertEqual(w.web.host.software["sshd"], "9.3")
        ok = w.cp.fleet.send("i-web", "install_update", {"product": "sshd", "version": "9.4"}, "approved", None, [ADM], "approve"); self.assertEqual(ok["status"], "executed"); self.assertTrue(ok["detail"]["healthy"])

    def test_the_device_reports_what_broke_so_the_ring_can_halt_and_its_own_undo_restores_the_version(self):
        w = World6(); w.host.update_defects[("pdfviewer", "11.2")] = ["document-preview"]
        r = w.cp.fleet.send("LT-17", "install_update", {"product": "pdfviewer", "version": "11.2"}, "x", None, [], "notify")
        self.assertEqual(r["status"], "executed"); self.assertFalse(r["detail"]["healthy"]); self.assertEqual(r["detail"]["broken"], ["document-preview"]); self.assertIn("document-preview", r["message"])
        res = w.agent.engine.request(ActionRequest("install_update", ADM, ["LT-17"], "device-side", None, {"product": "officesuite", "version": "17.0"})); self.assertEqual(res.status, "executed")
        self.assertEqual(w.host.software["officesuite"], "17.0"); u = w.agent.engine.undo(res.action_id, ADM); self.assertEqual(u.status, "executed"); self.assertEqual(w.host.software["officesuite"], "16.9")

    def test_undo_puts_the_old_version_back(self):
        w = World6(); r = w.cp.engine.request(ActionRequest("install_update", AN, ["LT-17", "LT-22"], "test", None, {"product": "pdfviewer", "version": "11.2"}))
        self.assertEqual((r.status, versions(w)), ("executed", {"LT-17": "11.2", "LT-22": "11.2"}))
        u = w.cp.engine.undo(r.action_id, AN); self.assertEqual(u.status, "executed"); self.assertEqual(versions(w), {"LT-17": "11.1", "LT-22": "11.1"})


if __name__ == "__main__":
    unittest.main()
