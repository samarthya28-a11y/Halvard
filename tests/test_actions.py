import os, tempfile, unittest, pathlib
from helpers import *
from halvard.relay.actions import ActionRequest, Principal
from halvard.ward.agent import SYSTEM

ADMIN, ANALYST, DESK = Principal("u-admin", "it_admin"), Principal("u-an", "analyst"), Principal("u-desk", "service_desk")


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.a, self.host, self.clock, self.fs = make_agent(self.tmp); self.e = self.a.engine
        self.f = os.path.join(self.tmp, "x.bin"); pathlib.Path(self.f).write_bytes(b"suspicious")

    def req(self, action, actor=ADMIN, **kw): return self.e.request(ActionRequest(action, actor, kw.pop("targets", ["LT-17"]), kw.pop("reason", "test"), **kw))

    def test_role_without_permission_is_denied_and_logged(self):
        r = self.req("remote_command", DESK, params={"command": "whoami"})
        self.assertEqual(r.status, "denied")
        self.assertTrue(any(e["kind"] == "relay.action_denied" for e in self.a.spool.entries()))

    def test_service_desk_can_isolate_standard_laptop_and_everyone_is_told(self):
        r = self.req("isolate_host", DESK); self.assertEqual(r.status, "executed"); self.assertTrue(self.host.isolated)
        self.assertTrue(any(e["kind"] == "relay.notice_sent" for e in self.a.spool.entries()))

    def test_executed_action_record_has_actor_reason_scope_approval_reversal(self):
        self.req("isolate_host", ANALYST, reason="phishing click")
        rec = next(e for e in self.a.spool.entries() if e["kind"] == "relay.action_executed")
        for k in ("scope", "approval_rule", "approvers", "reversal", "cannot_undo"): self.assertIn(k, rec["public"])
        self.assertIn("reason", rec["private"])        # the reason is free text and may name a person, so it lives in the private half; an auditor sees that it exists and how to ask for it
        self.assertEqual(rec["public"]["reversal"], "release_isolation"); self.assertEqual(rec["actor_role"], "analyst")

    def test_isolation_keeps_management_channel_only(self):
        self.req("isolate_host"); self.assertTrue(self.host.can_reach("mgmt.halvard.example"))
        self.assertFalse(self.host.can_reach("intranet.example")); self.assertFalse(self.host.can_reach("8.8.8.8"))

    def test_irreversible_action_says_so_before_and_after_and_undo_is_refused(self):
        self.host.spawn(9, "evil.exe")
        r = self.req("stop_process", params={"pid": 9})
        self.assertEqual(r.status, "executed"); self.assertIn("in-memory state of the stopped process", r.cannot_undo)
        u = self.e.undo(r.action_id, ADMIN)
        self.assertEqual(u.status, "denied"); self.assertIn("cannot be undone", u.message); self.assertIn("in-memory state", u.message)

    def test_undo_preview_lists_what_will_not_come_back(self):
        self.host.persistence["a"] = "1"
        r = self.req("remove_persistence", params={"keys": ["a"]})
        pv = self.e.handlers["undo_action"].preview(self.e, ActionRequest("undo_action", ADMIN, ["LT-17"], "u", params={"target_action": r.action_id}))
        self.assertIn("cannot be undone", pv["summary"])

    def test_stop_process_preview_lists_irreversible_effects(self):
        self.host.spawn(9, "evil.exe"); r = self.req("stop_process", params={"pid": 9})
        self.assertIn("Unsaved data", r.preview["summary"])

    def test_quarantine_and_release_roundtrip(self):
        r = self.req("quarantine_file", targets=[self.f]); self.assertFalse(os.path.exists(self.f))
        self.assertEqual(r.status, "executed")
        rel = self.req("release_quarantine", params={"qids": r.detail["qids"]}); self.assertEqual(rel.status, "pending_approval")
        self.assertEqual(self.e.approve(rel.action_id, ANALYST).status, "executed")
        self.assertEqual(pathlib.Path(self.f).read_bytes(), b"suspicious")

    def test_service_desk_cannot_release_without_it_or_analyst_approval(self):
        r = self.req("quarantine_file", targets=[self.f])
        rel = self.req("release_quarantine", DESK, params={"qids": r.detail["qids"]})
        self.assertEqual(rel.status, "pending_approval")
        self.assertEqual(self.e.approve(rel.action_id, DESK).status, "denied")          # desk cannot approve (nor self-approve)
        self.assertEqual(self.e.approve(rel.action_id, ANALYST).status, "executed")

    def test_requester_cannot_approve_own_request(self):
        r = self.req("remote_command", ANALYST, params={"command": "whoami"}); self.assertEqual(r.status, "pending_approval")
        self.assertEqual(self.e.approve(r.action_id, ANALYST).status, "denied")

    def test_remote_command_never_auto_and_is_recorded(self):
        r = self.req("remote_command", ANALYST, params={"command": "ipconfig /all"})
        self.assertEqual(r.status, "pending_approval"); self.assertEqual(self.host.commands_run, [])
        self.assertEqual(self.e.approve(r.action_id, ADMIN).status, "executed"); self.assertEqual(self.host.commands_run, ["ipconfig /all"])
        rec = [x for x in self.a.spool.entries() if x["kind"] == "relay.action_executed"][-1]
        self.assertEqual(rec["private"]["command"], "ipconfig /all"); self.assertIn("output_sha256", rec["public"])

    def test_keeper_needs_jit_elevation(self):
        k = Principal("keeper-1", "keeper_crew", elevated_until=0)
        self.assertEqual(self.req("isolate_host", k).status, "denied")
        k = Principal("keeper-1", "keeper_crew", elevated_until=self.clock.now() + 600)
        self.assertEqual(self.req("isolate_host", k).status, "executed")
        self.clock.advance(601); self.assertEqual(self.req("release_isolation", k).status, "denied")

    def test_keeper_propose_only_actions_wait_for_customer_approver(self):
        k = Principal("keeper-1", "keeper_crew", elevated_until=self.clock.now() + 600)
        r = self.req("release_isolation", k); self.assertEqual(r.status, "pending_approval")
        self.assertEqual(self.e.approve(r.action_id, k).status, "denied")
        self.assertEqual(self.req("break_glass_local" if False else "release_legal_hold", k).status, "denied")

    def test_automatic_action_must_come_from_system_principal(self):
        r = self.e.request(ActionRequest("isolate_host", ADMIN, ["LT-17"], "x", automatic=True, pattern="p"))
        self.assertEqual(r.status, "denied")

    def test_first_run_of_automation_shows_its_work_then_runs_after_acceptance(self):
        a, host, clock, fs = make_agent(self.tmp + "2", accepted=())
        mk = lambda: a.engine.request(ActionRequest("isolate_host", SYSTEM, ["LT-17"], "auto", automatic=True, pattern="isolate_on_high_confidence"))
        r = mk(); self.assertEqual(r.status, "pending_pattern_acceptance"); self.assertFalse(host.isolated); self.assertIn("network access", r.preview["summary"])
        a.engine.accept_pattern("isolate_on_high_confidence", ADMIN)
        self.assertEqual(mk().status, "executed"); self.assertTrue(host.isolated)

    def test_only_admins_accept_patterns(self):
        with self.assertRaises(PermissionError): self.e.accept_pattern("x", DESK)

    def test_maintenance_window_defers_ordinary_action_but_never_critical(self):
        self.e.auth.policy.maintenance_windows["LT-17"] = (self.clock.now() - 10, self.clock.now() + 3600)
        self.assertEqual(self.req("isolate_host").status, "deferred"); self.assertFalse(self.host.isolated)
        self.assertEqual(self.req("isolate_host", critical=True).status, "executed")

    def test_legal_hold_blocks_cleanup_until_evidence_is_frozen(self):
        self.assertEqual(self.req("legal_hold", case_id="c1").status, "executed")
        r = self.req("quarantine_file", targets=[self.f], case_id="c1"); self.assertEqual(r.status, "blocked"); self.assertTrue(os.path.exists(self.f))
        self.e.freeze_evidence("c1", [self.f], ADMIN)
        self.assertEqual(self.req("quarantine_file", targets=[self.f], case_id="c1").status, "executed")
        self.assertTrue(any(True for _ in pathlib.Path(self.e.evidence_dir, "c1").iterdir()))

    def test_unknown_or_unbuilt_action_is_refused(self):
        self.assertEqual(self.req("disable_account").status, "denied")    # Signet arrives in Phase 3

    def test_config_rollback_restores_persistence(self):
        self.host.persistence["run:good"] = "ok"; snap = self.host.snapshot_config()
        self.host.persistence["run:evil"] = "payload"
        r = self.req("remove_persistence", params={"keys": ["run:evil"]}); self.assertNotIn("run:evil", self.host.persistence)
        self.assertEqual(self.e.undo(r.action_id, ADMIN).status, "executed"); self.assertIn("run:evil", self.host.persistence)


if __name__ == "__main__":
    unittest.main()
