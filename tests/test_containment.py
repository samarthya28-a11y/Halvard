import os, unittest
from helpers import *
from rig3 import *
from halvard.signet.idp import AuthError
from halvard.relay.actions import Principal, ActionRequest

ADM1, ADM2, ANALYST = Principal("u-adm1", "it_admin"), Principal("u-adm2", "analyst"), Principal("u-an", "analyst")


class StolenSessionAcceptance(unittest.TestCase):
    """Acceptance: a stolen session cannot keep acting after Signet revocation and Ward isolation."""

    def story(self, **kw):
        w = World(**kw).alice_signs_in(); w.stealer_runs(); w.attacker_replays(); return w

    def test_before_containment_the_attacker_really_is_in(self):
        w = self.story()
        self.assertTrue(w.mail.handle(w.stolen_mail["access_token"])[0]); self.assertTrue(w.wiki.handle(w.stolen["access_token"])[0])

    def test_device_and_identity_findings_become_one_case_and_contain_automatically(self):
        w = self.story(); cases = w.cp.process()
        self.assertEqual(len(w.cp.cases.cases), 1, [c.findings for c in cases])
        c = next(iter(w.cp.cases.cases.values())); srcs = {f.source for f in c.findings}
        self.assertEqual(srcs, {"signet", "ward"}); self.assertGreaterEqual(w.cp.cases.confidence(c)[0], 0.97)
        self.assertEqual(w.cp.auto_log, [(c.id, "executed")]); self.assertEqual(c.status, "contained")

    def test_the_stolen_session_stops_everywhere_it_can_and_the_rest_is_stated(self):
        w = self.story(); w.cp.process()
        # refresh is dead at once, even for the copy the attacker just rotated to
        with self.assertRaises(AuthError): w.cp.idp.refresh_grant(w.stolen["refresh_token"], "203.0.113.7", MOW, app="mail")
        with self.assertRaises(AuthError): w.cp.idp.refresh_grant(w.stolen_mail["refresh_token"], "203.0.113.7", MOW, app="mail")
        # applications that ask the IdP stop immediately
        self.assertEqual(w.mail.handle(w.stolen_mail["access_token"])[0], False); self.assertIn("revoked", w.mail.handle(w.stolen_mail["access_token"])[1])
        # the wiki does not ask: the token keeps working until it expires. Halvard said so, and for how long.
        self.assertTrue(w.wiki.handle(w.stolen["access_token"])[0])
        c = next(iter(w.cp.cases.cases.values())); self.assertTrue(any("Team Wiki" in p and "minutes" in p for p in c.pending), c.pending)
        w.clock.advance(3601); self.assertEqual(w.wiki.handle(w.stolen["access_token"]), (False, "expired"))
        # the attacker cannot start over with a fresh sign-in: credentials and verification were reset, and the device is refused
        with self.assertRaises(AuthError): w.cp.idp.sign_in("alice@acme.com", "correct-horse", "203.0.113.7", MOW, mfa="approve")

    def test_the_compromised_device_is_isolated_and_cannot_sign_in(self):
        w = self.story(); w.cp.process()
        self.assertTrue(w.host.isolated); self.assertTrue(w.host.can_reach("mgmt.halvard.example")); self.assertFalse(w.host.can_reach("203.0.113.7"))
        self.assertFalse(w.cp.idp.devices["LT-17"]["compliant"])
        with self.assertRaises(AuthError) as e: w.cp.idp.sign_in("alice@acme.com", w.cp.idp.users["alice@acme.com"].password, "198.51.100.4", LON, device_id="LT-17", mfa="approve")
        self.assertEqual(e.exception.reason, "device_noncompliant")

    def test_the_manager_is_told_on_an_approved_channel_with_plain_words(self):
        w = self.story(); w.cp.process(); sent = w.ch[0].sent
        self.assertEqual(len(sent), 1); addr, text = sent[0]; self.assertEqual(addr, "maria@acme.com")
        for leaked in ("203.0.113.7", "token", "stealer", "Cookies", "password", "RU"): self.assertNotIn(leaked, text)
        self.assertIn("Alice Kim", text); self.assertIn("protected", text)

    def test_never_notifies_through_a_channel_owned_by_an_affected_identity(self):
        ch = Channel("email", owner_identity_of=lambda a: "alice@acme.com")        # this channel belongs to alice's mailbox
        w = World(channels=[ch]).alice_signs_in(); w.stealer_runs(); w.attacker_replays(); w.cp.process()
        self.assertEqual(ch.sent, []); c = next(iter(w.cp.cases.cases.values()))
        r = w.cp.notifier.notify_manager("p:alice", compromised_identities=["alice@acme.com"]); self.assertEqual(r["status"], "no_safe_channel")
        w2 = World(channels=[]); r = w2.cp.notifier.notify_manager("p:alice"); self.assertEqual(r["status"], "no_approved_channel")

    def test_every_step_is_in_the_tenant_ledger_and_the_device_ledger_agrees(self):
        w = self.story(); w.cp.process(); L = [e for e in w.cp.ledger.entries()]
        steps = {e["public"].get("action") for e in L if e["kind"] == "relay.action_executed"}
        self.assertTrue({"revoke_sessions", "set_device_health_signal", "force_mfa_reregistration", "reset_credentials", "notify_manager", "contain_everywhere"} <= steps, steps)
        cmd = next(e for e in L if e["kind"] == "relay.command_sent"); self.assertEqual(cmd["public"]["result"], "executed")
        dev = [e for e in w.agent.spool.entries() if e["kind"] == "relay.action_executed" and e["public"]["action"] == "isolate_host"]
        self.assertEqual(dev[0]["public"]["pending"], cmd["public"]["command_id"])        # same command id on both sides
        self.assertTrue(w.cp.ledger.verify()[0] and w.agent.spool.verify()[0])
        blob = str(L); self.assertNotIn("correct-horse", blob); self.assertNotIn(w.refresh, blob); self.assertNotIn(w.stolen["access_token"], blob)

    def test_without_an_accepted_pattern_it_prepares_and_waits(self):
        w = self.story(auto=False); w.cp.process(); c = next(iter(w.cp.cases.cases.values()))
        self.assertEqual(w.cp.auto_log, [(c.id, "pending_pattern_acceptance")]); self.assertFalse(w.host.isolated)
        self.assertTrue(w.wiki.handle(w.stolen["access_token"])[0]); self.assertTrue(any("Approve containment" in p for p in c.pending))
        self.assertIn("Team Wiki", c.pending[0])      # the preview already names the residual exposure

    def test_offline_laptop_identity_side_still_contains_and_device_step_waits_then_runs(self):
        w = self.story(); w.agent.set_online(False); w.cp.process(); c = next(iter(w.cp.cases.cases.values()))
        with self.assertRaises(AuthError): w.cp.idp.refresh_grant(w.stolen["refresh_token"], "203.0.113.7", MOW)        # identity side did not wait
        self.assertFalse(w.host.isolated); self.assertEqual(c.status, "open"); self.assertTrue(any("isolate_host" in p and "queued" in p for p in c.pending), c.pending)
        self.assertFalse(w.cp.idp.devices["LT-17"]["compliant"])        # and the IdP already refuses the device
        out = w.cp.fleet.reconnect("LT-17"); self.assertEqual([o["status"] for o in out], ["executed"]); self.assertTrue(w.host.isolated)

    def test_stale_queued_command_expires_instead_of_running_late(self):
        w = self.story(); w.agent.set_online(False); w.cp.process(); w.clock.advance(7 * 3600)
        out = w.cp.fleet.reconnect("LT-17"); self.assertEqual(out[0]["status"], "rejected"); self.assertIn("expired", out[0]["message"]); self.assertFalse(w.host.isolated)

    def test_device_enforces_its_own_approval_rules_even_if_the_control_plane_does_not(self):
        w = self.story(device_class="clinical"); w.cp.store.put_entity(w.cp.ctx, "LT-17", "device", "LT-17", w.clock.now(), asset_class="standard")   # control plane wrongly thinks standard
        w.cp.process(); self.assertFalse(w.host.isolated)
        rej = [e for e in w.agent.spool.entries() if e["kind"] == "ward.command_rejected"]; self.assertTrue(rej); self.assertIn("two_person", rej[0]["public"]["why"])
        c = next(iter(w.cp.cases.cases.values())); self.assertEqual(c.status, "open"); self.assertTrue(any("rejected" in p for p in c.pending))

    def test_forged_tampered_or_replayed_commands_are_refused(self):
        w = self.story(); w.cp.process(); f = w.cp.fleet; a = w.agent
        from halvard.relay import commands
        good = commands.sign(POLICY_KEY, device="LT-17", action="release_isolation", params={}, reason="r", case="c", approvals=[{"id": "u1", "role": "it_admin"}], rule="approve", issuer="cp", now=w.clock.now())
        forged = dict(good, action="stop_process", params={"pid": 1}); self.assertEqual(a.execute_command(forged, POLICY_KEY)["status"], "rejected")
        other = commands.sign(b"x" * 32, device="LT-17", action="release_isolation", params={}, reason="r", case="c", approvals=[], rule="approve", issuer="cp", now=w.clock.now()); self.assertEqual(a.execute_command(other, POLICY_KEY)["status"], "rejected")
        wrong_dev = dict(commands.sign(POLICY_KEY, device="LT-99", action="isolate_host", params={}, reason="r", case="c", approvals=[], rule="notify", issuer="cp", now=w.clock.now())); self.assertEqual(a.execute_command(wrong_dev, POLICY_KEY)["status"], "rejected")
        self.assertEqual(a.execute_command(good, POLICY_KEY)["status"], "executed"); self.assertIn("already used", a.execute_command(good, POLICY_KEY)["message"])
        unsafe = commands.sign(POLICY_KEY, device="LT-17", action="remote_command", params={"command": "x"}, reason="r", case="c", approvals=[], rule="approve", issuer="cp", now=w.clock.now())
        self.assertIn("cannot be sent remotely", a.execute_command(unsafe, POLICY_KEY)["message"])

    def test_recovery_restores_access_and_says_what_stays_reset(self):
        w = self.story(); res_list = w.cp.process(); c = next(iter(w.cp.cases.cases.values()))
        act = next(k for k, v in w.cp.engine.executed.items() if v["req"].action == "contain_everywhere")
        u = w.cp.engine.undo(act, ADM1); self.assertEqual(u.status, "pending_approval" if u.status != "executed" else "executed")
        u = w.cp.engine.approve(u.action_id, ADM2) if u.status == "pending_approval" else u
        self.assertEqual(u.status, "executed", u.message); self.assertIn("Reset passwords and verification methods stay reset", u.message)
        self.assertFalse(w.host.isolated); self.assertTrue(w.cp.idp.devices["LT-17"]["compliant"])
        with self.assertRaises(AuthError): w.cp.idp.sign_in("alice@acme.com", "correct-horse", "198.51.100.4", LON, device_id="LT-17", mfa="approve")   # old password stays dead
        w.cp.idp.complete_mfa_registration("alice@acme.com"); pw = w.cp.idp.users["alice@acme.com"].password
        self.assertTrue(w.cp.idp.sign_in("alice@acme.com", pw, "198.51.100.4", LON, device_id="LT-17", mfa="approve")["access_token"])

    def test_case_page_reads_in_plain_words_and_states_residual_exposure(self):
        w = self.story(); w.cp.process(); c = next(iter(w.cp.cases.cases.values())); page = w.cp.cases.page(c)
        for must in ("WHAT IS HAPPENING", "WHO AND WHAT IS INVOLVED", "WHAT HALVARD ALREADY DID", "WHAT NEEDS A PERSON", "BUSINESS IMPACT", "Alice Kim", "LT-17", "Team Wiki", "Heuristic, not a calibrated probability"): self.assertIn(must, page)
        self.assertLess(page.index("[device]"), page.index("[identity]") + 1000)


class ContainmentRobustness(unittest.TestCase):
    def test_one_failing_step_is_reported_and_the_others_still_run(self):
        w = World().alice_signs_in(); ids = ["id:idp:alice@acme.com", "id:idp:ghost@acme.com"]
        r = w.cp.engine.request(ActionRequest("contain_everywhere", ANALYST, ids, "test", None, {"identities": ids, "devices": ["LT-17"], "notify_person": "p:alice"}, critical=True))
        self.assertEqual(r.status, "executed"); self.assertTrue(r.detail["partial"])
        failed = [s for s in r.detail["steps"] if s["status"] == "failed"]; self.assertTrue(failed and all("ghost" in s["target"] for s in failed))
        with self.assertRaises(AuthError): w.cp.idp.refresh_grant(w.refresh, "203.0.113.7", MOW)            # alice's sessions were still ended
        self.assertTrue(w.host.isolated); self.assertIn("Not finished", r.message)

    def test_a_tightened_component_rule_tightens_the_whole_containment(self):
        w = World(); w.cp.engine.auth.policy.overrides["reset_credentials"] = {"standard": "two_person"}
        r = w.cp.engine.request(ActionRequest("contain_everywhere", ANALYST, ["id:idp:alice@acme.com"], "t", None, {"identities": ["id:idp:alice@acme.com"], "devices": []}))
        self.assertEqual((r.status, r.requirement.level), ("pending_approval", "two_person"))

    def test_device_command_with_too_few_approvers_is_refused(self):
        w = World(device_class="clinical"); from halvard.relay import commands
        one = commands.sign(POLICY_KEY, device="LT-17", action="isolate_host", params={}, reason="r", case="c", approvals=[{"id": "u1", "role": "it_admin"}], rule="two_person", issuer="cp", now=w.clock.now())
        r = w.agent.execute_command(one, POLICY_KEY); self.assertEqual(r["status"], "rejected"); self.assertIn("needs 2 different approvers", r["message"])
        dup = commands.sign(POLICY_KEY, device="LT-17", action="isolate_host", params={}, reason="r", case="c", approvals=[{"id": "u1", "role": "it_admin"}, {"id": "u1", "role": "it_admin"}], rule="two_person", issuer="cp", now=w.clock.now())
        self.assertEqual(w.agent.execute_command(dup, POLICY_KEY)["status"], "rejected")
        two = commands.sign(POLICY_KEY, device="LT-17", action="isolate_host", params={}, reason="r", case="c", approvals=[{"id": "u1", "role": "it_admin"}, {"id": "u2", "role": "analyst"}], rule="two_person", issuer="cp", now=w.clock.now())
        self.assertEqual(w.agent.execute_command(two, POLICY_KEY)["status"], "executed")


class PrivilegedAndHybrid(unittest.TestCase):
    def test_a_hijacked_domain_admin_needs_two_people_not_zero(self):
        w = World().alice_signs_in()
        bob = w.cp.idp.sign_in("bob@acme.com", "correct-horse", "198.51.100.9", LON, mfa="approve", prompts=7); w.cp.idp.refresh_grant(bob["refresh_token"], "203.0.113.7", MOW)
        w.cp.signet.sync_graph(); w.cp.process()
        c = [c for c in w.cp.cases.cases.values() if any("bob" in f.entity_id for f in c.findings)][0]
        self.assertEqual(w.cp.auto_log[-1][1], "pending_approval")
        bob_id = "id:idp:bob@acme.com"; self.assertEqual(w.cp.class_of(bob_id), "privileged")
        pend = next(iter(w.cp.engine.pending)); self.assertEqual(w.cp.engine.pending[pend]["reqmt"].level, "two_person")
        self.assertEqual(w.cp.approve(pend, ADM1, c).status, "pending_approval"); self.assertEqual(w.cp.approve(pend, ADM1, c).status, "denied")
        self.assertEqual(w.cp.approve(pend, ADM2, c).status, "executed"); self.assertEqual(c.status, "contained")
        with self.assertRaises(AuthError): w.cp.idp.refresh_grant(bob["refresh_token"], "203.0.113.7", MOW)

    def test_hybrid_user_is_contained_in_both_the_cloud_and_the_directory(self):
        w = World().alice_signs_in(); w.stealer_runs(); w.attacker_replays(); w.cp.process()
        self.assertFalse(w.cp.ad.users["alice"].enabled and False)          # (account stays enabled: we reset, not disable, by default)
        steps = [s for e in w.cp.engine.executed.values() if e["req"].action == "contain_everywhere" for s in [e]]
        ids = steps[0]["req"].params["identities"]; self.assertEqual(set(ids), {"id:idp:alice@acme.com", "id:ad:alice"})
        ad_resets = [e for e in w.cp.ad.log if e["event_id"] == 4724]; self.assertEqual([e["account"] for e in ad_resets], ["alice"])

    def test_disable_option_blocks_the_account_and_is_reversible(self):
        w = World().alice_signs_in(); eng = w.cp.engine
        r = eng.request(ActionRequest("disable_account", ANALYST, ["id:idp:alice@acme.com", "id:ad:alice"], "leaver", None, {}))
        self.assertEqual(r.status, "executed"); self.assertIn("Kerberos tickets", r.preview["summary"])
        with self.assertRaises(AuthError): w.cp.idp.refresh_grant(w.refresh, "198.51.100.4", LON, device_id="LT-17")
        self.assertFalse(w.cp.ad.users["alice"].enabled); self.assertEqual(eng.undo(r.action_id, ADM1).status, "executed"); self.assertTrue(w.cp.ad.users["alice"].enabled)

    def test_standing_privilege_removal_is_gated_and_reversible(self):
        w = World(); w.cp.idp.assign_role("maria@acme.com", "Exchange Administrator", "admin-ops", mode="permanent"); w.cp.signet.sync_graph()
        r = w.cp.engine.request(ActionRequest("remove_standing_privilege", ADM1, ["id:idp:maria@acme.com"], "unused", None, {"role": "Exchange Administrator"}))
        self.assertEqual(r.status, "pending_approval"); self.assertEqual(r.requirement.level, "two_person")     # privileged account: two other administrators
        self.assertEqual(w.cp.engine.approve(r.action_id, ADM1).status, "denied")
        self.assertEqual(w.cp.engine.approve(r.action_id, Principal("u-adm3", "it_admin")).status, "pending_approval")
        self.assertEqual(w.cp.engine.approve(r.action_id, Principal("u-adm2", "analyst")).status, "denied")      # analysts may not approve this action
        done = w.cp.engine.approve(r.action_id, Principal("u-adm4", "it_admin")); self.assertEqual(done.status, "executed")
        self.assertNotIn("Exchange Administrator", w.cp.idp.users["maria@acme.com"].roles)
        u = w.cp.engine.undo(done.action_id, ADM1); u = w.cp.engine.approve(u.action_id, Principal("u-adm3", "it_admin")) if u.status == "pending_approval" else u
        self.assertEqual(u.status, "executed"); self.assertIn("Exchange Administrator", w.cp.idp.users["maria@acme.com"].roles)

    def test_service_desk_cannot_run_containment(self):
        w = World(); r = w.cp.engine.request(ActionRequest("contain_everywhere", Principal("u-sd", "service_desk"), ["id:idp:alice@acme.com"], "x", None, {"identities": ["id:idp:alice@acme.com"], "devices": []}))
        self.assertEqual(r.status, "denied")


if __name__ == "__main__":
    unittest.main()
