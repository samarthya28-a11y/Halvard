import hashlib, os, unittest, json
from helpers import *
from rig4 import *
from halvard.ward.agent import Blocked
from halvard.relay.actions import ActionRequest

ADM, ADM2, AN, SD = Principal("u-adm", "it_admin"), Principal("u-adm2", "it_admin"), Principal("u-an", "analyst"), Principal("u-sd", "service_desk")


class MailedAttachmentAcceptance(unittest.TestCase):
    """Acceptance: a malicious mailed attachment and the device that opened it appear as one case."""

    def scenario(self):
        w = World4(); self.d = docx_like(b"campaign-seed-1"); self.h = hashlib.sha256(self.d).hexdigest()
        w.msg = w.send("billing@vendor-docs.example", "Invoice 4471 - please review", "Please open the attached invoice and enable editing.", to=("alice@acme.com", "bob@acme.com", "maria@acme.com"), attachments=[("invoice.docx", self.d)])
        w.cp.process()                                               # at delivery nothing is known: the file looks like an ordinary document
        w.clock.advance(30); w.opens_on_laptop("alice@acme.com", w.msg, "invoice.docx"); w.word_spawns_powershell()
        w.clock.advance(300); w.cp.process()                         # Ward's rule fires on the laptop; still only one source
        return w

    def test_nothing_is_wrong_at_delivery_and_the_delay_is_measured_not_assumed(self):
        w = self.scenario(); self.assertEqual(w.cp.courier.records[("alice@acme.com", w.msg.id)].verdict, "allow")
        self.assertEqual(len(w.cp.cases.cases), 1); c = next(iter(w.cp.cases.cases.values())); self.assertEqual({f.source for f in c.findings}, {"ward"})
        w.cp.intel.add_bad_hash(self.h, "reported in a campaign targeting finance teams"); w.clock.advance(60); w.cp.process()
        f = next(x for x in w.cp.courier.findings if x.detector == "malicious_mail" and x.entity == "mbx:alice@acme.com")
        self.assertTrue(f.details["delayed"]); self.assertEqual(f.details["exposure_s"], 390); self.assertIn("verdict changed after delivery", f.why)

    def test_the_attachment_and_the_laptop_are_one_case_with_a_story(self):
        w = self.scenario(); w.cp.intel.add_bad_hash(self.h); w.clock.advance(60); w.cp.process()
        self.assertEqual(len(w.cp.cases.cases), 1, [[(x.source, x.detector if hasattr(x, 'detector') else x.family) for x in c.findings] for c in w.cp.cases.cases.values()])
        c = next(iter(w.cp.cases.cases.values())); self.assertEqual({f.source for f in c.findings}, {"ward", "courier"})
        dets = {f.details.get("detector") for f in c.findings}; self.assertIn("malicious_attachment_landed", dets)          # found by hunting telemetry for the file's fingerprint
        self.assertGreaterEqual(w.cp.cases.confidence(c)[0], 0.97); page = w.cp.cases.page(c)
        for must in ("Alice Kim", "LT-17", "alice@acme.com", "bob@acme.com", "maria@acme.com", "[device]", "[mail]", "Bob Ng (only received it)", "LT-22 (only received it)"): self.assertIn(must, page)
        self.assertEqual(c.campaigns, {self.h})

    def test_containment_pulls_every_copy_isolates_the_laptop_removes_the_file_and_does_not_reset_passwords(self):
        w = self.scenario(); w.cp.intel.add_bad_hash(self.h); w.clock.advance(60); w.cp.process(); c = next(iter(w.cp.cases.cases.values()))
        self.assertEqual(c.status, "contained"); mb = w.cp.mail.mailboxes
        for a in ("bob@acme.com", "maria@acme.com", "alice@acme.com"): self.assertIn(w.msg.id, mb[a].folders["quarantine"], a)
        self.assertTrue(w.host.isolated); self.assertFalse(os.path.exists(os.path.join(w.tmp, "mailtmp", "invoice.docx")), "the saved attachment should be quarantined on the laptop")
        steps = {e["public"].get("action") for e in w.cp.ledger.entries() if e["kind"] == "relay.action_executed"}
        self.assertTrue({"clawback_message", "set_device_health_signal", "contain_everywhere"} <= steps, steps); self.assertNotIn("reset_credentials", steps)
        self.assertTrue(any("password" in p.lower() or "credential" in p.lower() for p in c.pending), c.pending)                  # a human decides about passwords
        self.assertTrue(any(k.startswith("clawback") and st == "executed" for k, st in w.cp.auto_log), w.cp.auto_log)

    def test_clawback_is_honest_about_what_it_cannot_undo(self):
        w = self.scenario(); w.cp.intel.add_bad_hash(self.h); w.clock.advance(60); w.cp.process()
        ex = {r["mailbox"]: r for r in w.cp.courier.exposure(self.h)}
        self.assertTrue(ex["alice@acme.com"]["at_risk"]); self.assertIn("attachment_opened", ex["alice@acme.com"]["state"]); self.assertFalse(ex["bob@acme.com"]["at_risk"])
        ent = next(e for e in w.cp.ledger.entries() if e["kind"] == "relay.action_executed" and e["public"].get("action") == "clawback_message")
        self.assertEqual(ent["public"]["at_risk"], 1); self.assertIn("what recipients already did", " ".join(ent["public"]["cannot_undo"]))

    def test_the_same_file_is_blocked_on_every_other_device_and_cannot_run_there(self):
        w = self.scenario(); w.cp.intel.add_bad_hash(self.h); w.clock.advance(60); w.cp.process()
        self.assertIn(self.h, w.agent2.bundle.known_bad_sha256); w.agent2.set_online(False)
        with self.assertRaises(Blocked): w.agent2.pre_execute("C:/Users/bob/Downloads/invoice.docx", self.d)           # offline, on the device itself

    def test_an_offline_device_gets_the_new_block_list_when_it_returns(self):
        w = self.scenario(); w.agent2.set_online(False); w.cp.intel.add_bad_hash(self.h); w.clock.advance(60); w.cp.process()
        self.assertNotIn(self.h, w.agent2.bundle.known_bad_sha256); out = w.cp.fleet.reconnect("LT-22"); self.assertIn(self.h, w.agent2.bundle.known_bad_sha256); self.assertEqual(out[0]["action"], "policy")

    def test_no_message_text_or_subject_is_kept_by_halvard(self):
        w = self.scenario(); w.cp.intel.add_bad_hash(self.h); w.clock.advance(60); w.cp.process()
        blob = json.dumps(list(w.cp.ledger.entries())) + json.dumps(list(w.agent.spool.entries())) + str([vars(r) | {"subject_hint": ""} for r in w.cp.courier.records.values()]) + str(w.cp.cases.page(next(iter(w.cp.cases.cases.values()))))
        for text in ("enable editing", "Invoice 4471", "Please open the attached", "campaign-seed-1"): self.assertNotIn(text, blob, text)
        self.assertTrue(w.cp.ledger.verify()[0])

    def test_auditor_export_of_detections_carries_no_addresses_names_or_file_names(self):
        w = self.scenario(); w.cp.intel.add_bad_hash(self.h); w.clock.advance(60); w.cp.process()
        w.send("m.lopez@gmail.example", "Quick favour", "Buy gift cards today and do not tell anyone.", display_name="Maria Lopez", reply_to="x@proton.example"); w.cp.process()
        from halvard.ledger.audit import verify_export
        for ctl in ("COURIER.DETECTION", "RELAY.CLAWBACK_MESSAGE"):
            exp = w.cp.ledger.export_for_control(ctl); blob = json.dumps(exp); self.assertEqual(verify_export(exp), (True, []))
            for secret in ("alice@acme.com", "bob@acme.com", "maria@acme.com", "Maria Lopez", "Alice Kim", "invoice.docx", "mbx:"): self.assertNotIn(secret, blob, f"{ctl}: {secret}")
            self.assertTrue(any(not e.get("elided") for e in exp["entries"]), ctl)

    def test_without_the_accepted_patterns_it_prepares_and_waits(self):
        w = World4(); w.cp.engine.auth.policy.accepted_patterns.clear(); d = docx_like(b"x2"); h = hashlib.sha256(d).hexdigest()
        m = w.send("billing@vendor-docs.example", "Invoice", "see attached", attachments=[("i.docx", d)]); w.cp.process(); w.cp.intel.add_bad_hash(h); w.clock.advance(10); w.cp.process()
        self.assertEqual(w.cp.auto_log[0][1], "pending_pattern_acceptance"); self.assertNotIn(m.id, w.cp.mail.mailboxes["alice@acme.com"].folders["quarantine"])


class TelemetryLinks(unittest.TestCase):
    def test_documents_are_fingerprinted_other_files_and_contents_are_not(self):
        w = World4(); host, fs = w.host, w.fs; host.spawn(50, "outlook.exe")
        fs.create(50, os.path.join(w.tmp, "t", "a.docx"), b"doc bytes"); fs.create(50, os.path.join(w.tmp, "t", "n.txt"), b"plain")
        ev = [e for e in w.agent.outbox if e["kind"] == "file" and e["op"] == "create"]; by = {os.path.basename(e["path"]): e for e in ev}
        self.assertEqual(by["a.docx"]["file_sha256"], hashlib.sha256(b"doc bytes").hexdigest()); self.assertIsNone(by["n.txt"]["file_sha256"]); self.assertNotIn("doc bytes", str(ev))

    def test_process_lineage_is_recorded(self):
        w = World4(); w.host.spawn(60, "winword.exe"); w.host.spawn(61, "powershell.exe", ppid=60); ev = w.agent.emit("process", "exec", 61, "x"); self.assertEqual(ev["parent_proc"], "winword.exe")

    def test_a_hash_hunt_finds_every_device_that_saved_the_file(self):
        w = World4(); d = b"same bytes"; h = hashlib.sha256(d).hexdigest()
        w.host.spawn(70, "outlook.exe"); w.host2.spawn(71, "outlook.exe"); w.fs.create(70, os.path.join(w.tmp, "x", "i.docx"), d); w.fs2.create(71, os.path.join(w.tmp, "y", "i.docx"), d); w.cp.process()
        self.assertEqual(sorted(l["device"] for l in w.cp.courier.landings(h)), ["LT-17", "LT-22"])


class ImpersonationAndFraud(unittest.TestCase):
    def test_payment_fraud_from_a_lookalike_supplier_is_pulled_before_anyone_pays(self):
        w = World4(); m = w.send("ar@g1obex-supplies.com", "Invoice overdue - urgent payment", f"Our bank details changed. Please pay to {ROGUE_IBAN} today.", display_name="Globex Accounts", reply_to="ar@mail-pay.example")
        w.cp.process(); self.assertTrue({"lookalike_domain", "payment_request_unknown_account"} <= {f.detector for f in w.cp.courier.findings})
        self.assertIn(m.id, w.cp.mail.mailboxes["alice@acme.com"].folders["quarantine"]); self.assertEqual(w.cp.auto_log[0][1], "executed")

    def test_sender_only_fraud_is_reported_as_impersonation_not_as_a_harmful_attachment(self):
        w = World4(); w.send("ar@globex-supplies.com", "Updated bank details", f"New bank account for payments: {ROGUE_IBAN}", display_name="Globex AR")
        dets = {f.detector for f in w.cp.courier.poll()}; self.assertEqual(dets, {"bank_details_changed"})

    def test_a_colleagues_name_on_an_outside_address_is_caught_in_the_integrated_system(self):
        w = World4(); w.send("m.lopez@gmail.example", "Quick favour", "Buy gift cards today and do not tell anyone.", display_name="Maria Lopez", reply_to="x@proton.example")
        f = [x for x in w.cp.courier.poll() if x.detector == "display_name_spoof"]; self.assertEqual(len(f), 1); self.assertGreaterEqual(f[0].confidence, 0.9)

    def test_only_confident_verdicts_are_pulled_automatically(self):
        w = World4(); m = w.send("sales@newvendor.example", "Our invoice", "Our invoice attached, please pay by Friday."); w.cp.process()
        self.assertTrue(any(f.confidence < 0.9 for f in w.cp.courier.findings)); self.assertIn(m.id, w.cp.mail.mailboxes["alice@acme.com"].folders["inbox"])
        self.assertEqual([x for x in w.cp.auto_log if x[0].startswith("clawback")], [])

    def test_bank_detail_change_from_the_genuine_supplier_domain_is_flagged_for_a_person(self):
        w = World4(); m = w.send("ar@globex-supplies.com", "Updated bank details", f"New bank account for payments: {ROGUE_IBAN}", display_name="Globex AR")
        f = [x for x in w.cp.courier.poll() if x.detector == "bank_details_changed"]; self.assertEqual(len(f), 1); self.assertEqual(f[0].confidence, 0.95)

    def test_normal_business_mail_is_left_alone(self):
        w = World4(); w.send("maria@acme.com", "Lunch?", "Shall we meet at noon?"); w.send("ar@globex-supplies.com", "Invoice", f"Invoice attached. IBAN {SUPPLIER_IBAN}"); w.send("news@vendor.example", "Newsletter", "Our June offers")
        self.assertEqual(w.cp.courier.poll(), []); self.assertEqual(w.cp.mail.mailboxes["alice@acme.com"].folders["quarantine"], [])

    def test_block_sender_stops_future_mail_and_is_reversible(self):
        w = World4(); r = w.cp.engine.request(ActionRequest("block_sender", AN, ["g1obex-supplies.com"], "lookalike", None, {}))
        self.assertEqual(r.status, "executed"); m = w.send("ar@g1obex-supplies.com", "again", "x"); self.assertIn(m.id, w.cp.mail.mailboxes["alice@acme.com"].folders["quarantine"])
        w.cp.engine.undo(r.action_id, ADM); m2 = w.send("ar@g1obex-supplies.com", "later", "x"); self.assertIn(m2.id, w.cp.mail.mailboxes["alice@acme.com"].folders["inbox"])


class MailboxTamperingMergesWithTakeover(unittest.TestCase):
    def attack(self):
        w = World4().alice_signs_in(); w.stealer_runs(); w.attacker_replays(); mail = w.cp.mail
        mail.set_forwarding("alice@acme.com", "collector@evil.example", actor="alice@acme.com", ip="203.0.113.7")
        mail.add_rule("alice@acme.com", {"subject_contains": ["invoice", "payment"]}, {"mark_read": True, "move_to": "RSS Feeds"}, actor="alice@acme.com", ip="203.0.113.7")
        mail.add_rule("alice@acme.com", {}, {"forward_to": "collector@evil.example"}, actor="alice@acme.com", ip="203.0.113.7")
        w.cp.process(); return w

    def test_rules_forwarding_and_the_stolen_session_are_one_case_and_all_are_undone(self):
        w = self.attack(); self.assertEqual(len(w.cp.cases.cases), 1); c = next(iter(w.cp.cases.cases.values()))
        dets = {f.details.get("detector") for f in c.findings if f.source == "courier"}; self.assertTrue({"external_forwarding", "forwarding_rule", "hiding_rule"} <= dets, dets)
        self.assertTrue(all(f.confidence >= 0.9 for f in c.findings if f.details.get("detector") in ("external_forwarding", "forwarding_rule", "hiding_rule")))     # created from an address already flagged
        self.assertEqual(c.status, "contained"); mb = w.cp.mail.mailboxes["alice@acme.com"]
        self.assertIsNone(mb.forwarding); self.assertEqual(w.cp.mail.active_rules("alice@acme.com"), [])
        w.send("customer@client.example", "Invoice payment", "Please confirm payment", to=("alice@acme.com",)); self.assertEqual([m for m in w.cp.mail.log if m["kind"] == "auto_forward" and m.get("external")][-1:], [m for m in w.cp.mail.log if m["kind"] == "auto_forward" and m.get("external")][:1])

    def test_mail_sent_after_containment_is_no_longer_copied_out(self):
        w = self.attack(); n_before = len([e for e in w.cp.mail.log if e["kind"] == "auto_forward"])
        w.send("customer@client.example", "Invoice payment", "Please confirm payment", to=("alice@acme.com",)); self.assertEqual(len([e for e in w.cp.mail.log if e["kind"] == "auto_forward"]), n_before)

    def test_recovery_restores_rules_for_an_investigator_who_wants_to_look(self):
        w = self.attack(); act = next(k for k, v in w.cp.engine.executed.items() if v["req"].action == "contain_everywhere")
        u = w.cp.engine.undo(act, ADM); u = w.cp.engine.approve(u.action_id, ADM2) if u.status == "pending_approval" else u
        self.assertEqual(u.status, "executed", u.message); self.assertEqual(len(w.cp.mail.active_rules("alice@acme.com")), 2); self.assertEqual(w.cp.mail.mailboxes["alice@acme.com"].forwarding, "collector@evil.example")

    def test_an_ordinary_internal_rule_is_not_an_incident(self):
        w = World4(); w.cp.mail.add_rule("alice@acme.com", {"from": "newsletter@vendor.example"}, {"move_to": "Newsletters"}, actor="alice@acme.com", ip="198.51.100.4")
        w.cp.mail.add_rule("alice@acme.com", {}, {"forward_to": "maria@acme.com"}, actor="alice@acme.com", ip="198.51.100.4"); self.assertEqual(w.cp.courier.poll(), [])

    def test_external_forwarding_from_an_unflagged_address_is_lower_confidence(self):
        w = World4(); w.cp.mail.set_forwarding("alice@acme.com", "me@personal.example", actor="alice@acme.com", ip="198.51.100.4"); f = w.cp.courier.poll()
        self.assertEqual([x.confidence for x in f], [0.8]); self.assertNotIn("created from an address already flagged", f[0].why)


class ServiceDeskReleasePath(unittest.TestCase):
    def test_low_risk_release_by_service_desk_with_a_reason_and_audit(self):
        w = World4(); m = w.send("hr@partner.example", "Holiday calendar", "see attached"); w.cp.process()
        w.cp.engine.request(ActionRequest("clawback_message", AN, [m.id], "precaution", None, {}))
        view = w.cp.courier.quarantined_for("alice@acme.com"); self.assertEqual(view[0]["sender"], "hr@partner.example"); self.assertFalse(view[0]["needs_analyst"]); self.assertLessEqual(len(view[0]["subject_hint"]), 40)
        no_reason = w.cp.engine.request(ActionRequest("release_message", SD, [f"alice@acme.com|{m.id}"], "please", None, {})); self.assertEqual(no_reason.status, "denied"); self.assertIn("reason", no_reason.message)
        r = w.cp.engine.request(ActionRequest("release_message", SD, [f"alice@acme.com|{m.id}"], "user expects HR calendar", None, {"reason_text": "user expects it"}))
        self.assertEqual(r.status, "executed"); self.assertIn(m.id, w.cp.mail.mailboxes["alice@acme.com"].folders["inbox"])
        rec = next(e for e in w.cp.ledger.entries() if e["kind"] == "relay.action_executed" and e["public"].get("action") == "release_message")
        self.assertEqual(rec["actor_role"], "service_desk"); self.assertNotIn("Holiday", json.dumps(rec))

    def test_a_message_judged_harmful_needs_an_analyst_even_though_the_desk_asked(self):
        w = World4(); m = w.send("billing@vendor-docs.example", "Invoice", "see attached", attachments=[("i.docm", macro_doc())]); w.cp.process()
        self.assertIn(m.id, w.cp.mail.mailboxes["alice@acme.com"].folders["quarantine"]); self.assertTrue(w.cp.courier.quarantined_for("alice@acme.com")[0]["needs_analyst"])
        r = w.cp.engine.request(ActionRequest("release_message", SD, [f"alice@acme.com|{m.id}"], "user insists", None, {"reason_text": "user insists"}))
        self.assertEqual((r.status, r.requirement.level), ("pending_approval", "approve")); self.assertIn("downloader", r.preview["summary"])
        self.assertEqual(w.cp.engine.approve(r.action_id, SD).status, "denied")                                             # the desk cannot approve its own request
        self.assertNotIn(m.id, w.cp.mail.mailboxes["alice@acme.com"].folders["inbox"]); self.assertEqual(w.cp.engine.approve(r.action_id, AN).status, "executed")

    def test_user_report_loop(self):
        w = World4(); m = w.send("sales@newvendor.example", "Our invoice", "Our invoice attached, please pay by Friday."); w.cp.process()
        w.cp.mail.report("alice@acme.com", m.id); f = w.cp.courier.poll(); self.assertTrue(any(x.detector == "user_reported" for x in f)); self.assertIn("reported", f[0].summary)

    def test_purge_is_a_separate_gated_irreversible_action_and_respects_legal_hold(self):
        w = World4(); m = w.send("billing@vendor-docs.example", "Invoice", "x", attachments=[("i.docm", macro_doc())]); w.cp.process(); t = [f"alice@acme.com|{m.id}"]
        r = w.cp.engine.request(ActionRequest("purge_message", AN, t, "cleanup", "case-9", {})); self.assertEqual(r.status, "pending_approval")
        w.cp.engine.request(ActionRequest("legal_hold", ADM, ["acme"], "litigation", "case-9")); blocked = w.cp.engine.request(ActionRequest("purge_message", AN, t, "cleanup", "case-9", {}))
        self.assertEqual(blocked.status, "denied"); self.assertIn("legal hold", blocked.message)
        done = w.cp.engine.approve(r.action_id, ADM) if "case-9" not in w.cp.engine.holds else None
        self.assertIn(m.id, w.cp.mail.mailboxes["alice@acme.com"].folders["quarantine"])        # nothing was deleted under hold


if __name__ == "__main__":
    unittest.main()
