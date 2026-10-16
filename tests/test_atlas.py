import json, unittest
from helpers import *
from rig5 import *
from halvard.atlas import posture as P
from halvard.coverage import CoverageMonitor
from halvard.vaultline.inspection import InspectionNotAllowed
from halvard.relay.actions import ActionRequest
from halvard.courier.mail import Message, Attachment

ADM, ADM2, AN, SD = Principal("u-adm", "it_admin"), Principal("u-adm2", "it_admin"), Principal("u-an", "analyst"), Principal("u-sd", "service_desk")


class PostureTests(unittest.TestCase):
    def setUp(self): self.w = World5(); self.cp = self.w.cp

    def test_findings_name_the_fact_the_context_and_a_fix_in_an_order_that_makes_sense(self):
        self.w.scan_all(); fs = self.cp.atlas.run_posture(); ids = [(f.check_id, f.resource, f.severity) for f in fs]
        self.assertEqual(fs[0].severity, "critical"); self.assertTrue(all(P.SEV[a.severity] >= P.SEV[b.severity] for a, b in zip(fs, fs[1:])))
        self.assertIn(("EC2_PUBLIC_ADMIN_ROLE", "i-bastion", "critical"), ids); self.assertIn(("SG_WORLD_ADMIN", "i-bastion", "critical"), ids)       # internet + administrator role
        self.assertIn(("IAM_NO_MFA", "cloud:user:deploy", "high"), ids); self.assertIn(("IAM_UNUSED_KEY", "cloud:user:deploy", "medium"), ids)
        imds = next(f for f in fs if f.check_id == "EC2_IMDSV1"); self.assertEqual((imds.severity, imds.exposure, imds.fix_action), ("high", "internet", "enforce_imdsv2")); self.assertIn("server-side request forgery", imds.why)
        self.assertTrue(all(f.evidence for f in fs)); self.assertFalse(any("secret" in json.dumps(f.evidence).lower() for f in fs))

    def test_a_public_bucket_is_critical_only_when_it_holds_regulated_data(self):
        self.cp.aws.make_bucket_public("cust-exports", "x"); self.cp.atlas.sync_graph(); before = [f for f in self.cp.atlas.run_posture() if f.check_id == "S3_PUBLIC" and "cust-exports" in f.title][0]
        self.assertEqual(before.severity, "high"); self.w.scan_all(); after = [f for f in self.cp.atlas.run_posture() if f.check_id == "S3_PUBLIC" and "cust-exports" in f.title][0]
        self.assertEqual(after.severity, "critical"); self.assertIn("regulated data", after.why)

    def test_internet_to_data_paths_are_found_and_the_critical_ones_come_first(self):
        self.w.scan_all(); paths = self.cp.atlas.paths(); self.assertEqual(paths[0]["end"], "the whole account (administrator role)"); self.assertTrue(paths[0]["critical"])
        web = [p for p in paths if "i-web" in p["path"]][0]; self.assertIn("s3:cust-exports", web["path"]); self.assertTrue(web["critical"])               # reaches a bucket Halvard found to be regulated

    def test_graph_reaches_a_crown_jewel_from_the_internet_through_the_instance_and_its_role(self):
        self.cp.store.update_entity(self.cp.ctx, "s3:cust-exports", criticality="crown_jewel"); paths = self.cp.signet.access_paths("cloud:internet")
        self.assertTrue(any("i-web" in p and "cloud:role:web-role" in p and p.endswith("s3:cust-exports") for p in paths), paths)

    def test_customer_values_are_never_overwritten_by_a_sync_or_a_scan(self):
        self.cp.store.update_entity(self.cp.ctx, "s3:cust-exports", sensitivity="internal", criticality="low"); self.w.scan_all(); self.cp.atlas.sync_graph()
        e = next(x for x in self.cp.store.entities(self.cp.ctx) if x["entity_id"] == "s3:cust-exports"); self.assertEqual((e["sensitivity"], e["criticality"], e["suggested_sensitivity"]), ("internal", "low", "regulated"))
        self.assertEqual(self.cp.atlas.sensitivity_of("s3:cust-exports"), "internal")               # the person's word wins

    def test_fixes_preview_what_breaks_and_can_be_undone(self):
        eng = self.cp.engine
        r = eng.request(ActionRequest("block_public_access", AN, ["s3:public-site"], "scan", None, {})); self.assertEqual(r.status, "pending_approval")           # production
        self.assertIn("TAGGED AS A WEBSITE", r.preview["summary"]); done = eng.approve(r.action_id, ADM); self.assertEqual(done.status, "executed")
        with self.assertRaises(PermissionError): self.cp.aws.anonymous_read("public-site", "index.html")
        u = eng.undo(done.action_id, ADM); u = eng.approve(u.action_id, ADM2) if u.status == "pending_approval" else u
        self.assertEqual(u.status, "executed"); self.assertEqual(self.cp.aws.anonymous_read("public-site", "index.html"), b"<html>hello</html>")           # the site is back
        s = eng.request(ActionRequest("restrict_security_group_rule", AN, ["sg-admin|22|0.0.0.0/0"], "ssh from anywhere", None, {}))
        self.assertEqual(s.status, "executed"); self.assertIn("i-bastion", s.preview["summary"]); self.assertEqual(self.cp.aws.reachable_from_internet("i-bastion"), [])
        eng.undo(s.action_id, ADM); self.assertEqual(self.cp.aws.reachable_from_internet("i-bastion"), [22])
        k = eng.request(ActionRequest("disable_access_key", AN, ["deploy|AKIAOLDKEY0000001"], "unused", None, {})); self.assertEqual(k.status, "executed"); self.assertFalse(self.cp.aws.users["deploy"].keys[0]["active"])
        eng.undo(k.action_id, ADM); self.assertTrue(self.cp.aws.users["deploy"].keys[0]["active"])
        self.assertEqual(eng.request(ActionRequest("enforce_imdsv2", AN, ["i-web"], "ssrf", None, {})).status, "pending_approval")


class SuggestionJoin(unittest.TestCase):
    def test_a_public_store_with_only_a_scan_suggestion_is_still_reported_and_labelled_as_a_suggestion(self):
        w = World5(); cp = w.cp
        cp.store.update_entity(cp.vault.ctx, "s3:cust-exports", w.clock.now(), suggested_sensitivity="regulated")
        cp.aws.make_bucket_public("cust-exports", "mallory", "203.0.113.7"); cp.atlas.sync_graph()
        hits = [x for x in cp.vault.exposed_sensitive() if x["store"] == "s3:cust-exports"]
        self.assertEqual(len(hits), 1); self.assertFalse(hits[0]["customer_set"]); self.assertIn("suggestion", hits[0]["why"])


class ExposureAcceptance(unittest.TestCase):
    """Acceptance: a bucket holding customer card numbers is made public; Halvard sees it, knows what it holds, and closes it."""

    def test_regulated_bucket_opened_to_the_internet_is_closed_within_one_cycle_and_the_data_was_never_read(self):
        w = World5(); w.scan_all(); cp, aws = w.cp, w.cp.aws
        aws.make_bucket_public("cust-exports", "mallory", "203.0.113.7"); self.assertEqual(aws.anonymous_read("cust-exports", "2026/orders.csv")[:4], b"name")         # really exposed
        cp.process()
        with self.assertRaises(PermissionError): aws.anonymous_read("cust-exports", "2026/orders.csv")                                                                    # really closed
        f = [x for x in cp.atlas.findings if x.detector == "bucket_made_public"][0]; self.assertEqual((f.confidence, f.technique), (0.98, "T1530")); self.assertIn("regulated data", f.why)
        self.assertIn(("revert:s3:cust-exports", "executed"), cp.auto_log); c = next(iter(cp.cases.cases.values())); self.assertEqual(c.findings[0].source, "aws")
        self.assertEqual([x["store"] for x in cp.vault.exposed_sensitive()], [])                 # nothing exposed any more

    def test_the_case_page_says_what_was_exposed_what_was_done_and_what_cannot_be_undone(self):
        w = World5(); w.scan_all(); w.cp.aws.make_bucket_public("cust-exports", "mallory", "203.0.113.7"); w.cp.process(); c = next(iter(w.cp.cases.cases.values())); page = w.cp.cases.page(c)
        for must in ("[cloud]", "Owner (from the resource's tag): Alice Kim", "closed the exposure: done", "Reads made while the data was public cannot be undone", "cust-exports holds regulated data (Halvard's suggestion)"): self.assertIn(must, page)
        self.assertEqual(c.status, "contained"); self.assertEqual(w.cp.cases.impact(c)[0], 1.0)

    def test_it_is_recoverable_and_the_ledger_says_what_the_reversal_would_expose(self):
        w = World5(); w.scan_all(); w.cp.aws.make_bucket_public("cust-exports", "mallory"); w.cp.process()
        act = next(k for k, v in w.cp.engine.executed.items() if v["req"].action == "block_public_access"); u = w.cp.engine.undo(act, ADM)
        self.assertEqual(u.status, "executed"); self.assertIn("exposed again", u.message); self.assertTrue(w.cp.aws.buckets["cust-exports"].effective_public)

    def test_a_production_bucket_waits_for_an_approver_and_the_case_says_so(self):
        w = World5(); w.scan_all(); cp = w.cp; cp.aws.make_bucket_public("prod-ledgers", "mallory", "203.0.113.7"); cp.process()
        self.assertEqual(cp.auto_log[-1], ("revert:s3:prod-ledgers", "pending_approval")); self.assertTrue(cp.aws.buckets["prod-ledgers"].effective_public)          # still open until a person approves
        pend = [p for p in cp.engine.pending.values() if p["req"].action == "block_public_access"][0]; self.assertIn("anonymous reads stop at once", pend["plan"]["summary"])
        pid = next(k for k, v in cp.engine.pending.items() if v["req"].action == "block_public_access"); self.assertEqual(cp.engine.approve(pid, ADM).status, "executed")
        with self.assertRaises(PermissionError): cp.aws.anonymous_read("prod-ledgers", "q1.csv")

    def test_a_deliberately_public_website_is_not_reverted_automatically(self):
        w = World5(); w.cp.aws.log.clear(); w.cp.atlas.cursor = 0; w.cp.aws.make_bucket_public("public-site", "web-deployer"); w.cp.process()
        self.assertTrue(w.cp.aws.buckets["public-site"].effective_public); self.assertEqual(w.cp.auto_log[-1][1], "pending_approval")

    def test_without_the_accepted_pattern_it_prepares_and_waits(self):
        w = World5(); w.cp.engine.auth.policy.accepted_patterns.discard("cloud_exposure_revert"); w.scan_all(); w.cp.aws.make_bucket_public("cust-exports", "mallory"); w.cp.process()
        self.assertEqual(w.cp.auto_log[-1][1], "pending_pattern_acceptance"); self.assertTrue(w.cp.aws.buckets["cust-exports"].effective_public)

    def test_firewall_changes_keys_and_admin_rights_are_detected_and_a_flagged_address_raises_confidence(self):
        w = World5(); aws = w.cp.aws; aws.open_sg("sg-web", 5432, "0.0.0.0/0", "ops", "198.51.100.9"); aws.open_sg("sg-web", 8080, "0.0.0.0/0", "ops"); aws.create_key("deploy", "deploy"); aws.create_key("deploy", "mallory", "198.51.100.77"); aws.attach_admin("deploy", "mallory")
        d = {f.detector: f for f in w.cp.atlas.poll()}; self.assertEqual(d["world_open_port"].details["port"], 5432); self.assertEqual(d["foreign_access_key"].confidence, 0.8); self.assertEqual(d["admin_attached"].confidence, 0.8)
        self.assertEqual(len([f for f in w.cp.atlas.findings if f.detector == "world_open_port"]), 1)           # 8080 is not an admin or database port
        w2 = World5(); w2.cp.signet.findings.append(type("F", (), {"details": {"ip": "203.0.113.7"}})()); w2.cp.aws.create_key("deploy", "mallory", "203.0.113.7")
        self.assertEqual(w2.cp.atlas.poll()[0].confidence, 0.95)

    def test_ledger_and_auditor_export_carry_no_card_numbers_object_names_or_account_names(self):
        w = World5(); w.scan_all(); w.cp.aws.make_bucket_public("cust-exports", "mallory", "203.0.113.7"); w.cp.process()
        from halvard.ledger.audit import verify_export
        blob = json.dumps([e["public"] for e in w.cp.ledger.entries()]); self.assertNotIn(VISA, blob); self.assertNotIn("orders.csv", blob); self.assertNotIn(VISA, json.dumps(list(w.cp.ledger.entries())))        # object names are private fields, tokenized in exports
        exp = w.cp.ledger.export_for_control("VAULTLINE.CLASSIFICATION"); self.assertEqual(verify_export(exp), (True, [])); eb = json.dumps(exp); self.assertNotIn("orders.csv", eb); self.assertNotIn("s3:cust-exports", eb)
        self.assertTrue(any(not e.get("elided") for e in exp["entries"]))


class WorkloadsAndCoverage(unittest.TestCase):
    def test_a_crown_jewel_workload_without_an_agent_is_a_coverage_incident_until_it_is_enrolled(self):
        w = World5(); cp = w.cp; mon = CoverageMonitor(cp.store, cp.ctx, w.clock, cp.ledger); gaps = {g.entity_id: g for g in mon.evaluate()}
        self.assertEqual(gaps["i-web"].severity, "incident"); self.assertEqual(gaps["i-bastion"].severity, "gap"); self.assertIn("No Halvard agent", gaps["i-web"].reason)
        agent, host, _, fs = make_agent(os.path.join(w.tmp, "iweb")); agent.device_id = "i-web"; agent.clock = w.clock; cp.fleet.register(agent); cp.atlas.enroll_workload("i-web", agent)
        self.assertNotIn("i-web", [g.entity_id for g in mon.evaluate()]); w.clock.advance(1000); self.assertIn("i-web", [g.entity_id for g in mon.evaluate()])               # silence is a gap again
        cp.atlas.heartbeat("i-web"); self.assertNotIn("i-web", [g.entity_id for g in mon.evaluate()])

    def test_cloud_workloads_follow_the_same_policy_mechanism_and_drift_is_reported(self):
        w = World5(); cp = w.cp; agent, host, _, fs = make_agent(os.path.join(w.tmp, "iweb"), prevention={"bulk_encryption": "audit_only", "known_bad": "enforce"}); agent.device_id = "i-web"; cp.fleet.register(agent)
        found = cp.atlas.workload_policy_findings(cp.fleet); kinds = {(f["workload"], f["kind"]) for f in found}
        self.assertIn(("i-web", "prevention_not_enforcing"), kinds); self.assertIn(("i-web", "policy_out_of_date"), kinds)
        self.assertEqual(cp.push_dlp(w.dlp)["i-web"], "applied"); self.assertTrue(agent.inspector.policy.enabled)       # the same signed bundle path as a laptop


class StoreScanning(unittest.TestCase):
    def test_scanning_a_store_needs_the_gate_and_reports_counts_only(self):
        w = World5(dlp_on=False)
        with self.assertRaises(InspectionNotAllowed): w.cp.vault.scan_bucket("cust-exports")
        w2 = World5(); r = w2.cp.vault.scan_bucket("cust-exports"); self.assertEqual((r["objects"], r["objects_with_hits"], r["suggested_sensitivity"], r["labels"]), (2, 1, "regulated", {"pci_card": 3}))
        self.assertNotIn(VISA, json.dumps(r)); self.assertEqual(w2.cp.vault.scan_bucket("prod-ledgers")["suggested_sensitivity"], "regulated")

    def test_weakly_protected_sensitive_stores_are_listed(self):
        w = World5(); w.scan_all(); w.cp.aws.buckets["cust-exports"].encryption = None; w.cp.aws.buckets["cust-exports"].versioning = False; u = w.cp.vault.unprotected_sensitive_stores()
        self.assertEqual(u[0]["gaps"], ["not encrypted", "no versioning"])


class OutboundMail(unittest.TestCase):
    def setUp(self): self.w = World5(); self.mail = self.w.cp.mail

    def msg(self, to, attach=None, body="Please find the file.", mid="OUT-1"):
        return Message(mid, self.w.clock.now(), "alice@acme.com", "Alice Kim", "Customer data", body, list(to), attachments=[Attachment(n, d) for n, d in (attach or [])])

    def test_regulated_data_to_an_outside_address_is_held_before_it_leaves(self):
        r = self.mail.send_outbound("alice@acme.com", self.msg(["someone@gmail.example"], [("orders.csv", CARD_CSV)]))
        self.assertEqual((r["status"], r["rule"]), ("held", "email-regulated-external")); self.assertIn("held, not sent", r["message"]); self.assertIn("OUT-1", self.mail.mailboxes["alice@acme.com"].folders["held"])
        self.assertEqual([e for e in self.mail.log if e["kind"] == "sent"], [])

    def test_internal_mail_and_plain_attachments_are_untouched(self):
        self.assertEqual(self.mail.send_outbound("alice@acme.com", self.msg(["bob@acme.com"], [("orders.csv", CARD_CSV)], mid="O2"))["status"], "sent")
        self.assertEqual(self.mail.send_outbound("alice@acme.com", self.msg(["someone@gmail.example"], [("notes.txt", PLAIN)], mid="O3"))["status"], "sent")

    def test_partner_needs_a_reason_the_sender_gives_it_and_it_is_recorded_privately(self):
        m = self.msg(["ap@globex-supplies.com"], [("orders.csv", CARD_CSV)], mid="O4"); r = self.mail.send_outbound("alice@acme.com", m); self.assertEqual(r["rule"], "email-regulated-partner")
        with self.assertRaises(ValueError): self.w.cp.vault.justify_outbound("alice@acme.com", "O4", "no")
        self.assertEqual(self.w.cp.vault.justify_outbound("alice@acme.com", "O4", "Contracted monthly reconciliation file for the supplier")["status"], "sent")
        j = [e for e in self.w.cp.ledger.entries() if e["kind"] == "vaultline.outbound_justified"][0]; self.assertIn("reconciliation", j["private"]["justification"]); self.assertNotIn("reconciliation", json.dumps(j["public"]))

    def test_blocked_mail_cannot_be_unlocked_by_the_sender_but_a_second_person_can_release_it(self):
        self.mail.send_outbound("alice@acme.com", self.msg(["someone@gmail.example"], [("orders.csv", CARD_CSV)]))
        with self.assertRaises(PermissionError): self.w.cp.vault.justify_outbound("alice@acme.com", "OUT-1", "I need to send this to a customer today")
        eng = self.w.cp.engine; tgt = ["alice@acme.com|OUT-1"]
        self.assertEqual(eng.request(ActionRequest("release_outbound_message", SD, tgt, "please", None, {})).status, "denied")               # a reason is required
        r = eng.request(ActionRequest("release_outbound_message", SD, tgt, "customer asked", None, {"reason_text": "customer asked for their own records"})); self.assertEqual(r.status, "pending_approval")
        self.assertEqual(eng.approve(r.action_id, SD).status, "denied"); self.assertEqual(eng.approve(r.action_id, AN).status, "executed")
        self.assertEqual([e["to"] for e in self.mail.log if e["kind"] == "sent"], ["someone@gmail.example"])

    def test_secrets_in_the_body_are_held_and_cannot_be_justified(self):
        self.mail.send_outbound("alice@acme.com", self.msg(["ap@globex-supplies.com"], body=SECRET_ENV.decode(), mid="O5"))
        with self.assertRaises(PermissionError): self.w.cp.vault.justify_outbound("alice@acme.com", "O5", "the vendor needs the credentials to start")

    def test_with_inspection_off_mail_is_not_read_and_the_refusal_is_recorded(self):
        w = World5(dlp_on=False); w.cp.vault.policy.enabled = False
        r = w.cp.mail.send_outbound("alice@acme.com", self.msg(["someone@gmail.example"], [("orders.csv", CARD_CSV)], mid="O6")); self.assertEqual(r["status"], "sent")
        self.assertTrue(any(e["kind"] == "vaultline.inspection_refused" for e in w.cp.ledger.entries()))


if __name__ == "__main__":
    unittest.main()
