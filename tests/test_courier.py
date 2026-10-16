import os, unittest
from helpers import *
from rig4 import *
from halvard.courier import analysis, exercises
from halvard.courier.analysis import AttachmentAnalyzer, LinkAnalyzer, Intel, ReferenceWeb, lookalike_of
from halvard.courier.impersonation import ImpersonationDetector, iban_hash
from halvard.courier.auth import DomainAuthMonitor, ReferenceDNS
from halvard.signet.hr import HR, HRRecord
from halvard.relay.actions import ActionRequest

ADM, AN, SD = Principal("u-adm", "it_admin"), Principal("u-an", "analyst"), Principal("u-sd", "service_desk")


class AnalyzerTests(unittest.TestCase):
    def setUp(self): self.intel = Intel(); self.A = AttachmentAnalyzer(self.intel)

    def test_macro_downloader_is_malicious_plain_macro_is_only_suspicious_plain_document_is_quiet(self):
        v = self.A.analyze("invoice.docm", macro_doc()); self.assertEqual((v.decision, v.evidence), ("malicious", "static")); self.assertTrue(any("downloader" in r for r in v.reasons))
        import io, zipfile
        z = io.BytesIO(); zf = zipfile.ZipFile(z, "w"); zf.writestr("word/vbaProject.bin", b"Sub x() MsgBox 1 End Sub"); zf.close()
        v2 = self.A.analyze("budget.xlsm", z.getvalue()); self.assertEqual(v2.decision, "allow" if v2.score < 0.4 else "suspicious"); self.assertLess(v2.score, 0.85)
        self.assertEqual(self.A.analyze("minutes.docx", docx_like()).decision, "allow")

    def test_known_bad_hash_and_the_test_string_are_malicious_with_reputation_evidence(self):
        d = docx_like(b"campaign-1"); self.assertEqual(self.A.analyze("a.docx", d).decision, "allow")
        import hashlib; self.intel.add_bad_hash(hashlib.sha256(d).hexdigest(), "seen in a campaign"); v = self.A.analyze("a.docx", d)
        self.assertEqual((v.decision, v.evidence), ("malicious", "reputation")); self.assertEqual(self.A.analyze("t.txt", analysis.EICAR).decision, "malicious")

    def test_container_tricks_and_double_extensions(self):
        self.assertGreaterEqual(self.A.analyze("invoice.pdf.exe", b"MZ" + b"\0" * 50).score, 0.8)
        self.assertGreaterEqual(self.A.analyze("scan.iso", b"CD001" + b"x" * 50).score, 0.5)
        import io, zipfile
        z = io.BytesIO(); zf = zipfile.ZipFile(z, "w"); zf.writestr("a.txt", "x"); zf.close(); raw = bytearray(z.getvalue()); raw[6] |= 1                     # mark the entry as encrypted
        raw[raw.index(b"PK\x01\x02") + 8] |= 1
        self.assertIn("encrypted archive", " ".join(self.A.analyze("docs.zip", bytes(raw)).reasons))
        smug = b"<html><script>var b=new Blob([atob('AAAA')]);a.download='x.iso';</script></html>"; self.assertGreaterEqual(self.A.analyze("view.html", smug).score, 0.85)

    def test_nothing_is_executed_and_the_verdict_says_how_it_knows(self):
        v = self.A.analyze("x.docm", macro_doc()); self.assertEqual(v.evidence, "static")        # evidence is named; no dynamic sandbox exists here


class LinkTests(unittest.TestCase):
    def setUp(self):
        phish = '<html><h1>Microsoft</h1><form><input type="password"></form></html>'
        self.web = ReferenceWeb({"http://bit.ly/x1": {"redirect": "http://login-m1crosoft.example/a"}, "http://login-m1crosoft.example/a": {"redirect": "http://secure.login-m1crosoft.example/p"},
                                 "http://secure.login-m1crosoft.example/p": {"html": phish}, "https://login.microsoftonline.com/": {"html": '<html>Microsoft <input type="password"></html>'},
                                 "https://acme.com/wiki": {"html": "<html>docs</html>"}})
        self.intel = Intel(); self.L = LinkAnalyzer(self.intel, self.web, {"acme.com"})

    def test_shortened_link_to_a_fake_sign_in_page_is_followed_and_judged_by_where_it_ends(self):
        v = self.L.analyze("Open your document", "http://bit.ly/x1"); self.assertEqual(v.decision, "malicious"); self.assertEqual(v.evidence, "offline-web-model")
        self.assertIn("looks like microsoft", " ".join(v.reasons)); self.assertEqual(v.indicators["final_host"], "secure.login-m1crosoft.example"); self.assertEqual(len(v.indicators["chain"]), 3)

    def test_the_real_sign_in_page_and_internal_links_are_quiet(self):
        self.assertEqual(self.L.analyze("Sign in", "https://login.microsoftonline.com/").decision, "allow"); self.assertEqual(self.L.analyze("wiki", "https://acme.com/wiki").decision, "allow")

    def test_text_that_shows_one_address_and_goes_to_another(self):
        v = self.L.analyze("https://acme.com/payroll", "http://evil.example/p"); self.assertIn("link text shows acme.com", " ".join(v.reasons))

    def test_lookalike_domains(self):
        for d in ("acme-corp.co", "acrne.com", "acme.co", "acme-payments.com"): self.assertEqual(lookalike_of(d, ["acme.com"]), "acme.com", d)
        for d in ("acme.com", "mail.acme.com", "pacmeter.com", "example.org"): self.assertIsNone(lookalike_of(d, ["acme.com"]), d)
        self.assertEqual(lookalike_of("rn1crosoft.com", ["microsoft.com"]), "microsoft.com")      # 'rn' for 'm' and '1' for 'i': too far apart for edit distance, caught by how it reads
        self.assertEqual(lookalike_of("micr0soft.com", ["microsoft.com"]), "microsoft.com")

    def test_new_domains_are_flagged_old_ones_are_not(self):
        self.intel.domain_age_days["fresh.example"] = 3; self.assertIn("registered 3 days ago", " ".join(self.L.analyze("hi", "http://fresh.example/").reasons))


class ImpersonationTests(unittest.TestCase):
    def setUp(self):
        self.hr = HR(); self.hr.add(HRRecord("p:maria", "Maria Lopez", "maria@acme.com", "maria", "active", "Finance", None, 0)); self.hr.add(HRRecord("p:alice", "Alice Kim", "alice@acme.com", "alice", "active", "Finance", "p:maria", 0))
        self.D = ImpersonationDetector(self.hr, {"acme.com"}, {"globex-supplies.com"}, {"globex-supplies.com": {iban_hash(SUPPLIER_IBAN)}})
        self.M = lambda **k: Message("M", 0, k.pop("sender", "x@y.com"), k.pop("name", "x"), k.pop("subject", "hi"), k.pop("body", "hello"), ["alice@acme.com"], **k)

    def kinds(self, m): return {s.kind: s for s in self.D.analyze(m, "alice@acme.com")}

    def test_ceo_style_gift_card_request(self):
        k = self.kinds(self.M(sender="m.lopez@gmail.example", name="Maria Lopez", subject="Quick favour", body="I am in a meeting. Buy gift cards today and do not tell anyone.", reply_to="x@proton.example"))
        self.assertIn("display_name_spoof", k); self.assertGreaterEqual(k["display_name_spoof"].confidence, 0.9)

    def test_internal_mail_and_known_partner_names_are_quiet(self):
        self.assertEqual(self.kinds(self.M(sender="maria@acme.com", name="Maria Lopez", body="Can we meet?")), {})
        self.assertEqual(self.kinds(self.M(sender="ops@globex-supplies.com", name="Globex Ops", body="Your order shipped.")), {})

    def test_changed_bank_details_from_the_real_supplier_domain_are_caught_by_account_comparison(self):
        k = self.kinds(self.M(sender="ar@globex-supplies.com", name="Globex AR", subject="Updated bank details", body=f"Please use our new bank account {ROGUE_IBAN} for the next invoice."))
        self.assertEqual(k["bank_details_changed"].confidence, 0.95)
        ok = self.kinds(self.M(sender="ar@globex-supplies.com", name="Globex AR", subject="Invoice attached", body=f"Invoice attached. IBAN {SUPPLIER_IBAN}."))
        self.assertNotIn("bank_details_changed", ok)

    def test_lookalike_supplier_and_spoofed_own_domain(self):
        k = self.kinds(self.M(sender="ar@g1obex-supplies.com", name="Globex AR", subject="Invoice overdue", body=f"Urgent payment overdue. Bank details changed: {ROGUE_IBAN}", reply_to="ar@mail-pay.example"))
        self.assertIn("lookalike_domain", k); self.assertIn("payment_request_unknown_account", k)
        s = self.kinds(self.M(sender="ceo@acme.com", body="hi", auth={"spf": "fail", "dkim": "none", "dmarc": "fail"})); self.assertEqual(s["spoofed_own_domain"].confidence, 0.9)

    def test_people_who_join_after_start_up_are_protected_too(self):
        self.kinds(self.M(body="hello"))                      # the detector has already been running
        self.hr.add(HRRecord("p:new", "Nadia Okafor", "nadia@acme.com", "nadia", "active", "Finance", None, 0))
        k = self.kinds(self.M(sender="n.okafor@gmail.example", name="Nadia Okafor", body="Buy gift cards today, urgent.")); self.assertIn("display_name_spoof", k)

    def test_first_contact_with_payment_words_is_only_low_confidence(self):
        k = self.kinds(self.M(sender="sales@newvendor.example", name="Sam", body="Our invoice attached, please pay by Friday.")); self.assertLess(max(s.confidence for s in k.values()), 0.5)
        self.D.remember("alice@acme.com", "sales@newvendor.example"); self.assertEqual(self.kinds(self.M(sender="sales@newvendor.example", name="Sam", body="Our invoice attached, please pay by Friday.")), {})


class DomainAuthTests(unittest.TestCase):
    def test_posture_and_staged_advice(self):
        dns = ReferenceDNS({"acme.com": ["v=spf1 include:_spf.google.example ~all"], "_spf.google.example": ["v=spf1 ip4:1.2.3.0/24 ~all"], "_dmarc.acme.com": ["v=DMARC1; p=none"],
                            "open.com": ["v=spf1 +all"], "toomany.com": ["v=spf1 " + " ".join(f"include:s{i}.example" for i in range(11)) + " -all"], "_dmarc.good.com": ["v=DMARC1; p=quarantine; rua=mailto:r@good.com"], "good.com": ["v=spf1 -all"]})
        M = DomainAuthMonitor(["acme.com", "open.com", "toomany.com", "none.com", "good.com"], dns); f = {(x.domain, x.summary[:30]): x for x in M.posture(dkim_selectors=["s1"])}
        text = " ".join(x.summary for x in M.posture(dkim_selectors=["s1"]))
        for must in ("none.com publishes no SPF", "open.com's SPF record allows every sender", "needs 12 lookups", "none.com has no DMARC", "acme.com's DMARC policy is p=none", "no report address", "No DKIM key is published for selector 's1'"): self.assertIn(must, text)
        self.assertIn("Move to quarantine", next(x.action for x in M.posture() if "p=none" in x.summary))

    def test_spoofing_attempts_against_the_company_domain_are_counted_and_alignment_gates_the_advice(self):
        dns = ReferenceDNS({"acme.com": ["v=spf1 -all"], "_dmarc.acme.com": ["v=DMARC1; p=quarantine; rua=mailto:r@acme.com"]}); M = DomainAuthMonitor(["acme.com"], dns)
        for i in range(30): M.ingest(Message(f"m{i}", 0, "a@acme.com", "A", "s", "b", ["x@y"], auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"}))
        M.ingest(Message("bad", 0, "ceo@acme.com", "CEO", "s", "b", ["x@y"], auth={"spf": "fail", "dkim": "none", "dmarc": "fail"}))
        self.assertEqual(len(M.spoof_attempts), 1); self.assertEqual(M.alignment("acme.com")["dmarc_pass_rate"], 0.97)
        self.assertFalse(any("move to p=reject" in x.action.lower() for x in M.posture()))            # 97% is not enough
        for i in range(30): M.ingest(Message(f"n{i}", 0, "a@acme.com", "A", "s", "b", ["x@y"]))
        self.assertTrue(any("p=reject" in x.action for x in M.posture()))


class ExerciseTests(unittest.TestCase):
    def test_exercise_is_safe_taught_and_private(self):
        ex = exercises.build_from_finding("bank_details_changed", "Finance"); self.assertEqual(ex.tactic, "lookalike_domain")
        blob = f"{ex.subject} {ex.body}"; self.assertNotIn("http", blob); self.assertNotIn("@", blob); self.assertTrue(ex.clues and ex.right_action)
        self.assertIsNone(exercises.build_from_finding("something_else", "Finance"))
        for i in range(4): exercises.answer(ex, f"p{i}", 2, i % 2 == 0)
        self.assertFalse(exercises.department_summary(ex)["shown"])           # four people: not enough to show a group number
        exercises.answer(ex, "p4", 3, True); s = exercises.department_summary(ex); self.assertTrue(s["shown"]); self.assertEqual(s["people"], 5); self.assertNotIn("p0", str(s))
        self.assertIn("clues", exercises.answer(ex, "p5", 1, False))


if __name__ == "__main__":
    unittest.main()
