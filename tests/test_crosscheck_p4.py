"""Independent cross-check, phase 4. Mail parsing and impersonation bypasses."""
import unittest
from helpers import *
from rig5 import *
from halvard.courier.analysis import lookalike_of
from halvard.courier.impersonation import ImpersonationDetector
from halvard.courier.mail import Attachment, Message


class OutboundAddressTests(unittest.TestCase):
    def test_a_recipient_with_an_extra_at_sign_is_not_treated_as_internal(self):
        w = World5()
        msg = Message("M-trick", w.clock.now(), "alice@acme.com", "Alice", "orders", "see attached",
                      ["victim@gmail.example@acme.com"], attachments=[Attachment("orders.csv", CARD_CSV)])
        r = w.cp.mail.send_outbound("alice@acme.com", msg)
        self.assertEqual(r["status"], "held")
        self.assertNotEqual(r.get("rule"), None)
        sent = [e for e in w.cp.mail.log if e["kind"] == "sent" and e.get("msg_id") == "M-trick"]
        self.assertEqual(sent, [])


class ImpersonationBypassTests(unittest.TestCase):
    def test_a_payment_request_that_exists_only_in_an_attachment_is_still_a_payment_signal(self):
        class HR:
            records = {}
        det = ImpersonationDetector(HR(), ["acme.com"], supplier_ibans={"vendor.com": {__import__("hashlib").sha256(b"GB29NWBK60161331926819").hexdigest()}})
        msg = Message("m", 0, "ap@vendor.com", "Accounts", "statement", "Please see the attached statement.",
                      ["alice@acme.com"], attachments=[Attachment("inv.txt", b"Please wire transfer today to new bank account GB82WEST12345698765432")])
        kinds = [s.kind for s in det.analyze(msg, "alice@acme.com")]
        self.assertTrue(kinds, "attachment asked for a new bank account and produced no signal")

    def test_three_unmapped_homoglyphs_still_count_as_a_lookalike(self):
        alpha = "\u03b1"  # Greek alpha, not in the confusables table
        domain = f"p{alpha}yp{alpha}l-{alpha}ccount.com"
        self.assertEqual(lookalike_of(domain, {"paypal-account.com"}), "paypal-account.com")

    def test_a_single_mapped_homoglyph_is_still_caught(self):
        self.assertEqual(lookalike_of("аcme.com", {"acme.com"}), "acme.com")  # Cyrillic a
        self.assertIsNone(lookalike_of("acme.com", {"acme.com"}))
        self.assertIsNone(lookalike_of("mail.acme.com", {"acme.com"}))

    def test_the_same_display_name_on_the_companys_own_domain_is_not_an_impersonation(self):
        class Rec:
            def __init__(self, name): self.name = name
        class HR:
            records = {"p:alice": Rec("Alice Kim")}
        det = ImpersonationDetector(HR(), ["acme.com"])
        msg = Message("m", 0, "alice@acme.com", "Alice Kim", "hello", "normal note", ["bob@acme.com"],
                      auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"})
        self.assertEqual(det.analyze(msg, "bob@acme.com"), [])


class FixedFindingsTests(unittest.TestCase):
    def test_a_homoglyph_that_no_table_lists_is_still_a_lookalike_when_it_lines_up_with_a_protected_name(self):
        self.assertEqual(lookalike_of("tօօntօwn.com", {"toontown.com"}), "toontown.com")      # three Armenian letters: beyond the edit-distance net
        self.assertIsNone(lookalike_of("tօօntօwn-news.org", {"toontown.com"}))                 # different length: not claimed
