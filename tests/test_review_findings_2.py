"""Independent review findings, batch 2 (0.9.3): classifier blind spots, Keeper redaction, audit field leaks, sensor and placement guards.
Each test failed before its fix."""
import io, json, os, tempfile, unittest, zipfile, zlib
from helpers import *
from halvard.vaultline.classifiers import Classifier

VISA = "4111111111111111"
C = Classifier()


def grouped(sep, n=VISA): return sep.join(n[i:i + 4] for i in range(0, 16, 4))


def digits_in(script_zero, n=VISA): return "".join(chr(script_zero + int(d)) for d in n)


def pdf_with(text, compress=True):
    body = f"BT /F1 12 Tf 72 700 Td ({text}) Tj ET".encode()
    if compress: body = zlib.compress(body)
    return b"%PDF-1.4\n1 0 obj\n<< /Length " + str(len(body)).encode() + b" >>\nstream\n" + body + b"\nendstream\nendobj\ntrailer\n<< >>\n%%EOF\n"


def ooxml(extra):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>"); z.writestr("word/document.xml", "<w:document><w:t>Quarterly notes, nothing to see</w:t></w:document>")
        for k, v in extra.items(): z.writestr(k, v)
    return b.getvalue()


class CardSeparatorsAndScripts(unittest.TestCase):
    def test_card_numbers_written_with_other_separators_are_found(self):
        """Medium: tab, comma, slash, underscore, colon, middle dot and an ideographic space hid a card."""
        for name, sep in {"tab": "\t", "comma": ",", "slash": "/", "underscore": "_", "colon": ":", "middle dot": "·", "ideographic space": "　", "thin space": " "}.items():
            c = C.classify("x.txt", f"order total 12.50 card {grouped(sep)} thanks".encode())
            self.assertIn("pci_card", c.labels, f"separator: {name}")

    def test_card_numbers_in_other_digit_scripts_are_found(self):
        """Medium: fullwidth, Arabic-Indic and Devanagari digits produced no label."""
        for name, zero in {"fullwidth": 0xFF10, "arabic-indic": 0x0660, "devanagari": 0x0966}.items():
            c = C.classify("x.txt", f"card {digits_in(zero)} end".encode("utf-8"))
            self.assertIn("pci_card", c.labels, name)
            c2 = C.classify("x.txt", f"card {grouped(' ', digits_in(zero))} end".encode("utf-8"))
            self.assertIn("pci_card", c2.labels, name + " grouped")

    def test_a_lowercase_iban_is_found_and_so_is_one_followed_by_an_uppercase_word(self):
        self.assertIn("iban", C.classify("x.txt", b"pay to gb82west12345698765432 please").labels)
        self.assertIn("iban", C.classify("x.txt", b"PAY TO GB82WEST12345698765432 PLEASE").labels, "a real IBAN is not hidden by the next word")
        self.assertIn("iban", C.classify("x.txt", b"iban GB82 WEST 1234 5698 7654 32 thanks").labels)
        self.assertNotIn("iban", C.classify("x.txt", b"GB82WEST12345698765433 not valid").labels)

    def test_normal_numbers_are_still_not_cards(self):
        """The widening must not turn order ids and lists of numbers into regulated data."""
        for text in ["order 1234567890123456789012345678901234567 shipped", "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16", "invoice 2024/10/17/0001/0002/0003",
                     "tel 0044 20 7946 0958 ext 12", "ids: 1111111111111111", "ref 4111_1111_1111_1112"]:
            self.assertNotIn("pci_card", C.classify("x.txt", text.encode()).labels, text)


class UnreadableContainers(unittest.TestCase):
    def test_a_card_inside_a_pdf_is_found(self):
        """High: a PDF with a Visa number was only 'unscannable, confidential, justify'."""
        for compress in (True, False):
            c = C.classify("statement.pdf", pdf_with(f"Visa {grouped(' ')} exp 12/29", compress))
            self.assertIn("pci_card", c.labels, f"compressed={compress}")
            self.assertEqual(c.sensitivity, "regulated")
            self.assertIsNone(c.unscannable)

    def test_a_pdf_whose_text_cannot_be_read_is_still_called_unscannable(self):
        c = C.classify("scan.pdf", b"%PDF-1.4\n1 0 obj\n<< /Filter /DCTDecode >>\nstream\n\xff\xd8\xff\x00\x01binaryimage\nendstream\nendobj\n")
        self.assertTrue(c.unscannable); self.assertEqual(c.sensitivity, "confidential")

    def test_a_card_in_a_non_xml_part_of_an_office_file_is_found(self):
        """High: a docx whose only card sat in word/media/card.bin was 'internal, no labels'."""
        c = C.classify("report.docx", ooxml({"word/media/card.bin": f"customer card {grouped(' ')}".encode()}))
        self.assertIn("pci_card", c.labels)

    def test_a_card_in_a_document_nested_in_an_office_file_is_found(self):
        inner = ooxml({"word/embeddings/oleObject1.bin": f"{grouped('-')}".encode()})
        c = C.classify("report.docx", ooxml({"word/embeddings/attached.docx": inner}))
        self.assertIn("pci_card", c.labels)

    def test_images_inside_an_office_file_are_not_scanned_as_text(self):
        import random
        noise = random.Random(3).randbytes(200000)
        c = C.classify("deck.pptx", ooxml({"ppt/media/image1.png": noise, "ppt/media/image2.jpg": noise}))
        self.assertEqual(c.labels, {})

    def test_deeply_nested_archives_do_not_loop(self):
        data = b"nothing"
        for _ in range(8): data = ooxml({"inner.docx": data})
        C.classify("bomb.docx", data)      # must return, not recurse forever


class KeeperRedaction(unittest.TestCase):
    def setUp(self):
        from rig8 import World8
        from test_fabric_keeper import desk, seed_case
        from halvard.signet.hr import HRRecord
        self.w = World8(); self.desk, self.seed, self.HR = desk, seed_case, HRRecord

    def headline(self, summary):
        cp, c = self.seed(self.w, "acme", summary); d = self.desk(self.w)
        return d.queue("k1")[0]["headline"], d.case_view("k1", "acme", c.id)

    def test_a_first_name_or_family_name_alone_is_redacted(self):
        """Medium: HR name 'Alice Kim' with a headline that said just 'Alice' left the name in the text."""
        h, page = self.headline("Alice opened a strange attachment; Kim then reported it.")
        for text in (h, page):
            self.assertNotIn("Alice", text); self.assertNotIn("Kim", text)

    def test_short_names_do_not_mangle_ordinary_words(self):
        """Medium: HR names Ann and Bo turned 'Annual' into '[person]ual' and 'boat' into '[person]at'."""
        cp = self.w.p.tenants["acme"].cp
        for pid, name in (("p:ann", "Ann"), ("p:bo", "Bo")):
            cp.hr.add(self.HR(pid, name, f"{name.lower()}@acme.com", name.lower(), "active", "Sales", None, 0.0, email=f"{name.lower()}@acme.com"))
        h, page = self.headline("Annual report on the boat shows Ann copied files; Bo was away.")
        self.assertIn("Annual", h); self.assertIn("boat", h)
        self.assertNotIn("Ann copied", h); self.assertNotIn(" Ann ", " " + h + " ")

    def test_an_email_address_or_account_name_is_redacted_whole(self):
        h, _ = self.headline("Login by alice.kim@acme.com from alice-laptop failed.")
        self.assertNotIn("alice.kim@acme.com", h)


class AuditPrivacy(unittest.TestCase):
    def log(self):
        from halvard.ledger.audit import AuditLog
        from halvard.clock import ManualClock
        return AuditLog(os.path.join(tempfile.mkdtemp(), "t.log"), "acme", b"k" * 32, ManualClock())

    def test_an_email_address_in_the_subject_never_reaches_the_public_head_or_the_auditor_export(self):
        """Medium: the subject went into the public head unscrubbed."""
        l = self.log(); l.append("x.event", "halvard", "system", "alice.kim@acme.com", {"n": 1}, controls=("C.1",))
        rec = next(iter(l.entries())); self.assertNotIn("alice.kim@acme.com", json.dumps({k: v for k, v in rec.items() if k != "private"}))
        self.assertNotIn("alice.kim@acme.com", json.dumps(l.export_for_control("C.1")))

    def test_personal_keys_are_private_whatever_their_capitalisation_or_nesting(self):
        """Medium: 'User', 'Path' and a nested {'meta': {'user': ...}} stayed public."""
        l = self.log()
        l.append("x.event", "halvard", "system", "s", {"User": "alice", "Path": "/home/alice/payroll.xlsx", "meta": {"user": "bob", "n": 2}, "items": [{"host": "LT-1"}], "count": 3}, controls=("C.1",))
        rec = next(iter(l.entries())); pub = json.dumps(rec["public"])
        for secret in ("alice", "payroll", "bob", "LT-1"): self.assertNotIn(secret, pub, secret)
        self.assertEqual(rec["public"].get("count"), 3, "harmless fields stay public")
        exp = json.dumps(l.export_for_control("C.1"))
        for secret in ("alice", "payroll", "bob", "LT-1"): self.assertNotIn(secret, exp, secret)
        self.assertTrue(l.verify()[0])


if __name__ == "__main__":
    unittest.main()
