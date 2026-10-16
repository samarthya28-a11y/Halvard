import io, unittest, zipfile
from helpers import *
from halvard.vaultline.classifiers import *

VISA, MC, AMEX = "4111111111111111", "5555555555554444", "378282246310005"
GB_IBAN, DE_IBAN = "GB82WEST12345698765432", "DE89370400440532013000"


def aadhaar(prefix11="23456789012"): return prefix11 + verhoeff_check_digit(prefix11)
def xlsx(text): z = io.BytesIO(); zf = zipfile.ZipFile(z, "w"); zf.writestr("xl/sharedStrings.xml", f"<sst><si><t>{text}</t></si></sst>"); zf.writestr("[Content_Types].xml", "x"); zf.close(); return z.getvalue()


class ChecksumTests(unittest.TestCase):
    def test_known_valid_and_invalid_values(self):
        for n in (VISA, MC, AMEX): self.assertTrue(card_plausible(n), n)
        self.assertFalse(card_plausible("4111111111111112")); self.assertFalse(card_plausible("1234567890123456")); self.assertFalse(card_plausible("0000000000000000"))
        self.assertTrue(iban_ok(GB_IBAN)); self.assertTrue(iban_ok(DE_IBAN)); self.assertFalse(iban_ok("GB82WEST12345698765433")); self.assertFalse(iban_ok("GB82WEST1234569876543"))
        self.assertTrue(verhoeff_ok("2363")); self.assertFalse(verhoeff_ok("2364")); self.assertTrue(verhoeff_ok(aadhaar()))
        self.assertTrue(ssn_ok("123", "45", "6789")); self.assertFalse(ssn_ok("000", "45", "6789")); self.assertFalse(ssn_ok("987", "65", "4321")); self.assertFalse(ssn_ok("123", "00", "6789"))


class ClassifierTests(unittest.TestCase):
    def setUp(self): self.C = Classifier()

    def test_cards_ids_and_secrets_are_labelled_with_counts_and_reasons_but_no_values(self):
        text = f"Customer cards (expiry 12/28): {VISA}, {MC}, {AMEX}\nBank {GB_IBAN}\nSSN 123-45-6789\nAadhaar {aadhaar()[:4]} {aadhaar()[4:8]} {aadhaar()[8:]}\nPAN ABCPE1234F\nAKIAIOSFODNN7EXAMPLE"
        c = self.C.classify("export.csv", text.encode()); self.assertEqual(set(c.labels), {"pci_card", "iban", "us_ssn", "in_aadhaar", "in_pan", "secret_key"})
        self.assertEqual(c.labels["pci_card"]["count"], 3); self.assertEqual(c.sensitivity, "regulated"); self.assertIn("card words appear nearby", c.labels["pci_card"]["why"])
        blob = str(c)
        for v in (VISA, MC, AMEX, GB_IBAN, "123-45-6789", "ABCPE1234F", "AKIAIOSFODNN7EXAMPLE"): self.assertNotIn(v, blob)

    def test_ordinary_numbers_are_not_regulated_data(self):
        text = "Order 4111111111111112 shipped. Tel 0044 20 7946 0958. Invoice 20260415. Ref 123456789012. Part 000-00-0000. Version 2.31.14.159"
        self.assertEqual(self.C.classify("orders.txt", text.encode()).labels, {})
        self.assertEqual(self.C.classify("a.txt", b"hello world").sensitivity, "internal")

    def test_a_twelve_digit_number_with_a_bad_check_digit_is_not_an_aadhaar(self):
        good = aadhaar(); bad = good[:-1] + str((int(good[-1]) + 1) % 10)
        self.assertIn("in_aadhaar", self.C.classify("a.txt", f"id {good[:4]} {good[4:8]} {good[8:]}".encode()).labels)
        self.assertNotIn("in_aadhaar", self.C.classify("b.txt", f"id {bad[:4]} {bad[4:8]} {bad[8:]}".encode()).labels)

    def test_office_files_are_read_and_unreadable_formats_are_reported_not_guessed(self):
        c = self.C.classify("cards.xlsx", xlsx(f"Card {VISA}")); self.assertIn("pci_card", c.labels)
        for name, data, why in (("x.pdf", b"%PDF-1.4 " + VISA.encode(), "PDF"), ("old.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"x" * 20, "legacy"), ("img.bin", b"\x00\x01\x02" * 100, "binary")):
            c = self.C.classify(name, data); self.assertEqual(c.labels, {}); self.assertIn(why, c.unscannable)
        z = io.BytesIO(); zf = zipfile.ZipFile(z, "w"); zf.writestr("a.txt", "x"); zf.close(); raw = bytearray(z.getvalue()); raw[raw.index(b"PK\x01\x02") + 8] |= 1
        self.assertEqual(self.C.classify("e.zip", bytes(raw)).unscannable, "encrypted archive")

    def test_generic_secrets_need_randomness_and_custom_patterns_are_the_customers(self):
        self.assertIn("secret_generic", self.C.classify("c.env", b"API_KEY=q8Zr2LmX9vB4nT7pW1sD6yK3").labels)
        self.assertEqual(self.C.classify("c.env", b"password=aaaaaaaaaaaaaaaaaaaaaaaa").labels, {})
        C = Classifier(custom=[{"label": "project_atlas", "regex": r"PROJECT-ATLAS-\d{4}", "min_count": 2}])
        self.assertEqual(C.classify("m.txt", b"PROJECT-ATLAS-0001 and PROJECT-ATLAS-0002").labels["custom:project_atlas"]["count"], 2); self.assertEqual(C.classify("m.txt", b"PROJECT-ATLAS-0001").labels, {})

    def test_a_single_card_is_lower_confidence_than_a_list(self):
        one = self.C.classify("a.txt", VISA.encode()).labels["pci_card"]["confidence"]; many = self.C.classify("a.txt", (" ".join([VISA, MC, AMEX, "6011111111111117", "3530111333300000"])).encode()).labels["pci_card"]["confidence"]
        self.assertLess(one, many)


if __name__ == "__main__":
    unittest.main()
