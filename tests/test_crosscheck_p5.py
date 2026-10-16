"""Independent cross-check, phase 5. Card-data exits the author's fixtures do not try."""
import os, pathlib, unittest
from helpers import *
from rig5 import *
from halvard.vaultline.classifiers import Classification, Classifier
from halvard.vaultline.dlp import decide
from halvard.ward.agent import EgressBlocked, NeedsJustification

VISA_GROUPS = (VISA[:4], VISA[4:8], VISA[8:12], VISA[12:])


def card_bytes(sep):
    return ("name,card\nA Customer," + sep.join(VISA_GROUPS) + "\n").encode()


class ClassifierBypassTests(unittest.TestCase):
    def test_a_real_card_number_split_by_dots_newlines_or_nbsp_is_still_a_card(self):
        c = Classifier()
        for sep, name in ((".", "dots.csv"), ("\n", "lines.csv"), ("\u00a0", "nbsp.csv")):
            got = c.classify(name, card_bytes(sep))
            self.assertIn("pci_card", got.labels, sep.encode("unicode_escape"))
            self.assertEqual(got.sensitivity, "regulated")

    def test_a_pdf_that_contains_a_card_number_is_not_treated_as_clean(self):
        data = b"%PDF-1.4\n" + CARD_CSV
        got = Classifier().classify("orders.pdf", data)
        self.assertTrue(got.unscannable)
        self.assertNotEqual(got.sensitivity, "internal")


class EgressBypassTests(unittest.TestCase):
    def setUp(self):
        self.w = World5(); self.w.agent.set_online(False)
        self.host, self.fs = self.w.host, self.w.fs
        self.host.spawn(300, "explorer.exe")
        self.plain = os.path.join(self.w.tmp, "mnt", "plain"); os.makedirs(self.plain, exist_ok=True)
        self.host.mounts[self.plain] = {"removable": True, "encrypted": False, "vendor": "Kingston", "serial": "SN-APPROVED"}

    def test_dotted_cards_and_unreadable_pdfs_cannot_be_copied_to_an_approved_plain_drive(self):
        src = os.path.join(self.w.tmp, "work", "dots.csv"); pathlib.Path(src).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(src).write_bytes(card_bytes("."))
        with self.assertRaises(EgressBlocked):
            self.fs.copy_out(300, src, os.path.join(self.plain, "dots.csv"))
        pdf = os.path.join(self.w.tmp, "work", "orders.pdf")
        pathlib.Path(pdf).write_bytes(b"%PDF-1.4\n" + CARD_CSV)
        with self.assertRaises((EgressBlocked, NeedsJustification)):       # unread file: never a silent allow; a recorded reason can unlock it
            self.fs.copy_out(300, pdf, os.path.join(self.plain, "orders.pdf"))
        self.assertFalse(os.path.exists(os.path.join(self.plain, "dots.csv")))
        self.assertFalse(os.path.exists(os.path.join(self.plain, "orders.pdf")))

    def test_a_justification_cannot_be_stretched_past_an_hour(self):
        body = b"PROJECT-ATLAS-0001 PROJECT-ATLAS-0002 roadmap"
        src = os.path.join(self.w.tmp, "work", "road.txt"); pathlib.Path(src).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(src).write_bytes(body)
        self.w.cp.push_dlp({**self.w.dlp, "custom_labels": [{"label": "project_atlas", "regex": r"PROJECT-ATLAS-\d{4}", "min_count": 1}]})
        self.w.cp.fleet.reconnect("LT-17"); self.w.agent.set_online(False)
        dest = {"mount": self.host.mount_of(self.plain)}
        self.w.agent.justify("usb", src, body, dest, "Handing the roadmap to the printer vendor on site", minutes=60 * 24 * 365)
        self.w.clock.advance(3601)
        with self.assertRaises((EgressBlocked, NeedsJustification)):
            self.fs.copy_out(300, src, os.path.join(self.plain, "year.txt"))

    def test_a_secret_on_an_approved_encrypted_drive_stays_unjustifiable(self):
        enc = os.path.join(self.w.tmp, "mnt", "enc"); os.makedirs(enc, exist_ok=True)
        self.host.mounts[enc] = {"removable": True, "encrypted": True, "vendor": "Kingston", "serial": "SN-APPROVED"}
        src = os.path.join(self.w.tmp, "work", "creds.env"); pathlib.Path(src).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(src).write_bytes(SECRET_ENV)
        with self.assertRaises(EgressBlocked) as cm:
            self.fs.copy_out(300, src, os.path.join(enc, "creds.env"))
        self.assertFalse(cm.exception.decision.justifiable)
        cls = Classification({"secret_key": {"count": 1, "confidence": 0.97}, "pci_card": {"count": 3, "confidence": 0.9}}, "regulated")
        d = decide(cls, "usb", "approved_encrypted")
        self.assertEqual((d.action, d.justifiable, d.rule), ("block", False, "secrets-anywhere"))

    def test_a_customer_label_of_public_is_not_upgraded_when_a_scan_finds_cards(self):
        w = World5()
        w.cp.store.update_entity(w.cp.ctx, "s3:cust-exports", sensitivity="public")
        w.scan_all(); w.cp.atlas.sync_graph()
        e = next(x for x in w.cp.store.entities(w.cp.ctx) if x["entity_id"] == "s3:cust-exports")
        self.assertEqual(e["sensitivity"], "public")
        self.assertEqual(e["suggested_sensitivity"], "regulated")
        self.assertEqual(w.cp.atlas.sensitivity_of("s3:cust-exports"), "public")


class FixedFindingsTests(unittest.TestCase):
    def test_two_long_numbers_side_by_side_are_not_one_card_but_a_card_written_in_groups_is(self):
        c = Classifier()
        self.assertNotIn("pci_card", c.classify("a.txt", b"orders 41111111 11111111 shipped").labels)       # the two halves of a valid number, but eight-digit groups are not how cards are written
        self.assertIn("pci_card", c.classify("b.txt", b"card 4111 1111 1111 1111").labels)
