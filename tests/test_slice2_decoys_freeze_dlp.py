"""Slice 2 — decoys, freeze safety, and unread or disguised regulated data."""
import os, tempfile, unittest
from pathlib import Path
from helpers import *
from halvard.vaultline.classifiers import Classifier
from halvard.vaultline.dlp import decide
from halvard.ward.agent import Blocked, EgressBlocked

FIX = Path(__file__).resolve().parent / "fixtures" / "dlp"
CARD_SEPS = ("card-tab.txt", "card-comma.txt", "card-slash.txt", "card-underscore.txt", "card-colon.txt", "card-middot.txt", "card-ideographic-space.txt")


class DecoyRoots(unittest.TestCase):
    def test_var_opt_root_and_run_are_refused_the_same_way_as_etc(self):
        tmp = tempfile.mkdtemp()
        specs = [{"id": root.strip("/"), "path": f"{root}/halvard-should-not-create.xlsx", "kind": "encryption"} for root in ("/etc", "/var", "/opt", "/root", "/run")]
        a, host, clock, fs = make_agent(tmp, tripwires=specs)
        a._place_tripwires()
        why = {e["public"]["tripwire"]: e["public"]["why"] for e in a.spool.entries() if e["kind"] == "ward.tripwire_skipped"}
        for root in ("etc", "var", "opt", "root", "run"):
            self.assertIn("operating-system", why[root], why)
            self.assertFalse(os.path.exists(f"/{root}/halvard-should-not-create.xlsx"))

    def test_an_unwritable_directory_is_skipped_and_later_decoys_still_run(self):
        tmp = tempfile.mkdtemp(); locked = Path(tmp) / "locked"; locked.mkdir(); os.chmod(locked, 0o555)
        good = str(Path(tmp) / "docs"); os.mkdir(good); good_file = str(Path(good) / "!000-ok.xlsx")
        bad = str(locked / "!000-x.xlsx")
        try:
            a, host, clock, fs = make_agent(tmp, tripwires=[{"id": "bad", "path": bad, "kind": "encryption"}, {"id": "ok", "path": good_file, "kind": "encryption"}])
            a._place_tripwires()
        finally:
            os.chmod(locked, 0o755)
        self.assertTrue(os.path.exists(good_file))
        why = {e["public"]["tripwire"]: e["public"]["why"] for e in a.spool.entries() if e["kind"] == "ward.tripwire_skipped"}
        self.assertIn("bad", why)


class FreezeSafety(unittest.TestCase):
    def test_suspend_refuses_a_configurable_denylist_as_well_as_the_agent_and_its_parent(self):
        import signal, unittest.mock as m
        from halvard.platforms.linux import LinuxHost
        h = LinuxHost("t", tempfile.mkdtemp(), denylist={4242, 7})
        with m.patch.object(signal, "SIGSTOP", 19, create=True), m.patch("os.kill") as k:
            for pid in (0, 1, 2, os.getpid(), os.getppid(), 4242, 7):
                with self.assertRaises(PermissionError): h.suspend(pid)
            k.assert_not_called()

    def test_blocked_remembers_pid_and_start_time_and_a_reused_pid_is_not_blocked(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp)
        work = Path(tmp) / "docs"; work.mkdir(); p = work / "note.txt"; p.write_bytes(b"ORIGINAL")
        host.spawn(10, "bad.exe"); a.block_pid(10)
        self.assertEqual(set(a.blocked), {10})
        self.assertIsNotNone(a.blocked[10])
        with self.assertRaises(Blocked): fs.overwrite(10, str(p), b"ENC")
        self.assertEqual(p.read_bytes(), b"ORIGINAL")
        host.spawn(10, "innocent.exe")
        self.assertFalse(a.is_blocked(10))
        fs.overwrite(10, str(p), b"OK-NEW-PROCESS")
        self.assertEqual(p.read_bytes(), b"OK-NEW-PROCESS")

    def test_blocked_is_cleared_when_containment_is_released(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp)
        host.spawn(10, "bad.exe"); a.block_pid(10); host.isolate()
        a.release_containment()
        self.assertFalse(host.isolated)
        self.assertFalse(a.is_blocked(10))
        self.assertEqual(a.blocked, {})


class ClassifierFixtures(unittest.TestCase):
    def setUp(self): self.c = Classifier()

    def test_cards_grouped_by_the_extra_separators_are_cards(self):
        for name in CARD_SEPS:
            got = self.c.classify(name, (FIX / name).read_bytes())
            self.assertIn("pci_card", got.labels, name)
            self.assertEqual(got.sensitivity, "regulated", name)

    def test_digits_in_other_scripts_that_are_the_same_number_are_a_card(self):
        for name in ("card-fullwidth.txt", "card-arabic-indic.txt"):
            got = self.c.classify(name, (FIX / name).read_bytes())
            self.assertIn("pci_card", got.labels, name)

    def test_a_lowercase_iban_is_an_iban(self):
        got = self.c.classify("iban-lower.txt", (FIX / "iban-lower.txt").read_bytes())
        self.assertIn("iban", got.labels)

    def test_unread_formats_and_unknown_bytes_are_regulated(self):
        for name in ("sample.pdf", "legacy.doc", "encrypted.zip", "ooxml-binary.docx", "unknown.bin"):
            got = self.c.classify(name, (FIX / name).read_bytes())
            self.assertEqual(got.sensitivity, "regulated", (name, got.unscannable, got.sensitivity))
            self.assertTrue(got.unscannable, name)

    def test_no_justification_can_copy_unread_bytes_to_an_unapproved_drive_or_an_external_address(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp)
        host.spawn(3, "explorer.exe")
        plain = Path(tmp) / "usb"; plain.mkdir()
        host.mounts[str(plain)] = {"removable": True, "encrypted": False, "vendor": "No", "serial": "SN-NO"}
        pdf = (FIX / "sample.pdf").read_bytes()
        src = Path(tmp) / "sample.pdf"; src.write_bytes(pdf)
        dest = {"mount": host.mount_of(str(plain))}
        with self.assertRaises(PermissionError):
            a.justify("usb", str(src), pdf, dest, "Sending the unread file to the vendor on site")
        with self.assertRaises(EgressBlocked) as cm:
            fs.copy_out(3, str(src), str(plain / "sample.pdf"))
        self.assertFalse(cm.exception.decision.justifiable)
        for name in ("legacy.doc", "encrypted.zip", "ooxml-binary.docx", "unknown.bin"):
            data = (FIX / name).read_bytes()
            cls = self.c.classify(name, data)
            for channel, dest_class in (("usb", "unapproved"), ("email_external", "external")):
                d = decide(cls, channel, dest_class)
                self.assertEqual(d.action, "block", (name, channel, d.action, d.rule))
                self.assertFalse(d.justifiable, (name, channel))
