"""Slice 1 — recovery contract. Each test names a hole that used to lose bytes or hide a file."""
import os, tempfile, unittest
from pathlib import Path
from helpers import *
from halvard.ward.agent import Blocked
from halvard.ward.incident import render
from halvard.relay.recovery import recovery_note


def can_symlink():
    d = tempfile.mkdtemp()
    try:
        os.symlink(os.path.join(d, "a"), os.path.join(d, "l")); return True
    except (OSError, NotImplementedError):
        return False


def can_hardlink():
    d = tempfile.mkdtemp(); p = os.path.join(d, "a"); Path(p).write_bytes(b"x")
    try:
        os.link(p, os.path.join(d, "b")); return True
    except (OSError, NotImplementedError):
        return False


def page_for(agent, rep):
    note = recovery_note(rep)
    inc = {"process": "burst.exe", "confidence": 0.9, "reasons": ["bulk encryption"], "online": False,
           "mode": "enforce", "results": [("journal_rollback", "executed", note["headline"], "rb")],
           "files_at_detection": len(note.get("files") or []), "recovery": note}
    return render(inc, agent.device_id), note


class RecoveryContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.a, self.host, self.clock, self.fs = make_agent(self.tmp)
        self.work = Path(self.tmp) / "docs"; self.work.mkdir()
        self.a.set_online(False); self.host.spawn(4242, "burst.exe")

    def test_rename_of_a_onto_existing_b_keeps_bs_bytes(self):
        a, b = self.work / "a.txt", self.work / "b.txt"
        a.write_bytes(b"ALPHA-ORIGINAL"); b.write_bytes(b"BRAVO-ORIGINAL-MUST-SURVIVE")
        self.fs.rename(4242, str(a), str(b))
        rep = self.a.journal.rollback([4242])
        self.assertEqual(a.read_bytes(), b"ALPHA-ORIGINAL")
        self.assertEqual(b.read_bytes(), b"BRAVO-ORIGINAL-MUST-SURVIVE")
        text, note = page_for(self.a, rep)
        for path in (str(a), str(b)):
            self.assertIn(path, text)
            row = next(f for f in note["files"] if f["path"] == path)
            self.assertEqual(row["status"], "restored")
            self.assertTrue(row["reason"])

    @unittest.skipUnless(can_symlink(), "this account may not create symbolic links")
    def test_overwrite_through_a_symlink_restores_the_target_and_the_link_stays_a_link(self):
        secret, link = self.work / "payroll.txt", self.work / "shortcut.txt"
        secret.write_bytes(b"PAYROLL"); os.symlink(secret, link)
        self.fs.overwrite(4242, str(link), b"ENCRYPTED")
        rep = self.a.journal.rollback([4242])
        self.assertEqual(secret.read_bytes(), b"PAYROLL")
        self.assertTrue(os.path.islink(link))
        text, note = page_for(self.a, rep)
        self.assertIn(str(secret), text)
        row = next(f for f in note["files"] if f["path"] == str(secret))
        self.assertEqual(row["status"], "restored")

    @unittest.skipUnless(can_hardlink(), "hard links not available")
    def test_a_hard_link_to_a_tripwire_is_stopped_before_the_bytes_change(self):
        trap = str(self.work / "!000-budget.xlsx")
        self.a.bundle.tripwires = [{"id": "t1", "path": trap, "kind": "encryption"}]
        self.a._place_tripwires()
        other = self.work / "innocent-name.xlsx"; os.link(trap, other)
        before = Path(trap).read_bytes()
        with self.assertRaises(Blocked):
            self.fs.overwrite(4242, str(other), b"ENCRYPTED-VIA-HARDLINK")
        self.assertEqual(Path(trap).read_bytes(), before)
        self.assertTrue(self.a.tripwire_hits[-1]["stopped"])

    def test_an_open_whose_after_never_runs_is_not_a_clean_rollback(self):
        p = self.work / "memo.txt"; p.write_bytes(b"ORIGINAL-NOTE")
        self.a.journal.before(4242, "open", str(p))
        p.write_bytes(b"ENCRYPTED")
        rep = self.a.journal.rollback([4242])
        self.assertEqual(p.read_bytes(), b"ENCRYPTED")
        self.assertFalse(rep.complete)
        text, note = page_for(self.a, rep)
        row = next(f for f in note["files"] if f["path"] == str(p))
        self.assertEqual(row["status"], "not_restorable")
        self.assertIn(str(p), text)
        self.assertIn(row["reason"], text)

    def test_a_dropped_pending_open_is_not_a_clean_rollback_while_the_new_bytes_remain(self):
        """The sensor took a pre-image, then dropped the pending close record, so after() never runs."""
        p = self.work / "dropped.txt"; p.write_bytes(b"ORIGINAL-NOTE")
        rid, _ = self.a.journal.before(4242, "open", str(p))
        self.a.journal.drop_pending(rid)
        p.write_bytes(b"ENCRYPTED-STILL-THERE")
        rep = self.a.journal.rollback([4242])
        self.assertEqual(p.read_bytes(), b"ENCRYPTED-STILL-THERE")
        self.assertFalse(rep.complete, rep)
        text, note = page_for(self.a, rep)
        row = next(f for f in note["files"] if f["path"] == str(p))
        self.assertEqual(row["status"], "not_restorable")
        self.assertIn("pending", row["reason"].lower())
        self.assertIn(str(p), text)
        self.assertIn(row["reason"], text)

    def test_the_incident_lists_every_file_restored_left_or_not_restorable(self):
        restored = self.work / "restored.txt"; restored.write_bytes(b"KEEP-ME")
        self.fs.overwrite(4242, str(restored), b"ENC")
        later = self.work / "later.txt"; later.write_bytes(b"BRAVO")
        self.fs.overwrite(4242, str(later), b"ENC-B")
        self.host.spawn(7, "editor.exe"); self.fs.overwrite(7, str(later), b"EDITED-LATER")
        lost = self.work / "lost.txt"; lost.write_bytes(b"ORIGINAL")
        self.a.journal.before(4242, "open", str(lost)); lost.write_bytes(b"ENCRYPTED")
        rep = self.a.journal.rollback([4242])
        text, note = page_for(self.a, rep)
        by_path = {f["path"]: f for f in note["files"]}
        self.assertEqual(by_path[str(restored)]["status"], "restored")
        self.assertEqual(by_path[str(later)]["status"], "left_changed_later")
        self.assertIn("changed", by_path[str(later)]["reason"])
        self.assertEqual(by_path[str(lost)]["status"], "not_restorable")
        self.assertFalse(rep.complete)
        for path in (str(restored), str(later), str(lost)):
            self.assertIn(path, text)
            self.assertIn(by_path[path]["reason"], text)
        self.assertEqual(restored.read_bytes(), b"KEEP-ME")
        self.assertEqual(later.read_bytes(), b"EDITED-LATER")
        self.assertEqual(lost.read_bytes(), b"ENCRYPTED")
