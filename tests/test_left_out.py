"""Holes the review left open after slices 1–7. Each test names the hole."""
import hashlib, os, tempfile, unittest, unittest.mock
from pathlib import Path
from helpers import *
from halvard.coverage import CoverageMonitor
from halvard.fabric.connector_auth import CONNECTOR_KEY, PUBLISHED_STAND_IN, seal, verified
from halvard.ledger.audit import AuditLog
from halvard.platforms import linux
from halvard.vaultline.classifiers import Classifier
from halvard.vaultline.dlp import decide


class RollbackNames(unittest.TestCase):
    def test_an_excluded_temp_file_is_named_and_the_report_is_not_complete(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp)
        work = Path(tmp) / "docs"; work.mkdir(); host.spawn(4, "enc.exe")
        victim = work / "scratch.tmp"; victim.write_bytes(b"ORIGINAL")
        fs.overwrite(4, str(victim), b"ENCRYPTED")
        rep = a.journal.rollback([4])
        self.assertFalse(rep.complete)
        self.assertEqual(victim.read_bytes(), b"ENCRYPTED")
        named = [p for p, _ in rep.not_restorable]
        self.assertIn(str(victim), named)
        self.assertTrue(any("excluded" in r for _, r in rep.not_restorable))

    def test_a_rename_onto_a_too_big_file_names_that_destination(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp)
        a.journal.max_file = 32
        work = Path(tmp) / "docs"; work.mkdir(); host.spawn(4, "enc.exe")
        src, dest = work / "note.txt", work / "big.bin"
        src.write_bytes(b"hello hello hello"); dest.write_bytes(b"B" * 80)
        fs.rename(4, str(src), str(dest))
        rep = a.journal.rollback([4])
        reasons = {p: r for p, r in rep.not_restorable}
        self.assertIn(str(dest), reasons)
        self.assertIn("per-file journal cap", reasons[str(dest)])
        self.assertFalse(rep.complete)
        self.assertEqual(src.read_bytes(), b"hello hello hello")


class EvidenceHolds(unittest.TestCase):
    def test_a_legal_hold_is_still_there_on_a_new_log_and_release_lifts_it(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp)
        self.assertFalse(a.spool.hold("p:one"))
        self.assertTrue(a.spool.hold("p:two"))
        fresh = AuditLog(a.spool.path, a.spool.tenant, a.spool._key, a.spool.clock)
        self.assertTrue(fresh.pinned)
        self.assertEqual(fresh._holders, {"p:one", "p:two"})
        with self.assertRaises(PermissionError): fresh.export_for_control("WARD.TAMPER_PROTECTION")
        self.assertFalse(fresh.release("p:one"))
        again = AuditLog(a.spool.path, a.spool.tenant, a.spool._key, a.spool.clock)
        self.assertFalse(again.pinned)
        again.export_for_control("WARD.TAMPER_PROTECTION")

    def test_deleting_the_log_the_head_and_the_beside_witness_still_fails_verify(self):
        tmp = tempfile.mkdtemp(); clock = ManualClock()
        path = os.path.join(tmp, "t.log")
        log = AuditLog(path, "acme", b"k" * 32, clock)
        log.append("x.event", "halvard", "system", "s", {"n": 1})
        self.assertTrue(log.verify()[0])
        os.remove(path); os.remove(str(log.anchor)); os.remove(str(log._witness_path()))
        fresh = AuditLog(path, "acme", b"k" * 32, clock)
        ok, problems = fresh.verify()
        self.assertFalse(ok)
        self.assertTrue(any("witness" in p for p in problems), problems)


class CoverageAndIdentity(unittest.TestCase):
    def test_a_later_heartbeat_clears_a_failed_open_row(self):
        from rig3 import World
        w = World()
        w.agent.note_coverage("failed_open")
        self.assertIn("failed_open", [r["reason"] for r in w.cp.coverage.rows])
        w.agent.heartbeat()
        self.assertNotIn("failed_open", [r["reason"] for r in w.cp.coverage.rows])
        self.assertTrue(any(e["kind"] == "coverage.cleared" for e in w.cp.ledger.entries()))

    def test_linux_proc_hashes_the_image_it_can_read(self):
        if not os.path.exists("/proc/self/exe"):
            self.skipTest("no /proc")
        host = linux.LinuxHost("t", tempfile.mkdtemp())
        info = host.proc(os.getpid())
        raw = Path("/proc/self/exe").read_bytes()
        self.assertEqual(info["exe_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertIsNone(info["publisher"])

    def test_the_exec_hook_uses_pre_execute(self):
        bad = b"BAD-SAMPLE-LEFT-OUT"
        tmp = tempfile.mkdtemp()
        a, host, clock, fs = make_agent(tmp, known_bad_sha256=[hashlib.sha256(bad).hexdigest()], prevention={"known_bad": "enforce", "bulk_encryption": "enforce"})
        sensor = linux.FanotifySensor(a, tmp)
        sensor.stats = {"exec_perm": 0}
        st = type("S", (), {"st_size": len(bad)})()
        with unittest.mock.patch("os.fstat", return_value=st), unittest.mock.patch("os.pread", return_value=bad):
            self.assertEqual(sensor._on_exec(50, 3, os.path.join(tmp, "bad.bin")), linux.FAN_DENY)
        kinds = [e["kind"] for e in a.spool.entries()]
        self.assertIn("ward.exec_verdict", kinds)


class UnreadAndConnector(unittest.TestCase):
    def test_unread_bytes_cannot_be_justified_on_upload_ai_or_partner_mail(self):
        pdf = (Path(__file__).resolve().parent / "fixtures" / "dlp" / "sample.pdf").read_bytes()
        cls = Classifier().classify("sample.pdf", pdf)
        for channel, dest in (("upload", "unsanctioned"), ("upload", "personal"), ("ai_prompt", "ai_shadow"), ("ai_prompt", "ai_enterprise"), ("email_external", "partner"), ("print", "any")):
            d = decide(cls, channel, dest)
            self.assertEqual(d.action, "block", (channel, dest, d.action, d.rule))
            self.assertFalse(d.justifiable, (channel, dest))
            self.assertTrue(d.message.endswith("file not read."), d.message)

    def test_resealing_with_the_published_string_does_not_verify(self):
        event = {"source": "idp", "kind": "signin", "user": "a"}
        seal(event)
        self.assertTrue(verified(event))
        forged = {"source": "idp", "kind": "signin", "user": "a"}
        seal(forged, key=PUBLISHED_STAND_IN)
        self.assertFalse(verified(forged))
        self.assertNotEqual(CONNECTOR_KEY, PUBLISHED_STAND_IN)


class MonitorShape(unittest.TestCase):
    def test_resolve_drops_only_the_named_reason(self):
        class C:
            def now(self): return 1
        m = CoverageMonitor(None, None, C())
        m.record("d", "failed_open"); m.record("d", "pending_dropped"); m.record("other", "failed_open")
        self.assertEqual(m.resolve("d", "failed_open"), 1)
        self.assertEqual(sorted(r["reason"] + r["device"] for r in m.rows), ["failed_openother", "pending_droppedd"])
