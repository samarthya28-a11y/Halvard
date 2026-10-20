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
    def test_one_hold_copy_keeps_the_pin_and_a_stale_log_cannot_drop_the_other_holder(self):
        tmp = tempfile.mkdtemp(); clock = ManualClock()
        path = os.path.join(tmp, "t.log")
        first = AuditLog(path, "acme", b"k" * 32, clock)
        stale = AuditLog(path, "acme", b"k" * 32, clock)
        self.assertFalse(first.hold("p:one"))
        self.assertTrue(stale.hold("p:two"))
        fresh = AuditLog(path, "acme", b"k" * 32, clock)
        self.assertEqual(fresh._holders, {"p:one", "p:two"})
        self.assertTrue(fresh.pinned)
        copies = list(fresh._hold_paths())
        self.assertEqual(len(copies), 2)
        self.assertTrue(all(p.exists() for p in copies))
        copies[0].unlink()
        kept = AuditLog(path, "acme", b"k" * 32, clock)
        self.assertTrue(kept.pinned)
        self.assertEqual(kept._holders, {"p:one", "p:two"})
        for p in kept._hold_paths():
            if p.exists(): p.unlink()
        lifted = AuditLog(path, "acme", b"k" * 32, clock)
        self.assertFalse(lifted.pinned)
        self.assertEqual(lifted._holders, set())

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
    def test_repeated_notes_of_one_reason_stay_one_row_until_that_reason_clears(self):
        from rig3 import World
        w = World()
        for _ in range(3):
            w.agent.note_coverage("failed_open")
        rows = [r for r in w.cp.coverage.rows if r["reason"] == "failed_open" and r["device"] == "LT-17"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["count"], 3)
        led = [e for e in w.cp.ledger.entries() if e["kind"] == "coverage.row" and e["private"].get("reason") == "failed_open"]
        self.assertEqual(len(led), 1)
        spool = [e for e in w.agent.spool.entries() if e["kind"] == "ward.coverage" and e["private"].get("reason") == "failed_open"]
        self.assertEqual(len(spool), 1)
        w.agent.note_coverage("pending_dropped")
        w.agent.note_coverage("pending_dropped")
        w.agent.heartbeat()
        self.assertNotIn("failed_open", [r["reason"] for r in w.cp.coverage.rows])
        pending = [r for r in w.cp.coverage.rows if r["reason"] == "pending_dropped"]
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["count"], 2)
        w.agent.note_coverage("failed_open")
        led = [e for e in w.cp.ledger.entries() if e["kind"] == "coverage.row" and e["private"].get("reason") == "failed_open"]
        self.assertEqual(len(led), 2)
        again = [r for r in w.cp.coverage.rows if r["reason"] == "failed_open"]
        self.assertEqual(len(again), 1)
        self.assertEqual(again[0]["count"], 1)
        from halvard.relay.actions import Principal
        page = w.cp.board.page(Principal("u-own", "owner"))
        self.assertIn("Failed open: LT-17", page)

    def test_coverage_notes_without_a_monitor_remain_audit_lines(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp)
        self.assertIsNone(getattr(a, "coverage", None))
        a.note_coverage("failed_open")
        a.note_coverage("failed_open")
        spool = [e for e in a.spool.entries() if e["kind"] == "ward.coverage"]
        self.assertEqual(len(spool), 2)

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

    def test_a_hash_only_blocked_app_matches_that_image(self):
        from halvard.ward.agent import Blocked
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp)
        raw = b"MZ hash-only-sample"
        digest = hashlib.sha256(raw).hexdigest()
        a.bundle.blocked_apps.append({"image_hash": digest, "why": "this image", "control": "GLASS.COMPENSATING_CONTROL"})
        with self.assertRaises(Blocked):
            a.pre_execute("/apps/renamed.exe", raw, publisher="Other Co")
        self.assertEqual(a.pre_execute("/apps/renamed.exe", b"MZ different bytes", publisher="Other Co").decision, "allow")
        a.bundle.blocked_apps.clear()
        a.bundle.blocked_apps.append({"publisher": "Other Co", "app": "renamed", "why": "publisher only"})
        self.assertEqual(a.pre_execute("/apps/renamed.exe", b"MZ different bytes", publisher="Other Co").decision, "allow")
        a.bundle.blocked_apps.clear()
        a.bundle.blocked_apps.append({"app": "renamed", "why": "name only", "control": "GLASS.COMPENSATING_CONTROL"})
        with self.assertRaises(Blocked):
            a.pre_execute("/apps/renamed.exe", b"MZ anything", publisher="Whoever")

    def test_an_allowed_exec_is_still_an_audit_record(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp)
        verdict = a.pre_execute(os.path.join(tmp, "memo.txt"), b"quarterly numbers")
        self.assertEqual(verdict.decision, "allow")
        self.assertTrue(any(e["kind"] == "ward.exec_verdict" and e["public"].get("decision") == "allow" for e in a.spool.entries()))

    def test_quarantine_of_a_denied_exec_runs_after_the_permission_callback(self):
        bad = b"BAD-SAMPLE-DEFER"
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "bad.bin")
        Path(path).write_bytes(bad)
        a, host, clock, fs = make_agent(tmp, known_bad_sha256=[hashlib.sha256(bad).hexdigest()], prevention={"known_bad": "enforce", "bulk_encryption": "enforce"})
        sensor = linux.FanotifySensor(a, tmp)
        calls = []
        real = a.engine.request
        def wrapped(req):
            calls.append(req.action)
            return real(req)
        a.engine.request = wrapped
        st = type("S", (), {"st_size": len(bad)})()
        with unittest.mock.patch("os.fstat", return_value=st), unittest.mock.patch("os.pread", return_value=bad):
            decision = sensor._on_exec(50, 3, path)
        self.assertEqual(decision, linux.FAN_DENY)
        self.assertEqual(calls, [])
        self.assertTrue(os.path.exists(path))
        sensor.work.get_nowait()()
        self.assertEqual(calls, ["quarantine_file"])
        self.assertFalse(os.path.exists(path))
        self.assertIn("ward.exec_verdict", [e["kind"] for e in a.spool.entries()])

    def test_two_processes_of_one_binary_share_one_hash_and_a_changed_binary_does_not(self):
        if not os.path.exists("/proc/self/exe"):
            self.skipTest("no /proc")
        import shutil, subprocess, time
        sleep = shutil.which("sleep")
        if not sleep:
            self.skipTest("no sleep")
        tmp = tempfile.mkdtemp()
        binpath = os.path.join(tmp, "sleepbin")
        shutil.copy(sleep, binpath)
        os.chmod(binpath, 0o755)
        host = linux.LinuxHost("t", tmp)
        p1 = subprocess.Popen([binpath, "30"])
        time.sleep(0.05)
        p2 = subprocess.Popen([binpath, "30"])
        reads = []
        real_open = open
        def counting(file, mode="r", *args, **kwargs):
            name = os.fspath(file)
            if "b" in str(mode) and name.endswith("/exe"):
                reads.append(name)
            return real_open(file, mode, *args, **kwargs)
        try:
            with unittest.mock.patch("builtins.open", counting):
                h1 = host.proc(p1.pid)["exe_sha256"]
                h2 = host.proc(p2.pid)["exe_sha256"]
            self.assertEqual(reads, [f"/proc/{p1.pid}/exe"])
            self.assertEqual(h1, h2)
            self.assertEqual(h1, hashlib.sha256(Path(binpath).read_bytes()).hexdigest())
            self.assertIsNone(host.proc(p1.pid)["publisher"])
        finally:
            for p in (p1, p2):
                if p.poll() is None:
                    p.kill()
                p.wait(timeout=5)
        original = hashlib.sha256(Path(binpath).read_bytes()).hexdigest()
        Path(binpath).write_bytes(Path(binpath).read_bytes() + b"\n#pad")
        os.chmod(binpath, 0o755)
        p3 = subprocess.Popen([binpath, "30"])
        try:
            h3 = host.proc(p3.pid)["exe_sha256"]
            self.assertNotEqual(h3, original)
            self.assertEqual(h3, hashlib.sha256(Path(binpath).read_bytes()).hexdigest())
        finally:
            if p3.poll() is None:
                p3.kill()
            p3.wait(timeout=5)


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
