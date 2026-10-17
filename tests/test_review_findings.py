"""Findings from the independent review (Cursor, 2026-10-17, docs/27), each reproduced as a test that failed before its fix.
Batch 1: data loss, bypass, authorization. Each test names the finding it covers."""
import hashlib, os, tempfile, unittest
from pathlib import Path
from helpers import *
from halvard.ward.agent import Blocked
from halvard.relay.journal import Journal
from halvard.clock import ManualClock


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


class JournalFindings(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.a, self.host, self.clock, self.fs = make_agent(self.tmp)
        self.work = Path(self.tmp) / "docs"; self.work.mkdir()
        self.a.set_online(False); self.host.spawn(4242, "burst.exe")

    def test_rename_over_an_existing_file_does_not_lose_the_destination(self):
        """High: rename a.txt onto an existing b.txt, then rollback: b.txt used to be destroyed."""
        a, b = self.work / "a.txt", self.work / "b.txt"
        a.write_bytes(b"ALPHA-ORIGINAL"); b.write_bytes(b"BRAVO-ORIGINAL-MUST-SURVIVE")
        self.fs.rename(4242, str(a), str(b))
        self.assertEqual(b.read_bytes(), b"ALPHA-ORIGINAL")
        rep = self.a.journal.rollback([4242])
        self.assertEqual(a.read_bytes(), b"ALPHA-ORIGINAL", "the renamed file comes back")
        self.assertTrue(b.exists() and b.read_bytes() == b"BRAVO-ORIGINAL-MUST-SURVIVE", f"the file that was overwritten by the rename must be restored; report={rep}")

    @unittest.skipUnless(can_symlink(), "this account may not create symbolic links")
    def test_overwriting_through_a_symlink_restores_the_target_and_keeps_the_link(self):
        """High: overwrite through a symlink, then rollback: the target stayed encrypted and the link was replaced by a regular file."""
        secret, link = self.work / "payroll.txt", self.work / "shortcut.txt"
        secret.write_bytes(b"PAYROLL"); os.symlink(secret, link)
        self.fs.overwrite(4242, str(link), b"ENCRYPTED")
        self.assertEqual(secret.read_bytes(), b"ENCRYPTED")
        self.a.journal.rollback([4242])
        self.assertEqual(secret.read_bytes(), b"PAYROLL", "the real file is restored")
        self.assertTrue(os.path.islink(link), "the link is still a link")

    def test_a_file_opened_but_never_reported_written_is_reported_not_silently_left_encrypted(self):
        """High: the sensor journals an open and never calls after(); the file is then overwritten. Rollback used to say nothing."""
        p = self.work / "memo.txt"; p.write_bytes(b"ORIGINAL-NOTE")
        self.a.journal.before(4242, "open", str(p))
        p.write_bytes(b"ENCRYPTED")                      # the program wrote it; the sensor never saw the close
        rep = self.a.journal.rollback([4242])
        self.assertEqual(p.read_bytes(), b"ENCRYPTED", "unattributed content is not overwritten blindly")
        self.assertIn(str(p), [x[0] for x in rep.not_restorable] + rep.skipped_changed_after, f"it must be reported: {rep}")
        self.assertFalse(rep.complete)

    def test_an_open_that_vanished_is_still_restored(self):
        p = self.work / "gone.txt"; p.write_bytes(b"ORIGINAL-NOTE")
        self.a.journal.before(4242, "open", str(p)); os.remove(p)
        self.a.journal.rollback([4242]); self.assertEqual(p.read_bytes(), b"ORIGINAL-NOTE")


class TripwireFindings(unittest.TestCase):
    def burst_world(self, tmp, path):
        a, host, clock, fs = make_agent(tmp, tripwires=[{"id": "t1", "path": path, "kind": "encryption"}])
        a._place_tripwires(); host.spawn(5, "burst.exe"); return a, host, fs

    @unittest.skipUnless(can_hardlink(), "hard links not available")
    def test_a_hard_link_to_a_tripwire_is_the_tripwire(self):
        """High: hard-link the decoy and overwrite the link: the write used to go through."""
        tmp = tempfile.mkdtemp(); d = Path(tmp) / "docs"; d.mkdir(); trap = str(d / "!000-budget.xlsx")
        a, host, fs = self.burst_world(tmp, trap)
        other = d / "innocent-name.xlsx"; os.link(trap, other)
        with self.assertRaises(Blocked): fs.overwrite(5, str(other), b"ENCRYPTED-VIA-HARDLINK")
        self.assertNotEqual(Path(trap).read_bytes(), b"ENCRYPTED-VIA-HARDLINK")

    def test_placement_never_replaces_a_file_that_appears_between_the_check_and_the_write(self):
        """High: a user file created inside the exists-check window was replaced by the decoy."""
        tmp = tempfile.mkdtemp(); d = Path(tmp) / "docs"; d.mkdir(); trap = str(d / "!000-budget.xlsx")
        a, host, clock, fs = make_agent(tmp)                 # no tripwire yet: the placement below is the one under test
        a.bundle.tripwires = [{"id": "t1", "path": trap, "kind": "encryption"}]
        real = os.path.lexists
        def racy(p, *x):
            r = real(p, *x)
            if os.path.normcase(str(p)) == os.path.normcase(os.path.realpath(trap)) and not r:
                Path(trap).write_bytes(b"USER-PAYROLL")      # the user saves a file right after the check says "free"
            return r
        os.path.lexists = racy
        try: a._place_tripwires()
        finally: os.path.lexists = real
        self.assertEqual(Path(trap).read_bytes(), b"USER-PAYROLL", "a user file is never replaced")

    def test_removal_leaves_a_file_that_changed_and_no_quarantine_debris(self):
        tmp = tempfile.mkdtemp(); d = Path(tmp) / "docs"; d.mkdir(); trap = str(d / "!000-budget.xlsx")
        a, host, clock, fs = make_agent(tmp, tripwires=[{"id": "t1", "path": trap, "kind": "encryption"}])
        a._place_tripwires(); Path(trap).write_bytes(b"USER-EDITED-AFTER-PLACEMENT")
        a.bundle.tripwires = []; a._place_tripwires()
        self.assertEqual(Path(trap).read_bytes(), b"USER-EDITED-AFTER-PLACEMENT")
        self.assertEqual(sorted(x.name for x in d.iterdir()), ["!000-budget.xlsx"])

    def test_one_unusable_folder_does_not_stop_the_other_tripwires_from_being_placed(self):
        """Medium: a decoy in a folder we may not write raised out of _place_tripwires and skipped every later one."""
        tmp = tempfile.mkdtemp(); d = Path(tmp) / "docs"; d.mkdir(); good = str(d / "!000-ok.xlsx")
        bad = os.path.join(tmp, "no-such-dir", "!000-x.xlsx")
        a, host, clock, fs = make_agent(tmp, tripwires=[{"id": "bad", "path": bad, "kind": "encryption"}, {"id": "ok", "path": good, "kind": "encryption"}])
        a._place_tripwires()
        self.assertTrue(os.path.exists(good))
        why = {e["public"]["tripwire"]: e["public"]["why"] for e in a.spool.entries() if e["kind"] == "ward.tripwire_skipped"}
        self.assertIn("bad", why)


class GatewayFindings(unittest.TestCase):
    def world(self):
        from rig7 import World7
        return World7()

    def test_untrusted_content_taint_follows_the_agent_not_the_session_id(self):
        """High: read a web page on session A, then send protected data on session B (or a rotated id): it used to be judged clean."""
        w = self.world(); g = w.cp.lumen.gateway; agent_id = "report-bot"
        s1 = g.session(agent_id, "sess-A"); g.ingest(s1, "web")
        s2 = g.session(agent_id, "sess-B")
        self.assertTrue(s2.taint, "a new session of the same agent inherits recent untrusted content")
        s3 = g.session(agent_id, "sess-C-rotated")
        self.assertTrue(s3.taint)

    def test_sending_out_after_reading_a_page_on_another_session_needs_a_person(self):
        w = self.world(); g = w.cp.lumen.gateway; agent_id = "report-bot"
        a = g.session(agent_id, "sess-A"); r = g.call(agent_id, a, "web", "fetch_url", {"target": "https://news.example.test/a"})
        self.assertEqual(r["decision"], "allow")
        b = g.session(agent_id, "totally-new-id")
        r2 = g.call(agent_id, b, "files", "read", {"target": "/reports/q1.csv"}); self.assertEqual(r2["decision"], "allow")
        r3 = g.call(agent_id, b, "mail", "send_mail", {"target": "someone@outside.test", "data": w.cp.lumen.tools.files["/reports/notes.txt"]})
        self.assertEqual((r3["decision"], r3["rule"]), ("ask", "agent-untrusted-context"), "same agent, brand-new session id: the earlier web page still counts")

    def test_a_person_can_clear_the_agents_taint(self):
        w = self.world(); g = w.cp.lumen.gateway; agent_id = "report-bot"
        s1 = g.session(agent_id, "sess-A"); g.ingest(s1, "web")
        g.clear_taint(agent_id, "p:alice")
        self.assertFalse(g.session(agent_id, "sess-B").taint)
        self.assertFalse(s1.taint)

    def test_rotating_session_ids_does_not_reset_the_runaway_limit(self):
        w = self.world(); g = w.cp.lumen.gateway; agent_id = "report-bot"
        spec = w.cp.lumen.registry.agents[agent_id].tools
        tool, action, res = "files", "read", "/reports/q1.csv"
        asks = 0
        for i in range(40):
            s = g.session(agent_id, f"rot-{i}")
            r = g.call(agent_id, s, tool, action, {"target": res})
            asks += r["decision"] == "ask" and r["rule"] == "agent-runaway"
        self.assertGreater(asks, 0, "40 calls in a minute across rotated sessions is still a loop")


class PlatformFindings(unittest.TestCase):
    def test_export_and_dependency_report_need_a_caller_from_that_company(self):
        """High: export('bank', region) and dependency_report('bank') worked with no member at all."""
        from rig8 import World8
        from halvard.fabric.platform import AccessRefused, Member
        w = World8()
        with self.assertRaises((TypeError, AccessRefused)): w.p.export("bank", "eu-central")
        with self.assertRaises((TypeError, AccessRefused)): w.p.dependency_report("bank")
        with self.assertRaises(AccessRefused): w.p.export(Member("bank", "mallory", "it_admin"), "eu-central")
        owner = w.m("bank")
        self.assertTrue(w.p.export(owner, "eu-central"))
        self.assertTrue(w.p.dependency_report(owner))
        self.assertNotEqual(w.p.dependency_report(w.m("acme")), w.p.dependency_report(owner), "each company only ever gets its own report")


class LedgerFindings(unittest.TestCase):
    def log(self, d, witness=None):
        from halvard.ledger.audit import AuditLog
        l = AuditLog(os.path.join(d, "t.log"), "acme", b"k" * 32, ManualClock())
        if witness is not None: l.witness = lambda seq, h: witness.append((seq, h))
        return l

    def test_deleting_the_log_and_its_local_anchor_is_caught_by_the_off_box_witness(self):
        """High: empty the log and delete the .head anchor: verify() said (True, []) and a new log started at sequence 0."""
        d = tempfile.mkdtemp(); seen = []
        l = self.log(d, seen)
        for i in range(5): l.append("x.event", "halvard", "system", "s", {"n": i})
        os.remove(os.path.join(d, "t.log")); os.remove(os.path.join(d, "t.head"))
        fresh = self.log(d)
        # The previous expectation was (True, []): a wiped log plus a deleted anchor verified clean, and only an in-memory witness caught it. That was the hole.
        ok, problems = fresh.verify()
        self.assertFalse(ok, problems)
        ok, problems = fresh.verify(witnessed=seen[-1])
        self.assertFalse(ok); self.assertTrue(any("off-box witness" in p for p in problems), problems)

    def test_a_healthy_log_verifies_against_its_witness_and_a_rewritten_entry_does_not(self):
        d = tempfile.mkdtemp(); seen = []; l = self.log(d, seen)
        for i in range(3): l.append("x.event", "halvard", "system", "s", {"n": i})
        self.assertEqual(l.verify(witnessed=seen[-1]), (True, []))
        self.assertEqual(l.verify(witnessed=(2, "0" * 64))[0], False)

    def test_a_witness_that_fails_does_not_stop_the_log_but_the_failure_is_counted(self):
        d = tempfile.mkdtemp(); l = self.log(d)
        def down(seq, h): raise OSError("witness unreachable")
        l.witness = down; l.append("x.event", "halvard", "system", "s", {}); l.append("x.event", "halvard", "system", "s", {})
        self.assertEqual((l.head[0], l.witness_failures), (2, 2))


class FreezeFindings(unittest.TestCase):
    def host(self):
        try:
            from halvard.platforms.linux import LinuxHost
        except Exception as e:                                     # module needs POSIX
            self.skipTest(f"linux platform module not importable here: {e}")
        return LinuxHost("t", tempfile.mkdtemp())

    def test_a_kernel_thread_or_low_pid_is_never_signalled(self):
        """High: LinuxHost.suspend(2) would have sent SIGSTOP to kthreadd (pid 2 and 100 were both signalled)."""
        import signal, unittest.mock as m
        h = self.host()
        with m.patch.object(signal, "SIGSTOP", 19, create=True), m.patch.object(signal, "SIGCONT", 18, create=True), m.patch.object(signal, "SIGKILL", 9, create=True), m.patch("os.kill") as k:
            for pid in (0, 1, 2):
                with self.assertRaises(PermissionError): h.suspend(pid)
                with self.assertRaises(PermissionError): h.terminate(pid)
            k.assert_not_called()

    def test_a_child_of_kthreadd_is_a_kernel_thread_and_an_ordinary_process_is_not(self):
        h = self.host()
        import unittest.mock as m
        with m.patch("pathlib.Path.read_text", side_effect=lambda *a, **k: "9 (kworker/0:1) I 2 0 0 0"):
            self.assertTrue(h._is_kernel_thread(9))
        with m.patch("pathlib.Path.read_text", side_effect=lambda *a, **k: "500 (bash) S 400 500 500 0"):
            self.assertFalse(h._is_kernel_thread(500))
        self.assertFalse(h._is_kernel_thread(10**9), "an unreadable pid is not treated as a kernel thread")


if __name__ == "__main__":
    unittest.main()
