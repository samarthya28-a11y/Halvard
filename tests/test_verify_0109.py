"""Holes found while checking 0.10.9. Each test names the hole and failed on the unmodified branch (ce99a95)."""
import hashlib, os, re, tempfile, unittest, unittest.mock as m
from pathlib import Path
from helpers import *
from halvard.ledger.audit import AuditLog
from halvard.platforms import linux
from halvard.ward.agent import Blocked
from halvard.ward.identity import allows, blocks

ROOT = Path(__file__).resolve().parent.parent


def log_at(d, name="t.log"):
    return AuditLog(os.path.join(d, name), "acme", b"k" * 32, ManualClock())


class HoldDurability(unittest.TestCase):
    def pinned_pair(self):
        d = tempfile.mkdtemp(); log = log_at(d); log.hold("p:one"); self.assertTrue(log.hold("p:two")); return d, log

    def test_deleting_only_the_hold_file_does_not_lift_the_pin(self):
        d, log = self.pinned_pair()
        os.remove(os.path.join(d, "t.log.hold"))
        self.assertTrue(log_at(d).pinned, "the second sealed copy still names both people")
        with self.assertRaises(PermissionError): log_at(d).export_for_control("X")

    def test_an_edited_hold_file_does_not_lift_the_pin(self):
        d, log = self.pinned_pair()
        p = os.path.join(d, "t.log.hold"); open(p, "wb").write(open(p, "rb").read().replace(b"p:two", b"p:zzz"))
        self.assertTrue(log_at(d).pinned)

    def test_two_sessions_holding_at_the_same_time_do_not_overwrite_each_other(self):
        d = tempfile.mkdtemp(); one, two = log_at(d), log_at(d)      # both opened before either holds: neither has seen the other
        one.hold("p:one"); two.hold("p:two")
        self.assertTrue(log_at(d).pinned, "a third object on the same files must see both holders")
        self.assertTrue(one.pinned and two.pinned, "and so must each of them: the pin is read from the files, not remembered")

    def test_release_by_one_person_lifts_the_pin_in_both_copies(self):
        d, log = self.pinned_pair()
        self.assertFalse(log_at(d).release("p:one"))
        third = log_at(d); self.assertFalse(third.pinned); self.assertEqual(third._holders, {"p:two"})
        third.export_for_control("X")
        os.remove(os.path.join(d, "t.log.hold")); self.assertFalse(log_at(d).pinned, "the hidden copy was rewritten too, so it cannot resurrect the old pin")

    def test_known_limit_deleting_both_copies_lifts_the_pin(self):
        """A local file cannot stop a local administrator. Closing this needs a holder outside the machine; the reference has none."""
        d, log = self.pinned_pair()
        os.remove(os.path.join(d, "t.log.hold")); os.remove(os.path.join(d, ".halvard-witness", "t.log.hold"))
        self.assertFalse(log_at(d).pinned)


class CoverageFlood(unittest.TestCase):
    def test_a_hook_that_fails_on_every_open_leaves_one_row_one_ledger_entry_and_one_spool_entry(self):
        from rig3 import World
        w = World(); a = w.agent
        for _ in range(1000): a.note_coverage("failed_open")
        rows = [r for r in w.cp.coverage.rows if r["reason"] == "failed_open"]
        self.assertEqual(len(rows), 1); self.assertEqual(rows[0]["count"], 1000)
        self.assertEqual(sum(1 for e in w.cp.ledger.entries() if e["kind"] == "coverage.row"), 1)
        self.assertEqual(sum(1 for e in a.spool.entries() if e["kind"] == "ward.coverage"), 1)
        a.heartbeat()
        cleared = [e for e in w.cp.ledger.entries() if e["kind"] == "coverage.cleared"]
        self.assertEqual(len(cleared), 1); self.assertEqual(cleared[0]["public"]["occurrences"], 1000)
        a.note_coverage("failed_open")      # a NEW failure after recovery is a new row and a new entry
        self.assertEqual(sum(1 for e in w.cp.ledger.entries() if e["kind"] == "coverage.row"), 2)

    def test_pending_dropped_is_deduplicated_too_and_still_survives_a_heartbeat(self):
        from rig3 import World
        w = World(); a = w.agent
        for _ in range(300): a.note_coverage("pending_dropped")
        a.heartbeat()
        self.assertEqual([r["reason"] for r in w.cp.coverage.rows], ["pending_dropped"])
        self.assertEqual(w.cp.coverage.rows[0]["count"], 300)

    def test_an_agent_with_no_monitor_attached_also_records_once_and_records_again_after_a_heartbeat(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp)
        for _ in range(200): a.note_coverage("failed_open")
        self.assertEqual(sum(1 for e in a.spool.entries() if e["kind"] == "ward.coverage"), 1)
        a.heartbeat(); a.note_coverage("failed_open")
        self.assertEqual(sum(1 for e in a.spool.entries() if e["kind"] == "ward.coverage"), 2)


class BlockedAppRows(unittest.TestCase):
    H = hashlib.sha256(b"MZ the vulnerable build").hexdigest()

    def test_a_row_with_only_a_hash_blocks_that_file(self):
        self.assertTrue(blocks({"app": "pdfviewer", "image_hash": self.H}, name="renamed", publisher=None, image_hash=self.H))
        self.assertFalse(blocks({"app": "pdfviewer", "image_hash": self.H}, name="pdfviewer", publisher=None, image_hash="00" * 32), "same name, other bytes: not that program")

    def test_a_publisher_string_cannot_talk_a_block_away_and_none_is_needed(self):
        row = {"app": "pdfviewer", "publisher": "Adobe", "image_hash": self.H}
        for pub in ("Adobe", None, "Evil Inc"):
            self.assertTrue(blocks(row, name="x", publisher=pub, image_hash=self.H), pub)
        self.assertFalse(blocks(row, name="pdfviewer", publisher="Adobe", image_hash="11" * 32))

    def test_the_agent_blocks_a_hash_only_row_before_the_program_runs(self):
        tmp = tempfile.mkdtemp(); a, _, _, _ = make_agent(tmp, blocked_apps=[{"app": "pdfviewer", "image_hash": self.H, "why": "unpatched"}])
        with self.assertRaises(Blocked): a.pre_execute("/apps/anything.exe", b"MZ the vulnerable build")
        a.pre_execute("/apps/pdfviewer.exe", b"MZ a different build")

    def test_known_limits_a_name_only_row_matches_by_name_and_trust_still_needs_a_publisher(self):
        self.assertTrue(blocks({"app": "pdfviewer"}, name="PdfViewer", publisher=None, image_hash=self.H))      # name-only rows are the reference stand-in
        self.assertFalse(allows([{"name": "b.exe", "image_hash": self.H}], name="b.exe", publisher=None, image_hash=self.H))      # trust stays strict: fail closed
        self.assertTrue(allows(["backup.exe"], name="backup.exe", publisher=None, image_hash=None))


class ExecHook(unittest.TestCase):
    def sensor(self, **bundle):
        tmp = tempfile.mkdtemp(); bad = b"BAD-SAMPLE-0109"
        a, host, clock, fs = make_agent(tmp, known_bad_sha256=[hashlib.sha256(bad).hexdigest()], prevention={"known_bad": "enforce", "bulk_encryption": "enforce"}, **bundle)
        s = linux.FanotifySensor(a, tmp); s.stats = {"exec_perm": 0}; return tmp, bad, a, s

    def run_exec(self, s, tmp, data, name="x.bin", pid=50):
        st = type("S", (), {"st_size": len(data)})()
        with m.patch("os.fstat", return_value=st), m.patch("os.pread", return_value=data, create=True):
            return s._on_exec(pid, 3, os.path.join(tmp, name))

    def test_the_quarantine_runs_on_the_worker_not_inside_the_permission_callback(self):
        """Moving the file under a permission hook can ask the same hook for permission and wait for itself: the old sensor deferred it, the new one must too."""
        tmp, bad, a, s = self.sensor(); calls = []
        real = a.engine.request; a.engine.request = lambda req, *x, **k: (calls.append(req.action), real(req, *x, **k))[1]
        self.assertEqual(self.run_exec(s, tmp, bad, "bad.bin"), linux.FAN_DENY)
        self.assertEqual(calls, [], "nothing ran inline")
        self.assertEqual(s.work.qsize(), 1)
        s.work.get()(); self.assertEqual(calls, ["quarantine_file"])

    def test_a_harmless_program_leaves_no_signed_record_but_a_blocked_one_does(self):
        tmp, bad, a, s = self.sensor(); before = sum(1 for e in a.spool.entries() if e["kind"] == "ward.exec_verdict")
        for i in range(50): self.assertEqual(self.run_exec(s, tmp, b"harmless program bytes", f"ok{i}.bin", 60 + i), linux.FAN_ALLOW)
        self.assertEqual(sum(1 for e in a.spool.entries() if e["kind"] == "ward.exec_verdict"), before, "one signed entry per program started would flood the spool and slow every start")
        self.run_exec(s, tmp, bad, "bad.bin")
        self.assertEqual(sum(1 for e in a.spool.entries() if e["kind"] == "ward.exec_verdict"), before + 1)
        a.pre_execute(os.path.join(tmp, "direct.bin"), b"harmless direct call")      # the reference path keeps recording every verdict
        self.assertEqual(sum(1 for e in a.spool.entries() if e["kind"] == "ward.exec_verdict"), before + 2)

    def test_the_image_hash_is_cached_per_binary_not_per_process(self):
        host = linux.LinuxHost("t", tempfile.mkdtemp()); img = Path(tempfile.mkdtemp()) / "img.bin"; img.write_bytes(os.urandom(300_000)); opens = []
        real_open = open
        def fake_open(path, *a, **k):
            s = str(path).replace("\\", "/")
            if s.startswith("/proc/") and s.endswith("/exe"): opens.append(s); return real_open(img, "rb")
            return real_open(path, *a, **k)
        stamp = {"mtime": 1}
        host._exe_stat = lambda pid: (img.stat().st_size, stamp["mtime"])
        with m.patch("builtins.open", fake_open):
            hs = [host._exe_hash(pid, "/usr/bin/tool", started) for pid, started in ((101, 1000), (102, 2000), (103, 3000))]
            self.assertEqual(len(opens), 1, "three processes of one binary: the image is read once")
            self.assertEqual(set(hs), {hashlib.sha256(img.read_bytes()).hexdigest()})
            stamp["mtime"] = 2; host._exe_hash(104, "/usr/bin/tool", 4000)
            self.assertEqual(len(opens), 2, "a replaced binary (new modification time) is read again")


class ManifestMatchesInstaller(unittest.TestCase):
    def test_the_manifests_name_what_the_installer_and_the_service_really_use(self):
        from halvard.install.manifest import INSTALL_MANIFEST, UPDATE_MANIFEST
        wxs = (ROOT / "native" / "installer" / "halvard.wxs").read_text(encoding="utf-8")
        svc = re.findall(r'<ServiceInstall[^>]*?\sName="([^"]+)"', wxs); ctl = re.findall(r'<ServiceControl[^>]*?\sName="([^"]+)"', wxs)
        service_rs = (ROOT / "native" / "halvard-svc" / "src" / "service.rs").read_text(encoding="utf-8")
        for man in (INSTALL_MANIFEST, UPDATE_MANIFEST):
            self.assertEqual(man["service_name"], "HalvardGuard")
            self.assertEqual({man["service_name"]}, set(svc) | set(ctl) if svc and ctl else {man["service_name"]}, "the installer and the manifest name one service")
            self.assertFalse(man["built"])
            built_from = wxs + service_rs + (ROOT / "tools" / "build_msi.ps1").read_text(encoding="utf-8")
            for name in man["files"]: self.assertIn(name, built_from, f"{name} is not something the installer lays down")
            for name in man.get("created_by_configure", []): self.assertIn(name, service_rs, f"the service never reads {name}")
        self.assertEqual(svc, ["HalvardGuard"]); self.assertEqual(ctl, ["HalvardGuard"])

    def test_no_msi_or_driver_is_tracked(self):
        import subprocess
        out = subprocess.run(["git", "ls-files", "*.msi", "*.sys", "*.cat", "*.inf"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        self.assertEqual(out, "")


if __name__ == "__main__":
    unittest.main()
