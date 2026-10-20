"""Privileged lane: runs the REAL fanotify sensor against REAL separate processes on a private tmpfs mount.
Skipped (loudly, in the summary) when not root or fanotify is unavailable."""
import hashlib, os, pathlib, signal, subprocess, sys, tempfile, time, unittest
if not sys.platform.startswith("linux"): raise unittest.SkipTest("the real fanotify sensor exists only on Linux")
from helpers import *
from halvard.clock import Clock
from halvard.platforms import linux
from halvard.ward import simulate as sim
from halvard.ward.agent import WardAgent
from halvard.ward.policy import PolicyBundle
from halvard.relay.actions import ActionRequest, Principal
from halvard.relay import forensics
from halvard.ledger.audit import AuditLog

SRC = str(pathlib.Path(__file__).resolve().parent.parent / "src")
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def digests(paths): return {p: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in paths if os.path.exists(p)}


@unittest.skipUnless(linux.available(), "needs root + fanotify (privileged lane)")
class LinuxSensorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.mnt = os.path.join(self.tmp, "mnt"); os.makedirs(self.mnt)
        subprocess.run(["mount", "-t", "tmpfs", "-o", "size=96m", "tmpfs", self.mnt], check=True)
        self.clock = Clock()
        self.host = linux.LinuxHost("LX-1", os.path.join(self.tmp, "host"))
        b = PolicyBundle(tenant="acme", version=1, platform="linux", accepted_patterns=["ransomware_stop", "malware_quarantine", "undo"]).sign(POLICY_KEY)
        self.agent = WardAgent("LX-1", os.path.join(self.tmp, "agent"), b, self.host, self.clock, DEV_KEY, UNINSTALL_KEY)
        self.sensor = None; self.children = []

    def tearDown(self):
        if self.sensor: self.sensor.stop()
        for c in self.children:
            try: c.kill(); c.wait(5)
            except Exception: pass
        os.chdir("/")
        if subprocess.run(["umount", self.mnt]).returncode: subprocess.run(["umount", "-l", self.mnt])

    def start(self, **kw):
        self.sensor = linux.FanotifySensor(self.agent, self.mnt, **kw).start(); return self.sensor

    def burst(self, style, pace_ms=5):
        root = os.path.join(self.mnt, "docs"); sim.authorize(root); paths = sim.seed_files(root, 40)
        orig = digests(paths); self.start()
        child = subprocess.Popen([sys.executable, "-m", "halvard.ward.simulate", root, style], env=dict(os.environ, PYTHONPATH=SRC, HALVARD_SIM_PACE_MS=str(pace_ms)),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE); self.children.append(child)
        try: child.wait(40)
        except subprocess.TimeoutExpired: self.fail("burst process was never stopped")
        self.sensor.drain(); time.sleep(0.3); self.sensor.drain()
        return root, paths, orig, child

    # ---- the real thing: acceptance 1 on Linux with real processes ----
    def test_real_process_burst_overwrite_rename_is_stopped_and_files_restored(self):
        root, paths, orig, child = self.burst("overwrite_rename")
        self.assertNotEqual(child.returncode, 0, "the burst finished unhindered")
        self.assertEqual(len(self.agent.incidents), 1, self.sensor.errors)
        self.assertIn(child.pid, self.agent.blocked)
        self.assertEqual(digests(paths), orig, "files must be byte-identical after rollback")
        self.assertEqual(list(pathlib.Path(root).rglob("*.locked")), [])
        self.assertEqual(self.sensor.errors, []); self.assertTrue(self.agent.spool.verify()[0])
        kinds = [r[0] for r in self.agent.incidents[0]["results"]]
        self.assertIn("stop_process", kinds); self.assertIn("journal_rollback", kinds)

    def test_burst_faster_than_detection_is_still_fully_restored(self):
        """Pace 0: the process can finish before the kernel events are even processed. Prevention loses the race;
        the journal still restores everything. This is the reason the journal exists independently of detection speed."""
        root, paths, orig, child = self.burst("overwrite_rename", pace_ms=0)
        self.assertEqual(len(self.agent.incidents), 1, self.sensor.errors)
        self.assertEqual(digests(paths), orig); self.assertEqual(list(pathlib.Path(root).rglob("*.locked")), [])

    def test_real_process_burst_copy_and_delete_is_stopped_and_files_restored(self):
        root, paths, orig, child = self.burst("copy_delete")
        self.assertNotEqual(child.returncode, 0)
        self.assertEqual(digests(paths), orig, f"missing/changed after rollback; errors={self.sensor.errors}")
        self.assertEqual(list(pathlib.Path(root).rglob("*.locked")), [])

    def test_blocked_process_is_denied_further_opens_by_the_kernel(self):
        root, paths, orig, child = self.burst("overwrite_rename")
        p2 = subprocess.run([sys.executable, "-c", "import os,sys;os.kill(os.getpid(),0)"], capture_output=True)   # unrelated process unaffected
        self.assertEqual(p2.returncode, 0)
        self.assertIn(child.returncode, (3, -signal.SIGKILL), "the process must have been denied by the kernel or killed")
        self.assertIn(child.pid, self.agent.blocked)

    def test_kernel_denies_every_open_by_a_frozen_process(self):
        """Direct proof of the freeze: mark a live process blocked and watch the kernel refuse its next write."""
        target = os.path.join(self.mnt, "precious.txt"); pathlib.Path(target).write_text("original", encoding="utf-8")
        self.start()
        child = subprocess.Popen([sys.executable, "-c", f"import sys; sys.stdin.readline(); open({target!r}, 'wb').write(b'overwritten')"],
                                 stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True); self.children.append(child)
        time.sleep(0.4); self.agent.blocked.add(child.pid)
        _, err = child.communicate("go\n", timeout=20)
        self.assertNotEqual(child.returncode, 0); self.assertIn("PermissionError", err)
        self.assertEqual(pathlib.Path(target).read_text(encoding="utf-8"), "original"); self.assertGreaterEqual(self.sensor.stats["denied"], 1)

    # ---- F006 on Linux: pre-execution verdict, kernel-enforced ----
    def test_known_bad_executable_is_denied_by_the_kernel_and_quarantined(self):
        bindir = os.path.join(self.mnt, "bin"); os.makedirs(bindir)
        bad, ok = os.path.join(bindir, "bad.sh"), os.path.join(bindir, "ok.sh")
        pathlib.Path(bad).write_bytes(b"#!/bin/sh\n" + EICAR + b"\necho pwned\n"); pathlib.Path(ok).write_bytes(b"#!/bin/sh\necho hello\n")
        os.chmod(bad, 0o755); os.chmod(ok, 0o755)
        self.agent.set_online(False); self.start()
        # Launch through /bin/sh: CPython's posix_spawn holds the GIL while the child's exec waits for the sensor's reply,
        # which would deadlock a sensor living in the same process. (The sensor never execs from its own mount.)
        run = lambda path: subprocess.run(["/bin/sh", "-c", '"$0"', path], capture_output=True, text=True, timeout=20)
        r = run(ok); self.assertEqual(r.stdout.strip(), "hello")
        r = run(bad); self.assertNotEqual(r.returncode, 0); self.assertNotIn("pwned", r.stdout)
        self.assertRegex(r.stderr, r"(?i)permission denied|not permitted")
        self.sensor.drain(); time.sleep(0.2)
        self.assertFalse(os.path.exists(bad), "known-bad file should have been quarantined")
        rec = next(e for e in self.agent.spool.entries() if e["kind"] == "ward.exec_verdict")
        self.assertEqual(rec["public"]["platform"], "linux"); self.assertIn("WARD.OFFLINE_PREVENTION", rec["controls"])

    # ---- F019 telemetry from the real sensor ----
    def test_exec_and_file_events_become_telemetry(self):
        bindir = os.path.join(self.mnt, "bin"); os.makedirs(bindir); ok = os.path.join(bindir, "tool.sh")
        pathlib.Path(ok).write_bytes(b"#!/bin/sh\necho 'work' > \"$1\"\n"); os.chmod(ok, 0o755)
        self.start(); out = os.path.join(self.mnt, "report.txt")
        subprocess.run(["/bin/sh", "-c", '"$0" "$1"', ok, out], check=True, timeout=20); self.sensor.drain(); time.sleep(0.3)
        evs = list(self.agent.outbox)
        self.assertTrue(any(e["kind"] == "process" and e["op"] == "exec" and e["path"].endswith("tool.sh") for e in evs), evs[-5:])
        self.assertTrue(any(e["kind"] == "file" and e["op"] == "create" and e["path"].endswith("report.txt") for e in evs))
        self.assertFalse(any("content" in e for e in evs))

    # ---- F026 on a real process ----
    def test_forensic_memory_collection_of_a_real_process_is_scoped_sealed_and_verifiable(self):
        child = subprocess.Popen([sys.executable, "-c", "m='HALVARD-MEM-MARKER-7Q'*50;import time;time.sleep(60)"]); self.children.append(child)
        time.sleep(0.5)
        eng = self.agent.engine; analyst, admin = Principal("u-an", "analyst"), Principal("u-ad", "it_admin")
        bad = eng.request(ActionRequest("collect_forensics", analyst, ["LX-1"], "suspect", "c9", {"profile": "memory", "pids": [child.pid]}))
        self.assertEqual(bad.status, "denied"); self.assertIn("personal_data_ack", bad.message)       # memory needs the acknowledgement
        r = eng.request(ActionRequest("collect_forensics", analyst, ["LX-1"], "suspect", "c9",
                                      {"profile": "memory", "pids": [child.pid], "personal_data_ack": True}))
        self.assertEqual(r.status, "pending_approval"); res = eng.approve(r.action_id, admin); self.assertEqual(res.status, "executed", res.message)
        d = pathlib.Path(res.detail["dir"]); self.assertIn(b"HALVARD-MEM-MARKER-7Q", (d / "memory" / f"{child.pid}.bin").read_bytes())
        self.assertEqual(forensics.verify_collection(d, self.agent.spool.seal_bytes), (True, []))
        (d / "triage.json").write_text("{}", encoding="utf-8"); ok, problems = forensics.verify_collection(d, self.agent.spool.seal_bytes)
        self.assertFalse(ok); self.assertTrue(any("triage.json" in p for p in problems))
        led = next(e for e in self.agent.spool.entries() if e["kind"] == "relay.action_executed" and e["public"].get("profile") == "memory")
        self.assertTrue(led["public"]["personal_data"]); self.assertNotIn("HALVARD-MEM-MARKER", str(led))      # contents never enter the ledger


class FanotifyRecordLength(unittest.TestCase):
    """Malformed lengths must stop the parser. These do not need root or a kernel mark."""

    def _sensor(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp)
        return linux.FanotifySensor(a, tmp)

    def test_a_zero_length_event_is_an_error_and_does_not_spin(self):
        import struct
        s = self._sensor()
        s._consume_perm(struct.pack("<IBBHQii", 0, 0, 0, 0, 0, -1, 0))
        self.assertEqual(s.stats["errors"], 1)
        self.assertIn("impossible length 0", s.errors[0])

    def test_a_short_info_record_is_an_error_and_does_not_spin(self):
        import struct
        s = self._sensor()
        info = struct.pack("<BBH", 2, 0, 0)
        elen = linux.HDR.size + len(info)
        buf = struct.pack("<IBBHQii", elen, 0, 0, linux.HDR.size, 0, -1, 1) + info
        s._consume_notify(buf)
        self.assertEqual(s.stats["errors"], 1)
        self.assertIn("info record with impossible length 0", s.errors[0])
        self.assertFalse(s._busy_notify)


if __name__ == "__main__":
    unittest.main()
