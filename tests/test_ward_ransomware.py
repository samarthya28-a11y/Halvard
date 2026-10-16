import hashlib, os, tempfile, unittest, pathlib
from helpers import *
from halvard.ward import simulate as sim
from halvard.ward.agent import Blocked
from halvard.relay.actions import Principal
from halvard.ledger.audit import AuditLog


def digests(paths): return {p: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in paths if os.path.exists(p)}


class RansomwareTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = os.path.join(self.tmp, "docs"); sim.authorize(self.root)
        self.paths = sim.seed_files(self.root, 60); self.orig = digests(self.paths)

    def restored(self): return sum(1 for p, d in self.orig.items() if digests([p]).get(p) == d)

    # ---- acceptance: offline burst is stopped and the journal restores the files ----
    def test_offline_burst_overwrite_rename_is_stopped_and_restored(self):
        a, host, clock, fs = make_agent(self.tmp); a.set_online(False)
        host.spawn(4242, "burst.exe")
        touched = sim.run_simulation(fs, 4242, self.root, "overwrite_rename")
        self.assertLessEqual(touched, 10, "should be stopped after a handful of files, not 60")
        self.assertIn(4242, a.blocked); self.assertEqual(host.proc(4242)["state"], "terminated")
        self.assertEqual(self.restored(), len(self.orig))
        self.assertFalse([f for f in pathlib.Path(self.root).rglob("*.locked")])
        with self.assertRaises(Blocked): fs.overwrite(4242, self.paths[-1], b"more")      # still frozen out of the filesystem

    def test_offline_burst_copy_and_delete_style_is_stopped_and_restored(self):
        a, host, clock, fs = make_agent(self.tmp); a.set_online(False); host.spawn(5, "burst2.exe")
        sim.run_simulation(fs, 5, self.root, "copy_delete")
        self.assertIn(5, a.blocked); self.assertEqual(self.restored(), len(self.orig))
        self.assertFalse([f for f in pathlib.Path(self.root).rglob("*.locked")])

    def test_offline_decisions_are_in_the_spool_and_reach_ledger_after_reconnect(self):
        a, host, clock, fs = make_agent(self.tmp); a.set_online(False); host.spawn(7, "burst.exe")
        sim.run_simulation(fs, 7, self.root)
        self.assertEqual(a.sync(None), None)        # offline: nothing forwarded
        kinds = [e["kind"] for e in a.spool.entries()]
        self.assertIn("ward.bulk_encryption_detected", kinds); self.assertIn("relay.action_executed", kinds)
        det = next(e for e in a.spool.entries() if e["kind"] == "ward.bulk_encryption_detected")
        self.assertIn("WARD.OFFLINE_PREVENTION", det["controls"]); self.assertFalse(det["public"]["online"])
        tenant = AuditLog(os.path.join(self.tmp, "tenant.log"), "acme", b"t" * 32, clock)
        a.set_online(True); r = a.sync(tenant)
        self.assertEqual(r["kind"], "ledger.spool_ingested"); self.assertTrue(tenant.verify()[0])
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "tenant.log").replace("tenant.log", "segments/LT-17.jsonl")))

    def test_tampered_spool_is_rejected_at_ingest(self):
        a, host, clock, fs = make_agent(self.tmp); host.spawn(7, "burst.exe"); sim.run_simulation(fs, 7, self.root)
        lines = pathlib.Path(a.spool.path).read_text().splitlines(); pathlib.Path(a.spool.path).write_text("\n".join(lines[1:]) + "\n")
        tenant = AuditLog(os.path.join(self.tmp, "tenant.log"), "acme", b"t" * 32, clock)
        self.assertEqual(a.sync(tenant)["kind"], "ledger.spool_rejected")

    # ---- the detector must not stop honest bulk work ----
    def test_legitimate_bulk_work_is_not_stopped(self):
        a, host, clock, fs = make_agent(self.tmp); host.spawn(11, "7z.exe")
        for i, p in enumerate(self.paths):                       # compressor: reads many, creates NEW archives
            fs.read(11, p); fs.create(11, p + ".zip.part", os.urandom(2000)); fs.rename(11, p + ".zip.part", p + ".zip")
        for i in range(30):                                      # photo batch export: overwrites but keeps JPEG signature
            q = os.path.join(self.root, f"p{i}.jpg"); fs.create(11, q, b"\xff\xd8\xff" + os.urandom(1000))
            fs.overwrite(11, q, b"\xff\xd8\xff" + os.urandom(1200))
        for p in self.paths[:20]:                                # mass edit of text keeps text
            if p.endswith(".txt"): fs.overwrite(11, p, b"edited line\n" * 100)
        self.assertEqual(a.incidents, []); self.assertNotIn(11, a.blocked)

    def test_slow_trickle_is_not_a_burst(self):
        a, host, clock, fs = make_agent(self.tmp); host.spawn(12, "odd.exe")
        for p in self.paths[:12]:
            fs.overwrite(12, p, os.urandom(1500)); clock.advance(20)
        self.assertEqual(a.incidents, [])        # 1 file per 20s never reaches 8 files / 30s (documented limit; see threat model)

    # ---- prevention mode and asset class ----
    def test_audit_only_mode_logs_but_does_not_block(self):
        a, host, clock, fs = make_agent(self.tmp, prevention={"bulk_encryption": "audit_only", "known_bad": "enforce"})
        host.spawn(20, "burst.exe"); sim.run_simulation(fs, 20, self.root)
        self.assertEqual(len(a.incidents), 1); self.assertNotIn(20, a.blocked); self.assertIn("Audit-only", a.incidents[0]["note"])

    def test_production_server_freezes_io_immediately_but_waits_for_approver_to_terminate(self):
        a, host, clock, fs = make_agent(self.tmp, asset_class="production"); host.spawn(30, "burst.exe")
        sim.run_simulation(fs, 30, self.root)
        self.assertIn(30, a.blocked); self.assertEqual(host.proc(30)["state"], "suspended")      # damage stopped
        self.assertTrue(all(r[1] == "pending_approval" for r in a.incidents[0]["results"] if r[0] != "isolate_host"))
        self.assertLess(self.restored(), len(self.orig))                                         # cleanup waits for a human
        admin = Principal("u-admin", "it_admin"); analyst = Principal("u-an", "analyst")
        for r in a.incidents[0]["results"]:
            res = a.engine.approve(r[3], admin)
            self.assertEqual(res.status, "executed", res.message)
        self.assertEqual(self.restored(), len(self.orig))

    def test_clinical_device_needs_two_different_people(self):
        a, host, clock, fs = make_agent(self.tmp, asset_class="clinical"); host.spawn(31, "burst.exe")
        sim.run_simulation(fs, 31, self.root)
        stop = next(r for r in a.incidents[0]["results"] if r[0] == "stop_process")
        self.assertEqual(a.engine.approve(stop[3], Principal("u1", "it_admin")).status, "pending_approval")
        self.assertEqual(a.engine.approve(stop[3], Principal("u1", "it_admin")).status, "denied")     # same person twice
        self.assertEqual(a.engine.approve(stop[3], Principal("u2", "analyst")).status, "executed")

    def test_unaccepted_pattern_prepares_but_does_not_run(self):
        a, host, clock, fs = make_agent(self.tmp, accepted=()); host.spawn(40, "burst.exe")
        sim.run_simulation(fs, 40, self.root)
        self.assertIn(40, a.blocked)                                                    # prevention still froze it
        self.assertEqual({r[1] for r in a.incidents[0]["results"]}, {"pending_pattern_acceptance"})
        self.assertNotEqual(host.proc(40)["state"], "terminated")

    # ---- journal honesty ----
    def test_file_changed_after_incident_is_left_alone_and_reported(self):
        a, host, clock, fs = make_agent(self.tmp, accepted=()); host.spawn(50, "burst.exe")
        sim.run_simulation(fs, 50, self.root)
        victim = next(str(p) for p in pathlib.Path(self.root).rglob("*.locked"))
        pathlib.Path(victim).write_bytes(b"user fixed this by hand")
        rep = a.journal.rollback([50])
        self.assertIn(victim, rep.skipped_changed_after); self.assertEqual(pathlib.Path(victim).read_bytes(), b"user fixed this by hand")
        self.assertFalse(rep.complete)

    def test_quota_exhaustion_is_reported_as_not_restorable(self):
        a, host, clock, fs = make_agent(self.tmp, journal_quota_mb=0); host.spawn(60, "burst.exe")
        sim.run_simulation(fs, 60, self.root)
        rep = a.journal.rollback([60], dry_run=True)
        self.assertTrue(rep.not_restorable); self.assertIn("quota", rep.not_restorable[0][1]); self.assertFalse(rep.complete)

    def test_rollback_can_be_undone(self):
        a, host, clock, fs = make_agent(self.tmp); host.spawn(70, "burst.exe"); sim.run_simulation(fs, 70, self.root)
        rb = next(r for r in a.incidents[0]["results"] if r[0] == "journal_rollback")
        res = a.engine.undo(rb[3], Principal("u-admin", "it_admin"))
        self.assertEqual(res.status, "executed", res.message)
        self.assertLess(self.restored(), len(self.orig))    # files are back to their post-incident (scrambled) state
        self.assertTrue(res.preview is not None)

    # ---- safety rails on the simulator itself ----
    def test_simulation_refuses_unauthorized_directory(self):
        a, host, clock, fs = make_agent(self.tmp); other = os.path.join(self.tmp, "real-docs"); os.makedirs(other)
        pathlib.Path(other, "keep.txt").write_text("precious")
        with self.assertRaises(sim.SimulationNotAuthorized): sim.run_simulation(fs, 1, other)
        self.assertEqual(pathlib.Path(other, "keep.txt").read_text(), "precious")


if __name__ == "__main__":
    unittest.main()
