import os, unittest
from helpers import *
from rig7 import *
from halvard.ward import simulate as sim


def root_with_files(w, name="docs", n=16):
    root = os.path.join(w.tmp, name); sim.authorize(root); sim.seed_files(root, n=n); return root


def place(w, device, specs, actor=ADM, **kw):
    return w.cp.engine.request(ActionRequest("place_tripwires", actor, [device], "ransomware tripwires", None, {"specs": specs}, **kw))


def burst(w, root, pid=700, name="locker.exe"):
    w.host.spawn(pid, name, exe_sha256="cd" * 32); return sim.run_simulation(w.fs, pid, root)


class PlacementTests(unittest.TestCase):
    def test_tripwires_are_created_by_the_device_from_signed_policy_with_bland_filler_and_recorded(self):
        w = World7(); root = root_with_files(w); r = place(w, "LT-17", [{"id": "tw-a", "path": os.path.join(root, "!000-budget.xlsx"), "kind": "encryption"}, {"id": "tw-b", "path": os.path.join(root, "old-passwords.docx"), "kind": "decoy_file"}])
        self.assertEqual(r.status, "executed"); p = os.path.join(root, "!000-budget.xlsx"); data = open(p, "rb").read(); self.assertTrue(data.startswith(b"PK\x03\x04")); self.assertNotIn(b"halvard", data.lower()); self.assertNotIn(b"tripwire", data.lower())
        self.assertEqual(sorted(e["public"]["tripwire"] for e in w.agent.spool.entries() if e["kind"] == "ward.tripwire_placed"), ["tw-a", "tw-b"]); self.assertEqual(len(w.agent.tripwires), 2)
        self.assertTrue(any(e["kind"] == "relay.action_executed" and e["public"].get("tripwires") == 2 for e in w.cp.ledger.entries()))

    def test_a_tripwire_never_replaces_a_real_file_never_goes_in_system_folders_and_never_into_nowhere(self):
        w = World7(); root = root_with_files(w); real = os.path.join(root, "dept0", "file000.txt"); before = open(real, "rb").read()
        place(w, "LT-17", [{"id": "t1", "path": real, "kind": "encryption"}, {"id": "t2", "path": "/etc/halvard-no-such-dir/trap.conf", "kind": "decoy_file"}, {"id": "t3", "path": "relative/trap.txt", "kind": "decoy_file"}, {"id": "t4", "path": os.path.join(root, "nodir", "x.txt"), "kind": "decoy_file"}])
        self.assertEqual(open(real, "rb").read(), before); self.assertEqual(w.agent.tripwires, {}); self.assertFalse(os.path.exists("/etc/halvard-no-such-dir"))
        why = {e["public"]["tripwire"]: e["public"]["why"] for e in w.agent.spool.entries() if e["kind"] == "ward.tripwire_skipped"}
        self.assertIn("already exists", why["t1"]); self.assertIn("operating-system", why["t2"]); self.assertIn("not absolute", why["t3"]); self.assertIn("does not exist", why["t4"])

    def test_a_production_server_waits_for_an_approver_and_roles_are_enforced(self):
        w = World7(); d = os.path.join(w.tmp, "i-web-data"); os.makedirs(d)
        r = place(w, "i-web", [{"id": "s1", "path": os.path.join(d, "!000.xlsx"), "kind": "encryption"}]); self.assertEqual(r.status, "pending_approval"); self.assertEqual(len(w.web.tripwires), 0)
        self.assertEqual(w.cp.engine.approve(r.action_id, ADM2).status, "executed"); self.assertEqual(len(w.web.tripwires), 1)
        self.assertEqual(place(w, "LT-17", [{"id": "x", "path": os.path.join(d, "x.txt"), "kind": "decoy_file"}], actor=SD).status, "denied")

    def test_undo_removes_the_files_unless_someone_has_changed_them(self):
        w = World7(); root = root_with_files(w); r = place(w, "LT-17", [{"id": "u1", "path": os.path.join(root, "!a.xlsx"), "kind": "decoy_file"}, {"id": "u2", "path": os.path.join(root, "!b.xlsx"), "kind": "decoy_file"}])
        open(os.path.join(root, "!b.xlsx"), "ab").write(b"someone's edit")
        u = w.cp.engine.undo(r.action_id, ADM); self.assertEqual(u.status, "executed"); self.assertFalse(os.path.exists(os.path.join(root, "!a.xlsx"))); self.assertTrue(os.path.exists(os.path.join(root, "!b.xlsx")))
        self.assertEqual(w.agent.tripwires, {})

    def test_an_offline_device_gets_its_tripwires_when_it_returns(self):
        w = World7(); root = root_with_files(w); w.agent.set_online(False); r = place(w, "LT-17", [{"id": "o1", "path": os.path.join(root, "!o.xlsx"), "kind": "encryption"}])
        self.assertEqual(r.status, "executed"); self.assertFalse(os.path.exists(os.path.join(root, "!o.xlsx"))); w.cp.fleet.reconnect("LT-17"); self.assertTrue(os.path.exists(os.path.join(root, "!o.xlsx")))


class StopTests(unittest.TestCase):
    def test_changing_an_encryption_tripwire_stops_the_process_before_any_real_file_is_touched_and_it_works_offline(self):
        w = World7(); root = root_with_files(w, n=20); place(w, "LT-17", [{"id": "e1", "path": os.path.join(root, "!000-budget.xlsx"), "kind": "encryption"}]); w.agent.set_online(False)
        files = {str(p): open(p, "rb").read() for p in __import__("pathlib").Path(root).rglob("*") if p.is_file()}
        touched = burst(w, root); self.assertEqual(touched, 0)
        self.assertEqual({str(p): open(p, "rb").read() for p in __import__("pathlib").Path(root).rglob("*") if p.is_file()}, files)              # nothing changed, not even the tripwire
        self.assertIn(w.host.proc(700)["state"], ("suspended", "terminated"))
        h = w.agent.tripwire_hits[-1]; self.assertEqual((h["tripwire"], h["op"], h["stopped"], h["confidence"]), ("e1", "write", True, 0.9)); self.assertTrue(w.agent.incidents)

    def test_without_the_tripwire_the_same_burst_gets_through_several_files_first(self):
        w = World7(); root = root_with_files(w, n=20); self.assertEqual(burst(w, root), 7)

    def test_renaming_or_deleting_an_encryption_tripwire_stops_the_process_too(self):
        w = World7(); root = root_with_files(w); a, b = os.path.join(root, "!r.xlsx"), os.path.join(root, "!d.xlsx"); place(w, "LT-17", [{"id": "r", "path": a, "kind": "encryption"}, {"id": "d", "path": b, "kind": "encryption"}])
        w.host.spawn(710, "x.exe"); 
        from halvard.ward.agent import Blocked
        with self.assertRaises(Blocked): w.fs.rename(710, a, a + ".locked")
        self.assertTrue(os.path.exists(a)); w.host.spawn(711, "y.exe")
        with self.assertRaises(Blocked): w.fs.delete(711, b)
        self.assertTrue(os.path.exists(b)); self.assertEqual([h["op"] for h in w.agent.tripwire_hits if h["stopped"]], ["rename", "delete"])

    def test_a_tripwire_the_process_reaches_last_does_not_help_and_that_is_why_placement_matters(self):
        w = World7(); root = root_with_files(w, n=20); place(w, "LT-17", [{"id": "late", "path": os.path.join(root, "zzz-last.xlsx"), "kind": "encryption"}])
        self.assertEqual(burst(w, root), 7)             # Ward's own detector stops it after 7 files; the tripwire is never reached. Tripwires add early warning; they do not replace the detector.

    def test_readers_such_as_indexers_and_backups_do_not_stop_anything_and_exempt_programs_are_recorded(self):
        w = World7(); root = root_with_files(w); tw = os.path.join(root, "!idx.xlsx"); place(w, "LT-17", [{"id": "r1", "path": tw, "kind": "encryption"}])
        w.host.spawn(800, "indexer.exe"); w.fs.read(800, tw); self.assertEqual(w.host.proc(800)["state"], "running"); self.assertEqual(w.agent.tripwire_hits[-1]["confidence"], 0.3)
        with self.assertRaises(PermissionError): w.cp.hearth.exempt_process(AN, "LT-17", "backupd.exe", "nightly backup")
        w.cp.hearth.exempt_process(ADM, "LT-17", "backupd.exe", "nightly backup copies every file"); w.host.spawn(801, "backupd.exe")
        n = len(w.agent.tripwire_hits); w.fs.overwrite(801, tw, b"restored copy"); self.assertEqual(len(w.agent.tripwire_hits), n); self.assertEqual(w.host.proc(801)["state"], "running")
        self.assertTrue(any(e["kind"] == "ward.tripwire_exempt" for e in w.agent.spool.entries())); self.assertTrue(any(e["kind"] == "hearth.process_exempted" for e in w.cp.ledger.entries()))

    def test_in_audit_only_mode_it_alarms_and_blocks_nothing(self):
        import dataclasses
        w = World7(); root = root_with_files(w); tw = os.path.join(root, "!audit.xlsx"); place(w, "LT-17", [{"id": "a1", "path": tw, "kind": "encryption"}])
        b = dataclasses.replace(w.agent.bundle, version=w.agent.bundle.version + 1, prevention={"bulk_encryption": "audit", "known_bad": "enforce"}); self.assertTrue(w.agent.apply_bundle(b.sign(w.cp.fleet.key).__dict__.copy(), w.cp.fleet.key))
        w.host.spawn(900, "x.exe"); w.fs.overwrite(900, tw, b"changed"); self.assertFalse(w.agent.tripwire_hits[-1]["stopped"]); self.assertEqual(open(tw, "rb").read(), b"changed")

    def test_a_tripwire_removed_or_changed_behind_the_hook_is_noticed_once(self):
        w = World7(); root = root_with_files(w); a, b = os.path.join(root, "!a.xlsx"), os.path.join(root, "!b.xlsx")
        place(w, "LT-17", [{"id": "v1", "path": a, "kind": "decoy_file"}, {"id": "v2", "path": b, "kind": "decoy_file"}]); self.assertEqual(w.agent.verify_tripwires(), [])
        os.remove(a); open(b, "ab").write(b"x"); ops = sorted(h["op"] for h in w.agent.verify_tripwires()); self.assertEqual(ops, ["changed", "removed"]); self.assertEqual(w.agent.verify_tripwires(), [])

    def test_a_decoy_file_that_is_opened_raises_a_finding_but_does_not_freeze_the_process(self):
        w = World7(); root = root_with_files(w); tw = os.path.join(root, "passwords-old.docx"); place(w, "LT-17", [{"id": "d1", "path": tw, "kind": "decoy_file"}])
        w.host.spawn(950, "explorer.exe"); w.fs.read(950, tw); self.assertEqual(w.host.proc(950)["state"], "running"); fs = w.cp.hearth.poll()
        self.assertEqual([(f.family, f.confidence, f.entity_id, f.details["op"]) for f in fs], [("tripwire", 0.9, "LT-17", "read")])


class CaseTests(unittest.TestCase):
    def test_a_stopped_burst_becomes_a_case_that_says_it_was_stopped_before_real_files_were_touched(self):
        w = World7(); root = root_with_files(w); place(w, "LT-17", [{"id": "c1", "path": os.path.join(root, "!c.xlsx"), "kind": "encryption"}]); burst(w, root); w.cp.process()
        c = next(c for c in w.cp.cases.cases.values() if any(f.source == "hearth" for f in c.findings)); page = w.cp.cases.page(c)
        self.assertIn("stopped before real files were touched", page); self.assertEqual(c.status, "contained"); self.assertTrue(any(a[1] == "stopped the program" for a in c.actions)); self.assertIn("[tripwire]", page); self.assertEqual(next(f for f in c.findings if f.source == "hearth").technique, "T1486")


if __name__ == "__main__":
    unittest.main()
