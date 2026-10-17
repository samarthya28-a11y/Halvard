"""M0 of the Windows client: the sensor interface fixtures replay to the expected decisions, and the budget checker works."""
import hashlib, json, os, tempfile, unittest
from pathlib import Path
from helpers import *
from halvard import sensor
from halvard.paths import policy_dir

FIX = Path(__file__).resolve().parent / "fixtures" / "sensor"


def digests(root): return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(root).rglob("*") if p.is_file()}


class ReplayTests(unittest.TestCase):
    def run_fixture(self, name):
        header, events = sensor.load(FIX / f"{name}.jsonl")
        tmp = tempfile.mkdtemp(); root = os.path.join(tmp, "work"); os.makedirs(root)
        specs = sensor.tripwire_specs(root, header)
        a, host, clock, fs = make_agent(tmp, **({"tripwires": specs} if specs else {}))
        a.set_online(not header.get("offline", False))
        for pid, n in header["processes"].items(): host.spawn(int(pid), n)
        seeded = sensor.seed(root, header)
        if specs: a._place_tripwires()
        res = sensor.replay(fs, events, root)
        return header, events, res, a, root, seeded

    def check(self, name):
        header, events, res, a, root, seeded = self.run_fixture(name); ex = header["expect"]
        self.assertEqual(sorted(a.blocked), sorted(ex["deny_pids"]), name)
        if ex.get("all_allowed"): self.assertTrue(all(d == "allow" for _, d in res), name)
        if "first_deny_seq" in ex: self.assertEqual(next(s for s, d in res if d == "deny"), ex["first_deny_seq"], name)
        if "max_allowed_changes" in ex:
            by_seq = {e["seq"]: e for e in events}
            changes = [s for s, d in res if d == "allow" and by_seq[s]["op"] in ("write", "rename", "delete", "create")]
            self.assertLessEqual(len(changes), ex["max_allowed_changes"], name)
        if ex.get("files_restored"):
            now = digests(root)
            for p, h in seeded.items(): self.assertEqual(now.get(p), h, f"{name}: {p} not restored")
        if ex.get("no_locked_files"): self.assertFalse(list(Path(root).rglob("*.locked")), name)
        return res

    def test_ransomware_overwrite_rename_is_stopped_and_restored(self): self.check("ransomware_overwrite_rename")
    def test_tripwire_first_touch_stops_before_any_real_file_changes(self): self.check("tripwire_first_touch")
    def test_office_session_is_never_blocked(self): self.check("benign_office_session")
    def test_compressor_is_never_blocked(self): self.check("benign_compressor")

    def test_replay_is_deterministic(self):
        a = self.run_fixture("ransomware_overwrite_rename")[2]; b = self.run_fixture("ransomware_overwrite_rename")[2]
        self.assertEqual(a, b)

    def test_every_fixture_in_the_folder_is_covered_and_valid(self):
        names = sorted(p.stem for p in FIX.glob("*.jsonl"))
        self.assertEqual(names, ["benign_compressor", "benign_office_session", "ransomware_overwrite_rename", "tripwire_first_touch"])
        for n in names: sensor.load(FIX / f"{n}.jsonl")

    def test_unknown_op_or_version_is_refused(self):
        d = tempfile.mkdtemp(); p = Path(d, "x.jsonl")
        p.write_text(json.dumps({"fixture": 2}) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError): sensor.load(p)
        p.write_text(json.dumps({"fixture": 1}) + "\n" + json.dumps({"seq": 1, "op": "chmod", "pid": 1, "path": "a"}) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError): sensor.load(p)


class BudgetTests(unittest.TestCase):
    B = json.loads((policy_dir() / "perf_budget.json").read_text(encoding="utf-8"))["windows_native_service"]
    GOOD = {"idle_cpu_percent_of_one_core": 0.2, "memory_mb": 18, "added_latency_p50_microseconds": 300, "added_latency_p99_microseconds": 2500, "install_footprint_mb": 9}

    def test_a_report_inside_the_budget_passes(self): self.assertEqual(sensor.check_budget(self.GOOD, self.B), [])

    def test_each_breach_is_named(self):
        bad = dict(self.GOOD, memory_mb=80, added_latency_p99_microseconds=9000)
        self.assertEqual(len(sensor.check_budget(bad, self.B)), 2)

    def test_an_unmeasured_item_is_a_breach_not_a_pass(self):
        r = dict(self.GOOD); del r["memory_mb"]
        self.assertEqual(sensor.check_budget(r, self.B), ["memory_mb: not measured"])

    def test_native_budget_is_tighter_than_the_reference_budget(self):
        ref = json.loads((policy_dir() / "perf_budget.json").read_text(encoding="utf-8"))
        self.assertLess(self.B["memory_mb_max"], ref["memory_mb_max"]); self.assertLess(self.B["added_latency_p99_microseconds_max"], ref["added_latency_p99_microseconds_max"])


if __name__ == "__main__":
    unittest.main()
