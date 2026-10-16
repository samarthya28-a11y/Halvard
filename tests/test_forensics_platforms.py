import hashlib, json, os, pathlib, tempfile, unittest
from helpers import *
from halvard.relay.actions import ActionRequest, Principal
from halvard.relay import forensics, isolation
from halvard.platforms import PROFILES, MACOS, LINUX, WINDOWS
from halvard.ward.agent import WardAgent, ProtectedFS
from halvard.ward.policy import PolicyBundle
from halvard.relay.host import SimHost
from halvard.ward import simulate as sim

AN, ADM = Principal("u-an", "analyst"), Principal("u-adm", "it_admin")


class ForensicTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.a, self.host, self.clock, self.fs = make_agent(self.tmp); self.e = self.a.engine
        self.host.spawn(5, "dropper.exe", cmdline="dropper.exe --x", exe_sha256="ab" * 32); self.host.persistence["run:evil"] = "C:/x/dropper.exe"
        self.host.connections.append({"pid": 5, "dst_ip": "203.0.113.9", "dst_port": 443, "state": "ESTABLISHED"}); self.host.memory[5] = b"MEMORY-MARKER" * 100
        self.f = os.path.join(self.tmp, "evidence.doc"); pathlib.Path(self.f).write_bytes(b"customer data")

    def ask(self, **params): return self.e.request(ActionRequest("collect_forensics", AN, ["LT-17"], "suspected dropper", "case-1", params))

    def collect(self, **params):
        r = self.ask(**params); self.assertEqual(r.status, "pending_approval", r.message); res = self.e.approve(r.action_id, ADM); self.assertEqual(res.status, "executed", res.message); return res

    def test_always_needs_an_approver_and_triage_is_metadata_only(self):
        r = self.ask(profile="triage"); self.assertEqual(r.status, "pending_approval"); self.assertFalse(r.preview["personal_data"])
        res = self.e.approve(r.action_id, ADM); d = pathlib.Path(res.detail["dir"])
        self.assertEqual(sorted(p.name for p in d.iterdir()), ["manifest.json", "triage.json"])
        t = json.loads((d / "triage.json").read_text(encoding="utf-8")); self.assertEqual(t["connections"][0]["dst_ip"], "203.0.113.9"); self.assertIn("run:evil", t["persistence"])
        self.assertNotIn("customer data", (d / "triage.json").read_text(encoding="utf-8"))

    def test_files_profile_copies_only_named_paths_and_flags_personal_data(self):
        r = self.ask(profile="files", paths=[self.f, "/no/such/file"]); self.assertTrue(r.preview["personal_data"]); self.assertIn("personal", r.preview["summary"])
        res = self.e.approve(r.action_id, ADM); m = res.detail["manifest"]
        self.assertEqual([i["name"] for i in m["items"] if i["kind"] == "file"], [self.f]); self.assertEqual(m["skipped"], [("/no/such/file", "not found")])
        self.assertEqual(m["items"][-1]["sha256"], hashlib.sha256(b"customer data").hexdigest()); self.assertTrue(m["personal_data"])

    def test_memory_needs_acknowledgement_and_named_pids(self):
        self.assertEqual(self.ask(profile="memory", pids=[5]).status, "denied")
        self.assertEqual(self.ask(profile="memory", personal_data_ack=True).status, "denied")
        self.assertEqual(self.ask(profile="nonsense").status, "denied")
        res = self.collect(profile="memory", pids=[5, 99], personal_data_ack=True); m = res.detail["manifest"]
        self.assertEqual([i["name"] for i in m["items"] if i["kind"] == "memory"], ["pid 5"]); self.assertEqual(len(m["skipped"]), 1)

    def test_manifest_is_sealed_and_tamper_evident(self):
        res = self.collect(profile="files", paths=[self.f]); d = pathlib.Path(res.detail["dir"]); seal = self.a.spool.seal_bytes
        self.assertEqual(forensics.verify_collection(d, seal), (True, []))
        (d / "files" / "0000").write_bytes(b"planted"); ok, p = forensics.verify_collection(d, seal); self.assertFalse(ok); self.assertIn("files/0000 changed", p[0])
        (d / "files" / "0000").write_bytes(b"customer data")
        doc = json.loads((d / "manifest.json").read_text(encoding="utf-8")); doc["manifest"]["reason"] = "edited"; (d / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
        self.assertIn("manifest seal invalid", forensics.verify_collection(d, seal)[1])

    def test_ledger_records_counts_and_hashes_never_contents_or_paths_in_public(self):
        self.collect(profile="files", paths=[self.f])
        rec = [x for x in self.a.spool.entries() if x["kind"] == "relay.action_executed" and x["public"].get("profile") == "files"][0]
        for k in ("items", "skipped", "manifest_sha256", "personal_data", "retention_days"): self.assertIn(k, rec["public"])
        self.assertNotIn("customer data", json.dumps(rec)); self.assertNotIn(self.f, json.dumps(rec["public"]))

    def test_role_rules(self):
        r = self.e.request(ActionRequest("collect_forensics", Principal("u-sd", "service_desk"), ["LT-17"], "x", "c", {"profile": "triage"})); self.assertEqual(r.status, "denied")
        r = self.ask(profile="triage"); self.assertEqual(self.e.approve(r.action_id, AN).status, "denied")          # requester cannot approve
        self.assertEqual(self.e.approve(r.action_id, Principal("u-owner", "owner")).status, "denied")

    def test_collection_can_be_deleted_unless_under_legal_hold(self):
        res = self.collect(profile="triage"); d = res.detail["dir"]
        self.assertEqual(self.e.undo(res.action_id, ADM).status, "executed"); self.assertFalse(os.path.exists(d))
        res2 = self.collect(profile="triage"); self.e.request(ActionRequest("legal_hold", ADM, ["LT-17"], "litigation", "case-1"))
        with self.assertRaises(PermissionError): self.e.undo(res2.action_id, ADM)
        self.assertTrue(os.path.exists(res2.detail["dir"]))


class PlatformTests(unittest.TestCase):
    def test_profiles_exist_with_honest_sensor_status(self):
        self.assertEqual(set(PROFILES), {"windows", "macos", "linux"})
        self.assertIn("not in this repository", WINDOWS.sensor); self.assertIn("not in this repository", MACOS.sensor); self.assertNotIn("not in this repository", LINUX.sensor)

    def test_path_identity_follows_the_filesystem(self):
        self.assertEqual(MACOS.path_key("/Users/A/Docs/Résumé.PDF"), MACOS.path_key("/users/a/docs/Re\u0301sume\u0301.pdf"))      # case + NFC/NFD
        self.assertEqual(WINDOWS.path_key("C:\\Users\\A\\x.TXT"), WINDOWS.path_key("c:/users/a/x.txt"))
        self.assertNotEqual(LINUX.path_key("/home/a/File"), LINUX.path_key("/home/a/file"))

    def test_agent_uses_the_platform_exclusion_list_unless_overridden(self):
        for plat, noisy, doc in (("macos", "/Users/a/Library/Caches/x/db", "/Users/a/Documents/plan.docx"), ("linux", "/home/a/.cache/x/db", "/home/a/Documents/plan.odt")):
            tmp = tempfile.mkdtemp(); clock = ManualClock(); host = SimHost("H", tmp + "/h")
            b = PolicyBundle(tenant="t", version=1, platform=plat).sign(POLICY_KEY)
            a = WardAgent("H", tmp + "/a", b, host, clock, DEV_KEY, UNINSTALL_KEY); fs = ProtectedFS(a)
            self.assertTrue(fs._excluded(noisy), plat); self.assertFalse(fs._excluded(doc), plat)
        b = PolicyBundle(tenant="t", version=1, platform="linux", journal_exclude=[]).sign(POLICY_KEY)
        a = WardAgent("H", tempfile.mkdtemp(), b, SimHost("H", tempfile.mkdtemp()), ManualClock(), DEV_KEY, UNINSTALL_KEY)
        self.assertFalse(ProtectedFS(a)._excluded("/home/a/.cache/x"))

    def test_case_insensitive_volumes_share_one_journal_rate_limit_key(self):
        tmp = tempfile.mkdtemp(); clock = ManualClock(); host = SimHost("H", tmp + "/h")
        a = WardAgent("H", tmp + "/a", PolicyBundle(tenant="t", version=1, platform="macos").sign(POLICY_KEY), host, clock, DEV_KEY, UNINSTALL_KEY)
        p = os.path.join(tmp, "Doc.TXT"); pathlib.Path(p).write_text("v1", encoding="utf-8")
        a.journal.before(1, "write", p); self.assertTrue(a.journal.recently_captured(1, p.lower()))

    def test_every_platform_renders_default_deny_with_only_the_management_path(self):
        for prof in PROFILES.values():
            text = "\n".join(prof.render_isolation(["203.0.113.10"], "10.0.0.2")); self.assertIn("203.0.113.10", text)
            self.assertTrue(any(w in text.lower() for w in ("block", "policy drop")), prof.name)
            self.assertNotIn("0.0.0.0/0", text); self.assertTrue(prof.render_release())
        pf = MACOS.render_isolation(["203.0.113.10"])[0]
        self.assertIn("block drop all", pf); self.assertIn("pass out quick proto tcp to 203.0.113.10 port 443", pf); self.assertIn("pfctl -a halvard/isolate", isolation.macos_release()[0])

    def test_same_core_stops_and_restores_on_each_platform_profile(self):
        for plat in ("windows", "macos", "linux"):
            tmp = tempfile.mkdtemp(); clock = ManualClock(); host = SimHost("H", tmp + "/h")
            b = PolicyBundle(tenant="t", version=1, platform=plat, accepted_patterns=["ransomware_stop"]).sign(POLICY_KEY)
            a = WardAgent("H", tmp + "/a", b, host, clock, DEV_KEY, UNINSTALL_KEY); fs = ProtectedFS(a)
            root = os.path.join(tmp, "Docs"); sim.authorize(root); paths = sim.seed_files(root, 30); orig = {p: pathlib.Path(p).read_bytes() for p in paths}
            host.spawn(3, "x"); sim.run_simulation(fs, 3, root)
            self.assertEqual({p: pathlib.Path(p).read_bytes() for p in paths}, orig, plat); self.assertIn(3, a.blocked)


if __name__ == "__main__":
    unittest.main()
