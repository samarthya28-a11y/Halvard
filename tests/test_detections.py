import json, os, tempfile, unittest, copy
from helpers import *
from halvard.detect.library import DetectionLibrary, RuleError, Runtime, verify_pack, PackError, ATTACK, MAX_EXPIRY_DAYS
from halvard.detect.learning import LearningStore, LearningError, DeviceMatcher
from halvard.hunt.events import EventStore
from halvard.ledger.audit import AuditLog
from halvard.relay.actions import Principal
from halvard.tenancy import TenantStore, TenantContext

DAY = 86400
AUTHOR, REVIEWER, DESK = Principal("u-author", "analyst"), Principal("u-rev", "analyst"), Principal("u-desk", "service_desk")
KEY = b"content-key" * 3

SPEC = dict(name="Encoded PowerShell", description="PowerShell with an encoded command", query='kind=process AND proc~"powershell*" AND cmdline contains "-enc"',
            techniques=["T1059.001"], severity="high", confidence=0.7,
            tests={"positive": [dict(kind="process", proc="powershell.exe", cmdline="powershell -enc AAA")],
                   "negative": [dict(kind="process", proc="powershell.exe", cmdline="powershell Get-Date")]})


def lib(clock=None):
    clock = clock or ManualClock(); tmp = tempfile.mkdtemp()
    audit = AuditLog(os.path.join(tmp, "a.log"), "acme", b"k" * 32, clock)
    return DetectionLibrary(clock, audit), clock, audit


def spec(clock, **kw): return {**copy.deepcopy(SPEC), "expires_at": clock.now() + 90 * DAY, **kw}


class GovernanceTests(unittest.TestCase):
    def test_full_lifecycle_needs_tests_and_a_different_reviewer(self):
        L, clock, audit = lib(); r = L.create(AUTHOR, spec(clock))
        self.assertEqual(r.status, "draft"); self.assertTrue(L.submit(r, AUTHOR)["ok"]); self.assertEqual(r.status, "in_review")
        with self.assertRaises(PermissionError): L.approve(r, AUTHOR)                       # no self-approval
        with self.assertRaises(PermissionError): L.approve(r, DESK)                         # wrong role
        L.approve(r, REVIEWER, "looks right"); self.assertEqual((r.status, r.reviewer), ("active", "u-rev"))
        kinds = [e["kind"] for e in audit.entries()]; self.assertEqual(kinds, ["detect.rule_created", "detect.rule_submitted", "detect.rule_approved"])

    def test_cannot_ship_without_working_examples(self):
        L, clock, _ = lib()
        r = L.create(AUTHOR, spec(clock, tests={"positive": [], "negative": []})); res = L.submit(r, AUTHOR)
        self.assertFalse(res["ok"]); self.assertIn("positive and one negative", res["failures"][0]); self.assertEqual(r.status, "draft")
        r = L.create(AUTHOR, spec(clock, tests={"positive": [dict(kind="process", proc="cmd.exe")], "negative": [dict(kind="process", proc="powershell.exe", cmdline="x -enc y")]}))
        f = L.submit(r, AUTHOR)["failures"]; self.assertTrue(any("positive example 0 does not match" in x for x in f)); self.assertTrue(any("negative example 0 matches" in x for x in f))

    def test_every_rule_expires_and_expiry_is_bounded(self):
        L, clock, audit = lib()
        with self.assertRaises(RuleError): L.create(AUTHOR, spec(clock, expires_at=clock.now() + (MAX_EXPIRY_DAYS + 1) * DAY))
        with self.assertRaises(RuleError): L.create(AUTHOR, spec(clock, expires_at=clock.now() - 1))
        r = L.create(AUTHOR, spec(clock, expires_at=clock.now() + 10 * DAY)); L.submit(r, AUTHOR); L.approve(r, REVIEWER)
        clock.advance(11 * DAY); self.assertEqual(L.sweep(), [r.id]); self.assertEqual(r.status, "expired"); self.assertIsNone(L.active(r.id))
        with self.assertRaises(RuleError): L.rollback(r.id, 1, REVIEWER)                         # cannot resurrect an expired version
        self.assertTrue(any(e["kind"] == "detect.rule_expired" for e in audit.entries()))

    def test_validation(self):
        L, clock, _ = lib()
        for bad in (dict(techniques=["T9999"]), dict(techniques=[]), dict(severity="catastrophic"), dict(query="kind=process | count"), dict(query=""),
                    dict(query="nonsense=1"), dict(threshold=dict(count=1, window_s=5, by="device"))):
            with self.assertRaises((RuleError, Exception), msg=str(bad)): L.create(AUTHOR, spec(clock, **bad))
        with self.assertRaises(PermissionError): L.create(DESK, spec(clock))

    def test_attack_tags_are_validated_against_a_bundled_subset_that_says_so(self):
        self.assertIn("T1486", ATTACK["techniques"]); self.assertIn("subset", ATTACK["source"].lower()); self.assertIsNone(ATTACK["synced_with_upstream"])
        self.assertTrue(all(len(k) in (5, 9) and k[0] == "T" for k in ATTACK["techniques"]))

    def test_new_version_needs_new_review_and_old_stays_active_until_then(self):
        L, clock, _ = lib(); r1 = L.create(AUTHOR, spec(clock)); L.submit(r1, AUTHOR); L.approve(r1, REVIEWER)
        r2 = L.create(AUTHOR, spec(clock, severity="critical"), rid=r1.id); self.assertEqual(r2.version, 2)
        self.assertEqual(L.active(r1.id).version, 1); L.submit(r2, AUTHOR); L.approve(r2, REVIEWER)
        self.assertEqual(L.active(r1.id).version, 2); self.assertEqual(r1.status, "retired")
        L.rollback(r1.id, 1, REVIEWER); self.assertEqual(L.active(r1.id).version, 1)

    def test_noisy_rule_is_stopped_by_backtest(self):
        L, clock, _ = lib(); tmp = TenantStore(); tmp.create_tenant("acme", "A"); ctx = TenantContext("acme", "u", "analyst")
        ev = EventStore(tmp, clock=clock); L.events = ev
        ev.add(ctx, [dict(kind="process", op="exec", proc="powershell.exe", cmdline="x -enc y", device="d", ts=clock.now() - 3600 - i) for i in range(700)])
        r = L.create(AUTHOR, spec(clock, max_hits_per_day=50)); res = L.submit(r, AUTHOR, ctx)
        self.assertFalse(res["ok"]); self.assertIn("too noisy", res["failures"][0]); self.assertEqual(res["backtest"]["matches"], 700)

    def test_threshold_rule_counts_within_window_per_key(self):
        L, clock, _ = lib(); r = L.create(AUTHOR, spec(clock, query='kind=net AND dst_port=22', threshold=dict(count=3, window_s=60, by="device"),
                                                       tests={"positive": [dict(kind="net", dst_port=22)], "negative": [dict(kind="net", dst_port=443)]}, techniques=["T1110"]))
        L.submit(r, AUTHOR); L.approve(r, REVIEWER); rt = Runtime(clock); rt.load(L.build_pack(KEY))
        ev = lambda d: dict(kind="net", dst_port=22, device=d)
        self.assertEqual([len(rt.on_event(ev("A"))) for _ in range(3)], [0, 0, 1])
        self.assertEqual(len(rt.on_event(ev("B"))), 0)                                           # different key, own counter
        rt.on_event(ev("A")); clock.advance(61); rt.on_event(ev("A")); self.assertEqual(len(rt.on_event(ev("A"))), 0)   # window slid


class ContentPackTests(unittest.TestCase):
    def pack(self):
        L, clock, _ = lib(); r = L.create(AUTHOR, spec(clock)); L.submit(r, AUTHOR); L.approve(r, REVIEWER); return L, clock, L.build_pack(KEY)

    def test_signed_monotonic_and_only_active_rules(self):
        L, clock, p = self.pack(); verify_pack(p, KEY, 0)
        bad = copy.deepcopy(p); bad["rules"][0]["query"] = "kind=process"
        with self.assertRaises(PackError): verify_pack(bad, KEY, 0)
        with self.assertRaises(PackError): verify_pack(p, KEY, p["version"])
        L.rules[p["rules"][0]["id"]][1].status = "retired"; self.assertEqual(L.build_pack(KEY)["rules"], [])

    def test_device_enforces_expiry_even_if_the_pack_is_stale(self):
        L, clock, p = self.pack(); rt = Runtime(clock); rt.load(p)
        e = dict(kind="process", proc="powershell.exe", cmdline="x -enc y", device="d")
        self.assertEqual(len(rt.on_event(e)), 1); clock.advance(91 * DAY); self.assertEqual(rt.on_event(e), [])

    def test_agent_applies_content_without_upgrade_detects_offline_and_logs(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp); L = DetectionLibrary(clock)
        r = L.create(AUTHOR, spec(clock)); L.submit(r, AUTHOR); L.approve(r, REVIEWER); pack = L.build_pack(KEY)
        a.set_online(False); self.assertTrue(a.apply_content(pack, KEY)); self.assertFalse(a.apply_content(pack, KEY))      # replay refused
        tampered = dict(pack, version=9); self.assertFalse(a.apply_content(tampered, KEY))
        a.emit("process", "exec", 1, "C:/x/powershell.exe")        # pid 1 unknown -> no proc name; use a real spawn instead
        host.spawn(77, "powershell.exe", cmdline="powershell -enc QUJD", exe_sha256="ab" * 32)
        a.emit("process", "exec", 77, "C:/Windows/powershell.exe")
        self.assertEqual(len(a.detections), 1)
        rec = next(e for e in a.spool.entries() if e["kind"] == "ward.custom_detection")
        self.assertIn("WARD.OFFLINE_PREVENTION", rec["controls"]); self.assertEqual(rec["public"]["confidence_source"], "author-set"); self.assertEqual(rec["public"]["techniques"], ["T1059.001"])
        self.assertEqual(sum(1 for e in a.spool.entries() if e["kind"] == "ward.content_rejected"), 2)

    def test_telemetry_is_stored_and_forwarded_not_lost_offline(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp); host.spawn(5, "app.exe")
        fs.create(5, os.path.join(tmp, "n.txt"), b"hello"); a.set_online(False)
        ts = TenantStore(); ts.create_tenant("acme", "A"); ctx = TenantContext("acme", "u", "analyst"); ev = EventStore(ts, clock=clock)
        self.assertEqual(a.flush_telemetry(ev, ctx), 0); self.assertEqual(len(a.outbox), 1)
        a.set_online(True); self.assertEqual(a.flush_telemetry(ev, ctx), 1); self.assertEqual(ev.counts(ctx)["hot"], 1)


class LearningTests(unittest.TestCase):
    def setUp(self):
        self.clock = ManualClock(); self.tmp = tempfile.mkdtemp()
        self.audit = AuditLog(os.path.join(self.tmp, "a.log"), "acme", b"k" * 32, self.clock); self.L = LearningStore(self.clock, self.audit)
        self.ADM = Principal("u-adm", "it_admin")

    def hit(self, dev, sha="aa" * 32, rule="R-1", proc="backup.exe", path="D:/backups/x"):
        return dict(rule_id=rule, device=dev, event=dict(exe_sha256=sha, proc=proc, path=path, device=dev))

    def test_suggests_only_after_repeated_feedback_on_several_devices_and_never_activates_itself(self):
        for d in ("A", "A", "A"): self.assertIsNone(self.L.mark(self.hit(d), "benign", AUTHOR))
        e = self.L.mark(self.hit("B"), "benign", AUTHOR)
        self.assertEqual(e.status, "suggested"); self.assertIsNone(self.L.check(self.hit("A")))
        self.assertEqual(len([x for x in self.L.exceptions.values()]), 1)
        self.L.approve(e, ADM := self.ADM); self.assertIsNotNone(self.L.check(self.hit("A")))

    def test_scope_is_narrow_hash_detection_folder_devices(self):
        e = self.L.propose(AUTHOR, "R-1", "aa" * 32, "backup.exe", "nightly backup", dir_prefix="D:/backups", devices=["A"]); self.L.approve(e, self.ADM)
        self.assertIsNotNone(self.L.check(self.hit("A")))
        self.assertIsNone(self.L.check(self.hit("B")))                                   # other device
        self.assertIsNone(self.L.check(self.hit("A", sha="bb" * 32)))                    # other program hash (same name!)
        self.assertIsNone(self.L.check(self.hit("A", rule="R-2")))                       # other detection
        self.assertIsNone(self.L.check(self.hit("A", path="C:/Users/x")))                # other folder

    def test_cannot_hide_something_already_confirmed_malicious_or_known_bad(self):
        self.L.mark(self.hit("A"), "malicious", AUTHOR)
        e = self.L.propose(AUTHOR, "R-1", "aa" * 32, "backup.exe", "x")
        with self.assertRaisesRegex(LearningError, "confirmed as malicious"): self.L.approve(e, self.ADM)
        with self.assertRaises(LearningError): self.L.propose(AUTHOR, "known_bad_hash", "aa" * 32, "x", "x")
        with self.assertRaises(LearningError): self.L.propose(AUTHOR, "R-1", "", "x", "no hash")
        for d in ("A", "B", "C"): self.L.mark(self.hit(d, sha="cc" * 32), "benign", AUTHOR)
        self.assertEqual(self.L.mark(self.hit("D", sha="cc" * 32), "benign", AUTHOR).status, "suggested")
        self.L.mark(self.hit("D", sha="dd" * 32, rule="R-9"), "malicious", AUTHOR)
        for d in ("A", "B", "C", "D"): last = self.L.mark(self.hit(d, sha="dd" * 32, rule="R-9"), "benign", AUTHOR)
        self.assertIsNone(last)                                                          # a malicious mark blocks any suggestion

    def test_roles_and_proposer_cannot_approve_themselves(self):
        e = self.L.propose(AUTHOR, "R-1", "aa" * 32, "x", "r")
        with self.assertRaises(PermissionError): self.L.approve(e, AUTHOR)
        with self.assertRaises(PermissionError): self.L.approve(e, DESK)
        with self.assertRaises(PermissionError): self.L.mark(self.hit("A"), "benign", DESK)
        with self.assertRaises(LearningError): self.L.propose(AUTHOR, "R-1", "aa" * 32, "x", "r", days=365)

    def test_preview_replays_history(self):
        e = self.L.propose(AUTHOR, "R-1", "aa" * 32, "backup.exe", "r")
        hist = [self.hit("A"), self.hit("B"), self.hit("A", sha="zz" * 32)]
        self.assertEqual(self.L.preview(e, hist)["would_suppress"], 2)

    def test_revoke_restores_protection_at_once_and_lists_what_was_hidden(self):
        e = self.L.propose(AUTHOR, "R-1", "aa" * 32, "backup.exe", "r"); self.L.approve(e, self.ADM)
        for _ in range(3): self.L.check(self.hit("A"))
        reopened = self.L.revoke(e, self.ADM, "wrong call"); self.assertEqual(len(reopened), 3); self.assertIsNone(self.L.check(self.hit("A")))
        self.assertEqual(e.status, "revoked"); self.assertTrue(any(x["kind"] == "learning.exception_revoked" and x["public"]["to_retriage"] == 3 for x in self.audit.entries()))

    def test_exceptions_expire(self):
        e = self.L.propose(AUTHOR, "R-1", "aa" * 32, "backup.exe", "r", days=2); self.L.approve(e, self.ADM)
        self.clock.advance(3 * DAY); self.assertIsNone(self.L.check(self.hit("A"))); self.assertEqual(self.L.sweep(), [e.id])

    def test_custom_detection_suppressed_on_device_and_logged_as_suppressed(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp); L = DetectionLibrary(clock)
        r = L.create(AUTHOR, spec(clock)); L.submit(r, AUTHOR); L.approve(r, REVIEWER); a.apply_content(L.build_pack(KEY), KEY)
        host.spawn(77, "powershell.exe", cmdline="powershell -enc QUJD", exe_sha256="ab" * 32); a.emit("process", "exec", 77, "p")
        self.assertEqual(len(a.detections), 1)
        store = LearningStore(clock); e = store.propose(AUTHOR, r.id, "ab" * 32, "powershell.exe", "admin script"); store.approve(e, Principal("u-adm", "it_admin"))
        from halvard.ward.policy import PolicyBundle
        b = PolicyBundle(tenant="acme", version=2, accepted_patterns=["ransomware_stop"], learned_exceptions=store.export_active()).sign(POLICY_KEY).__dict__.copy()
        self.assertTrue(a.apply_bundle(b, POLICY_KEY)); a.emit("process", "exec", 77, "p"); self.assertEqual(len(a.detections), 1)     # suppressed

    def test_bulk_encryption_exception_is_observe_only_and_still_journals(self):
        from halvard.ward import simulate as sim
        from halvard.ward.policy import PolicyBundle
        import hashlib, pathlib
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp); sha = "ee" * 32
        store = LearningStore(clock); e = store.propose(AUTHOR, "ward.bulk_encryption", sha, "legit-crypto.exe", "approved encryption tool")
        self.assertEqual(e.effect, "observe_only"); store.approve(e, Principal("u-adm", "it_admin"))
        b = PolicyBundle(tenant="acme", version=2, accepted_patterns=["ransomware_stop"], learned_exceptions=store.export_active()).sign(POLICY_KEY).__dict__.copy()
        a.apply_bundle(b, POLICY_KEY); root = os.path.join(tmp, "docs"); sim.authorize(root); paths = sim.seed_files(root, 30)
        host.spawn(9, "legit-crypto.exe", exe_sha256=sha); sim.run_simulation(fs, 9, root)
        inc = a.incidents[0]; self.assertEqual(inc["suppressed_by"], e.id); self.assertNotIn(9, a.blocked); self.assertEqual(host.proc(9)["state"], "running")
        self.assertTrue(any(x["kind"] == "ward.suppressed_by_exception" for x in a.spool.entries()))
        rep = a.journal.rollback([9], dry_run=True); self.assertGreaterEqual(len(rep.restored), 8)        # still recoverable
        host.spawn(10, "legit-crypto.exe", exe_sha256="ff" * 32); paths2 = sim.seed_files(os.path.join(tmp, "docs2"), 30); sim.authorize(os.path.join(tmp, "docs2"))
        sim.run_simulation(fs, 10, os.path.join(tmp, "docs2")); self.assertIn(10, a.blocked)             # same name, different hash: not excepted


if __name__ == "__main__":
    unittest.main()
