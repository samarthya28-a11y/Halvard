import os, tempfile, unittest, pathlib
from helpers import *
from halvard.ward.agent import Blocked
from halvard.ward.verdict import EICAR, TEST_MARKER
from halvard.ward.policy import PolicyBundle, BundleError, load_bundle
from halvard.relay import isolation


class WardMiscTests(unittest.TestCase):
    def setUp(self): self.tmp = tempfile.mkdtemp(); self.a, self.host, self.clock, self.fs = make_agent(self.tmp)

    # F004 / F006
    def test_known_bad_blocked_with_no_connectivity_and_quarantined(self):
        self.a.set_online(False); f = os.path.join(self.tmp, "t.txt"); pathlib.Path(f).write_bytes(TEST_MARKER)       # on disk: a harmless marker, because real antivirus deletes the EICAR file the moment it is written
        with self.assertRaises(Blocked): self.a.pre_execute(f, TEST_MARKER)
        self.assertFalse(os.path.exists(f))
        rec = next(e for e in self.a.spool.entries() if e["kind"] == "ward.exec_verdict")
        self.assertIn("WARD.OFFLINE_PREVENTION", rec["controls"]); self.assertEqual(rec["public"]["source"], "local_cache")

    def test_policy_hash_list_blocks_offline(self):
        import hashlib
        bad = b"custom bad sample"; a, host, clock, fs = make_agent(self.tmp + "b", known_bad_sha256=[hashlib.sha256(bad).hexdigest()])
        a.set_online(False); p = os.path.join(self.tmp, "b.bin"); pathlib.Path(p).write_bytes(bad)
        with self.assertRaises(Blocked): a.pre_execute(p, bad)

    def test_normal_file_allowed_and_audit_only_does_not_block(self):
        self.assertEqual(self.a.pre_execute("memo.txt", b"quarterly numbers").decision, "allow")
        a, *_ = make_agent(self.tmp + "c", prevention={"known_bad": "audit_only", "bulk_encryption": "enforce"})
        self.assertEqual(a.pre_execute("t.txt", EICAR).decision, "block")      # logged as block, but not enforced

    def test_cloud_reputation_only_used_when_online(self):
        a, *_ = make_agent(self.tmp + "d"); a.verdicts.reputation = lambda h: "bad"
        a.set_online(False); self.assertEqual(a.pre_execute("x.bin", b"unknown file").decision, "allow")
        a.set_online(True); f = os.path.join(self.tmp, "unk.bin"); pathlib.Path(f).write_bytes(b"unknown file")
        with self.assertRaises(Blocked): a.pre_execute(f, b"unknown file")

    # F016
    def test_modified_agent_file_is_restored_and_logged(self):
        p = self.tmp + "/agent/install/ward.exe"; pathlib.Path(p).write_bytes(b"patched by malware")
        self.assertEqual([os.path.normpath(x) for x in self.a.tamper.check()], [os.path.normpath(p)]); self.assertEqual(pathlib.Path(p).read_bytes(), b"agent-binary")
        self.assertTrue(any(e["kind"] == "ward.tamper_detected" for e in self.a.spool.entries()))

    def test_deleted_agent_file_is_restored(self):
        p = self.tmp + "/agent/install/ward.conf"; os.remove(p); self.a.tamper.check(); self.assertTrue(os.path.exists(p))

    def test_uninstall_refused_without_console_code_and_logged(self):
        with self.assertRaises(PermissionError): self.a.tamper.stop_or_uninstall("123.abc.def")
        self.assertTrue(any(e["kind"] == "ward.tamper_attempt" for e in self.a.spool.entries()))

    def test_uninstall_code_is_single_use_expiring_and_states_what_remains(self):
        code = self.a.tamper.issue_uninstall_token("u-admin")
        msg = self.a.tamper.stop_or_uninstall(code); self.assertIn("30 days", msg)
        with self.assertRaises(PermissionError): self.a.tamper.stop_or_uninstall(code)     # replay
        code2 = self.a.tamper.issue_uninstall_token("u-admin", minutes=1); self.clock.advance(120)
        with self.assertRaises(PermissionError): self.a.tamper.stop_or_uninstall(code2)    # expired

    def test_uninstall_code_is_bound_to_the_device(self):
        code = self.a.tamper.issue_uninstall_token("u-admin"); other, *_ = make_agent(self.tmp + "e"); other.device_id = "LT-99"; other.tamper.device_id = "LT-99"
        with self.assertRaises(PermissionError): other.tamper.stop_or_uninstall(code)

    def test_journal_after_survives_a_file_that_vanishes_between_check_and_stat(self):
        """An asynchronous sensor can lose a race with a rename; that must not be an error (found by a flaky Linux-lane run)."""
        from halvard.relay import journal as J
        rid, _ = self.a.journal.before(1, "write", os.path.join(self.tmp, "gone.txt")); real = J.fingerprint
        J.fingerprint = lambda p, *a, **k: (_ for _ in ()).throw(FileNotFoundError(p))
        try: pathlib.Path(self.tmp, "gone.txt").write_text("x", encoding="utf-8"); self.a.journal.after(rid, os.path.join(self.tmp, "gone.txt"))
        finally: J.fingerprint = real

    # policy bundle
    def test_tampered_policy_bundle_rejected_last_good_kept(self):
        b = PolicyBundle(tenant="acme", version=2, prevention={"bulk_encryption": "off"}).sign(POLICY_KEY).__dict__.copy()
        b["prevention"] = {"bulk_encryption": "off", "known_bad": "off"}      # edited after signing
        self.assertFalse(self.a.apply_bundle(b, POLICY_KEY)); self.assertEqual(self.a.bundle.version, 1)
        self.assertEqual(self.a.bundle.prevention["bulk_encryption"], "enforce")

    def test_policy_rollback_refused(self):
        b = PolicyBundle(tenant="acme", version=1).sign(POLICY_KEY).__dict__.copy()
        self.assertFalse(self.a.apply_bundle(b, POLICY_KEY))
        good = PolicyBundle(tenant="acme", version=5, accepted_patterns=["ransomware_stop"]).sign(POLICY_KEY).__dict__.copy()
        self.assertTrue(self.a.apply_bundle(good, POLICY_KEY)); self.assertEqual(self.a.bundle.version, 5)

    def test_accepted_pattern_survives_policy_update(self):
        self.a.engine.accept_pattern("custom", Principal_admin()); good = PolicyBundle(tenant="acme", version=2).sign(POLICY_KEY).__dict__.copy()
        self.a.apply_bundle(good, POLICY_KEY); self.assertIn("custom", self.a.engine.auth.policy.accepted_patterns)

    # isolation rules (rendered, not executed)
    def test_rendered_isolation_rules_keep_only_management_path(self):
        w = "\n".join(isolation.windows_rules(["203.0.113.10"], "10.0.0.2")); self.assertIn("blockinbound,blockoutbound", w)
        self.assertIn("remoteip=203.0.113.10 protocol=TCP remoteport=443", w); self.assertNotIn("action=allow remoteip=any", w)
        n = isolation.linux_nft(["203.0.113.10"]); self.assertIn("policy drop", n); self.assertIn("203.0.113.10 tcp dport 443 accept", n)
        self.assertIn("halvard_isolate", isolation.linux_release())


def Principal_admin():
    from halvard.relay.actions import Principal
    return Principal("u-admin", "it_admin")


if __name__ == "__main__":
    unittest.main()
