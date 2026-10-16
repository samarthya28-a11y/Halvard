"""Independent cross-check, phase 1. Some of these fail: that is the finding, not a skip."""
import json, os, pathlib, tempfile, unittest
from helpers import *
from halvard.ledger.audit import AuditLog
from halvard.relay.actions import ActionRequest, Principal
from halvard.relay.journal import Journal
from halvard.tenancy import TenantContext, TenantIsolationError
from halvard.fabric.platform import Platform
from halvard.ward.detect import Verdict


class JournalFingerprintTests(unittest.TestCase):
    def _journal(self):
        return Journal(tempfile.mkdtemp(), ManualClock())

    def test_a_later_edit_with_the_same_size_and_mtime_is_not_overwritten(self):
        j = self._journal(); path = os.path.join(j.root, "doc.txt")
        pathlib.Path(path).write_bytes(b"original-content!!")
        rid, _ = j.before(7, "write", path)
        pathlib.Path(path).write_bytes(b"encrypted-content")
        j.after(rid, path)
        st = os.stat(path)
        pathlib.Path(path).write_bytes(b"USER-FIXED-CONTENT!")
        os.truncate(path, st.st_size)
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
        kept = pathlib.Path(path).read_bytes()
        rep = j.rollback([7])
        self.assertIn(path, rep.skipped_changed_after)
        self.assertEqual(pathlib.Path(path).read_bytes(), kept)

    def test_a_pure_mtime_touch_does_not_block_restore_of_the_pre_image(self):
        j = self._journal(); path = os.path.join(j.root, "doc2.txt")
        pathlib.Path(path).write_bytes(b"original-content!!")
        rid, _ = j.before(8, "write", path)
        pathlib.Path(path).write_bytes(b"encrypted-content")
        j.after(rid, path)
        os.utime(path, (1, 1))
        rep = j.rollback([8])
        self.assertNotIn(path, rep.skipped_changed_after)
        self.assertEqual(pathlib.Path(path).read_bytes(), b"original-content!!")


class PublicAuditTests(unittest.TestCase):
    def test_paths_and_person_names_do_not_appear_in_the_public_half_of_the_ledger(self):
        a, host, clock, _ = make_agent(tempfile.mkdtemp(), asset_class="production")
        secret = os.path.join(a.root, "payroll-alice.csv")
        a.handle_verdict(Verdict(9, 0.9, ["bulk encryption"], [secret]))
        host.spawn(4, "evil.exe", user="alice")
        a.engine.request(ActionRequest("stop_process", Principal("sam", "it_admin"), [a.device_id],
                                       "stop alice on the payroll laptop", params={"pid": 4}))
        note = os.path.join(tempfile.mkdtemp(), "alice-secret.txt")
        pathlib.Path(note).write_text("x", encoding="utf-8")
        a.engine.request(ActionRequest("quarantine_file", Principal("system", "system"), [note],
                                       "Alice Kim asked to quarantine this", automatic=True, pattern="malware_quarantine"))
        public = []
        for log in (a.spool, a.engine.ledger):
            for e in log.entries():
                public.append(json.dumps(e["public"]))
        blob = "\n".join(public)
        self.assertNotIn("payroll-alice", blob)
        self.assertNotIn("alice-secret", blob)
        self.assertNotIn("Alice", blob)
        self.assertNotIn("user alice", blob)


class TenancyTests(unittest.TestCase):
    def test_a_tenant_id_that_climbs_out_of_its_prefix_cannot_write_another_tenants_object(self):
        root = tempfile.mkdtemp(); p = Platform(root, ManualClock())
        p.create_tenant("globex", "Globex")
        g = p.tenants["globex"].cp.ctx
        p.store.put_object(g, "quarterly", b"SECRET-NUMBERS")
        for evil in ("../t/globex", "..", "a/b", "x\\y", ".hidden", ""):
            with self.assertRaises(ValueError): p.create_tenant(evil, "Evil")         # a company id is a folder name: it may not climb or nest
        self.assertEqual(p.store.get_object(g, "quarterly"), b"SECRET-NUMBERS")

    def test_a_normal_tenant_cannot_read_another_tenants_row_or_escape_with_a_key(self):
        root = tempfile.mkdtemp(); p = Platform(root, ManualClock())
        p.create_tenant("acme", "Acme"); p.create_tenant("globex", "Globex")
        acme, globex = p.tenants["acme"].cp.ctx, p.tenants["globex"].cp.ctx
        p.store.put_entity(globex, "p:gary", "person", "Gary", 1)
        p.store.put_object(globex, "note", b"globex-only")
        with self.assertRaises(KeyError):
            p.store.get_entity(acme, "p:gary")
        for key in ("../globex/note", "/etc/passwd", "..\\globex\\note"):
            with self.assertRaises((TenantIsolationError, KeyError)):
                p.store.get_object(acme, key)
        self.assertEqual(p.store.get_object(globex, "note"), b"globex-only")


class MaintenanceAndApprovalTests(unittest.TestCase):
    def test_a_deferred_action_is_kept_so_it_can_be_offered_when_the_window_ends(self):
        a, _, clock, _ = make_agent(tempfile.mkdtemp())
        a.engine.auth.policy.maintenance_windows[a.device_id] = (clock.now() - 10, clock.now() + 1000)
        res = a.engine.request(ActionRequest("isolate_host", Principal("sam", "it_admin"), [a.device_id], "window"))
        self.assertEqual(res.status, "deferred")
        stored = {**a.engine.pending, **getattr(a.engine, "deferred", {})}
        self.assertTrue(stored, res.message)

    def test_a_deferred_action_is_asked_again_after_the_window_ends_and_not_before(self):
        a, h, clock, _ = make_agent(tempfile.mkdtemp())
        a.engine.auth.policy.maintenance_windows[a.device_id] = (clock.now() - 10, clock.now() + 1000)
        res = a.engine.request(ActionRequest("isolate_host", Principal("sam", "it_admin"), [a.device_id], "window")); self.assertEqual(res.status, "deferred"); self.assertIn(res.action_id, a.engine.deferred)
        self.assertEqual(a.engine.offer_due(), []); self.assertFalse(h.isolated)                          # the window is still open: nothing runs
        clock.advance(1001); a.heartbeat(); self.assertTrue(h.isolated); self.assertEqual(a.engine.deferred, {})      # the next heartbeat after it ends runs it

    def test_the_requester_cannot_approve_their_own_production_isolation(self):
        a, _, _, _ = make_agent(tempfile.mkdtemp(), asset_class="production")
        res = a.engine.request(ActionRequest("isolate_host", Principal("sam", "it_admin"), [a.device_id], "contain"))
        self.assertEqual(res.status, "pending_approval")
        again = a.engine.approve(res.action_id, Principal("sam", "analyst"))
        self.assertEqual(again.status, "denied")
        self.assertIn("own", again.message)
        self.assertFalse(a.host.isolated)
