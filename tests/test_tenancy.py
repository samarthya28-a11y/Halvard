import tempfile, unittest, os, sqlite3
from helpers import *
from halvard.ledger.audit import AuditLog
from halvard.tenancy import TenantStore, TenantContext, TenantIsolationError, SupportGrants


class TenancyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.clock = ManualClock()
        self.audit = AuditLog(os.path.join(self.tmp, "a.log"), "platform", b"k" * 32, self.clock)
        self.grants = SupportGrants(self.clock)
        self.s = TenantStore(objects_root=os.path.join(self.tmp, "obj"), grants=self.grants, audit=self.audit)
        for t in ("acme", "globex"): self.s.create_tenant(t, t.title())
        self.a = TenantContext("acme", "u1", "it_admin"); self.g = TenantContext("globex", "u9", "it_admin")
        self.s.put_entity(self.a, "srv-1", "device", "ACME DB server", 0, criticality="crown_jewel")
        self.s.put_entity(self.g, "srv-9", "device", "Globex file server", 0)
        self.s.put_object(self.g, "reports/q3.txt", b"globex secret")

    def test_cross_tenant_read_fails_closed(self):
        with self.assertRaises(KeyError): self.s.get_entity(self.a, "srv-9")      # same answer as 'does not exist'
        self.assertEqual(self.s.list_entities(self.a), ["srv-1"])

    def test_forged_tenant_context_is_refused_and_logged(self):
        with self.assertRaises(TenantIsolationError): self.s.get_entity(TenantContext("evil' OR '1'='1", "u1", "it_admin"), "srv-9")
        self.assertTrue(any(e["kind"] == "tenant.access_denied" for e in self.audit.entries()))

    def test_sql_injection_in_entity_id_returns_nothing(self):
        with self.assertRaises(KeyError): self.s.get_entity(self.a, "x' OR tenant_id='globex")

    def test_cross_tenant_edge_refused_by_schema(self):
        self.s.put_entity(self.a, "srv-2", "device", "second", 0)
        with self.assertRaises(sqlite3.IntegrityError): self.s.add_edge_raw("acme", "srv-2", "can_access", "srv-9", "globex", 0)

    def test_object_storage_isolated_and_traversal_refused(self):
        with self.assertRaises(KeyError): self.s.get_object(self.a, "reports/q3.txt")
        with self.assertRaises(TenantIsolationError): self.s.get_object(self.a, "../globex/reports/q3.txt")
        with self.assertRaises(TenantIsolationError): self.s.get_object(self.a, "/etc/passwd")

    def test_support_needs_time_boxed_grant(self):
        sup = TenantContext("acme", "halvard-eng-3", "halvard_support")
        with self.assertRaises(TenantIsolationError): self.s.list_entities(sup)
        gid = self.grants.open("acme", "halvard-eng-3", 30, opened_by_customer="u1")
        sup = TenantContext("acme", "halvard-eng-3", "halvard_support", gid)
        self.assertEqual(self.s.list_entities(sup), ["srv-1"])
        self.clock.advance(31 * 60)
        with self.assertRaises(TenantIsolationError): self.s.list_entities(sup)
        wrong = TenantContext("globex", "halvard-eng-3", "halvard_support", gid)    # grant for acme is no good for globex
        with self.assertRaises(TenantIsolationError): self.s.list_entities(wrong)


if __name__ == "__main__":
    unittest.main()
