import unittest, sqlite3
from helpers import *
from halvard.tenancy import TenantStore, TenantContext, SCHEMA


class GraphTests(unittest.TestCase):
    def test_schema_loads_and_every_table_has_tenant(self):
        db = sqlite3.connect(":memory:"); db.executescript(SCHEMA)
        for (t,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
            cols = [r[1] for r in db.execute(f'PRAGMA table_info("{t}")')]
            self.assertIn("tenant_id", cols, t)

    def test_entity_kinds_are_the_specified_ten(self):
        s = TenantStore(); s.create_tenant("t", "T"); c = TenantContext("t", "u", "it_admin")
        for k in ("person", "identity", "device", "workload", "application", "data_store", "mailbox", "site", "supplier", "ai_agent"):
            s.put_entity(c, "e-" + k, k, k, 0)
        with self.assertRaises(sqlite3.IntegrityError): s.put_entity(c, "bad", "toaster", "x", 0)

    def test_suggested_does_not_overwrite_customer_value(self):
        s = TenantStore(); s.create_tenant("t", "T"); c = TenantContext("t", "u", "it_admin")
        s.put_entity(c, "d", "device", "d", 0, criticality="high")
        s.db.execute("UPDATE entity SET suggested_criticality='crown_jewel' WHERE entity_id='d'")
        e = s.get_entity(c, "d"); self.assertEqual((e["criticality"], e["suggested_criticality"]), ("high", "crown_jewel"))


if __name__ == "__main__":
    unittest.main()
