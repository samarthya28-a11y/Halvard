import os, tempfile, unittest, json
from helpers import *
from halvard.relay.actions import Principal
from halvard.setup.guide import GuidedSetup
from halvard.tenancy import TenantStore, TenantContext
from halvard.coverage import CoverageMonitor
from halvard.ledger.audit import AuditLog
from halvard import perf


class SetupTests(unittest.TestCase):
    def test_generalist_completes_day_one_using_only_the_guide(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp, accepted=())
        g = GuidedSetup(a, fs, Principal("u-admin", "it_admin"), os.path.join(tmp, "work"))
        seen = []
        while g.next_step():                      # the ONLY control flow the user has: "what's next?" and "do it"
            key, title = g.next_step(); seen.append(title); r = g.run_current()
            self.assertTrue(r.ok, f"{key}: {r.happened}"); self.assertTrue(r.protected and r.next)
            if len(seen) > 12: self.fail("setup does not converge")
        self.assertEqual(len(seen), 6); self.assertEqual(g.progress(), "6 of 6 protections proven on this computer")
        self.assertFalse(host.isolated)                                   # test left the machine usable
        self.assertIn("ransomware_stop", a.engine.auth.policy.accepted_patterns)
        for need in ("F004", "F006", "F016", "F037", "F040"): self.assertTrue(any(f == need for _, _, f in g.STEPS))
        self.assertTrue(any(e["kind"] == "setup.step" for e in a.spool.entries()))

    def test_failed_step_says_what_failed_and_what_is_still_protected(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp, prevention={"known_bad": "audit_only", "bulk_encryption": "enforce"})
        g = GuidedSetup(a, fs, Principal("u-admin", "it_admin"), os.path.join(tmp, "work")); g.run_current(); r = g.run_current()
        self.assertFalse(r.ok); self.assertIn("not blocked", r.happened); self.assertTrue(r.protected); self.assertIn("Enforce", r.next)
        self.assertEqual(g.next_step()[0], "offline_prevention")           # does not move on until proven

    def test_rollback_step_fails_honestly_when_journal_has_no_room(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp, journal_quota_mb=0)
        g = GuidedSetup(a, fs, Principal("u-admin", "it_admin"), os.path.join(tmp, "work"))
        for _ in range(10):                        # bounded: a step that never passes must not hang the suite
            if not g.next_step() or g.next_step()[0] == "rollback": break
            g.run_current()
        r = g.run_current(); self.assertFalse(r.ok); self.assertNotIn("ransomware_stop", a.engine.auth.policy.accepted_patterns)


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.clock = ManualClock(); self.tmp = tempfile.mkdtemp()
        self.audit = AuditLog(os.path.join(self.tmp, "a.log"), "acme", b"k" * 32, self.clock)
        self.s = TenantStore(); self.s.create_tenant("acme", "Acme"); self.c = TenantContext("acme", "u", "it_admin")
        self.s.put_entity(self.c, "srv-db", "device", "Finance DB server", 0, criticality="crown_jewel")
        self.s.put_entity(self.c, "lt-1", "device", "Laptop 1", 0)
        self.s.put_entity(self.c, "printer", "device", "Lobby printer", 0, should_be_protected=0)
        self.s.put_sensor(self.c, "s-lt-1", "lt-1", "ward", self.clock.now())
        self.m = CoverageMonitor(self.s, self.c, self.clock, self.audit)

    def test_missing_agent_on_crown_jewel_server_is_an_incident(self):
        gaps = self.m.evaluate(); g = next(x for x in gaps if x.entity_id == "srv-db")
        self.assertEqual(g.severity, "incident"); self.assertIn("No Halvard agent", g.reason)
        self.assertEqual([x.entity_id for x in gaps], ["srv-db"])          # healthy laptop and exempt printer are not gaps

    def test_silent_agent_raises_gap_after_promised_interval_not_before(self):
        self.s.heartbeat(self.c, "s-lt-1", self.clock.now()); self.clock.advance(800)
        self.assertNotIn("lt-1", [g.entity_id for g in self.m.evaluate()])
        self.clock.advance(200)           # 1000s > promised 900s
        self.assertIn("lt-1", [g.entity_id for g in self.m.evaluate()])
        self.assertTrue(self.s.findings(self.c, "coverage_gap"))
        self.assertTrue(any(e["kind"] == "coverage.gap_raised" for e in self.audit.entries()))

    def test_change_window_quiets_ordinary_gap_but_never_crown_jewel(self):
        self.clock.advance(5000); w = (self.clock.now() - 1, self.clock.now() + 3600)
        ids = [g.entity_id for g in self.m.evaluate({"lt-1": w, "srv-db": w})]
        self.assertEqual(ids, ["srv-db"])

    def test_other_tenant_assets_do_not_appear(self):
        self.s.create_tenant("globex", "G"); o = TenantContext("globex", "u", "it_admin")
        self.s.put_entity(o, "g-srv", "device", "Globex server", 0, criticality="crown_jewel")
        self.assertNotIn("g-srv", [g.entity_id for g in self.m.evaluate()])


class PerfTests(unittest.TestCase):
    @unittest.skipIf(os.environ.get('HALVARD_SKIP_PERF'), 'skipped for mutation sweep')
    def test_agent_stays_inside_published_budget_on_workday_trace(self):
        r = perf.run_median(4000, 3)
        print("\nperf:", json.dumps({k: r[k] for k in r if k != "checks"}))
        self.assertTrue(r["pass"], r["checks"])

    def test_budget_is_published_and_complete(self):
        b = perf.BUDGET
        for k in ("cpu_average_percent_of_one_core_max", "memory_mb_max", "journal_disk_mb_per_workday_max", "install_footprint_mb_max"): self.assertIn(k, b)


if __name__ == "__main__":
    unittest.main()
