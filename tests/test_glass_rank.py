import unittest
from helpers import *
from rig6 import *
from halvard.glass import exposure as X, baseline as B
from halvard.glass.feed import vkey, VulnFeed, Advisory


class RankingTests(unittest.TestCase):
    def test_a_flaw_used_in_attacks_on_an_internet_facing_crown_jewel_outranks_everything_and_the_page_shows_the_working(self):
        w = World6(); xs = w.cp.glass.evaluate(ADM); top = xs[0]
        self.assertEqual((top.id, top.tier), ("HLV-SAMPLE-0001@i-web", "now"))
        e = top.explain()
        for part in ("Known to be used in attacks", "reachable from the internet", "exploit 4", "reach 3", "not a probability"): self.assertIn(part, e)
        local = next(x for x in xs if x.id == "HLV-SAMPLE-0002@LT-17"); self.assertEqual((local.tier, local.reach), ("soon", "local")); self.assertLess(local.score, top.score)
        self.assertEqual([(["now", "soon", "scheduled"].index(x.tier), -x.score) for x in xs], sorted((["now", "soon", "scheduled"].index(x.tier), -x.score) for x in xs))

    def test_the_same_flaw_ranks_higher_where_the_asset_matters_more_and_each_factor_moves_the_number(self):
        base = X.make("x", "vulnerability", "e", "E", "t", exploit="none", reach="local", value_w=1.5, sev_w=0.8, first_seen=0, now=0).score
        self.assertGreater(X.make("x", "vulnerability", "e", "E", "t", exploit="exploited_in_wild", reach="local", value_w=1.5, sev_w=0.8, first_seen=0, now=0).score, base)
        self.assertGreater(X.make("x", "vulnerability", "e", "E", "t", exploit="none", reach="internet", value_w=1.5, sev_w=0.8, first_seen=0, now=0).score, base)
        self.assertGreater(X.make("x", "vulnerability", "e", "E", "t", exploit="none", reach="local", value_w=X.value_weight("crown_jewel", None, "standard"), sev_w=0.8, first_seen=0, now=0).score, base)
        self.assertGreater(X.value_weight(None, "regulated", "standard"), X.value_weight(None, None, "standard")); self.assertGreater(X.value_weight(None, None, "production"), X.value_weight(None, None, "standard"))
        self.assertEqual(X.tier_of("none", "local", 1.0, 0.3), "scheduled"); self.assertEqual(X.tier_of("exploited_in_wild", "internet", 1.5, 0.9), "now")
        self.assertEqual(X.tier_of("exploited_in_wild", "internet", 1.5, 0.9, compensated=True), "soon")      # a live protection steps 'now' down; nothing else
        self.assertEqual(X.tier_of("public_exploit", "local", 1.5, 0.5, compensated=True), "soon")

    def test_versions_compare_as_numbers_not_text_and_a_feed_must_state_the_exploit_status(self):
        self.assertTrue(vkey("2.4.9") < vkey("2.4.58")); self.assertTrue(vkey("11.2") > vkey("11.1.9"))
        self.assertTrue(Advisory("A", "p", "2.4.58", 5.0, "none", "local", None, "s").affects("p", "2.4.9")); self.assertFalse(Advisory("A", "p", "2.4.58", 5.0, "none", "local", None, "s").affects("p", "2.4.58"))
        with self.assertRaises(ValueError): VulnFeed([Advisory("A", "p", "1", 5.0, "maybe", "local", None, "s")])
        f = VulnFeed.load(__import__("os").path.join(__import__("os").path.dirname(__file__), "..", "policy", "advisories_sample.json")); self.assertTrue(all(a.id.startswith("HLV-SAMPLE") for a in f.advisories)); self.assertIsNone(f.synced_with_upstream)

    def test_an_update_closes_the_item_and_the_ledger_records_it_opening_and_closing(self):
        w = World6(); g = w.cp.glass; g.evaluate(); w.clock.advance(3 * DAY)
        w.host.software["pdfviewer"] = "11.2"; xs = {x.id for x in g.evaluate()}
        self.assertNotIn("HLV-SAMPLE-0002@LT-17", xs); self.assertIn("HLV-SAMPLE-0002@LT-22", xs)
        ev = [(r["kind"], r["public"]["exposure"]) for r in w.cp.ledger.entries() if r["kind"].startswith("glass.exposure_")]
        self.assertIn(("glass.exposure_opened", "HLV-SAMPLE-0002@LT-17"), ev); self.assertIn(("glass.exposure_closed", "HLV-SAMPLE-0002@LT-17"), ev)
        closed = next(r for r in w.cp.ledger.entries() if r["kind"] == "glass.exposure_closed" and r["public"]["exposure"] == "HLV-SAMPLE-0002@LT-17"); self.assertEqual(closed["public"]["age_days"], 3.0)

    def test_misconfigurations_rank_in_the_same_list_as_vulnerabilities(self):
        w = World6(); w.host.system_encrypted = False; xs = w.cp.glass.evaluate(ADM)
        m = next(x for x in xs if x.id == "baseline:disk_encryption@LT-17"); self.assertEqual((m.kind, m.exploit), ("misconfiguration", "none")); self.assertIn("expected True, found False", m.title)
        self.assertTrue(any(x.id.startswith("SG_WORLD_ADMIN") for x in xs) and any(x.kind == "vulnerability" for x in xs))

    def test_the_overdue_clock_runs_from_first_sight_and_follows_the_tier(self):
        w = World6(); g = w.cp.glass; g.evaluate(); w.clock.advance(1 * DAY + 1)
        self.assertFalse(any(x.overdue for x in g.evaluate() if x.tier == "now")); w.clock.advance(1 * DAY + 1)
        self.assertTrue(next(x for x in g.evaluate() if x.id == "HLV-SAMPLE-0001@i-web").overdue)                     # 'now' = 2 days
        self.assertFalse(next(x for x in g.evaluate() if x.id == "HLV-SAMPLE-0002@LT-17").overdue)                    # 'soon' = 14 days

    def test_only_staff_who_should_see_exposures_do_and_a_refusal_is_recorded(self):
        w = World6(); g = w.cp.glass
        for p in (SD, AUD):
            with self.assertRaises(PermissionError): g.evaluate(p)
        self.assertTrue(g.evaluate(OWNER)); self.assertTrue(g.evaluate(AN))
        self.assertEqual(sum(1 for r in w.cp.ledger.entries() if r["kind"] == "glass.denied"), 2)


class BaselineTests(unittest.TestCase):
    def test_a_missing_value_is_unknown_not_fine_and_drift_names_expected_and_found(self):
        d = B.check("D", {"firewall_enabled": False, "screen_lock_minutes": 30})
        got = {x.key: (x.expected, x.observed) for x in d}
        self.assertEqual(got["firewall_enabled"], ("True", False)); self.assertEqual(got["screen_lock_minutes"], ("at most 15", 30)); self.assertEqual(got["disk_encryption"][1], "not reported")
        self.assertEqual(B.check("D", {"disk_encryption": True, "firewall_enabled": True, "automatic_updates": True, "screen_lock_minutes": 15}), [])

    def test_an_exception_needs_a_reason_a_limit_and_a_role_and_it_expires(self):
        w = World6(); g = w.cp.glass; w.host.settings["firewall_enabled"] = False
        ids = lambda: {x.id for x in g.evaluate()}; self.assertIn("baseline:firewall_enabled@LT-17", ids())
        with self.assertRaises(PermissionError): g.grant_exception(AN, "LT-17", "firewall_enabled", 30, "test")
        with self.assertRaises(ValueError): g.grant_exception(ADM, "LT-17", "firewall_enabled", 30, " ")
        with self.assertRaises(ValueError): g.grant_exception(ADM, "LT-17", "firewall_enabled", 91, "long")
        g.grant_exception(ADM, "LT-17", "firewall_enabled", 30, "vendor tool conflicts until its next release"); self.assertNotIn("baseline:firewall_enabled@LT-17", ids())
        w.clock.advance(31 * DAY); self.assertIn("baseline:firewall_enabled@LT-17", ids())
        self.assertTrue(any(r["kind"] == "glass.baseline_exception" for r in w.cp.ledger.entries()))


class RiskAcceptanceTests(unittest.TestCase):
    def test_only_the_owner_can_accept_a_risk_it_is_time_limited_and_it_is_shown_not_hidden(self):
        w = World6(); g = w.cp.glass; xid = "HLV-SAMPLE-0001@i-web"
        with self.assertRaises(PermissionError): g.accept_risk(ADM, xid, 30, "we know")
        with self.assertRaises(ValueError): g.accept_risk(OWNER, xid, 91, "too long")
        with self.assertRaises(ValueError): g.accept_risk(OWNER, xid, 30, "")
        g.accept_risk(OWNER, xid, 30, "site is being retired"); w.clock.advance(5 * DAY)
        x = g.get(xid); self.assertEqual(x.status, "accepted_risk"); self.assertFalse(x.overdue); self.assertIn("site is being retired", x.note); self.assertIn(xid, [y.id for y in g.evaluate()])
        w.clock.advance(30 * DAY); self.assertEqual(g.get(xid).status, "open"); self.assertTrue(g.get(xid).overdue)


if __name__ == "__main__":
    unittest.main()
