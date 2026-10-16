import json, unittest
from helpers import *
from rig6 import *
from halvard.harbor.sensor import SiteSensor
from halvard.coverage import CoverageMonitor

CROWN = "10.0.20.5"


class Net:
    """World6 plus a head-office network: users (vlan 10), servers (vlan 20), guest wifi (vlan 30)."""
    def __init__(self):
        self.w = w = World6(); cp = w.cp; self.h = cp.harbor
        w.host.macs, w.host.ip = ["aa:00:00:00:00:17"], "10.0.10.17"; w.host2.macs, w.host2.ip = ["aa:00:00:00:00:22"], "10.0.10.22"
        self.h.register_site(ADM, "HQ", "Head office", {10: "users", 20: "servers", 30: "guest"}, [("users", "servers", 443), ("users", "servers", "*"), ("users", "servers", 3389), ("servers", "users", 5985)], crown_ips=[CROWN])
        self.s = SiteSensor("HQ", w.clock); self.sync()

    def sync(self): return self.s.flush(self.h.ingest)

    def known(self):
        self.s.seen("aa:00:00:00:00:17", "10.0.10.17", "lt-17", "MSFT 5.0", 10); self.s.seen("aa:00:00:00:00:22", "10.0.10.22", "lt-22", "MSFT 5.0", 10); self.sync()


class DiscoveryTests(unittest.TestCase):
    def test_devices_that_report_their_own_addresses_are_known_and_everything_else_is_not(self):
        n = Net(); n.known(); n.s.seen("de:ad:be:ef:00:01", "10.0.30.44", "phone", None, 30); n.sync()
        u = n.h.unknown(); self.assertEqual([x["mac"] for x in u], ["de:ad:be:ef:00:01"]); self.assertEqual(u[0]["zones"], ["guest"]); self.assertEqual(u[0]["confidence"], 0.5)        # new on guest wifi: low
        self.assertEqual(n.h.poll(), [])                                                                                                                                # below the bar for a finding

    def test_a_unknown_computer_on_the_server_network_talking_to_a_crown_jewel_is_a_strong_finding_with_its_reasons(self):
        n = Net(); n.known(); n.s.seen("de:ad:be:ef:00:02", "10.0.20.99", "kali", "MSFT 5.0", 20); n.s.flow("10.0.20.99", CROWN, 445, src_zone="servers", dst_zone="servers"); n.sync()
        u = n.h.unknown()[0]; self.assertEqual(u["confidence"], 0.9); w = " ".join(u["why"]); self.assertIn("servers network", w); self.assertIn("crown-jewel", w); self.assertIn("should have an agent", w)
        f = n.h.poll(); self.assertEqual((len(f), f[0].family, f[0].entity_id, f[0].confidence), (1, "unknown_device", "site:HQ", 0.9)); self.assertEqual(n.h.poll(), [])           # one finding, not one per cycle

    def test_the_finding_becomes_a_case_that_names_the_network(self):
        n = Net(); n.known(); n.s.seen("de:ad:be:ef:00:02", "10.0.20.99", "kali", "MSFT 5.0", 20); n.s.flow("10.0.20.99", CROWN, 445, src_zone="servers", dst_zone="servers"); n.sync(); n.w.cp.process()
        c = next(c for c in n.w.cp.cases.cases.values() if any(x.source == "harbor" for x in c.findings)); page = n.w.cp.cases.page(c); self.assertIn("[network]", page); self.assertIn("unknown device (10.0.20.99, kali) appeared on the servers network at Head office and has talked to a crown-jewel system", page)

    def test_adopting_a_device_records_it_and_a_protected_one_without_an_agent_becomes_a_coverage_gap(self):
        n = Net(); n.known(); n.s.seen("de:ad:be:ef:00:03", "10.0.20.70", "newsrv", None, 20); n.sync(); h = n.h
        with self.assertRaises(PermissionError): h.adopt(AN, "de:ad:be:ef:00:03", "New server", None)
        eid = h.adopt(ADM, "de:ad:be:ef:00:03", "New server", None, should_be_protected=True, criticality="high"); self.assertEqual(h.unknown(), [])
        self.assertTrue(json.loads(n.w.cp.store.get_entity(n.w.cp.ctx, eid)["attrs"])["adopted"])
        gaps = CoverageMonitor(n.w.cp.store, n.w.cp.ctx, n.w.clock).evaluate(); self.assertIn(eid, [g.entity_id for g in gaps]); self.assertIn("No Halvard agent", next(g for g in gaps if g.entity_id == eid).reason)
        with self.assertRaises(KeyError): h.adopt(ADM, "00:11:22:33:44:55", "ghost", None)

    def test_expected_unmanaged_devices_need_a_reason_a_limit_and_come_back_when_the_exception_ends(self):
        n = Net(); n.known(); n.s.seen("de:ad:be:ef:00:04", "10.0.10.80", "printer", None, 10); n.sync(); h = n.h
        for bad in (dict(reason="", days=30), dict(reason="printer", days=366)):
            with self.assertRaises(ValueError): h.expect(ADM, "de:ad:be:ef:00:04", "printer", **bad)
        with self.assertRaises(PermissionError): h.expect(AN, "de:ad:be:ef:00:04", "printer", reason="front-desk printer", days=30)
        h.expect(ADM, "DE:AD:BE:EF:00:04", "printer", reason="front-desk printer", days=30); self.assertEqual(h.unknown(), [])
        n.w.clock.advance(31 * DAY); self.assertEqual([x["mac"] for x in h.unknown()], ["de:ad:be:ef:00:04"])

    def test_the_list_is_for_it_and_registering_a_site_needs_a_role(self):
        n = Net()
        with self.assertRaises(PermissionError): n.h.register_site(AN, "X", "x", {}, [])
        with self.assertRaises(PermissionError): n.h.advice(SD, "HQ")
        self.assertEqual(sum(1 for r in n.w.cp.ledger.entries() if r["kind"] == "harbor.denied"), 2)


class EastWestTests(unittest.TestCase):
    def test_one_machine_reaching_administration_services_on_many_hosts_is_flagged_once_with_the_device_named(self):
        n = Net(); n.known()
        for i in range(20): n.s.flow("10.0.10.22", f"10.0.20.{100 + i}", 445, src_zone="users", dst_zone="servers")
        n.sync(); f = [x for x in n.h.poll() if x.family == "lateral_movement"]; self.assertEqual((len(f), f[0].entity_id, f[0].technique, f[0].details["targets"]), (1, "LT-22", "T1021", 20)); self.assertEqual(n.h.poll(), [])

    def test_slow_or_few_connections_and_non_admin_ports_are_not_fan_out(self):
        n = Net(); n.known()
        for i in range(30): n.s.flow("10.0.10.17", f"10.0.20.{i + 1}", 443, src_zone="users", dst_zone="servers")
        for i in range(10): n.s.flow("10.0.10.22", f"10.0.20.{i + 1}", 445, src_zone="users", dst_zone="servers")
        n.sync(); self.assertEqual([x for x in n.h.poll() if x.family == "lateral_movement"], [])
        for i in range(20): n.s.flow("10.0.10.17", f"10.0.20.{i + 1}", 22, src_zone="users", dst_zone="servers"); n.w.clock.advance(60)                    # 20 hosts but spread over 20 minutes
        n.sync(); self.assertEqual([x for x in n.h.poll() if x.family == "lateral_movement"], [])

    def test_traffic_across_a_zone_boundary_the_policy_does_not_allow_is_flagged_once_and_allowed_flows_are_quiet(self):
        n = Net(); n.known(); n.s.flow("10.0.10.17", CROWN, 443, src_zone="users", dst_zone="servers"); n.s.flow("10.0.30.44", CROWN, 445, src_zone="guest", dst_zone="servers"); n.s.flow("10.0.30.44", CROWN, 445, src_zone="guest", dst_zone="servers"); n.sync()
        f = [x for x in n.h.poll() if x.family == "zone_violation"]; self.assertEqual(len(f), 1); self.assertEqual((f[0].details["from"], f[0].details["to"], f[0].details["port"]), ("guest", "servers", 445)); self.assertIn("does not allow", f[0].summary)


class SensorTests(unittest.TestCase):
    def test_a_silent_sensor_is_a_gap_not_a_quiet_network(self):
        n = Net(); self.assertEqual(n.h.coverage_gaps(), [])
        n.h.last_seen.pop("HQ"); self.assertIn("ever reported", n.h.coverage_gaps()[0]["reason"]); n.known(); self.assertEqual(n.h.coverage_gaps(), [])
        n.w.clock.advance(901); self.assertIn("last reported 15 minutes ago", n.h.coverage_gaps()[0]["reason"])

    def test_a_site_that_loses_its_link_buffers_and_forwards_and_counts_what_it_could_not_keep(self):
        n = Net(); n.s.max = 50; n.s.online = False
        for i in range(80): n.s.flow("10.0.10.17", "10.0.20.5", 443, src_zone="users", dst_zone="servers")
        self.assertEqual(n.sync(), {"sent": 0, "lost": 30, "queued": 50}); n.s.online = True
        r = n.sync(); self.assertEqual((r["sent"], r["lost"]), (50, 30)); self.assertEqual(n.h.gaps[-1]["lost"], 30); self.assertTrue(any(e["kind"] == "harbor.sensor_gap" and e["public"]["records_lost"] == 30 for e in n.w.cp.ledger.entries()))

    def test_unregistered_sites_are_refused(self):
        n = Net()
        with self.assertRaises(KeyError): n.h.ingest("elsewhere", [])

    def test_no_payload_fields_exist_in_what_the_sensor_sends(self):
        n = Net(); n.s.flow("10.0.10.17", "10.0.20.5", 443, nbytes=1234, src_zone="users", dst_zone="servers"); rec = list(n.s.buf)[0]
        self.assertEqual(set(rec), {"kind", "src_ip", "dst_ip", "dst_port", "proto", "bytes", "src_zone", "dst_zone", "ts", "site"})


class AdviceTests(unittest.TestCase):
    def observe(self, n, days):
        n.known()
        for d in range(days):
            for i in range(5): n.s.flow("10.0.10.17", f"10.0.20.{i + 1}", 443, src_zone="users", dst_zone="servers")
            n.sync(); n.w.clock.advance(DAY)

    def test_advice_waits_for_enough_observation_and_says_so(self):
        n = Net(); self.observe(n, 5); a = n.h.advice(ADM, "HQ"); self.assertEqual((a["status"], a["changes"]), ("not_enough_observation", [])); self.assertIn("at least 14 days", a["message"])

    def test_after_two_weeks_unused_rules_are_proposed_for_removal_and_wide_rules_for_narrowing_with_nothing_broken(self):
        n = Net(); self.observe(n, 15); a = n.h.advice(ADM, "HQ"); self.assertEqual(a["status"], "draft"); ch = {(c["op"], c["rule"][2]): c for c in a["changes"]}
        self.assertEqual(set(ch), {("remove", 3389), ("remove", 5985), ("narrow", "*")}); self.assertEqual(ch[("narrow", "*")]["to_ports"], [443]); self.assertTrue(all(c["would_break"] == 0 for c in a["changes"]))
        self.assertIn("Rare but legitimate", a["change_request"]["caveat"])
        self.assertNotIn(("remove", 443), ch)                                                                                         # a rule that was used stays

    def test_the_change_request_is_filed_with_the_customers_tool_only_after_approval_and_can_be_withdrawn_and_nothing_else_changes(self):
        n = Net(); self.observe(n, 15); a = n.h.advice(ADM, "HQ"); before = list(n.h.sites["HQ"]["allow"]); eng = n.w.cp.engine
        r = eng.request(ActionRequest("request_network_change", ADM, ["site:HQ"], "tighten segmentation", None, {"change_request": a["change_request"]})); self.assertEqual(r.status, "pending_approval"); self.assertEqual(n.w.cp.change_tool.tickets, {})
        done = eng.approve(r.action_id, ADM2); self.assertEqual(done.status, "executed"); tid = done.detail["ticket"]; self.assertEqual(n.w.cp.change_tool.tickets[tid]["status"], "open")
        self.assertEqual(n.h.sites["HQ"]["allow"], before); self.assertIn("Nobody's network changed", done.message)                  # Halvard changed no rule
        u = eng.undo(done.action_id, ADM); u = eng.approve(u.action_id, ADM2) if u.status == "pending_approval" else u; self.assertEqual(u.status, "executed"); self.assertEqual(n.w.cp.change_tool.tickets[tid]["status"], "withdrawn")
        self.assertEqual(eng.request(ActionRequest("request_network_change", ADM, ["site:HQ"], "empty", None, {"change_request": {"changes": []}})).status, "denied")


if __name__ == "__main__":
    unittest.main()
