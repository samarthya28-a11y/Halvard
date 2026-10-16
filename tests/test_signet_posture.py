import unittest
from helpers import *
from rig3 import *
from halvard.signet import posture
from halvard.signet.hr import HRRecord
from halvard.signet.service import SignetService
from halvard.cases import CaseEngine, CaseFinding
from halvard.tenancy import TenantStore, TenantContext

DAY = 86400


class AccessPathTests(unittest.TestCase):
    def test_path_from_a_person_to_the_crown_jewel_and_none_for_others(self):
        w = World(); s = w.cp.signet
        paths = s.access_paths("id:ad:alice"); self.assertEqual(len(paths), 1); self.assertEqual(paths[0], "id:ad:alice -member_of-> grp:Finance-Users -can_access-> srv-fin")
        self.assertEqual(s.access_paths("id:ad:maria"), [])
        self.assertTrue(any("Domain Admins" in p for p in s.access_paths("id:ad:bob")))
        via_cloud = s.access_paths("id:idp:alice@acme.com"); self.assertTrue(via_cloud and "acts_for" in via_cloud[0])       # cloud account -> person -> directory account -> group -> server

    def test_paths_change_when_membership_changes(self):
        w = World(); s = w.cp.signet; w.cp.ad.remove_member("Finance-Users", "alice"); s.store.db.execute("DELETE FROM edge WHERE src='id:ad:alice' AND dst='grp:Finance-Users'"); s.store.db.commit()
        self.assertEqual(s.access_paths("id:ad:alice"), [])


class PostureTests(unittest.TestCase):
    def test_standing_and_unused_privilege(self):
        w = World(); idp, ad = w.cp.idp, w.cp.ad
        idp.assign_role("maria@acme.com", "Exchange Administrator", "admin-ops", mode="permanent"); idp.sign_in("maria@acme.com", "correct-horse", "198.51.100.4", LON, mfa="approve")
        w.clock.advance(5 * DAY); recs = posture.standing_privilege(idp, ad)
        by = {(r.kind, r.entity): r for r in recs}; self.assertIn(("standing_privilege", "id:idp:maria@acme.com"), by); self.assertEqual(by[("standing_privilege", "id:idp:maria@acme.com")].params["convert_to"], "jit")
        w.clock.advance(60 * DAY); recs = posture.standing_privilege(idp, ad)
        self.assertTrue(any(r.kind == "unused_privilege" and r.entity == "id:idp:maria@acme.com" and r.severity == "high" for r in recs))
        self.assertTrue(any(r.entity == "id:ad:bob" and r.kind == "unused_privilege" for r in recs))     # bob never logged on to the directory
        self.assertFalse(any(r.entity == "id:idp:bob@acme.com" for r in recs))                          # his cloud role is just-in-time

    def test_service_account_inventory_ranks_by_risk_and_names_reasons(self):
        w = World(); idp, ad = w.cp.idp, w.cp.ad
        ad.add_user("svc-sql", is_service=True, spns=["MSSQLSvc/db"]); ad.add_member("admin-ops", "Domain Admins", "svc-sql"); ad.logon("svc-sql", True, "10.0.0.5", "SQL1", logon_type=10)
        ad.add_user("svc-print", is_service=True); idp.add_user("svc-sync@acme.com", is_service=True); w.clock.advance(400 * DAY)
        inv = posture.service_account_inventory(idp, ad, owners={"svc-print": "it"}); self.assertEqual(inv[0]["name"], "svc-sql")
        self.assertEqual(set(inv[0]["risks"]) >= {"holds privileged access", "has been used interactively", "no owner recorded"}, True)
        self.assertTrue(any("Domain Admin rights" in r for r in inv[0]["risks"])); sp = next(r for r in inv if r["name"] == "svc-print"); self.assertNotIn("no owner recorded", sp["risks"])
        self.assertEqual({r["where"] for r in inv}, {"directory", "cloud"})

    def test_entitlement_drift_against_the_department_template(self):
        w = World(); base = {"Finance": {"cloud_roles": set(), "ad_groups": {"Finance-Users"}}}
        self.assertEqual(posture.entitlement_drift(w.cp.idp, w.cp.ad, w.cp.hr, base), [])
        w.cp.ad.add_member("x", "Backup Operators", "alice"); w.cp.idp.assign_role("alice@acme.com", "User Administrator", "x", mode="jit", via_jit_request="r")
        d = posture.entitlement_drift(w.cp.idp, w.cp.ad, w.cp.hr, base); self.assertEqual(len(d), 1); self.assertIn("group Backup Operators", d[0].evidence); self.assertIn("cloud role User Administrator", d[0].evidence)

    def test_joiner_mover_leaver(self):
        w = World(); cp = w.cp; idp, ad, hr = cp.idp, cp.ad, cp.hr
        hr.records["p:alice"].status = "terminated"; w.alice_signs_in()
        recs = posture.joiner_mover_leaver(idp, ad, hr); kinds = {r.kind for r in recs}
        self.assertTrue({"leaver_still_enabled", "leaver_active_sessions", "leaver_devices"} <= kinds, kinds)
        self.assertEqual(sum(1 for r in recs if r.kind == "leaver_still_enabled"), 2)       # cloud and directory
        hr.records["p:alice"].status = "active"; idp.users["alice@acme.com"].mfa_enrolled = False
        self.assertIn("joiner_without_mfa", {r.kind for r in posture.joiner_mover_leaver(idp, ad, hr)})
        hr.add(HRRecord("p:newbie", "New Hire", None, None, "active", "Finance", "p:maria", w.clock.now() - 10 * DAY)); self.assertIn("joiner_without_account", {r.kind for r in posture.joiner_mover_leaver(idp, ad, hr)})
        base = {"Finance": {"ad_groups": {"Finance-Users"}}, "IT": {"ad_groups": {"Helpdesk"}}}; ad.add_member("x", "Helpdesk", "alice")
        mv = [r for r in posture.joiner_mover_leaver(idp, ad, hr, base) if r.kind == "mover_keeps_old_access"]; self.assertEqual(len(mv), 1); self.assertIn("Helpdesk", mv[0].evidence)

    def test_recommendations_propose_actions_but_change_nothing(self):
        w = World(); w.cp.hr.records["p:alice"].status = "terminated"; before = (w.cp.idp.users["alice@acme.com"].enabled, w.cp.ad.users["alice"].enabled)
        recs = posture.joiner_mover_leaver(w.cp.idp, w.cp.ad, w.cp.hr); self.assertTrue(all(r.proposed_action in (None, "disable_account", "revoke_sessions", "force_mfa_reregistration", "remove_standing_privilege") for r in recs))
        self.assertEqual((w.cp.idp.users["alice@acme.com"].enabled, w.cp.ad.users["alice"].enabled), before)


class DeviceHealthAndConnectors(unittest.TestCase):
    def test_device_health_follows_the_agent_and_blocks_sign_in(self):
        w = World().alice_signs_in(); s = w.cp.signet
        self.assertTrue(s.push_device_health(w.agent)["compliant"])
        w.host.isolate(); h = s.push_device_health(w.agent); self.assertEqual((h["compliant"], h["reasons"]), (False, ["isolated"]))
        with self.assertRaises(Exception) as e: w.cp.idp.sign_in("alice@acme.com", "correct-horse", "198.51.100.4", LON, device_id="LT-17", mfa="approve")
        self.assertEqual(e.exception.reason, "device_noncompliant"); w.host.release(); self.assertTrue(s.push_device_health(w.agent)["compliant"])
        import pathlib; pathlib.Path(w.tmp, "lt17", "agent", "install", "ward.exe").write_bytes(b"patched"); w.agent.tamper.check()
        self.assertIn("agent tampering detected", s.push_device_health(w.agent)["reasons"])

    def test_a_silent_connector_is_a_coverage_gap(self):
        w = World(); s = w.cp.signet; self.assertEqual({g["connector"] for g in s.connector_health()}, {"idp", "ad"})
        s.poll(); self.assertEqual(s.connector_health(), []); w.clock.advance(1000); self.assertEqual(len(s.connector_health()), 2)

    def test_findings_are_stored_per_tenant_and_not_visible_to_another(self):
        w = World(); w.cp.idp.grant_consent("alice@acme.com", "mail", ["Mail.Read"]); w.cp.idp.apps["evil"] = App("evil", "Shiny Tool", publisher_verified=False, created_at=w.clock.now() - 86400)
        w.cp.idp.grant_consent("alice@acme.com", "evil", ["Mail.Read"]); w.cp.signet.poll()
        self.assertEqual(len(w.cp.store.findings(w.cp.ctx, "illicit_consent")), 1)
        w.cp.store.create_tenant("globex", "Globex"); other = TenantContext("globex", "u", "analyst"); self.assertEqual(w.cp.store.findings(other), [])
        with self.assertRaises(KeyError): w.cp.store.get_entity(other, "id:idp:alice@acme.com")


from rig3 import World


class CaseScoringTests(unittest.TestCase):
    def setUp(self):
        self.clock = ManualClock(); self.s = TenantStore(); self.s.create_tenant("t", "T"); self.c = TenantContext("t", "u", "analyst"); n = self.clock.now()
        self.s.put_entity(self.c, "p:a", "person", "Ann", n); self.s.put_entity(self.c, "p:b", "person", "Ben", n)
        self.s.put_entity(self.c, "id:a", "identity", "ann@x", n); self.s.put_entity(self.c, "id:b", "identity", "ben@x", n)
        self.s.put_entity(self.c, "D1", "device", "D1", n, criticality="high"); self.s.put_entity(self.c, "D2", "device", "D2", n)
        for e in (("id:a", "acts_for", "p:a"), ("id:b", "acts_for", "p:b"), ("p:a", "uses", "D1"), ("p:b", "uses", "D2")): self.s.put_edge(self.c, *e, n)
        self.E = CaseEngine(self.s, self.c, self.clock)

    def f(self, i, src, fam, ent, conf, ts=0): return CaseFinding(i, src, fam, ent, conf, f"s{i}", "w", self.clock.now() + ts)

    def test_same_person_across_sources_is_one_case_different_people_are_not(self):
        a = self.E.add(self.f(1, "signet", "identity_takeover", "id:a", 0.9)); b = self.E.add(self.f(2, "ward", "credential_theft", "D1", 0.7, 60)); o = self.E.add(self.f(3, "signet", "identity_takeover", "id:b", 0.9, 90))
        self.assertIs(a, b); self.assertIsNot(a, o); self.assertEqual(len(self.E.cases), 2)

    def test_time_window_separates_old_from_new(self):
        a = self.E.add(self.f(1, "signet", "identity_takeover", "id:a", 0.9)); b = self.E.add(self.f(2, "signet", "identity_takeover", "id:a", 0.9, 5 * 3600)); self.assertIsNot(a, b)

    def test_independent_sources_beat_one_detector_repeating(self):
        one = self.E.add(self.f(1, "signet", "identity_takeover", "id:b", 0.8)); self.E.add(self.f(2, "signet", "identity_takeover", "id:b", 0.8, 10)); self.E.add(self.f(3, "signet", "identity_takeover", "id:b", 0.8, 20))
        two = self.E.add(self.f(4, "signet", "identity_takeover", "id:a", 0.8)); self.E.add(self.f(5, "ward", "credential_theft", "D1", 0.8, 10))
        self.assertEqual(self.E.confidence(one)[0], 0.8); self.assertEqual(self.E.confidence(two)[0], 0.96)
        self.assertIn("Heuristic, not a calibrated probability", self.E.confidence(two)[1])

    def test_impact_orders_work_without_changing_confidence(self):
        hi = self.E.add(self.f(1, "signet", "identity_takeover", "id:a", 0.9)); lo = self.E.add(self.f(2, "signet", "identity_takeover", "id:b", 0.9))
        self.assertEqual(self.E.confidence(hi)[0], self.E.confidence(lo)[0]); self.assertGreater(self.E.priority(hi), self.E.priority(lo)); self.assertIn("D1 is high", self.E.impact(hi)[1])

    def test_impact_counts_what_the_account_can_reach_and_says_so(self):
        w = World(); w.cp.cases.reach = w.cp.signet.access_paths
        c = w.cp.cases.add(CaseFinding("x1", "signet", "identity_takeover", "id:idp:alice@acme.com", 0.9, "s", "w", w.clock.now()))
        imp, why = w.cp.cases.impact(c); self.assertEqual(imp, 1.0); self.assertIn("can reach Finance database", why)
        w2 = World(); c2 = w2.cp.cases.add(CaseFinding("x2", "signet", "identity_takeover", "id:idp:maria@acme.com", 0.9, "s", "w", w2.clock.now()))
        self.assertEqual(w2.cp.cases.impact(c2)[0], 0.7)       # maria reaches nothing marked crown jewel

    def test_repeated_identical_findings_read_as_one_line(self):
        mk = lambda i, ts: CaseFinding(i, "signet", "identity_takeover", "id:a", 0.9, "Session used elsewhere", "w", self.clock.now() + ts)
        a = self.E.add(mk(1, 0)); self.E.add(mk(2, 30))
        story = self.E.story(a); self.assertEqual(len(story), 1); self.assertIn("seen 2 times", story[0])

    def test_a_finding_that_bridges_two_cases_merges_them(self):
        a = self.E.add(self.f(1, "signet", "identity_takeover", "id:a", 0.9)); b = self.E.add(self.f(2, "signet", "identity_takeover", "id:b", 0.9, 5))
        self.assertEqual(len(self.E.cases), 2)                      # two people who merely share a computer are not one story (found by the cross-check)
        self.s.put_edge(self.c, "p:b", "acts_for", "id:a", self.clock.now())      # but a link that joins their identities does bridge them
        self.E.add(self.f(3, "signet", "identity_takeover", "id:a", 0.9, 10)); self.assertEqual(len(self.E.cases), 1)

    def test_findings_about_a_shared_computer_join_each_other_and_not_the_people_who_use_it(self):
        self.s.put_edge(self.c, "p:b", "uses", "D1", self.clock.now())
        x = self.E.add(self.f(1, "ward", "credential_theft", "D1", 0.7)); y = self.E.add(self.f(2, "hearth", "tripwire", "D1", 0.9, 5)); z = self.E.add(self.f(3, "signet", "identity_takeover", "id:b", 0.9, 8))
        self.assertEqual(x.id, y.id); self.assertNotEqual(x.id, z.id); self.assertNotIn("p:a", x.entities); self.assertNotIn("p:b", x.entities)

if __name__ == "__main__":
    unittest.main()
