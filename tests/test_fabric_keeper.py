import json, unittest
from rig8 import *
from halvard.cases import CaseFinding
from halvard.fabric.keeper import MAX_ELEVATION_MIN


def seed_case(w, tenant, summary="Alice Kim's laptop LT-1 ran something odd."):
    cp = w.p.tenants[tenant].cp
    cp.lumen.registry.register(Principal("u", "it_admin"), "bot", "Bot", "p:alice" if tenant == "acme" else "p:gary", {"kind": "aws_role", "ref": "r"}, {"files": {"actions": ["read"]}}); cp.lumen.sync_graph()
    c = cp.cases.add(CaseFinding("f1", "ward", "malware", "LT-1", 0.8, summary, "why", w.clock.now())); return cp, c


def desk(w, actions=("suspend_ai_agent", "place_tripwires"), mode="always", see_people=False, tenants=("acme",), crew="k1", home="eu-west"):
    d = KeeperDesk(w.p); d.hire(crew, home)
    for t in tenants:
        d.assign(crew, t); d.set_charter(w.m(t, "owner"), actions, mode=mode, contact="oncall", see_people=see_people)
    return d


class CharterTests(unittest.TestCase):
    def test_the_charter_is_the_customers_written_list_and_cannot_include_what_the_matrix_forbids(self):
        w = World8(); d = KeeperDesk(w.p)
        with self.assertRaises(ValueError): d.set_charter(w.m("acme", "owner"), ["release_legal_hold"])
        with self.assertRaises(ValueError): d.set_charter(w.m("acme", "owner"), ["not_an_action"])
        with self.assertRaises(PermissionError): d.set_charter(w.m("acme", "analyst"), ["suspend_ai_agent"])
        with self.assertRaises(AccessRefused): d.set_charter(Member("acme", "mallory", "owner"), ["suspend_ai_agent"])
        g = d.set_charter(w.m("acme", "owner"), ["suspend_ai_agent"]); self.assertTrue(g.standing); self.assertTrue(any(r["kind"] == "fabric.keeper_charter" for r in w.p.tenants["acme"].cp.ledger.entries()))

    def test_without_a_charter_an_assignment_or_a_grant_the_crew_gets_nothing(self):
        w = World8(); d = KeeperDesk(w.p); d.hire("k1", "eu-west")
        with self.assertRaises(PermissionError): d.queue("k1") or d.elevate("k1", "acme", 30, "x")
        d.assign("k1", "acme")
        with self.assertRaises(AccessRefused): d.elevate("k1", "acme", 30, "x")                          # no charter
        d.set_charter(w.m("acme", "owner"), ["suspend_ai_agent"]); self.assertTrue(d.elevate("k1", "acme", 30, "case C-1"))
        with self.assertRaises(AccessRefused): d.elevate("k1", "globex", 30, "x")                        # not assigned


class WallsAreIndependentTests(unittest.TestCase):
    def test_a_standing_grant_without_a_charter_is_not_enough(self):
        w = World8(); d = KeeperDesk(w.p); d.hire("k1", "eu-west"); d.assign("k1", "acme"); w.p.open_access(w.m("acme", "owner"), "keeper", "keeper_crew", "*", {"cases", "act"}, 60)
        with self.assertRaises(AccessRefused) as cm: d.elevate("k1", "acme", 30, "x")
        self.assertIn("no Keeper charter", str(cm.exception))

    def test_a_charter_and_a_grant_are_not_enough_for_a_crew_member_who_is_not_assigned(self):
        w = World8(); w.p.allow_access_from(w.m("globex", "owner"), "eu-west"); d = desk(w, tenants=("acme", "globex"), crew="k1")
        d.hire("k2", "eu-west"); d.assign("k2", "acme")
        with self.assertRaises(AccessRefused) as cm: d.elevate("k2", "globex", 30, "x")
        self.assertIn("not assigned", str(cm.exception)); self.assertTrue(d.elevate("k2", "acme", 30, "x"))


class DeskTests(unittest.TestCase):
    def test_the_queue_spans_assigned_companies_without_mixing_their_data_and_hides_people(self):
        w = World8(); w.p.allow_access_from(w.m("globex", "owner"), "eu-west"); cpa, ca = seed_case(w, "acme"); cpg, cg = seed_case(w, "globex", "Gary Stone's laptop LT-1 ran something odd.")
        d = desk(w, tenants=("acme", "globex")); q = d.queue("k1"); self.assertEqual(sorted(x["tenant"] for x in q), ["acme", "globex"])
        blob = json.dumps(q); self.assertNotIn("Alice", blob); self.assertNotIn("Gary", blob); self.assertIn("[person", blob)
        view = d.case_view("k1", "acme", ca.id); self.assertNotIn("Alice", view); self.assertNotIn("alice@acme.com", view); self.assertNotIn("Gary", view)
        d2 = desk(w, see_people=True, crew="k2"); self.assertIn("Alice Kim", d2.case_view("k2", "acme", ca.id))

    def test_a_crew_member_in_the_wrong_region_is_refused_and_the_company_can_allow_it(self):
        w = World8(); seed_case(w, "globex"); d = desk(w, tenants=("globex",), home="eu-west")
        self.assertEqual(d.queue("k1"), [])
        with self.assertRaises(AccessRefused) as cm: d.elevate("k1", "globex", 30, "x")
        self.assertIn("may not access this company's data", str(cm.exception)); self.assertTrue(any("may not access" in x for x in refused(w, "globex")))
        w.p.allow_access_from(w.m("globex", "owner"), "eu-west"); self.assertTrue(d.elevate("k1", "globex", 30, "x"))

    def test_acting_needs_just_in_time_elevation_for_that_company_that_expires(self):
        w = World8(); cp, c = seed_case(w, "acme"); d = desk(w)
        with self.assertRaises(PermissionError): d.act("k1", "acme", "suspend_ai_agent", ["ai:bot"], "r", c.id)
        with self.assertRaises(ValueError): d.elevate("k1", "acme", MAX_ELEVATION_MIN + 1, "x")
        with self.assertRaises(ValueError): d.elevate("k1", "acme", 30, " ")
        d.elevate("k1", "acme", 30, "investigating case"); self.assertEqual(d.act("k1", "acme", "suspend_ai_agent", ["ai:bot"], "agent exfil", c.id).status, "executed")
        w.clock.advance(31 * 60)
        with self.assertRaises(PermissionError): d.act("k1", "acme", "suspend_ai_agent", ["ai:bot"], "again", c.id)
        self.assertTrue(any("no elevation" in str(x) for x in [r["public"] for r in cp.ledger.entries() if r["kind"] == "fabric.keeper_refused"]))

    def test_elevation_in_one_company_does_not_work_in_another(self):
        w = World8(); w.p.allow_access_from(w.m("globex", "owner"), "eu-west"); seed_case(w, "acme"); cpg, cg = seed_case(w, "globex"); d = desk(w, tenants=("acme", "globex"))
        d.elevate("k1", "acme", 30, "acme case")
        with self.assertRaises(PermissionError): d.act("k1", "globex", "suspend_ai_agent", ["ai:bot"], "wrong company", cg.id)
        self.assertEqual(cpg.lumen.registry.agents["bot"].status, "active")

    def test_the_charter_limits_what_the_crew_may_do_even_where_the_matrix_would_allow_it(self):
        w = World8(); cp, c = seed_case(w, "acme"); d = desk(w, actions=("place_tripwires",)); d.elevate("k1", "acme", 30, "x")
        with self.assertRaises(PermissionError) as cm: d.act("k1", "acme", "suspend_ai_agent", ["ai:bot"], "r", c.id)
        self.assertIn("not on this company's Keeper charter", str(cm.exception)); self.assertEqual(cp.lumen.registry.agents["bot"].status, "active")

    def test_keeper_only_proposes_what_the_matrix_says_it_may_only_propose_and_a_customer_approver_runs_it(self):
        w = World8(); cp, c = seed_case(w, "acme"); d = desk(w); d.elevate("k1", "acme", 30, "x")
        r = d.act("k1", "acme", "place_tripwires", ["LT-1"], "ransomware tripwire", c.id, {"specs": [{"id": "k-1", "path": "/tmp/halvard-keeper-trap/x.xlsx", "kind": "encryption"}]})
        self.assertEqual(r.status, "pending_approval"); self.assertEqual(cp.fleet.agents["LT-1"].tripwires, {})
        self.assertEqual(cp.engine.approve(r.action_id, Principal("k1", "keeper_crew")).status, "denied"); self.assertIn(r.action_id, cp.engine.pending)      # the crew cannot approve its own proposal
        self.assertEqual(cp.engine.approve(r.action_id, Principal("acme-it_admin", "it_admin")).status, "executed")

    def test_out_of_hours_charters_refuse_action_during_business_hours_and_allow_it_at_night(self):
        w = World8(); cp, c = seed_case(w, "acme"); d = desk(w, mode="out_of_hours"); d.elevate("k1", "acme", 120, "x")        # clock starts at 08:53 UTC; business hours are 08:00-18:00
        with self.assertRaises(PermissionError) as cm: d.act("k1", "acme", "suspend_ai_agent", ["ai:bot"], "r", c.id)
        self.assertIn("out of hours", str(cm.exception)); w.clock.advance(9 * 3600 + 600); d.elevate("k1", "acme", 120, "night shift")
        self.assertEqual(d.act("k1", "acme", "suspend_ai_agent", ["ai:bot"], "r", c.id).status, "executed")

    def test_revoking_the_grant_stops_the_crew_at_once_and_the_report_shows_everything_it_did(self):
        w = World8(); cp, c = seed_case(w, "acme"); d = desk(w); d.elevate("k1", "acme", 30, "case C-1"); d.act("k1", "acme", "suspend_ai_agent", ["ai:bot"], "agent exfil", c.id); d.queue("k1")
        rep = d.report(w.m("acme", "owner")); kinds = [r["kind"] for r in rep]; self.assertEqual((kinds.count("fabric.keeper_elevated"), kinds.count("fabric.keeper_action"), kinds.count("fabric.keeper_viewed")), (1, 1, 1))
        self.assertEqual(next(r for r in rep if r["kind"] == "fabric.keeper_action")["action"], "suspend_ai_agent")
        with self.assertRaises(PermissionError): d.report(w.m("acme", "analyst"))
        gid = next(g.id for g in w.p.delegations.grants.values() if g.grantee == "keeper" and g.tenant == "acme"); w.p.revoke_access(w.m("acme", "owner"), gid)
        with self.assertRaises(AccessRefused): d.act("k1", "acme", "suspend_ai_agent", ["ai:bot"], "again", c.id)
        self.assertEqual(d.queue("k1"), [])

    def test_a_private_deployment_cannot_be_operated_by_a_remote_crew(self):
        w = World8(); d = KeeperDesk(w.p); d.hire("k1", "eu-central"); d.assign("k1", "bank"); d.set_charter(w.m("bank", "owner"), ["suspend_ai_agent"])
        with self.assertRaises(AccessRefused) as cm: d.elevate("k1", "bank", 30, "x")
        self.assertIn("private deployment", str(cm.exception))


def refused(w, tenant): return [r["public"]["why"] for r in w.p.tenants[tenant].cp.ledger.entries() if r["kind"] in ("fabric.access_refused",)]


if __name__ == "__main__":
    unittest.main()
