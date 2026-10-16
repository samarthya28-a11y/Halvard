import json, os, unittest
from rig8 import *
from halvard.tenancy import TenantContext, TenantIsolationError
from halvard.ledger.audit import AuditLog


def refused(w, tenant): return [r["public"]["why"] for r in w.p.tenants[tenant].cp.ledger.entries() if r["kind"] in ("fabric.access_refused", "tenant.access_denied", "fabric.support_refused")]


class WallTests(unittest.TestCase):
    def test_two_companies_with_the_same_entity_ids_on_one_database_never_see_each_other(self):
        w = World8(); a, g = w.p.tenants["acme"].cp, w.p.tenants["globex"].cp
        self.assertEqual(a.store.get_entity(a.ctx, "srv-fin")["tenant_id"], "acme"); self.assertEqual(g.store.get_entity(g.ctx, "srv-fin")["tenant_id"], "globex")
        self.assertIn("p:alice", a.store.list_entities(a.ctx)); self.assertNotIn("p:alice", g.store.list_entities(g.ctx)); self.assertNotIn("p:gary", a.store.list_entities(a.ctx))
        a.store.update_entity(a.ctx, "srv-fin", criticality="low"); self.assertEqual(g.store.get_entity(g.ctx, "srv-fin")["criticality"], "crown_jewel")

    def test_a_forged_company_identity_gets_nothing_and_the_attempt_is_recorded_in_the_targets_ledger(self):
        w = World8()
        with self.assertRaises(AccessRefused): w.p.customer(Member("globex", "mallory", "it_admin"))
        with self.assertRaises(AccessRefused): w.p.customer(Member("globex", "acme-it_admin", "it_admin"))             # another company's real admin id, claimed against globex
        with self.assertRaises(AccessRefused): w.p.open_access(Member("globex", "acme-it_admin", "owner"), "mallory", "service_provider", "eu-west", {"act"}, 60)
        self.assertEqual(len(refused(w, "globex")), 3); self.assertEqual(refused(w, "acme"), [])
        self.assertIs(w.p.customer(w.m("acme")), w.p.tenants["acme"].cp)

    def test_a_context_for_one_company_cannot_read_another_even_with_a_guessed_id(self):
        w = World8(); s = w.p.store; evil = TenantContext("acme", "x", "it_admin")
        with self.assertRaises(KeyError): s.get_entity(evil, "p:gary")
        with self.assertRaises(TenantIsolationError): s.get_entity(TenantContext("nope", "x", "it_admin"), "p:gary")
        with self.assertRaises(TenantIsolationError): s.get_object(evil, "../globex/anything")
        with self.assertRaises(TenantIsolationError): s.get_object(evil, "/etc/passwd")
        with self.assertRaises(TenantIsolationError): s.list_entities(TenantContext("globex", "halvard-eng", "halvard_support"))

    def test_support_access_needs_the_companys_grant_and_a_grant_for_one_company_is_useless_for_another(self):
        w = World8(); gid = w.p.open_support_grant(w.m("acme"), "halvard-eng-1", 30, "eu-west"); s = w.p.store
        self.assertTrue(s.list_entities(TenantContext("acme", "halvard-eng-1", "halvard_support", gid)))
        for ctx in (TenantContext("globex", "halvard-eng-1", "halvard_support", gid), TenantContext("acme", "halvard-eng-2", "halvard_support", gid)):
            with self.assertRaises(TenantIsolationError): s.list_entities(ctx)
        w.clock.advance(31 * 60)
        with self.assertRaises(TenantIsolationError): s.list_entities(TenantContext("acme", "halvard-eng-1", "halvard_support", gid))
        self.assertTrue(any("no open support grant" in x for x in refused(w, "globex")))        # the refused attempt is in the company it was aimed at

    def test_ledgers_are_separate_and_a_record_from_one_cannot_be_passed_off_in_another(self):
        w = World8(); a, g = w.p.tenants["acme"].cp.ledger, w.p.tenants["globex"].cp.ledger
        self.assertNotEqual(a._key, g._key); self.assertTrue(a.verify()[0] and g.verify()[0])
        w.p.tenants["acme"].cp.ledger.append("probe", "x", "system", "s", {"n": 1})
        line = open(a.path, "rb").read().splitlines()[-1]; open(g.path, "ab").write(line + b"\n")
        ok, problems = g.verify(); self.assertFalse(ok)

    def test_device_policy_signed_for_one_company_is_rejected_by_another_companys_device(self):
        w = World8(); a, g = w.p.tenants["acme"], w.p.tenants["globex"]
        import dataclasses
        agent_g = g.cp.fleet.agents["LT-1"]; b = dataclasses.replace(a.cp.fleet.agents["LT-1"].bundle, version=50).sign(a.cp.fleet.key)
        self.assertFalse(agent_g.apply_bundle(b.__dict__.copy(), g.cp.fleet.key)); self.assertTrue(any(e["kind"] == "ward.policy_rejected" for e in agent_g.spool.entries()))

    def test_activity_in_one_company_does_not_show_in_another(self):
        w = World8(); a, g = w.p.tenants["acme"].cp, w.p.tenants["globex"].cp
        a.fleet.agents["LT-1"].host.software["pdfviewer"] = "11.1"; ids = lambda cp: {x.id for x in cp.glass.evaluate()}
        self.assertIn("HLV-SAMPLE-0002@LT-1", ids(a)); self.assertNotIn("HLV-SAMPLE-0002@LT-1", ids(g))
        a.lumen.registry.register(Principal("u", "it_admin"), "bot", "Bot", "p:alice", {"kind": "aws_role", "ref": "r"}, {"files": {"actions": ["read"]}}); self.assertNotIn("bot", g.lumen.registry.agents)

    def test_a_company_can_only_be_reached_through_the_platform_by_its_own_enrolled_people(self):
        w = World8()
        with self.assertRaises(AccessRefused): w.p.open_support_grant(Member("acme", "intruder", "owner"), "halvard-eng", 30, "eu-west")
        with self.assertRaises(AccessRefused): w.p.portfolio(Member("holdco", "intruder", "owner"))


class DelegationTests(unittest.TestCase):
    def grant(self, w, tenant="acme", who="msp-1", role="service_provider", scopes=("summary",), minutes=60, region="eu-west"):
        return w.p.open_access(w.m(tenant, "owner"), who, role, region, set(scopes), minutes)

    def test_a_provider_sees_a_summary_only_after_the_company_grants_it_and_every_use_is_in_the_companys_ledger(self):
        w = World8()
        with self.assertRaises(AccessRefused): w.p.summary("acme", "msp-1", "service_provider", "eu-west")
        self.grant(w); s = w.p.summary("acme", "msp-1", "service_provider", "eu-west")
        self.assertEqual(set(s), {"tenant", "overall", "band", "outcomes", "open_items", "fix_now"}); self.assertNotIn("Alice", json.dumps(s))
        e = [r for r in w.p.tenants["acme"].cp.ledger.entries() if r["kind"] == "fabric.delegated_access"]; self.assertEqual((len(e), e[0]["public"]["scope"]), (1, "summary")); self.assertEqual(e[0]["private"]["_actor"], "msp-1")
        with self.assertRaises(AccessRefused): w.p.summary("globex", "msp-1", "service_provider", "eu-west")                   # the grant was acme's

    def test_scope_role_grantee_region_expiry_and_revocation_are_each_enforced(self):
        w = World8(); g = self.grant(w, minutes=60)
        with self.assertRaises(AccessRefused): w.p.delegated("acme", "msp-1", "service_provider", "eu-west", "act")           # summary only
        with self.assertRaises(AccessRefused): w.p.delegated("acme", "msp-2", "service_provider", "eu-west", "summary")        # someone else
        with self.assertRaises(AccessRefused): w.p.delegated("acme", "msp-1", "keeper_crew", "eu-west", "summary")             # another role
        with self.assertRaises(AccessRefused): w.p.delegated("acme", "msp-1", "service_provider", "us-east", "summary")        # grant was for eu-west
        w.clock.advance(61 * 60)
        with self.assertRaises(AccessRefused): w.p.summary("acme", "msp-1", "service_provider", "eu-west")
        g2 = self.grant(w); w.p.summary("acme", "msp-1", "service_provider", "eu-west"); w.p.revoke_access(w.m("acme", "owner"), g2.id)
        with self.assertRaises(AccessRefused): w.p.summary("acme", "msp-1", "service_provider", "eu-west")
        self.assertTrue(any(r["kind"] == "fabric.access_revoked" for r in w.p.tenants["acme"].cp.ledger.entries()))

    def test_a_grant_made_for_one_region_does_not_work_from_another_even_if_the_company_allows_that_region(self):
        w = World8(); w.p.allow_access_from(w.m("acme", "owner"), "us-east"); self.grant(w, region="eu-west")
        with self.assertRaises(AccessRefused) as cm: w.p.summary("acme", "msp-1", "service_provider", "us-east")
        self.assertIn("different region", str(cm.exception))
        w.p.open_access(w.m("acme", "owner"), "msp-2", "service_provider", "us-east", {"summary"}, 60); self.assertIn("overall", w.p.summary("acme", "msp-2", "service_provider", "us-east"))

    def test_a_locked_company_refuses_outsiders_even_ones_with_a_valid_grant(self):
        kms = ReferenceKMS(ManualClock(), "acme-kms"); w = World8(acme_kms=kms); self.grant(w); self.assertIn("overall", w.p.summary("acme", "msp-1", "service_provider", "eu-west"))
        kms.revoke()
        with self.assertRaises(AccessRefused) as cm: w.p.summary("acme", "msp-1", "service_provider", "eu-west")
        self.assertIn("locked", str(cm.exception)); kms.restore(); self.assertIn("overall", w.p.summary("acme", "msp-1", "service_provider", "eu-west"))

    def test_only_the_companys_own_owner_or_admin_can_open_or_revoke_access_and_limits_apply(self):
        w = World8()
        with self.assertRaises(PermissionError): w.p.open_access(w.m("acme", "analyst"), "msp-1", "service_provider", "eu-west", {"summary"}, 60)
        with self.assertRaises(ValueError): w.p.open_access(w.m("acme", "owner"), "msp-1", "service_provider", "eu-west", {"summary"}, 31 * 1440)
        with self.assertRaises(ValueError): w.p.open_access(w.m("acme", "owner"), "msp-1", "service_provider", "eu-west", {"everything"}, 60)
        with self.assertRaises(ValueError): w.p.open_access(w.m("acme", "owner"), "msp-1", "superuser", "eu-west", {"summary"}, 60)
        g = self.grant(w)
        with self.assertRaises(PermissionError): w.p.revoke_access(w.m("globex", "owner"), g.id)

    def test_being_the_parent_gives_nothing_a_subsidiary_must_grant_the_summary(self):
        w = World8(); hold = w.m("holdco", "owner"); p = w.p.portfolio(hold)
        self.assertEqual({t: v.get("access") for t, v in p.items()}, {"acme": "none", "globex": "none"}); self.assertNotIn("overall", json.dumps(p))
        w.p.open_access(w.m("acme", "owner"), "holdco-owner", "group_admin", "eu-west", {"summary"}, 600)
        p = w.p.portfolio(hold); self.assertIn("overall", p["acme"]); self.assertEqual(p["globex"]["access"], "none")
        w.p.open_access(w.m("globex", "owner"), "holdco-owner", "group_admin", "eu-west", {"summary"}, 600)
        self.assertIn("may not access this company's data", w.p.portfolio(hold)["globex"]["why"])                    # globex's data stays in the US unless globex allows an EU parent
        with self.assertRaises(PermissionError): w.p.allow_access_from(w.m("globex", "analyst"), "eu-west")
        w.p.allow_access_from(w.m("globex", "owner"), "eu-west"); self.assertIn("overall", w.p.portfolio(hold)["globex"])

    def test_a_non_child_cannot_be_reached_through_the_portfolio(self):
        w = World8(); self.assertNotIn("bank", w.p.portfolio(w.m("holdco", "owner")))


if __name__ == "__main__":
    unittest.main()
