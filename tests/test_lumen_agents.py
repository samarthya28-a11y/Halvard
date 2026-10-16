import unittest
from helpers import *
from rig7 import *


class RegistryTests(unittest.TestCase):
    def test_identities_the_customer_tagged_as_agents_are_found_and_listed_as_unowned_and_unreviewed(self):
        w = World7(); cp = w.cp; cp.idp.add_user("bot-sales@acme.com", ai_agent=True, is_service=True); cp.aws.add_role("assistant-role", admin=True, ai_agent=True)
        found = cp.lumen.registry.discover_identities(); self.assertEqual(sorted(found), ["aws:assistant-role", "idp:bot-sales@acme.com"]); self.assertEqual(cp.lumen.registry.discover_identities(), [])
        r = {x["id"]: x for x in cp.lumen.registry.report()}["aws:assistant-role"]
        self.assertEqual((r["source"], r["tier"], r["admin"]), ("identity_tag", "unreviewed", True)); self.assertIn("no owner", r["problems"]); self.assertIn("no tools declared, so every call is refused", r["problems"]); self.assertIn("it is an administrator.", r["problems"])

    def test_registering_needs_a_role_an_owner_and_declared_actions(self):
        w = World7(); reg = w.cp.lumen.registry; ident = {"kind": "aws_role", "ref": "report-role"}
        with self.assertRaises(PermissionError): reg.register(SD, "x", "X", OWNER_P, ident, {"files": {"actions": ["read"]}})
        with self.assertRaises(ValueError): reg.register(AN, "x", "X", None, ident, {"files": {"actions": ["read"]}})
        with self.assertRaises(ValueError): reg.register(AN, "x", "X", OWNER_P, ident, {"files": {"actions": []}})
        self.assertEqual(reg.register(AN, "x", "X", OWNER_P, ident, {"files": {"actions": ["read"]}}).tier, "unreviewed")

    def test_a_review_is_refused_while_the_identity_can_reach_more_than_the_tools_need_and_names_what(self):
        w = World7(); reg = w.cp.lumen.registry
        with self.assertRaises(PermissionError): reg.review(AN, "report-bot")
        with self.assertRaises(ValueError) as cm: reg.review(ADM, "report-bot")
        self.assertIn("s3:cust-exports", str(cm.exception)); self.assertEqual(reg.agents["report-bot"].tier, "unreviewed")
        w.cp.aws.roles["report-role"].buckets = set(); a = reg.review(ADM, "report-bot"); self.assertEqual((a.tier, a.reviewed_by), ("reviewed", "u-adm"))
        w.cp.aws.roles["report-role"].admin = True; reg.agents["report-bot"].tier = "unreviewed"
        with self.assertRaises(ValueError): reg.review(ADM, "report-bot")

    def test_an_agent_with_no_tools_cannot_be_reviewed_and_an_administrator_identity_blocks_review(self):
        w = World7(); reg = w.cp.lumen.registry; w.cp.aws.add_role("admin-bot", admin=True)
        reg.register(AN, "admin-bot", "Admin bot", OWNER_P, {"kind": "aws_role", "ref": "admin-bot"}, {"files": {"actions": ["read"], "stores": []}})
        with self.assertRaises(ValueError) as cm: reg.review(ADM, "admin-bot")
        self.assertIn("administrator", str(cm.exception)); reg.agents["idp:x"] = reg.observe("idp:x")
        with self.assertRaises(ValueError): reg.review(ADM, "idp:x")

    def test_agents_are_graph_entities_that_act_for_their_owner(self):
        w = World7(); cp = w.cp; self.assertEqual(cp.store.get_entity(cp.ctx, "ai:report-bot")["kind"], "ai_agent")
        self.assertIn(("ai:report-bot", "acts_for", "p:alice"), [(s, r, d) for s, r, d, _ in cp.store.edges(cp.ctx)])


if __name__ == "__main__":
    unittest.main()
