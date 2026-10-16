import os, unittest
from helpers import *
from rig7 import *
from halvard.ward.agent import EgressBlocked, NeedsJustification

SHADOW, ENT = "askly.example-ai.test", "workspace.northwind-ai.example-ai.test"
ROWS = [{"user": f"u{i}@acme.com", "domain": SHADOW, "bytes_out": 6 << 20, "device": "LT-17"} for i in range(6)] + [{"user": "a@acme.com", "domain": "codepal.example-ai.test", "bytes_out": 1 << 20},
        {"user": "a@acme.com", "domain": "unrelated.example.test", "bytes_out": 99 << 20}]


class InventoryTests(unittest.TestCase):
    def test_tools_are_found_from_traffic_grants_and_devices_and_shadow_ones_are_listed_first_with_reasons(self):
        w = World7(); inv = w.cp.lumen.inventory
        self.assertIsNone(inv.tool_for_domain("notaskly.example-ai.test")); self.assertIsNone(inv.tool_for_domain("askly.example-ai.test.evil.test")); self.assertEqual(inv.tool_for_domain("chat.askly.example-ai.test").key, "askly")
        w.cp.idp.add_app("askly", "Askly", cae=False); w.cp.idp.grants.append({"user": "z@acme.com", "app": "askly", "scopes": ["Files.Read.All"], "by": "z", "ts": 0, "revoked": False})
        w.host.software["codepal-plugin"] = "1.0"; inv.from_proxy(ROWS); inv.from_idp(w.cp.idp); inv.from_devices(w.cp.glass.reports())
        r = {x["key"]: x for x in inv.report()}; self.assertEqual(set(r), {"askly", "codepal"})                     # the unrelated domain is not an AI tool
        self.assertEqual((r["askly"]["state"], r["askly"]["users"], r["askly"]["sent_mb"]), ("shadow", 7, 36.0)); self.assertIn("sign-in provider grant", r["askly"]["sources"]); self.assertIn("web proxy", r["askly"]["sources"])
        self.assertIn("installed on a device", r["codepal"]["sources"]); self.assertIn("customer record says the vendor trains on inputs", r["codepal"]["reasons"])
        self.assertIn("whether the vendor trains on inputs is unknown", r["askly"]["reasons"]); self.assertEqual(r["askly"]["rating"], "high")
        self.assertTrue(all(x["state"] == "shadow" for x in inv.report()))

    def test_the_rating_is_exactly_the_sum_of_its_reasons_so_unknown_vendor_terms_always_count(self):
        w = World7(); inv = w.cp.lumen.inventory; inv.sanction(ADM, "askly", "standard"); inv.from_proxy([{"user": "a@acme.com", "domain": "askly.example-ai.test", "bytes_out": 21 << 20}])
        r = inv.report()[0]; self.assertEqual(r["rating"], "medium"); self.assertEqual(sorted(r["reasons"]), ["21 MB sent", "how long the vendor keeps inputs is unknown", "whether the vendor trains on inputs is unknown"])
        inv.from_proxy([{"user": "a@acme.com", "domain": ENT, "bytes_out": 1}]); nw = next(x for x in inv.report() if x["key"] == "northwind-ai")
        self.assertEqual((nw["state"], nw["rating"], nw["reasons"]), ("shadow", "low", ["not approved by IT"]))              # known good terms: only the lack of approval counts

    def test_approving_a_tool_needs_a_role_and_an_enterprise_tier_needs_the_customers_own_record_of_the_terms(self):
        w = World7(); inv = w.cp.lumen.inventory; inv.from_proxy(ROWS)
        with self.assertRaises(PermissionError): inv.sanction(AN, "askly", "standard")
        with self.assertRaises(ValueError) as cm: inv.sanction(ADM, "askly", "enterprise"); 
        self.assertIn("does not train on inputs", str(cm.exception))
        inv.sanction(ADM, "askly", "standard"); inv.sanction(ADM, "northwind-ai", "enterprise")
        r = {x["key"]: x for x in inv.report()}; self.assertEqual((r["askly"]["state"], r["askly"]["tier"]), ("sanctioned", "standard")); self.assertLess(r["askly"]["reasons"].count("not approved by IT"), 1)
        inv.unsanction(ADM, "askly"); self.assertEqual({x["key"]: x["state"] for x in inv.report()}["askly"], "shadow")
        self.assertEqual([e["public"]["tool"] for e in w.cp.ledger.entries() if e["kind"] == "lumen.tool_sanctioned"], ["askly", "northwind-ai"])
        self.assertEqual(inv.dlp_map()[ENT], "ai_enterprise"); self.assertEqual(inv.dlp_map()[SHADOW], "ai_shadow")


class DevicePolicyTests(unittest.TestCase):
    def setup_world(self):
        w = World7(); inv = w.cp.lumen.inventory; inv.sanction(ADM, "askly", "standard"); inv.sanction(ADM, "northwind-ai", "enterprise")
        w.dlp = {**w.dlp, "ai": inv.dlp_map()}; w.cp.push_dlp(w.dlp); w.agent.set_online(False); return w

    def send(self, w, data, domain):
        return w.agent.check_egress(300, "ai_prompt", os.path.join(w.tmp, "work", "prompt.txt"), data, {"domain": domain})

    def test_regulated_data_cannot_go_to_an_ai_tool_except_the_enterprise_one_with_a_reason_and_this_works_offline(self):
        w = self.setup_world()
        d = self.send(w, CARDS, SHADOW); self.assertEqual((d.action, d.rule), ("block", "ai-regulated-shadow")); self.assertIn("cannot be sent to this AI tool", d.message)
        self.assertEqual(self.send(w, CARDS, "pixelmind.example-ai.test").rule, "ai-regulated-shadow")                  # a catalog tool nobody approved
        self.assertEqual(self.send(w, CARDS, "brand-new-ai.test").rule, "ai-regulated-shadow")                            # an AI domain the device has never heard of is shadow
        e = self.send(w, CARDS, ENT); self.assertEqual((e.action, e.rule), ("justify", "ai-regulated-enterprise"))
        w.agent.justify("ai_prompt", os.path.join(w.tmp, "work", "prompt.txt"), CARDS, {"domain": ENT}, "Reconciling the March card refunds"); self.assertEqual(self.send(w, CARDS, ENT).action, "allow")
        self.assertEqual(self.send(w, CARDS, SHADOW).action, "block")                                                       # a reason for one door does not open another
        blob = str(list(w.agent.spool.entries())); self.assertNotIn(VISA, blob); self.assertIn("ai-regulated-shadow", blob)

    def test_confidential_internal_and_plain_text_follow_the_tier_and_secrets_are_never_allowed(self):
        w = self.setup_world(); conf = b"CONFIDENTIAL salary table. Account GB82WEST12345698765432 " * 3
        self.assertEqual((self.send(w, conf, "pixelmind.example-ai.test").action, self.send(w, conf, "askly.example-ai.test").action, self.send(w, conf, ENT).action), ("block", "justify", "allow"))
        self.assertEqual(self.send(w, PLAIN, ENT).action, "allow"); self.assertEqual(self.send(w, PLAIN, SHADOW).action, "allow")
        for dom in (SHADOW, ENT, "askly.example-ai.test"):
            s = self.send(w, SECRET_ENV, dom); self.assertEqual((s.action, s.rule, s.justifiable), ("block", "secrets-anywhere", False))
        with self.assertRaises(PermissionError): w.agent.justify("ai_prompt", os.path.join(w.tmp, "work", "prompt.txt"), SECRET_ENV, {"domain": ENT}, "I really need this one")


if __name__ == "__main__":
    unittest.main()
