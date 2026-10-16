import json, pathlib, unittest
from helpers import *
from halvard.relay.authority import Authority, CustomerPolicy, PolicyError
from halvard.relay.matrix_def import MATRIX, CLASSES, ROLES
import importlib.util

ROOT = pathlib.Path(__file__).resolve().parent.parent


class AuthorityTests(unittest.TestCase):
    def test_generated_files_are_fresh(self):
        spec = importlib.util.spec_from_file_location("gen", ROOT / "tools" / "gen_matrix.py")
        g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
        js, md = g.render()
        self.assertEqual(js, (ROOT / "policy" / "authority_matrix.json").read_text(encoding="utf-8"))
        self.assertEqual(md, (ROOT / "docs" / "03-authority-matrix.md").read_text(encoding="utf-8"))

    def test_destructive_actions_never_auto_on_sensitive_classes(self):
        for a in MATRIX:
            if a["destructive"]:
                for c in ("production", "clinical", "privileged"):
                    self.assertIn(a["floor"][c], ("approve", "two_person"), f"{a['key']}/{c}")
                    self.assertIn(a["approval"][c], ("approve", "two_person"), f"{a['key']}/{c}")

    def test_every_action_has_reversal_statement_and_known_roles(self):
        for a in MATRIX:
            self.assertTrue(a["reversal"])
            for r in a["request_roles"] + a["approve_roles"]:
                self.assertIn(r, ROLES)
            self.assertNotIn("keeper_crew", a["approve_roles"])    # Keeper never approves

    def test_customer_cannot_loosen_below_floor(self):
        with self.assertRaises(PolicyError):
            Authority(CustomerPolicy(overrides={"isolate_host": {"production": "auto"}}))
        with self.assertRaises(PolicyError):
            Authority(CustomerPolicy(overrides={"remote_command": {"standard": "auto"}}))

    def test_customer_can_tighten(self):
        a = Authority(CustomerPolicy(overrides={"isolate_host": {"standard": "two_person"}}))
        self.assertEqual(a.requirement("isolate_host", "standard").approvals_needed, 2)

    def test_clinical_isolation_needs_two_people(self):
        self.assertEqual(Authority().requirement("isolate_host", "clinical").level, "two_person")

    def test_strictest_wins(self):
        a = Authority()
        r = a.strictest([a.requirement("isolate_host", "standard"), a.requirement("isolate_host", "clinical")])
        self.assertEqual(r.level, "two_person")


if __name__ == "__main__":
    unittest.main()
