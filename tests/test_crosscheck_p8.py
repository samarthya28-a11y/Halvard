"""Independent cross-check, phase 8. The wall, the lock, Keeper, and redaction."""
import os, unittest
from helpers import *
from rig8 import *
from halvard.cases import CaseFinding
from halvard.fabric.crypto import ReferenceKMS
from halvard.fabric.deployment import build_bundle
from halvard.fabric.keeper import KeeperDesk
from halvard.fabric.platform import AccessRefused, Member


class WallMethodTests(unittest.TestCase):
    def test_a_caller_who_is_not_a_member_cannot_import_a_bundle_or_place_a_call_for_another_company(self):
        w = World8()
        bdir = os.path.join(w.tmp, "bundle")
        build_bundle(bdir, 2, VENDOR_KEY, w.clock.now(), iocs=["deadbeef"])
        before = list(w.p.tenants["globex"].cp.fleet.agents["LT-1"].bundle.known_bad_sha256)
        with self.assertRaises(AccessRefused):
            w.p.import_bundle("globex", bdir, VENDOR_KEY)
        self.assertEqual(list(w.p.tenants["globex"].cp.fleet.agents["LT-1"].bundle.known_bad_sha256), before)
        with self.assertRaises(AccessRefused):
            w.p.external_call("acme", "https://evil.example", "lookup", lambda: None)
        with self.assertRaises(AccessRefused):
            w.p.customer(Member("globex", "acme-it_admin", "it_admin"))

    def test_revoking_the_customer_key_refuses_export_as_well_as_sign_in(self):
        kms = ReferenceKMS(ManualClock(), "bank-kms")
        w = World8(bank_kms=kms)
        self.assertTrue(w.p.export("bank", "eu-central"))
        kms.revoke(); w.p.refresh_key("bank")
        with self.assertRaises(AccessRefused):
            w.p.customer(w.m("bank"))
        with self.assertRaises(AccessRefused):
            w.p.export("bank", "eu-central")

    def test_two_companies_keep_the_same_entity_id_apart(self):
        w = World8()
        a, g = w.p.tenants["acme"].cp, w.p.tenants["globex"].cp
        self.assertEqual(a.store.get_entity(a.ctx, "srv-fin")["display_name"], g.store.get_entity(g.ctx, "srv-fin")["display_name"])
        a.store.update_entity(a.ctx, "srv-fin", criticality="low")
        self.assertEqual(g.store.get_entity(g.ctx, "srv-fin")["criticality"], "crown_jewel")
        self.assertNotIn("p:gary", a.store.list_entities(a.ctx))


class KeeperBoundaryTests(unittest.TestCase):
    def test_a_keeper_grant_for_one_region_does_not_let_a_crew_in_another_region_act(self):
        w = World8(); desk = KeeperDesk(w.p)
        w.p.allow_access_from(w.m("acme", "owner"), "us-east")
        grant = desk.set_charter(w.m("acme", "owner"), ["suspend_ai_agent"])
        w.p.revoke_access(w.m("acme", "owner"), grant.id)
        w.p.open_access(w.m("acme", "owner"), "keeper", "keeper_crew", "eu-west", {"cases", "act"}, 60, standing=True)
        desk.hire("crew-us", "us-east"); desk.assign("crew-us", "acme")
        with self.assertRaises(AccessRefused):
            w.p.delegated("acme", "keeper", "keeper_crew", "us-east", "act")
        with self.assertRaises(PermissionError):
            desk.elevate("crew-us", "acme", 30, "night shift from the US")

    def test_redaction_catches_a_name_when_the_case_text_uses_a_different_case(self):
        w = World8(); desk = KeeperDesk(w.p)
        desk.set_charter(w.m("acme", "owner"), ["suspend_ai_agent"])
        desk.hire("crew-eu", "eu-west"); desk.assign("crew-eu", "acme")
        w.p.tenants["acme"].cp.cases.add(CaseFinding(
            "f-redact", "ward", "endpoint_activity", "LT-1", 0.8,
            "ALICE KIM exported the payroll file", "why", w.clock.now()))
        rows = desk.queue("crew-eu")
        blob = " ".join(r["headline"] for r in rows)
        self.assertNotRegex(blob, r"(?i)alice")
        self.assertNotRegex(blob, r"(?i)\bkim\b")
