import json, os, unittest
from rig8 import *
from halvard.fabric.residency import ResidencyPolicy
from halvard.fabric.crypto import ObjectCipher


def put(w, tenant, key, data):
    cp = w.p.tenants[tenant].cp; w.p.store.put_object(cp.ctx, key, data)


def get(w, tenant, key): return w.p.store.get_object(w.p.tenants[tenant].cp.ctx, key)


class CustomerKeyTests(unittest.TestCase):
    def world(self):
        self.kms = ReferenceKMS(ManualClock(), "bank-hsm"); return World8(bank_kms=self.kms)

    def test_objects_are_stored_sealed_and_read_back_and_the_key_owner_is_recorded(self):
        w = self.world(); put(w, "bank", "reports/q3.txt", b"quarterly numbers 4111111111111111")
        raw = open(w.p.store.object_path(w.p.tenants["bank"].cp.ctx, "reports/q3.txt"), "rb").read(); self.assertNotIn(b"quarterly", raw); self.assertNotIn(b"4111", raw); self.assertEqual(get(w, "bank", "reports/q3.txt"), b"quarterly numbers 4111111111111111")
        self.assertEqual((w.p.tenants["bank"].key_owner, w.p.tenants["acme"].key_owner), ("customer", "halvard")); self.assertTrue(any(r["public"].get("key_owner") == "customer" for r in w.p.tenants["bank"].cp.ledger.entries() if r["kind"] == "fabric.tenant_created"))

    def test_tampering_is_detected_and_another_tenants_key_cannot_open_the_object(self):
        w = self.world(); put(w, "bank", "a.txt", b"secret"); put(w, "acme", "a.txt", b"other")
        pb = w.p.store.object_path(w.p.tenants["bank"].cp.ctx, "a.txt"); raw = bytearray(pb.read_bytes()); raw[25] ^= 1; pb.write_bytes(bytes(raw))
        with self.assertRaises(KeyUnavailable): get(w, "bank", "a.txt")
        pa = w.p.store.object_path(w.p.tenants["acme"].cp.ctx, "a.txt"); pb.write_bytes(pa.read_bytes())           # acme's sealed object dropped into the bank's storage
        with self.assertRaises(KeyUnavailable): get(w, "bank", "a.txt")

    def test_revoking_the_customers_key_locks_everything_at_once_and_restoring_it_unlocks(self):
        w = self.world(); put(w, "bank", "a.txt", b"secret"); self.kms.revoke(); w.p.refresh_key("bank")
        with self.assertRaises(KeyUnavailable): get(w, "bank", "a.txt")
        with self.assertRaises(KeyUnavailable): put(w, "bank", "b.txt", b"new")
        with self.assertRaises(AccessRefused): w.p.customer(w.m("bank"))
        put(w, "acme", "x.txt", b"fine"); self.assertEqual(get(w, "acme", "x.txt"), b"fine")                        # other companies are untouched
        states = [r["public"]["locked"] for r in w.p.tenants["bank"].cp.ledger.entries() if r["kind"] == "fabric.key_state"]; self.assertEqual(states, [True])
        self.kms.restore(); self.assertTrue(w.p.refresh_key("bank")); self.assertEqual(get(w, "bank", "a.txt"), b"secret"); self.assertIs(w.p.customer(w.m("bank")), w.p.tenants["bank"].cp)

    def test_delegated_and_crew_access_stop_while_the_key_is_revoked(self):
        w = self.world(); w.p.open_access(w.m("bank", "owner"), "msp-1", "service_provider", "eu-central", {"summary"}, 60)
        self.kms.revoke()
        with self.assertRaises(AccessRefused): w.p.summary("bank", "msp-1", "service_provider", "eu-central")

    def test_destroying_the_key_is_final(self):
        w = self.world(); put(w, "bank", "a.txt", b"secret"); self.kms.destroy(); self.assertFalse(w.p.refresh_key("bank"))
        with self.assertRaises(KeyUnavailable): self.kms.restore()
        with self.assertRaises(KeyUnavailable): get(w, "bank", "a.txt")

    def test_the_cipher_has_no_plain_text_in_its_output_and_rejects_foreign_bytes(self):
        c = ObjectCipher(b"k" * 32); sealed = c.seal(b"hello hello hello hello"); self.assertNotIn(b"hello", sealed); self.assertEqual(c.unseal(sealed), b"hello hello hello hello"); self.assertNotEqual(c.seal(b"x"), c.seal(b"x"))
        with self.assertRaises(KeyUnavailable): c.unseal(b"plain bytes")
        with self.assertRaises(KeyUnavailable): ObjectCipher(b"j" * 32).unseal(sealed)


class ResidencyTests(unittest.TestCase):
    def test_a_regions_rules_are_exactly_its_allowed_set(self):
        r = ResidencyPolicy("eu-west", allowed=["eu-central"]); self.assertTrue(r.check("store", "eu-central")[0]); self.assertTrue(r.check("store", "eu-west")[0]); self.assertFalse(r.check("replicate", "us-east")[0])
        self.assertFalse(r.check("export", "nowhere")[0]); self.assertFalse(r.check("teleport", "eu-west")[0]); self.assertTrue(r.check("staff_access", "eu-west")[0]); self.assertFalse(r.check("staff_access", "eu-central")[0])
        with self.assertRaises(ValueError): ResidencyPolicy("mars")

    def test_an_export_to_another_region_is_refused_and_recorded_and_nothing_moves(self):
        w = World8(); self.assertTrue(w.p.export("acme", "eu-west"))
        with self.assertRaises(AccessRefused) as cm: w.p.export("acme", "us-east")
        self.assertIn("stays in eu-west", str(cm.exception)); kinds = [r["kind"] for r in w.p.tenants["acme"].cp.ledger.entries() if r["kind"].startswith("fabric.export")]; self.assertEqual(kinds, ["fabric.export_allowed", "fabric.export_refused"])

    def test_staff_support_only_from_an_allowed_region_and_follow_the_sun_is_a_choice_the_company_makes(self):
        w = World8()
        with self.assertRaises(AccessRefused): w.p.open_support_grant(w.m("acme"), "halvard-eng-us", 30, "us-east")
        self.assertTrue(w.p.open_support_grant(w.m("acme"), "halvard-eng-eu", 30, "eu-west"))
        w.p.allow_access_from(w.m("acme", "owner"), "us-east"); self.assertTrue(w.p.open_support_grant(w.m("acme"), "halvard-eng-us", 30, "us-east"))
        with self.assertRaises(ValueError): w.p.allow_access_from(w.m("acme", "owner"), "mars")


if __name__ == "__main__":
    unittest.main()
