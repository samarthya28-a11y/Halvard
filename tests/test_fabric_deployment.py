import hashlib, json, os, unittest
from rig8 import *
from halvard.ward.agent import Blocked
from halvard.fabric.deployment import BundleError

NEW_ADV = {"synced_with_upstream": None, "advisories": [{"id": "HLV-SAMPLE-0900", "product": "labelprinter", "affected_below": "3.0", "base_severity": 8.0, "exploit": "exploited_in_wild", "surface": "network", "port": None, "summary": "Remote takeover of the label printer service", "workaround": None}]}
NEW_CAT = {"tools": [{"key": "inhouse-llm", "name": "In-house model", "kind": "chat", "domains": ["llm.bank.internal"], "products": [], "trains_on_inputs": False, "retention_days": 0, "enterprise_tier": True}]}
BAD = b"MZ the bank's own threat-intel file"


def bundle(w, name, version, **kw): d = os.path.join(w.tmp, name); build_bundle(d, version, VENDOR_KEY, w.clock.now(), **kw); return d


class ProfileTests(unittest.TestCase):
    def test_the_dependency_report_says_what_each_profile_does_instead_of_calling_out(self):
        w = World8(); r = {d["module"]: d for d in w.p.dependency_report(w.m("bank"))}; cloud = {d["module"]: d for d in w.p.dependency_report(w.m("acme"))}
        self.assertTrue(all(d["status"] == "online" and not d["instead"] for d in cloud.values()))
        self.assertEqual((r["Keeper"]["status"], r["Support"]["status"], r["Glass"]["status"]), ("substitute", "substitute", "substitute")); self.assertIn("signed offline bundle", r["Ward"]["instead"]); self.assertIn("customer's own people", r["Keeper"]["instead"])

    def test_a_private_deployment_makes_no_outbound_call_unless_the_customer_listed_the_destination(self):
        w = World8(); called = []
        with self.assertRaises(EgressDenied): w.p.external_call(w.m("bank"), "intel.halvard.example", "reputation lookup", lambda: called.append(1))
        self.assertEqual(called, []); self.assertTrue(any(r["kind"] == "fabric.egress_refused" and r["private"]["dst"] == "intel.halvard.example" for r in w.p.tenants["bank"].cp.ledger.entries()))
        w.p.tenants["bank"].egress.allow.add("mirror.bank.internal"); w.p.external_call(w.m("bank"), "mirror.bank.internal", "update mirror", lambda: called.append(2)); self.assertEqual(called, [2])
        w.p.external_call(w.m("acme"), "intel.halvard.example", "reputation lookup", lambda: called.append(3)); self.assertEqual(called, [2, 3])

    def test_remote_staff_and_providers_cannot_reach_a_private_deployment(self):
        w = World8()
        with self.assertRaises(AccessRefused): w.p.open_support_grant(w.m("bank"), "halvard-eng", 30, "eu-central")
        w.p.open_access(w.m("bank", "owner"), "msp-1", "service_provider", "eu-central", {"summary"}, 60)
        with self.assertRaises(AccessRefused) as cm: w.p.summary("bank", "msp-1", "service_provider", "eu-central")
        self.assertIn("private deployment", str(cm.exception)); self.assertTrue(any(r["kind"] == "fabric.support_refused" for r in w.p.tenants["bank"].cp.ledger.entries()))


class BundleTests(unittest.TestCase):
    def prepared(self):
        w = World8(); a, h, fs = w.add_laptop("bank", "LT-9", "bob"); h.software["labelprinter"] = "2.5"; w.p.tenants["bank"].cp.glass.evaluate(); a.set_online(False); return w, a, h, fs        # it reported once, then lost its link

    def test_a_signed_bundle_updates_a_site_with_no_connection_and_the_updates_take_effect(self):
        w, a, h, fs = self.prepared(); cp = w.p.tenants["bank"].cp; ioc = hashlib.sha256(BAD).hexdigest()
        a.pre_execute("/apps/tool.exe", BAD)                                                                              # unknown to the device today
        man = w.p.import_bundle(w.m("bank"), bundle(w, "b1", 5, advisories=NEW_ADV, ai_catalog=NEW_CAT, iocs=[ioc]), VENDOR_KEY); self.assertEqual(man["version"], 5)
        self.assertIn("HLV-SAMPLE-0900@LT-9", {x.id for x in cp.glass.evaluate()}); self.assertEqual(cp.lumen.inventory.catalog[0].key, "inhouse-llm")
        w.p.tenants["bank"].cp.fleet.reconnect("LT-9"); a.set_online(False)                                                   # the IOC reached the device when it was last reachable
        with self.assertRaises(Blocked): a.pre_execute("/apps/tool.exe", BAD)                                             # and it blocks with no connection
        e = [r for r in cp.ledger.entries() if r["kind"] == "fabric.bundle_applied"]; self.assertEqual((len(e), e[0]["public"]["parts"]), (1, ["advisories", "ai_catalog", "iocs"]))

    def test_a_bundle_that_is_unsigned_altered_old_or_signed_with_the_wrong_key_changes_nothing(self):
        w, a, h, fs = self.prepared(); cp = w.p.tenants["bank"].cp; before = {x.id for x in cp.glass.evaluate()}
        good = bundle(w, "g", 5, advisories=NEW_ADV)
        with self.assertRaises(BundleError): w.p.import_bundle(w.m("bank"), good, b"not-the-vendor-key-0123456789abcd")
        t = bundle(w, "t", 6, advisories=NEW_ADV, iocs=["ab" * 32]); p = os.path.join(t, "iocs.json"); open(p, "wb").write(b'["cd"]')
        with self.assertRaises(BundleError) as cm: w.p.import_bundle(w.m("bank"), t, VENDOR_KEY)
        self.assertIn("does not match the manifest", str(cm.exception))
        m = os.path.join(good, "manifest.json"); doc = json.loads(open(m).read()); doc["version"] = 99; open(m, "w").write(json.dumps(doc))
        with self.assertRaises(BundleError): w.p.import_bundle(w.m("bank"), good, VENDOR_KEY)                                   # version edited after signing
        with self.assertRaises(BundleError): w.p.import_bundle(w.m("bank"), os.path.join(w.tmp, "nowhere"), VENDOR_KEY)
        self.assertEqual({x.id for x in cp.glass.evaluate()}, before); self.assertEqual(w.p.tenants["bank"].bundle_version, 0)
        self.assertEqual(sum(1 for r in cp.ledger.entries() if r["kind"] == "fabric.bundle_refused"), 4)

    def test_an_older_or_repeated_bundle_is_refused_as_a_rollback(self):
        w, a, h, fs = self.prepared(); w.p.import_bundle(w.m("bank"), bundle(w, "b5", 5, advisories=NEW_ADV), VENDOR_KEY)
        for v in (5, 4):
            with self.assertRaises(BundleError) as cm: w.p.import_bundle(w.m("bank"), bundle(w, f"r{v}", v, advisories=NEW_ADV), VENDOR_KEY)
            self.assertIn("rollback refused", str(cm.exception))
        self.assertEqual(w.p.import_bundle(w.m("bank"), bundle(w, "b6", 6, advisories=NEW_ADV), VENDOR_KEY)["version"], 6)


if __name__ == "__main__":
    unittest.main()
