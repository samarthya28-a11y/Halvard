"""Slice 4 — the tenant wall and a customer key the agent does not hold."""
import os, tempfile, unittest
from helpers import *
from halvard.fabric.platform import AccessRefused, Member
from halvard.fabric.signing import customer_signer, customer_verifier, restore_reference_key, _D
from halvard.ledger.audit import AuditLog
from halvard.relay import commands
from halvard.signet.idp import ReferenceIdP, AuthError
from halvard.ward.policy import PolicyBundle, load_bundle
from rig8 import World8


class TenantWall(unittest.TestCase):
    def test_customer_export_import_external_call_and_dependency_report_need_an_enrolled_member(self):
        w = World8(); outsider = Member("bank", "mallory", "it_admin")
        for call in (
            lambda: w.p.customer(outsider),
            lambda: w.p.export(outsider, "eu-central"),
            lambda: w.p.import_bundle(outsider, "missing", b"k"),
            lambda: w.p.external_call(outsider, "https://example.test", "lookup", lambda: None),
            lambda: w.p.dependency_report(outsider),
        ):
            with self.assertRaises(AccessRefused): call()
        kinds = [e["kind"] for e in w.p.tenants["bank"].cp.ledger.entries()]
        self.assertTrue(any(k.startswith("fabric.") and "refused" in k for k in kinds), kinds)
        self.assertIs(tenant_cp(w.p, "acme"), w.p.tenants["acme"].cp)
        with self.assertRaises((AccessRefused, TypeError)): w.p.customer("globex")
        self.assertIs(w.p.customer(w.m("acme", "owner")), w.p.tenants["acme"].cp)

    def test_revoking_the_customer_key_refuses_export_sign_in_and_new_commands(self):
        restore_reference_key()
        self.addCleanup(restore_reference_key)
        signer, verifier = customer_signer(), customer_verifier()
        w = World8(); w.p.signing_key = verifier
        idp = w.acme.cp.idp; idp.signing_key = verifier
        owner = w.m("acme", "owner")
        self.assertTrue(w.p.export(owner, "eu-west"))
        idp.users["alice@acme.com"].mfa_enrolled = False
        self.assertTrue(idp.sign_in("alice@acme.com", "correct-horse", "1.2.3.4", None))
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp)
        a.policy_verifier = verifier
        cmd = commands.sign(signer, device=a.device_id, action="isolate_host", params={}, reason="contain", case="c",
                            approvals=[{"id": "u1", "role": "it_admin"}, {"id": "u2", "role": "analyst"}], rule="two_person", issuer="cp", now=a.clock.now())
        self.assertEqual(a.execute_command(cmd, b"not-the-customer-key")["status"], "executed")
        signer.revoke()
        with self.assertRaises(AccessRefused): w.p.export(owner, "eu-west")
        with self.assertRaises(AuthError): idp.sign_in("alice@acme.com", "correct-horse", "1.2.3.4", None)
        cmd2 = commands.sign.__wrapped__ if False else None
        try:
            cmd2 = commands.sign(signer, device=a.device_id, action="isolate_host", params={}, reason="again", case="c2",
                                 approvals=[{"id": "u1", "role": "it_admin"}, {"id": "u2", "role": "analyst"}], rule="two_person", issuer="cp", now=a.clock.now())
        except Exception as e:
            cmd2 = e
        self.assertIsInstance(cmd2, Exception)
        stale = commands.sign(b"policy-k" * 4, device=a.device_id, action="isolate_host", params={}, reason="hmac", case="c3",
                              approvals=[], rule="notify", issuer="cp", now=a.clock.now())
        self.assertEqual(a.execute_command(stale, b"policy-k" * 4)["status"], "rejected")

    def test_the_agent_verifies_with_the_public_key_and_ledger_entries_use_it(self):
        restore_reference_key()
        self.addCleanup(restore_reference_key)
        signer, verifier = customer_signer(), customer_verifier()
        raw = PolicyBundle(tenant="acme", version=2).sign(signer).__dict__.copy()
        loaded = load_bundle(raw, verifier, 1)
        self.assertEqual(loaded.version, 2)
        with self.assertRaises(AttributeError): verifier.private_exponent
        self.assertNotIn(_D, verifier.__dict__.values())
        d = tempfile.mkdtemp()
        log = AuditLog(os.path.join(d, "t.log"), "acme", b"k" * 32, ManualClock(), signer=signer, verifier=verifier)
        log.append("x.event", "halvard", "system", "s", {"n": 1})
        self.assertTrue(log.verify()[0])
        self.assertGreater(len(log.entries().__next__()["seal"]), 64)
