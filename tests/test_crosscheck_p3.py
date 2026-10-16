"""Independent cross-check, phase 3. Device command checks the author tests do not make."""
import unittest
from helpers import *
from halvard.relay.actions import ActionRequest, Principal
from halvard.relay.authority import Authority
from halvard.relay.commands import sign, verify


class DeviceRecheckTests(unittest.TestCase):
    def test_a_clinical_device_rejects_two_service_desk_approvals_for_isolation(self):
        a, _, clock, _ = make_agent(tempfile.mkdtemp(), asset_class="clinical")
        cmd = sign(DEV_KEY, device=a.device_id, action="isolate_host", params={}, reason="contain", case="C-9",
                   approvals=[{"id": "desk1", "role": "service_desk"}, {"id": "desk2", "role": "service_desk"}],
                   rule="two_person", issuer="control", now=clock.now())
        ok, why = verify(cmd, DEV_KEY, a.device_id, clock.now(), set(), Authority(), "clinical")
        self.assertFalse(ok, why)
        out = a.execute_command(cmd, DEV_KEY)
        self.assertEqual(out["status"], "rejected")
        self.assertFalse(a.host.isolated)

    def test_a_remote_update_during_a_maintenance_window_is_deferred_on_the_device(self):
        a, host, clock, _ = make_agent(tempfile.mkdtemp())
        host.software["pdfviewer"] = "11.1"
        a.engine.auth.policy.maintenance_windows[a.device_id] = (clock.now() - 10, clock.now() + 5000)
        cmd = sign(DEV_KEY, device=a.device_id, action="install_update", params={"product": "pdfviewer", "version": "11.2"},
                   reason="ring", case=None, approvals=[{"id": "ada", "role": "it_admin"}], rule="approve",
                   issuer="control", now=clock.now())
        out = a.execute_command(cmd, DEV_KEY)
        self.assertEqual(out["status"], "deferred")
        self.assertEqual(host.software["pdfviewer"], "11.1")

    def test_a_command_cannot_be_replayed_or_used_after_expiry_or_by_counting_one_person_twice(self):
        auth = Authority(); key = DEV_KEY; now = 1_700_000_000.0
        cmd = sign(key, device="LT-CLIN", action="isolate_host", params={}, reason="x", case=None,
                   approvals=[{"id": "ada", "role": "it_admin"}, {"id": "bea", "role": "analyst"}],
                   rule="two_person", issuer="control", now=now)
        seen = set()
        ok, why = verify(cmd, key, "LT-CLIN", now, seen, auth, "clinical")
        self.assertTrue(ok, why)
        seen.add(cmd["nonce"])
        ok, why = verify(cmd, key, "LT-CLIN", now, seen, auth, "clinical")
        self.assertFalse(ok)
        self.assertIn("already used", why)
        ok, why = verify(cmd, key, "LT-CLIN", now + 10**9, set(), auth, "clinical")
        self.assertFalse(ok)
        self.assertIn("expired", why)
        dup = sign(key, device="LT-CLIN", action="isolate_host", params={}, reason="x", case=None,
                   approvals=[{"id": "ada", "role": "it_admin"}, {"id": "ada", "role": "analyst"}],
                   rule="two_person", issuer="ada", now=now)
        ok, why = verify(dup, key, "LT-CLIN", now, set(), auth, "clinical")
        self.assertFalse(ok)
        self.assertIn("2 different", why)

    def test_a_command_for_another_device_or_a_bad_signature_is_refused(self):
        a, _, clock, _ = make_agent(tempfile.mkdtemp(), asset_class="clinical")
        cmd = sign(DEV_KEY, device="someone-else", action="isolate_host", params={}, reason="x", case=None,
                   approvals=[{"id": "ada", "role": "it_admin"}, {"id": "bea", "role": "analyst"}],
                   rule="two_person", issuer="control", now=clock.now())
        out = a.execute_command(cmd, DEV_KEY)
        self.assertEqual(out["status"], "rejected")
        cmd["device"] = a.device_id
        out = a.execute_command(cmd, DEV_KEY)
        self.assertEqual(out["status"], "rejected")
        self.assertFalse(a.host.isolated)

    def test_two_real_approvers_are_accepted_on_a_clinical_device(self):
        a, _, clock, _ = make_agent(tempfile.mkdtemp(), asset_class="clinical")
        cmd = sign(DEV_KEY, device=a.device_id, action="isolate_host", params={}, reason="contain", case=None,
                   approvals=[{"id": "ada", "role": "it_admin"}, {"id": "bea", "role": "analyst"}],
                   rule="two_person", issuer="control", now=clock.now())
        out = a.execute_command(cmd, DEV_KEY)
        self.assertEqual(out["status"], "executed")
        self.assertTrue(a.host.isolated)
