"""Slice 5: program identity is publisher plus image hash, and connector fixtures need that connector's signature."""
import dataclasses, hashlib, os, unittest
from helpers import *
from rig3 import *
from rig4 import ROGUE_IBAN, World4
from rig5 import World5
from halvard.ward.agent import Blocked


GOOD = "ab" * 32
OTHER = "cd" * 32
PUB = "Contoso Backup"


class ProgramIdentityTests(unittest.TestCase):
    def test_a_trusted_writer_matches_publisher_and_image_hash_not_the_file_name(self):
        tmp = tempfile.mkdtemp(); path = os.path.join(tmp, "docs", "budget.xlsx"); os.makedirs(os.path.dirname(path)); open(path, "wb").write(b"original")
        a, host, _, fs = make_agent(tmp, trusted_writers=[{"name": "backup.exe", "publisher": PUB, "image_hash": GOOD}])
        host.spawn(10, "backup.exe", publisher="Other Co", exe_sha256=OTHER)
        fs.overwrite(10, path, b"not-the-backup")
        journaled = a.journal.db.execute("select count(*) from rec where pid=?", (10,)).fetchone()[0]
        self.assertGreater(journaled, 0)
        host.spawn(11, "backup.exe", publisher=PUB, exe_sha256=GOOD)
        before = a.journal.db.execute("select count(*) from rec").fetchone()[0]
        fs.overwrite(11, path, b"the-real-backup")
        after = a.journal.db.execute("select count(*) from rec").fetchone()[0]
        self.assertEqual(after, before)
        self.assertEqual(open(path, "rb").read(), b"the-real-backup")

    def test_tripwire_exempt_matches_publisher_and_image_hash(self):
        tmp = tempfile.mkdtemp(); tw = os.path.join(tmp, "docs", "!000-budget.xlsx"); os.makedirs(os.path.dirname(tw))
        a, host, _, fs = make_agent(tmp)
        b = dataclasses.replace(a.bundle, version=a.bundle.version + 1, tripwires=[{"id": "e1", "path": tw, "kind": "encryption"}],
                                tripwire_exempt=[{"name": "backupd.exe", "publisher": PUB, "image_hash": GOOD}])
        self.assertTrue(a.apply_bundle(b.sign(POLICY_KEY).__dict__.copy(), POLICY_KEY))
        host.spawn(21, "backupd.exe", publisher=PUB, exe_sha256=OTHER)
        with self.assertRaises(Blocked):
            fs.overwrite(21, tw, b"wrong-binary")
        self.assertNotEqual(open(tw, "rb").read(), b"wrong-binary")
        self.assertFalse(any(e["kind"] == "ward.tripwire_exempt" and e["public"].get("process") == "backupd.exe" and e["public"].get("image_hash") == OTHER for e in a.spool.entries()))
        host.spawn(22, "renamed.exe", publisher=PUB, exe_sha256=GOOD)
        fs.overwrite(22, tw, b"allowed-backup")
        self.assertEqual(host.proc(22)["state"], "running")
        self.assertTrue(any(e["kind"] == "ward.tripwire_exempt" for e in a.spool.entries()))

    def test_a_blocked_app_matches_publisher_and_image_hash_not_another_program_with_the_same_name(self):
        tmp = tempfile.mkdtemp(); vuln = b"MZ the vulnerable build"; good = hashlib.sha256(vuln).hexdigest()
        a, _, _, _ = make_agent(tmp, blocked_apps=[{"app": "pdfviewer", "publisher": "Adobe", "image_hash": good, "why": "unpatched", "control": "cc-1"}])
        v = a.pre_execute("/apps/pdfviewer.exe", b"MZ different program", publisher="Adobe")
        self.assertNotEqual(v.decision, "block")
        self.assertFalse(any(e["kind"] == "ward.exec_blocked_by_temporary_protection" for e in a.spool.entries()))
        with self.assertRaises(Blocked):
            a.pre_execute("/apps/other-name.exe", vuln, publisher="Adobe")


class SignedConnectorTests(unittest.TestCase):
    def test_an_unsigned_identity_event_is_stored_and_does_not_isolate_or_reset_a_password(self):
        w = World(auto=True).alice_signs_in(); w.stealer_runs(); w.attacker_replays()
        for ev in w.cp.idp.log: ev.pop("connector_sig", None)
        for ev in w.cp.ad.log: ev.pop("connector_sig", None)
        cases = w.cp.process()
        signet = [f for c in cases for f in c.findings if f.source == "signet"]
        self.assertTrue(signet)
        self.assertTrue(all(f.details.get("reference_model") for f in signet))
        self.assertFalse(w.host.isolated)
        self.assertEqual(w.cp.idp.users["alice@acme.com"].password, "correct-horse")
        self.assertFalse(any(e["kind"] == "relay.action_executed" and e["public"].get("action") in ("isolate_host", "reset_credentials", "contain_everywhere") for e in w.cp.ledger.entries()))

    def test_an_unsigned_mail_event_is_stored_and_does_not_claw_back(self):
        w = World4()
        m = w.send("ar@g1obex-supplies.com", "Invoice overdue - urgent payment", f"Our bank details changed. Please pay to {ROGUE_IBAN} today.", display_name="Globex Accounts", reply_to="ar@mail-pay.example")
        for ev in w.cp.mail.log: ev.pop("connector_sig", None)
        w.cp.process()
        mail = [f for f in w.cp.courier.findings if f.family in ("malicious_mail", "impersonation")]
        self.assertTrue(mail)
        self.assertTrue(all(f.details.get("reference_model") for f in mail))
        self.assertNotIn(m.id, w.cp.mail.mailboxes["alice@acme.com"].folders["quarantine"])
        self.assertFalse(any(k.startswith("clawback") for k, _ in w.cp.auto_log))
        self.assertFalse(w.host.isolated)

    def test_an_unsigned_cloud_event_is_stored_and_does_not_close_the_bucket(self):
        w = World5(); w.scan_all()
        w.cp.aws.make_bucket_public("cust-exports", "mallory", "203.0.113.7")
        for ev in w.cp.aws.log: ev.pop("connector_sig", None)
        w.cp.process()
        self.assertTrue(w.cp.aws.buckets["cust-exports"].effective_public)
        cloud = [f for c in w.cp.cases.cases.values() for f in c.findings if f.source == "aws"]
        self.assertTrue(cloud)
        self.assertTrue(all(f.details.get("reference_model") for f in cloud))
        self.assertFalse(any(k.startswith("revert:") and st == "executed" for k, st in w.cp.auto_log))


if __name__ == "__main__":
    unittest.main()
