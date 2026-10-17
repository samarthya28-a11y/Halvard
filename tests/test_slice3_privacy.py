"""Slice 3 — privacy, sessions, and evidence. Each test names a hole a customer can still hit."""
import json, os, tempfile, unittest
from helpers import *
from halvard.ledger.audit import AuditLog
from halvard.signet.hr import HR, HRRecord
from halvard.fabric.keeper import KeeperDesk
from halvard.relay.actions import ActionRequest, Principal
from rig7 import World7
from rig8 import World8


class SessionBound(unittest.TestCase):
    def test_suspension_follows_the_agent_not_a_new_session_id(self):
        w = World7(); g = w.cp.lumen.gateway
        g.suspend("report-bot")
        fresh = g.session("report-bot", "brand-new")
        r = g.call("report-bot", fresh, "files", "read", {"target": "/reports/q1.csv"})
        self.assertEqual(r["decision"], "block")
        self.assertIn("Residual:", r["message"])

    def test_an_approval_runs_once_for_the_stored_digest_only(self):
        w = World7(); g = w.cp.lumen.gateway; agent = "report-bot"
        s = g.session(agent, "s1")
        body = w.cp.lumen.tools.files["/reports/notes.txt"]
        r = g.call(agent, s, "mail", "send_mail", {"target": "someone@outside.test", "data": body})
        self.assertEqual(r["decision"], "ask", r)
        pending = g.pending[r["pending_id"]]
        pending["params"] = dict(pending["params"], data=b"DIFFERENT-PAYLOAD")
        owner = next(p for p in w.cp.ledger.entries())  # placeholder to keep import use; approver comes from the world
        from halvard.relay.actions import Principal
        out = g.approve(r["pending_id"], Principal("p:alice", "it_admin"), "checked the stored call")
        self.assertNotEqual(out.get("status"), "executed")
        self.assertFalse(any(item[1] == b"DIFFERENT-PAYLOAD" for item in w.cp.lumen.tools.mail_sent))
        again = g.approve(r["pending_id"], Principal("p:alice", "it_admin"))
        self.assertEqual(again["status"], "unknown")


class LedgerPrivacy(unittest.TestCase):
    def test_pii_keys_are_case_insensitive_and_nested_and_subject_is_scrubbed(self):
        d = tempfile.mkdtemp(); log = AuditLog(os.path.join(d, "t.log"), "acme", b"k" * 32, ManualClock())
        log.append("x.event", "halvard", "system", "bob@example.com", {"Meta": {"User": "alice@example.com", "note": "ok"}, "Path": r"C:\secret\pay.csv"})
        rec = json.loads(open(log.path, encoding="utf-8").readline())
        pub = json.dumps(rec["public"]); priv = json.dumps(rec["private"]); whole = json.dumps({k: rec[k] for k in rec if k != "private"})
        self.assertNotIn("alice@example.com", pub)
        self.assertNotIn("secret", pub)
        self.assertIn("alice@example.com", priv)
        self.assertNotIn("bob@example.com", whole)
        self.assertIn("[address]", rec["subject"])

    def test_wiping_the_log_and_the_head_anchor_fails_verify_on_a_new_log(self):
        d = tempfile.mkdtemp(); path = os.path.join(d, "t.log")
        log = AuditLog(path, "acme", b"k" * 32, ManualClock())
        for i in range(4): log.append("x.event", "halvard", "system", "s", {"n": i})
        os.remove(path); os.remove(path[:-4] + ".head")
        fresh = AuditLog(path, "acme", b"k" * 32, ManualClock())
        ok, problems = fresh.verify()
        self.assertFalse(ok, problems)
        self.assertTrue(problems)

    def test_a_missing_head_anchor_fails_verify_when_the_log_is_empty(self):
        d = tempfile.mkdtemp(); path = os.path.join(d, "empty.log")
        log = AuditLog(path, "acme", b"k" * 32, ManualClock())
        os.remove(log.anchor)
        ok, problems = log.verify()
        self.assertFalse(ok)
        self.assertTrue(any("anchor" in p for p in problems))


class LegalHoldPins(unittest.TestCase):
    def test_two_people_pin_the_spool_and_the_anchor_against_compact_uninstall_and_export(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp)
        a.install_files({"ward.exe": b"agent-binary"})
        self.assertFalse(a.spool.hold("p:one"))
        self.assertTrue(a.spool.hold("p:two"))
        with self.assertRaises(PermissionError): a.spool.export_for_control("WARD.TAMPER_PROTECTION")
        with self.assertRaises(PermissionError): a.journal.compact(0)
        token = a.tamper.issue_uninstall_token("p:two")
        with self.assertRaises(PermissionError): a.tamper.stop_or_uninstall(token)
        self.assertTrue(a.spool.anchor.exists())
        self.assertTrue(a.spool.path.exists())


class KeeperWords(unittest.TestCase):
    def test_first_names_and_ids_are_hidden_and_unrelated_words_are_not(self):
        w = World8(); cp = w.p.tenants["acme"].cp
        cp.hr.add(HRRecord("p:ann", "Ann Lee", "Ann.Lee@acme.com", "alee", "active", "eng", None, 0, email="ann.lee@acme.com"))
        cp.hr.add(HRRecord("p:bo", "Bo Moss", "bo@acme.com", "bmoss", "active", "eng", None, 0, email="bo@acme.com"))
        d = KeeperDesk(w.p); d.hire("k1", "eu-west"); d.assign("k1", "acme")
        d.set_charter(w.m("acme", "owner"), ["suspend_ai_agent"], see_people=False)
        text = "Alice opened Annual boat plans. Bo left the file for ALEE and ANN.LEE@ACME.COM"
        out = d._redact(text, w.p.tenants["acme"], d.charters["acme"])
        self.assertNotIn("Alice", out)
        self.assertNotIn("alee", out.lower())
        self.assertNotIn("ann.lee@acme.com", out.lower())
        self.assertNotRegex(out, r"(?<!\w)Bo(?!\w)")
        self.assertIn("Annual", out)
        self.assertIn("boat", out)


class RefusalAndResidual(unittest.TestCase):
    def test_a_non_member_export_is_refused_in_that_companys_ledger(self):
        from halvard.fabric.platform import AccessRefused, Member
        w = World8()
        with self.assertRaises(AccessRefused): w.p.export(Member("bank", "mallory", "it_admin"), "eu-central")
        kinds = [e["kind"] for e in w.p.tenants["bank"].cp.ledger.entries()]
        self.assertIn("fabric.export_refused", kinds)

    def test_isolate_rollback_dlp_and_gateway_end_with_a_residual_line(self):
        tmp = tempfile.mkdtemp(); a, host, clock, fs = make_agent(tmp)
        host.spawn(9, "bad.exe"); p = os.path.join(tmp, "note.txt"); open(p, "wb").write(b"hello")
        a.block_pid(9)
        r = a.engine.request(ActionRequest("isolate_host", Principal("halvard:auto", "system"), [a.device_id], "bulk encryption", automatic=True, pattern="ransomware_stop", critical=True))
        self.assertTrue(r.message.rstrip().endswith("pid frozen only until release."), r.message)
        rep = a.journal.rollback([9])
        from halvard.relay.recovery import recovery_note
        note = recovery_note(rep)
        self.assertIn("Residual:", note["headline"])
        self.assertIn("not in the journal", note["headline"])
        from halvard.vaultline.classifiers import Classifier
        from halvard.vaultline.dlp import decide
        cls = Classifier().classify("x.pdf", open("tests/fixtures/dlp/sample.pdf", "rb").read())
        d = decide(cls, "usb", "unapproved")
        self.assertTrue(d.message.rstrip().endswith("file not read."), d.message)
        w = World7(); g = w.cp.lumen.gateway
        s = g.session("report-bot", "s-res")
        out = g.call("report-bot", s, "files", "read", {"target": "/reports/q1.csv"})
        self.assertIn("Residual:", out["message"])
        self.assertIn("minutes left", out["message"])
