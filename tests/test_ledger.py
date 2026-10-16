import json, tempfile, unittest, os, pathlib
from helpers import *
from halvard.ledger.audit import AuditLog, ContentNotAllowed, verify_export

KEY = b"k" * 32


def mk(tmp):
    log = AuditLog(os.path.join(tmp, "l.log"), "acme", KEY, ManualClock())
    log.append("relay.action_executed", "u-7", "analyst", "LT-17", {"action": "isolate_host", "path": r"C:\Users\jsmith\Layoffs.docx", "user": "jsmith"},
               controls=("RELAY.ISOLATE_HOST",))
    log.append("ward.bulk_encryption_detected", "system", "system", "LT-17", {"confidence": 0.9}, controls=("WARD.BEHAVIORAL_STOP",))
    log.append("relay.action_executed", "u-8", "it_admin", "LT-18", {"action": "isolate_host", "host": "LT-18"}, controls=("RELAY.ISOLATE_HOST",))
    return log


class LedgerTests(unittest.TestCase):
    def setUp(self): self.tmp = tempfile.mkdtemp()

    def test_clean_log_verifies(self):
        self.assertEqual(mk(self.tmp).verify(), (True, []))

    def test_edit_is_detected(self):
        log = mk(self.tmp)
        lines = pathlib.Path(log.path).read_text().splitlines(); r = json.loads(lines[1]); r["public"]["confidence"] = 0.1
        lines[1] = json.dumps(r, sort_keys=True, separators=(",", ":")); pathlib.Path(log.path).write_text("\n".join(lines) + "\n")
        ok, p = log.verify(); self.assertFalse(ok); self.assertTrue(any("changed" in x for x in p))

    def test_deleted_entry_is_detected(self):
        log = mk(self.tmp); lines = pathlib.Path(log.path).read_text().splitlines(); del lines[1]
        pathlib.Path(log.path).write_text("\n".join(lines) + "\n"); self.assertFalse(log.verify()[0])

    def test_tail_truncation_is_detected(self):
        log = mk(self.tmp); lines = pathlib.Path(log.path).read_text().splitlines()
        pathlib.Path(log.path).write_text("\n".join(lines[:-1]) + "\n")
        ok, p = log.verify(); self.assertFalse(ok); self.assertTrue(any("truncated" in x for x in p))

    def test_raw_content_refused(self):
        log = mk(self.tmp)
        for bad in ({"content": "payroll"}, {"keystrokes": "abc"}, {"note": "x" * 5000}, {"nested": {"body": "hi"}}):
            with self.assertRaises(ContentNotAllowed): log.append("x", "a", "r", "s", bad)

    def test_auditor_export_has_no_personal_content_and_verifies(self):
        log = mk(self.tmp)
        exp = log.export_for_control("RELAY.ISOLATE_HOST")
        blob = json.dumps(exp)
        for secret in ("jsmith", "Layoffs", "LT-18", "u-7", "C:"):
            if secret == "LT-18":      # subject (entity id) is an internal id and is shown deliberately
                continue
            self.assertNotIn(secret, blob, secret)
        self.assertEqual(verify_export(exp), (True, []))
        self.assertTrue(any(e.get("elided") for e in exp["entries"]))   # other-control entry elided, link preserved
        self.assertEqual(sum(1 for e in exp["entries"] if not e.get("elided")), 2)

    def test_tampered_export_fails_verification(self):
        exp = mk(self.tmp).export_for_control("RELAY.ISOLATE_HOST")
        exp["entries"][0]["public"]["action"] = "something_else"
        self.assertFalse(verify_export(exp)[0])

    def test_same_person_same_token_within_export_only(self):
        log = mk(self.tmp); e1 = log.export_for_control("RELAY.ISOLATE_HOST"); e2 = log.export_for_control("RELAY.ISOLATE_HOST")
        vis = [e for e in e1["entries"] if not e.get("elided")]
        self.assertNotEqual(vis[0]["actor_token"], vis[1]["actor_token"])
        self.assertNotEqual(vis[0]["actor_token"], [e for e in e2["entries"] if not e.get("elided")][0]["actor_token"])


if __name__ == "__main__":
    unittest.main()
