import json, os, random, tempfile, unittest
from helpers import *
from halvard.hunt import ql, nl
from halvard.hunt.events import EventStore, Retention
from halvard.hunt.service import HuntService, HuntDenied
from halvard.ledger.audit import AuditLog
from halvard.tenancy import TenantStore, TenantContext, TenantIsolationError

DAY = 86400
T0 = 1_760_000_000.0


def mkenv():
    clock = ManualClock(T0 + 100 * DAY); tmp = tempfile.mkdtemp()
    ts = TenantStore(); [ts.create_tenant(t, t) for t in ("acme", "globex")]
    audit = AuditLog(os.path.join(tmp, "a.log"), "platform", b"k" * 32, clock)
    ev = EventStore(ts, clock=clock); svc = HuntService(ev, audit)
    ctx = lambda role, t="acme", p="u": TenantContext(t, p, role)
    return clock, ts, ev, svc, ctx, audit


EVENTS = [
    dict(kind="process", op="exec", device="LT-1", pid=10, proc="powershell.exe", cmdline="powershell -enc SQBFAFgA", user="jsmith"),
    dict(kind="process", op="exec", device="LT-1", pid=11, proc="powershell.exe", cmdline="powershell Get-Date", user="jsmith"),
    dict(kind="process", op="exec", device="LT-2", pid=12, proc="7z.exe", cmdline="7z a x.7z C:/Finance", user="mlee"),
    dict(kind="file", op="rename", device="LT-1", pid=10, proc="powershell.exe", path="C:/Finance/q3.xlsx", dst_path="C:/Finance/q3.xlsx.locked", signals="ext_changed"),
    dict(kind="file", op="delete", device="LT-2", pid=12, proc="7z.exe", path="C:/Finance/old_100%_final.txt"),
    dict(kind="net", op="connect", device="LT-1", pid=10, proc="powershell.exe", dst_ip="203.0.113.9", dst_port=443),
]


class QLTests(unittest.TestCase):
    def test_sql_and_python_paths_agree_on_many_queries(self):
        """The same HQL must select the same events on the store (SQL) and on the device (Python)."""
        clock, ts, ev, svc, ctx, _ = mkenv(); c = ctx("analyst")
        rnd = random.Random(3); procs = ["PowerShell.exe", "7z.exe", "chrome.exe", "a_b%.exe", "[x].exe", "axb.exe", "a_bc.exe", "100abc.exe", "100%.exe"]
        paths = ["C:/Finance/q3.xlsx", "C:/Users/a/Docs/x.txt", "/home/u/.cache/z", "C:/Finance/100%_done.txt", "/tmp/[x]/f", None]
        evs = [dict(ts=T0 + i, device=rnd.choice(["LT-1", "lt-2", None]), kind=rnd.choice(["file", "process", "net"]), op=rnd.choice(["write", "exec", "delete"]),
                    pid=rnd.randrange(1, 50), proc=rnd.choice(procs), cmdline=rnd.choice(["-enc abc", None, "ls -la"]), path=rnd.choice(paths),
                    dst_port=rnd.choice([None, 80, 443]), signals=rnd.choice([None, "ext_changed", "magic_destroyed ext_changed"])) for i in range(400)]
        ev.add(c, evs)
        queries = ['proc~"power*"', 'proc="POWERSHELL.EXE"', 'path contains "100%"', 'path contains "_"', 'proc~"a_b%*"', 'proc~"a_b*"', 'proc~"100%*"', 'proc~"a?b*"', 'proc~"[x]*"', 'path startswith "C:/Finance"',
                   'path endswith ".txt"', 'device != "LT-1"', 'NOT (kind=file OR kind=net)', 'pid > 25 AND pid <= 40', 'dst_port in (80,443)', 'dst_port != 80',
                   'signals contains "magic"', 'proc in ("7z.exe","chrome.exe") AND cmdline contains "-enc"', 'cmdline != "ls -la"', 'proc~"?z.exe"', 'path~"*/.cache/*"']
        for q in queries:
            parsed = ql.parse(q)
            rows, _ = ev.query_rows(c, parsed.ast, 0)
            sql_ids = sorted(r["ts"] for r in rows)
            py_ids = sorted(e["ts"] for e in evs if ql.matches(parsed.ast, e))
            self.assertEqual(sql_ids, py_ids, q)

    def test_injection_is_just_a_value(self):
        clock, ts, ev, svc, ctx, _ = mkenv(); c = ctx("analyst"); ev.add(c, EVENTS)
        r = svc.hql(c, 'proc="x\'; DROP TABLE ev_hot; --"')
        self.assertEqual(r["rows"], []); self.assertEqual(ev.counts(c)["hot"], len(EVENTS))
        for bad in ('proc; DROP TABLE x', 'unknownfield="a"', 'proc ==', 'proc~"a" |  | head 1', 'pid > abc', 'proc > "a"', '| count by nonsense', ')'):
            with self.assertRaises(ql.QLError): ql.parse(bad)

    def test_stages(self):
        clock, ts, ev, svc, ctx, _ = mkenv(); c = ctx("analyst"); ev.add(c, EVENTS)
        r = svc.hql(c, "kind=process | count by proc | sort -count")["rows"]; self.assertEqual(r[0], {"proc": "powershell.exe", "count": 2})
        self.assertEqual(svc.hql(c, "kind=process | count")["rows"], [{"count": 3}])
        self.assertEqual(svc.hql(c, "kind=process | count by device | where count > 1")["rows"], [{"device": "LT-1", "count": 2}])
        self.assertEqual(len(svc.hql(c, "kind=process | head 1")["rows"]), 1)
        self.assertEqual(svc.hql(c, "kind=process | dedup proc | table proc")["rows"], [{"proc": "powershell.exe"}, {"proc": "7z.exe"}])


class NLTests(unittest.TestCase):
    def test_translates_common_phrases_and_shows_the_query(self):
        now = T0
        b, info = nl.translate("powershell with encoded commands in the last 24 hours", now)
        self.assertEqual(b["since"], now - 86400)
        self.assertIn("kind=process", b["query"]); self.assertIn('cmdline contains "-enc"', b["query"]); self.assertTrue(info["understood"])
        b, _ = nl.translate("files renamed on LT-17 in the last 2 hours", now); self.assertIn("op=rename", b["query"]); self.assertIn('device="LT-17"', b["query"])
        b, _ = nl.translate("connections to 203.0.113.9", now); self.assertIn('dst_ip="203.0.113.9"', b["query"])
        b, _ = nl.translate("count processes named 7z by device in the last week", now); self.assertTrue(b["query"].endswith("| count by device"))
        for b, _ in [nl.translate(x, now) for x in ("files renamed on LT-17", "powershell with encoded commands", "connections to 203.0.113.9")]:
            ql.parse(b["query"])        # whatever it builds must always be valid HQL

    def test_says_so_when_it_cannot_understand(self):
        b, info = nl.translate("what is the meaning of life", T0)
        self.assertIsNone(b); self.assertFalse(info["understood"]); self.assertIn("Try one like", info["message"])


class HuntAccessTests(unittest.TestCase):
    def setUp(self):
        self.clock, self.ts, self.ev, self.svc, self.ctx, self.audit = mkenv()
        self.ev.add(self.ctx("analyst"), [dict(e, ts=self.clock.now() - 3600) for e in EVENTS])

    def test_analyst_full_it_admin_simple_service_desk_status_only(self):
        self.assertEqual(len(self.svc.hql(self.ctx("analyst"), 'cmdline contains "-enc"')["rows"]), 1)
        with self.assertRaises(HuntDenied): self.svc.hql(self.ctx("it_admin"), "kind=process")
        for role in ("service_desk", "site_manager", "auditor", "owner"):
            with self.assertRaises(HuntDenied): self.svc.hql(self.ctx(role), "kind=process")
            with self.assertRaises(HuntDenied): self.svc.simple(self.ctx(role), "powershell")
        with self.assertRaises(HuntDenied): self.svc.natural(self.ctx("it_admin"), "files renamed")

    def test_simple_search_never_returns_command_lines_or_user_names(self):
        r = self.svc.simple(self.ctx("it_admin"), "powershell")
        self.assertTrue(r["rows"]); blob = json.dumps(r)
        for secret in ("SQBFAFgA", "jsmith", "cmdline", "user"): self.assertNotIn(secret, blob)
        self.assertEqual(set(r["rows"][0]), {"ts", "device", "kind", "op", "proc", "path", "dst_ip"})

    def test_simple_search_is_limited_to_seven_days(self):
        self.ev.add(self.ctx("analyst"), [dict(kind="process", op="exec", device="OLD", proc="old.exe", ts=self.clock.now() - 20 * DAY)])
        self.assertEqual(self.svc.simple(self.ctx("it_admin"), "old.exe", days=365)["rows"], [])
        self.assertIn("Older events", self.svc.simple(self.ctx("it_admin"), "old.exe")["message"])

    def test_service_desk_gets_a_plain_answer_without_telemetry(self):
        self.svc.cases = {"acme": [{"device": "LT-1", "status": "open", "title": "Encoded PowerShell"}]}
        r = self.svc.device_status(self.ctx("service_desk"), "LT-1")
        self.assertFalse(r["ok"]); self.assertNotIn("SQBFAFgA", json.dumps(r)); self.assertTrue(self.svc.device_status(self.ctx("service_desk"), "LT-2")["ok"])

    def test_every_search_and_denial_is_audited(self):
        self.svc.hql(self.ctx("analyst", p="u-an"), 'proc="7z.exe"')
        with self.assertRaises(HuntDenied): self.svc.hql(self.ctx("service_desk", p="u-sd"), "kind=file")
        kinds = [(e["kind"], e["actor_role"]) for e in self.audit.entries()]
        self.assertIn(("hunt.query", "analyst"), kinds); self.assertIn(("hunt.denied", "service_desk"), kinds)
        q = next(e for e in self.audit.entries() if e["kind"] == "hunt.query"); self.assertEqual(q["public"]["query"], 'proc="7z.exe"')

    def test_natural_language_runs_only_when_asked_and_shows_its_query(self):
        r = self.svc.natural(self.ctx("analyst"), "files renamed in the last 3 hours")
        self.assertIn("query", r); self.assertNotIn("rows", r)
        r = self.svc.natural(self.ctx("analyst"), "files renamed in the last 3 hours", run=True); self.assertEqual(len(r["rows"]), 1)

    def test_hunt_cannot_cross_tenants(self):
        self.ev.add(self.ctx("analyst", "globex"), [dict(kind="process", op="exec", device="G1", proc="secret.exe")])
        rows = self.svc.hql(self.ctx("analyst"), 'proc="secret.exe"')["rows"]; self.assertEqual(rows, [])
        with self.assertRaises(TenantIsolationError): self.svc.hql(TenantContext("nonexistent", "u", "analyst"), "kind=file")


class RetentionTests(unittest.TestCase):
    def test_hot_cold_purge_and_cold_needs_opt_in(self):
        clock, ts, ev, svc, ctx, _ = mkenv(); c = ctx("analyst"); now = clock.now()
        ev.set_retention(c, Retention(hot_days=7, cold_days=60))
        ev.add(c, [dict(kind="process", op="exec", proc="fresh.exe", ts=now - DAY), dict(kind="process", op="exec", proc="warm.exe", ts=now - 20 * DAY),
                   dict(kind="process", op="exec", proc="ancient.exe", ts=now - 90 * DAY)])
        self.assertEqual(ev.roll(c), (2, 1)); self.assertEqual(ev.counts(c), {"hot": 1, "cold": 1})
        self.assertEqual(svc.hql(c, "kind=process")["rows"][0]["proc"], "fresh.exe"); self.assertEqual(len(svc.hql(c, "kind=process")["rows"]), 1)
        self.assertEqual({r["proc"] for r in svc.hql(c, "kind=process", include_cold=True)["rows"]}, {"fresh.exe", "warm.exe"})
        with self.assertRaises(ValueError): Retention(hot_days=30, cold_days=10)

    def test_retention_is_per_tenant(self):
        clock, ts, ev, svc, ctx, _ = mkenv(); ev.set_retention(ctx("analyst"), Retention(1, 2))
        self.assertEqual(ev.retention(ctx("analyst", "globex")).hot_days, 30)

    def test_telemetry_refuses_content_fields_and_exports_documented_jsonl(self):
        clock, ts, ev, svc, ctx, _ = mkenv(); c = ctx("analyst")
        with self.assertRaisesRegex(ValueError, "content is never collected"): ev.add(c, [dict(kind="file", op="write", content="secret text")])
        with self.assertRaises(ValueError): ev.add(c, [dict(kind="file", surprise=1)])
        ev.add(c, [dict(kind="process", op="exec", proc="a.exe", ts=clock.now())]); lines = ev.export(c).splitlines()
        self.assertEqual(list(json.loads(lines[0])), sorted(__import__("halvard.hunt.events", fromlist=["x"]).COLS))


if __name__ == "__main__":
    unittest.main()
