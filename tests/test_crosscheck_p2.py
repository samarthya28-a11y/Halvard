"""Independent cross-check, phase 2. Hostile hunt and forensics inputs."""
import json, os, unittest
from helpers import *
from halvard.hunt.events import EventStore
from halvard.hunt.service import HuntDenied, HuntService
from halvard.ledger.audit import AuditLog
from halvard.relay.actions import ActionRequest, Principal
from halvard.tenancy import TenantContext, TenantStore

T0 = 1_760_000_000.0


def world():
    clock = ManualClock(T0 + 10 * 86400); tmp = tempfile.mkdtemp()
    ts = TenantStore(); ts.create_tenant("acme", "Acme"); ts.create_tenant("globex", "Globex")
    audit = AuditLog(os.path.join(tmp, "a.log"), "acme", b"k" * 32, clock)
    ev = EventStore(ts, clock=clock); svc = HuntService(ev, audit)
    return clock, ts, ev, svc, audit


class HuntBoundaryTests(unittest.TestCase):
    def test_it_admin_search_does_not_return_a_command_line_or_a_person_name_even_inside_a_path(self):
        _, ts, ev, svc, _ = world()
        ctx = TenantContext("acme", "it", "it_admin")
        ev.add(ctx, [dict(ts=T0 + 10 * 86400, device="LT-1", kind="file", op="write", pid=3, proc="excel.exe",
                          cmdline="excel /embed secret-token", user="jsmith", path="C:/Users/jsmith/Finance/q3.xlsx")])
        rows = svc.simple(ctx, "excel")["rows"]
        blob = json.dumps(rows)
        self.assertNotIn("secret-token", blob)
        self.assertNotIn("cmdline", blob)
        self.assertNotIn("jsmith", blob)
        self.assertTrue(rows)

    def test_a_service_desk_analyst_query_and_a_sqlish_string_cannot_cross_tenants_or_open_hql(self):
        _, ts, ev, svc, _ = world()
        acme, globex = TenantContext("acme", "a", "analyst"), TenantContext("globex", "g", "analyst")
        ev.add(globex, [dict(ts=T0, device="LT-9", kind="process", op="exec", pid=1, proc="cmd.exe",
                             cmdline="cmd /c whoami", user="gary")])
        with self.assertRaises(HuntDenied):
            svc.hql(TenantContext("acme", "it", "it_admin"), "kind=process OR 1=1")
        with self.assertRaises(HuntDenied):
            svc.simple(TenantContext("acme", "sd", "service_desk"), "cmd.exe' OR tenant_id!='acme")
        rows = svc.hql(acme, 'proc contains "cmd.exe" OR device = "LT-9"')["rows"]
        self.assertEqual(rows, [])
        self.assertEqual(len(svc.hql(globex, 'proc = "cmd.exe"')["rows"]), 1)

    def test_forensic_collection_is_refused_for_a_role_that_cannot_request_it(self):
        a, _, _, _ = make_agent(tempfile.mkdtemp())
        res = a.engine.request(ActionRequest("collect_forensics", Principal("sd", "service_desk"), [a.device_id],
                                            "just looking", params={"profile": "memory", "personal_data_ack": True}))
        self.assertEqual(res.status, "denied")
        self.assertFalse(any(p.name.startswith("col-") for p in a.engine.evidence_dir.rglob("*") if p.is_dir()))

    def test_an_it_admin_cannot_widen_simple_search_with_a_field_name_or_a_huge_day_count(self):
        _, _, ev, svc, _ = world()
        ctx = TenantContext("acme", "it", "it_admin")
        ev.add(ctx, [dict(ts=T0 + 10 * 86400, device="LT-1", kind="process", op="exec", pid=1, proc="old.exe",
                          cmdline="old-secret", user="jsmith"),
                     dict(ts=T0, device="LT-1", kind="process", op="exec", pid=2, proc="ancient.exe",
                          cmdline="ancient-secret", user="jsmith")])
        recent = svc.simple(ctx, "old.exe", days=10**9)
        blob = json.dumps(recent["rows"])
        self.assertNotIn("old-secret", blob)
        self.assertNotIn("jsmith", blob)
        self.assertEqual(svc.simple(ctx, "ancient.exe", days=10**9)["rows"], [])

    def test_service_desk_device_status_returns_no_telemetry_fields(self):
        _, _, ev, svc, _ = world()
        svc.cases = {"acme": [{"device": "LT-1", "status": "open", "title": "Browser session store copied"}]}
        ctx = TenantContext("acme", "sd", "service_desk")
        ev.add(ctx, [dict(ts=T0 + 10 * 86400, device="LT-1", kind="process", op="exec", pid=1, proc="powershell.exe",
                          cmdline="powershell -enc SECRET", user="jsmith", path="C:/Users/jsmith/a.txt")])
        status = svc.device_status(ctx, "LT-1")
        blob = json.dumps(status)
        self.assertNotIn("SECRET", blob)
        self.assertNotIn("jsmith", blob)
        self.assertNotIn("powershell", blob)
        self.assertIn("open case", status["message"])
