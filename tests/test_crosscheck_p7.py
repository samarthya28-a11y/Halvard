"""Independent cross-check, phase 7. Gateway address parsing, case merge, tripwires."""
import os, pathlib, unittest
from helpers import *
from rig7 import *
from halvard.cases import CaseEngine, CaseFinding
from halvard.lumen.gateway import digest_of
from halvard.relay.actions import ActionRequest
from halvard.tenancy import TenantContext, TenantStore
from halvard.ward.agent import Blocked

BOT = "report-bot"


class GatewayAddressTests(unittest.TestCase):
    def test_regulated_mail_with_an_extra_at_sign_is_not_treated_as_internal(self):
        w = World7(); w.review_agent()
        g = w.cp.lumen.gateway; s = g.session(BOT, "s-trick")
        r = g.call(BOT, s, "mail", "send_mail", {"target": "evil@gmail.example@acme.com", "data": CARDS})
        self.assertEqual(r["decision"], "block")
        self.assertEqual(w.cp.lumen.tools.mail_sent, [])

    def test_a_grant_for_one_call_cannot_be_reused_for_another_argument_or_after_suspension(self):
        w = World7(); w.review_agent(); T = w.cp.lumen.tools
        p = {"target": "/reports/notes.txt"}
        grant = T.mint(BOT, "files", "read", digest_of("files", "read", p))
        with self.assertRaises(PermissionError):
            T.run(grant, "files", "read", {"target": "/reports/q1.csv"})
        T.run(grant, "files", "read", p)
        with self.assertRaises(PermissionError):
            T.run(grant, "files", "read", p)
        w.cp.lumen.registry.agents[BOT].status = "suspended"
        s = w.cp.lumen.gateway.session(BOT, "s-sus")
        r = w.cp.lumen.gateway.call(BOT, s, "files", "read", p)
        self.assertEqual(r["rule"], "agent-suspended")


class CaseMergeTests(unittest.TestCase):
    def test_a_decoy_on_a_shared_computer_does_not_absorb_another_persons_finding(self):
        store = TenantStore(); store.create_tenant("acme", "Acme")
        ctx = TenantContext("acme", "it", "it_admin"); clock = ManualClock()
        for eid, name in (("p:alice", "Alice"), ("p:bob", "Bob"), ("WS", "Shared jump box")):
            store.put_entity(ctx, eid, "person" if eid.startswith("p:") else "device", name, clock.now())
        store.put_edge(ctx, "p:alice", "uses", "WS", clock.now())
        store.put_edge(ctx, "p:bob", "uses", "WS", clock.now())
        eng = CaseEngine(store, ctx, clock)
        bob = eng.add(CaseFinding("f-bob", "signet", "identity_takeover", "p:bob", 0.9, "Bob's password was sprayed", "why", clock.now()))
        decoy = eng.add(CaseFinding("f-decoy", "hearth", "tripwire", "WS", 0.95, "Someone opened a file on a decoy share.", "why",
                                    clock.now() + 1, None, {"campaign": "bait:d1", "decoy": "d1"}))
        self.assertNotEqual(bob.id, decoy.id)
        self.assertNotIn("p:alice", decoy.entities)
        self.assertNotIn("p:bob", decoy.entities)


class TripwireTests(unittest.TestCase):
    def test_a_write_through_a_symlink_is_still_a_touch_of_the_tripwire(self):
        w = World7()
        root = os.path.join(w.tmp, "guarded"); os.makedirs(root)
        bait = os.path.join(root, "!000-budget.xlsx")
        res = w.cp.engine.request(ActionRequest("place_tripwires", ADM, ["LT-17"], "ransomware tripwires", None,
                                               {"specs": [{"id": "e1", "path": bait, "kind": "encryption"}]}))
        self.assertEqual(res.status, "executed")
        before = pathlib.Path(bait).read_bytes()
        link = os.path.join(w.tmp, "via-link")
        os.symlink(root, link)
        via = os.path.join(link, "!000-budget.xlsx")
        w.host.spawn(8, "locker.exe")
        with self.assertRaises(Blocked):
            w.fs.overwrite(8, via, b"\x00" * 80)
        self.assertEqual(pathlib.Path(bait).read_bytes(), before)
        self.assertIn(8, w.agent.blocked)
