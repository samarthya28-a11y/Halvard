"""Slice 6: a fail-open, a dropped pending record, and a stopped heartbeat each leave a coverage row and a ledger event."""
import unittest
from helpers import *
from rig3 import World
from halvard.platforms.linux import FAN_ALLOW, FAN_OPEN_PERM, FanotifySensor
from halvard.relay.actions import Principal

OWNER = Principal("u-own", "owner")


class CoverageRowTests(unittest.TestCase):
    def test_a_dropped_pending_record_a_stopped_heartbeat_and_a_fail_open_each_leave_one_row_and_one_ledger_event(self):
        w = World()
        w.agent.stop_heartbeats()
        sensor = FanotifySensor.__new__(FanotifySensor)
        sensor.pending = {(1, 1, 1): (None, None, False)}
        sensor.agent = w.agent
        sensor._drop_pending()
        sensor.agent = w.agent
        sensor.stats = {"errors": 0}
        sensor.errors = []
        sensor.replies = []
        sensor._reply = lambda fd, resp: sensor.replies.append((fd, resp))
        sensor._on_perm_error(FAN_OPEN_PERM, 7, RuntimeError("hook threw"))
        self.assertEqual(sensor.replies, [(7, FAN_ALLOW)])
        reasons = [r["reason"] for r in w.cp.coverage.rows]
        self.assertEqual(reasons, ["heartbeat_stopped", "pending_dropped", "failed_open"])
        for reason in reasons:
            rows = [r for r in w.cp.coverage.rows if r["reason"] == reason]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["device"], "LT-17")
            self.assertIsNotNone(rows[0]["time"])
            led = [e for e in w.cp.ledger.entries() if e["kind"] == "coverage.row" and e["private"].get("reason") == reason]
            self.assertEqual(len(led), 1)
            self.assertEqual(led[0]["public"]["device"], "LT-17")
            self.assertEqual(led[0]["public"]["time"], rows[0]["time"])

    def test_the_board_lists_live_quiet_failed_open_and_no_agent_and_the_score_counts_a_failed_open(self):
        w = World()
        w.cp.store.put_entity(w.cp.ctx, "srv-bare", "device", "Bare server", w.clock.now())
        w.cp.store.put_entity(w.cp.ctx, "LT-quiet", "device", "Quiet laptop", w.clock.now())
        w.cp.store.put_sensor(w.cp.ctx, "ward-LT-quiet", "LT-quiet", "ward", w.clock.now() - 10_000)
        before = w.cp.board._stop()[0]
        w.agent.note_coverage("failed_open")
        after = w.cp.board._stop()[0]
        self.assertLess(after, before)
        page = w.cp.board.page(OWNER)
        self.assertIn("Live:", page)
        self.assertIn("Quiet: LT-quiet", page)
        self.assertIn("Failed open: LT-17", page)
        self.assertIn("No agent: srv-bare", page)
        self.assertNotIn("pager", page.lower())
        self.assertNotIn("email integration", page.lower())


if __name__ == "__main__":
    unittest.main()
