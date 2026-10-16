import dataclasses, os, unittest
from helpers import *
from rig6 import *
from halvard.controlplane import ControlPlane
from halvard.glass.board import CAP_URGENT, MIN_MEASURED
from halvard.glass.evidence import ControlEvidence, CATALOG
from halvard.ward import simulate as sim


def real_firings(w, c): return next(x for x in w.cp.evidence.report() if x["control"] == c)


class BoardScoreTests(unittest.TestCase):
    def test_each_outcome_shows_its_working_and_the_overall_number_is_the_mean_of_what_was_measured(self):
        w = World6(); s = w.cp.board.score(OWNER); self.assertEqual(set(s["outcomes"]), {1, 2, 3, 4, 5})
        for p in s["outcomes"].values(): self.assertTrue(p["why"]); self.assertTrue(0 <= p["score"] <= 100)
        raw = round(sum(p["score"] for p in s["outcomes"].values()) / 5); self.assertEqual(s["overall"], min(raw, CAP_URGENT) if s["caps"] else raw)
        self.assertIn("not a probability", s["weights"])

    def test_an_outcome_with_nothing_measured_is_left_out_not_counted_as_full_marks(self):
        tmp = __import__("tempfile").mkdtemp(); cp = ControlPlane(tmp, ManualClock(), POLICY_KEY)
        s = cp.board.score(OWNER)
        for k in (1, 2, 3, 4): self.assertIsNone(s["outcomes"][k]["score"], k)                            # nothing assessed is not "nothing wrong"
        self.assertEqual(s["measured"], 1); self.assertIsNone(s["overall"]); self.assertIn("not enough measured yet", s["band"])
        page = cp.board.page(OWNER); self.assertIn("Based on 1 of 5", page); self.assertIn("Score: n/a", page)

    def test_the_overall_number_is_the_mean_of_only_what_was_measured(self):
        w = World6(); b = w.cp.board; b._limit = lambda: (None, "x"); b._restore = lambda: (None, "x")
        s = b.score(OWNER); vals = [s["outcomes"][k]["score"] for k in (1, 2, 5)]; self.assertEqual(s["measured"], 3)
        self.assertEqual(s["overall"], min(round(sum(vals) / 3), CAP_URGENT) if s["caps"] else round(sum(vals) / 3))
        b._stop = lambda: (None, "x"); self.assertIsNone(b.score(OWNER)["overall"])                       # two of five is not enough to give a number

    def test_something_urgent_caps_the_number_so_a_good_average_cannot_hide_it(self):
        w = World6(); b = w.cp.board; w.cp.glass.evaluate(); w.clock.advance(3 * DAY)
        s = b.score(OWNER); self.assertLessEqual(s["overall"], CAP_URGENT); self.assertTrue(any("fix-now" in c for c in s["caps"]))
        self.assertIn("Note: capped at", b.page(OWNER))
        w.web.host.software["webserver"] = "2.4.58"; w.cp.aws.instances["i-web"].imds_v2_required = True; w.cp.glass_cycle()
        self.assertFalse(any("fix-now" in c for c in b.score(OWNER)["caps"]))                         # closing the urgent items lifts the cap

    def test_an_expired_temporary_protection_costs_points_and_is_named(self):
        w = World6(); g = w.cp.glass; g.compensate(AN, "HLV-SAMPLE-0002@LT-17", 3, "x"); before = w.cp.board.score(OWNER)["outcomes"][1]["score"]
        w.clock.advance(4 * DAY); g.review_controls(); s = w.cp.board.score(OWNER)
        self.assertTrue(any("past expiry" in c for c in s["caps"])); self.assertLess(s["outcomes"][1]["score"], before)

    def test_a_crown_jewel_machine_without_a_working_agent_caps_the_score_until_it_checks_in(self):
        w = World6(); w.cp.store.update_entity(w.cp.ctx, "LT-17", criticality="crown_jewel"); w.clock.advance(3600); w.checkin()
        w.cp.fleet.agents["LT-17"].online = False; w.clock.advance(3600); w.checkin()                      # LT-17 goes quiet; the others keep checking in
        s = w.cp.board.score(OWNER); self.assertTrue(any("crown-jewel machine" in c for c in s["caps"]), s["caps"])
        w.cp.fleet.reconnect("LT-17"); w.checkin(); self.assertFalse(any("crown-jewel machine" in c for c in w.cp.board.score(OWNER)["caps"]))

    def test_the_page_answers_the_four_questions_with_the_same_numbers_and_says_what_it_does_not_measure(self):
        w = World6(); w.scan_all(); w.cp.aws.make_bucket_public("cust-exports", "mallory", "203.0.113.7"); w.cp.process()
        page = w.cp.board.page(OWNER)
        for h in ("ARE WE COVERED?", "WHAT IS OPEN?", "WHAT DID WE STOP?", "WHAT EVIDENCE CAN WE HAND OVER?", "Not measured:"): self.assertIn(h, page)
        s = w.cp.board.history[-1]; self.assertIn(f"Score: {s['overall']} / 100", page)
        for k, p in s["outcomes"].items(): self.assertIn(f"{k}. {p['name']}: {p['score']}", page)
        self.assertIn("1 cloud exposures closed automatically", page); self.assertIn("not a forecast", page)
        for banned in ("EDR", "XDR", "SIEM", "EPP", "SOAR"): self.assertNotIn(banned, page)

    def test_who_may_read_the_board_and_each_snapshot_is_recorded_with_its_trend(self):
        w = World6(); b = w.cp.board
        with self.assertRaises(PermissionError): b.score(SD)
        self.assertTrue(b.score(AUD)); p1 = b.page(OWNER); self.assertNotIn("since the last snapshot", p1)
        w.host.system_encrypted = False; p2 = b.page(OWNER); self.assertIn("since the last snapshot", p2)
        snaps = [r for r in w.cp.ledger.entries() if r["kind"] == "glass.board_score"]; self.assertEqual(len(snaps), 2); self.assertIsNone(snaps[0]["public"]["previous"]); self.assertEqual(snaps[1]["public"]["previous"], snaps[0]["public"]["overall"])
        self.assertTrue(w.cp.ledger.verify()[0])


class BoardArithmeticTests(unittest.TestCase):
    def item(self, tier, days_old, status="open"):
        from halvard.glass.exposure import make
        reach, exploit = {"now": ("internet", "exploited_in_wild"), "soon": ("internet", "none"), "scheduled": ("local", "none")}[tier]
        return make("x-" + tier, "vulnerability", "e", "E", "t", exploit, reach, 1.5, 0.3 if tier == "scheduled" else 0.5, 0, days_old * DAY, status=status)

    def test_deductions_are_exactly_as_stated_on_the_page(self):
        w = World6(); b = w.cp.board
        self.assertEqual(b._shrink([self.item("now", 3)])[0], 80); self.assertEqual(b._shrink([self.item("soon", 15)])[0], 95); self.assertEqual(b._shrink([self.item("scheduled", 61)])[0], 99)
        self.assertEqual(b._shrink([self.item("now", 1)])[0], 100)                                              # within its deadline: no deduction
        self.assertEqual(b._shrink([self.item("soon", 1, "compensation_expired")])[0], 80)                       # an expired protection costs 20
        self.assertEqual(b._shrink([self.item("now", 3, "accepted_risk")])[0], 100)

    def test_the_cap_holds_even_when_every_outcome_scores_full_marks(self):
        w = World6(); b = w.cp.board; w.cp.glass.evaluate(); w.clock.advance(3 * DAY)
        b._shrink = lambda items: (100, "x"); b._stop = lambda: (100, "x"); b._limit = lambda: (100, "x"); b._restore = lambda: (100, "x"); b._prove = lambda: (100, "x")
        s = b.score(OWNER); self.assertEqual(s["overall"], CAP_URGENT); self.assertEqual(CAP_URGENT, 59)
        for k in ("_shrink", "_stop", "_limit", "_restore", "_prove"): delattr(b, k)

    def test_a_ledger_that_does_not_verify_costs_half_the_last_outcome_and_caps_the_score(self):
        w = World6(); b = w.cp.board; n, d = w.cp.evidence.proven_share(); good = b._prove()[0]
        w.cp.ledger.verify = lambda: (False, ["tampered"])
        bad, why = b._prove(); self.assertEqual(bad, round(100 * 0.5 * n / d)); self.assertLess(bad, good); self.assertIn("DOES NOT verify", why)
        self.assertTrue(any("does not verify" in c for c in b.score(OWNER)["caps"]))


class ControlEvidenceTests(unittest.TestCase):
    def authorized_root(self, w, name="sim"):
        root = os.path.join(w.tmp, name); sim.authorize(root); sim.seed_files(root, n=12); return root

    def test_a_control_that_never_acted_is_listed_as_never_fired_not_as_working(self):
        w = World6(); r = real_firings(w, "RELAY.JOURNAL_ROLLBACK"); self.assertEqual((r["status"], r["real_firings"]), ("never_fired", 0))
        self.assertEqual(real_firings(w, "GLASS.EXPOSURE_RANKING")["status"], "fired") if w.cp.glass.evaluate() else None

    def test_an_exercise_proves_the_stop_and_the_restore_and_releases_isolation_but_does_not_count_as_a_real_firing(self):
        w = World6(); root = self.authorized_root(w)
        r = w.cp.evidence.exercise_ransomware_stop(ADM, w.agent, w.fs, root)
        self.assertTrue(r["ok"], r); self.assertTrue(r["stopped"]); self.assertEqual(r["files_restored"], r["files_total"]); self.assertFalse(w.host.isolated)
        for c in ("WARD.BEHAVIORAL_STOP", "RELAY.JOURNAL_ROLLBACK"):
            x = real_firings(w, c); self.assertEqual((x["status"], x["real_firings"]), ("exercised", 0)); self.assertEqual(x["evidence"]["device"], "LT-17")
        self.assertTrue(any(x["kind"] == "glass.control_exercised" and x["public"]["simulation"] for x in w.cp.ledger.entries()))
        self.assertEqual(w.cp.board.score(OWNER)["outcomes"][4]["score"] >= 50, True)

    def test_isolation_applied_during_an_exercise_is_released_again(self):
        w = World6(); root = self.authorized_root(w); real = sim.run_simulation
        def with_isolation(fs, pid, r, **k):
            n = real(fs, pid, r, **k)
            res = w.agent.engine.request(ActionRequest("isolate_host", Principal("halvard:auto", "system"), ["LT-17"], "x", None, {}, automatic=True, pattern="ransomware_stop", critical=True))
            w.agent.incidents[-1]["results"].append(("isolate_host", res.status, res.message, res.action_id)); return n
        sim.run_simulation = with_isolation
        try: self.assertTrue(w.host.isolated is False); r = w.cp.evidence.exercise_ransomware_stop(ADM, w.agent, w.fs, root)
        finally: sim.run_simulation = real
        self.assertTrue(r["ok"]); self.assertTrue(r["isolation_released"]); self.assertFalse(w.host.isolated)
        self.assertEqual(real_firings(w, "RELAY.ISOLATE_HOST")["status"], "exercised")

    def test_an_exercise_that_fails_proves_nothing_and_leaves_the_test_files_as_they_were(self):
        w = World6(); b = dataclasses.replace(w.agent.bundle, version=w.agent.bundle.version + 1, prevention={"bulk_encryption": "audit", "known_bad": "enforce"})
        self.assertTrue(w.agent.apply_bundle(b.sign(w.cp.fleet.key).__dict__.copy(), w.cp.fleet.key))
        root = self.authorized_root(w); files = sorted(str(p) for p in __import__("pathlib").Path(root).rglob("*") if p.is_file() and p.name != sim.MARKER); orig = {p: open(p, "rb").read() for p in files}
        r = w.cp.evidence.exercise_ransomware_stop(ADM, w.agent, w.fs, root)
        self.assertFalse(r["ok"]); self.assertFalse(r["stopped"]); self.assertGreater(r["test_files_repaired_by_cleanup"], 0)
        self.assertEqual({p: open(p, "rb").read() for p in files}, orig); self.assertEqual(sorted(str(p) for p in __import__("pathlib").Path(root).rglob("*") if p.is_file() and p.name != sim.MARKER), files)
        for c in ("WARD.BEHAVIORAL_STOP", "RELAY.JOURNAL_ROLLBACK"): self.assertEqual(real_firings(w, c)["status"], "never_fired")
        self.assertFalse(next(x for x in w.cp.ledger.entries() if x["kind"] == "glass.control_exercised")["public"]["ok"])

    def test_real_traffic_counts_as_real_and_proof_goes_stale_after_ninety_days(self):
        w = World6(); root = os.path.join(w.tmp, "real"); sim.authorize(root); sim.seed_files(root, n=12)
        w.host.spawn(777, "cryptor.exe", exe_sha256="cd" * 32); sim.run_simulation(w.fs, 777, root)
        x = real_firings(w, "WARD.BEHAVIORAL_STOP"); self.assertEqual(x["status"], "fired"); self.assertGreater(x["real_firings"], 0)
        w.clock.advance(91 * DAY); self.assertEqual(real_firings(w, "WARD.BEHAVIORAL_STOP")["status"], "stale")

    def test_the_exercise_only_runs_where_the_customer_authorized_it_and_for_the_right_role(self):
        w = World6(); bad = os.path.join(w.tmp, "unmarked"); os.makedirs(bad); open(os.path.join(bad, "a.txt"), "wb").write(b"x" * 100)
        with self.assertRaises(sim.SimulationNotAuthorized): w.cp.evidence.exercise_ransomware_stop(ADM, w.agent, w.fs, bad)
        self.assertEqual(open(os.path.join(bad, "a.txt"), "rb").read(), b"x" * 100)
        with self.assertRaises(PermissionError): w.cp.evidence.exercise_ransomware_stop(SD, w.agent, w.fs, self.authorized_root(w))
        empty = os.path.join(w.tmp, "empty"); sim.authorize(empty)
        with self.assertRaises(ValueError): w.cp.evidence.exercise_ransomware_stop(ADM, w.agent, w.fs, empty)

    def test_every_control_in_the_catalog_is_tagged_with_one_of_the_five_outcomes_and_a_plain_name(self):
        self.assertTrue(all(o in (1, 2, 3, 4, 5) and n.strip() for _, o, _, n in CATALOG)); self.assertEqual({o for _, o, _, _ in CATALOG}, {1, 2, 3, 4, 5})
        self.assertEqual(len({c for c, *_ in CATALOG}), len(CATALOG))


if __name__ == "__main__":
    unittest.main()
