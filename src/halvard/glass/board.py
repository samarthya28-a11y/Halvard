"""The board's page (F099): four questions, one score, and the working shown.

The score is a plain calculation over things Halvard measured, not a prediction and not a benchmark against other companies. Each outcome is
0-100 from a stated formula; an outcome with nothing measured is shown as 'not measured' and left out, never counted as full marks. The overall
number is the mean of the measured outcomes, and it is capped when something urgent is open, so a pleasant average cannot hide a bad fact.
Deduction weights are Halvard defaults, labelled as such.
"""
from .evidence import OUTCOMES

DEDUCT = {"now": 20, "soon": 5, "scheduled": 1}           # per overdue item
CAP_URGENT, MIN_MEASURED = 59, 3
BANDS = ((85, "Strong"), (70, "Good"), (50, "Fair: a few things need attention"), (0, "Needs attention: see what is open"))


def band(n): return next(t for lo, t in BANDS if n >= lo)


class Board:
    def __init__(self, glass, coverage, evidence, ledger, clock, fleet, cases=None, store=None, ctx=None):
        self.glass, self.coverage, self.evidence, self.ledger, self.clock, self.fleet, self.cases, self.store, self.ctx = glass, coverage, evidence, ledger, clock, fleet, cases, store, ctx
        self.history = []

    # ---- the five outcomes ----
    def _shrink(self, items):
        if not items and not self.glass.reports() and not self.glass.atlas.posture_findings and not (self.glass.surface and self.glass.surface.observed):
            return None, "nothing has been assessed yet: no device reports software, no cloud posture run, no external scan"
        over = [x for x in items if x.overdue]; ded = sum(DEDUCT[x.tier] for x in over)
        expired = [x for x in items if x.status == "compensation_expired"]
        score = max(0, 100 - ded - 20 * len(expired))
        return score, f"{len(items)} open item(s); {len(over)} past their deadline; {len(expired)} temporary protection(s) past expiry. Deductions: fix-now 20, this-fortnight 5, schedule 1 per overdue item; 20 per expired protection."

    def _stop(self):
        prot = self.store.protected_entities(self.ctx)
        if not prot: return None, "no protected machines registered"
        gaps = self.coverage.evaluate(record=False)
        fresh = len(prot) - len(gaps)
        enforce = sum(1 for a in self.fleet.agents.values() if all(m == "enforce" for m in (a.bundle.prevention.get("bulk_encryption"), a.bundle.prevention.get("known_bad"))))
        pe = enforce / max(1, len(self.fleet.agents))
        return round(100 * fresh / len(prot) * pe), f"{fresh} of {len(prot)} protected machines checked in on time; {enforce} of {len(self.fleet.agents)} agents set to block (not just watch). Score = coverage x blocking share."

    def _limit(self):
        agents = list(self.fleet.agents.values())
        if not agents: return None, "no devices"
        online = sum(1 for a in agents if a.online)
        ev = {x["control"]: x for x in self.evidence.report()}
        proven = [c for c in ("RELAY.ISOLATE_HOST", "RELAY.APPROVAL_GATES", "RELAY.COMMAND_CHANNEL") if ev[c]["status"] in ("fired", "exercised")]
        return round(100 * (0.5 * online / len(agents) + 0.5 * len(proven) / 3)), f"{online} of {len(agents)} devices can take a containment command now; {len(proven)} of 3 containment controls have been seen working. Half and half."

    def _restore(self):
        agents = list(self.fleet.agents.values())
        if not agents: return None, "no devices"
        on = sum(1 for a in agents if a.journal.quota > 0)
        ev = {x["control"]: x for x in self.evidence.report()}["RELAY.JOURNAL_ROLLBACK"]
        proven = ev["status"] in ("fired", "exercised")
        return round(100 * (0.5 * on / len(agents) + 0.5 * proven)), f"{on} of {len(agents)} devices keep a file journal; a restore has {'been' if proven else 'not been'} seen working in the last 90 days. Backups are not measured yet."

    def _prove(self):
        ok, problems = self.ledger.verify(); n, d = self.evidence.proven_share()
        return round(100 * (0.5 * ok + 0.5 * n / d)), f"The Ledger {'verifies' if ok else 'DOES NOT verify'}; {n} of {d} controls have been seen firing or were exercised in the last 90 days."

    # ---- the page ----
    def score(self, principal):
        self.glass.require(principal, "view_board")
        items = self.glass.evaluate(); parts = {}
        for k, (v, why) in {1: self._shrink(items), 2: self._stop(), 3: self._limit(), 4: self._restore(), 5: self._prove()}.items(): parts[k] = {"name": OUTCOMES[k], "score": v, "why": why}
        measured = [p["score"] for p in parts.values() if p["score"] is not None]
        overall, caps = round(sum(measured) / len(measured)) if len(measured) >= MIN_MEASURED else None, []
        if overall is not None:
            now_over = [x for x in items if x.tier == "now" and x.overdue]
            expired = [x for x in items if x.status == "compensation_expired"]
            crown = [g for g in self.coverage.evaluate(record=False) if g.severity == "incident"]
            if now_over or expired or crown:
                caps.append(f"capped at {CAP_URGENT}: " + "; ".join(filter(None, [f"{len(now_over)} fix-now item(s) past deadline" if now_over else "", f"{len(expired)} temporary protection(s) past expiry" if expired else "", f"{len(crown)} crown-jewel machine(s) without a working agent" if crown else ""])))
                overall = min(overall, CAP_URGENT)
            ok_ledger, _ = self.ledger.verify()
            if not ok_ledger: caps.append(f"capped at {CAP_URGENT}: the Ledger does not verify"); overall = min(overall, CAP_URGENT)
        res = {"overall": overall, "band": band(overall) if overall is not None else f"not enough measured yet: a score needs at least {MIN_MEASURED} of 5 outcomes", "outcomes": parts, "caps": caps, "measured": len(measured), "ts": self.clock.now(),
               "open": len(items), "weights": "ordinal defaults; not a probability; not a comparison with other companies"}
        return res

    def snapshot(self, principal):
        s = self.score(principal); prev = self.history[-1] if self.history else None
        self.history.append(s)
        self.ledger.append("glass.board_score", "halvard:glass", "system", "board", {"overall": s["overall"], "outcomes": {k: v["score"] for k, v in s["outcomes"].items()}, "caps": len(s["caps"]), "previous": prev["overall"] if prev else None, "by": principal.id}, controls=("GLASS.BOARD_SCORE",))
        return s

    def page(self, principal):
        s = self.snapshot(principal); items = self.glass.evaluate(); prev = self.history[-2]["overall"] if len(self.history) > 1 else None
        L = []; add = L.append
        add("BOARD VIEW"); add(f"Score: {s['overall'] if s['overall'] is not None else 'n/a'} / 100 ({s['band']})" + (f"; {s['overall'] - prev:+d} since the last snapshot" if prev is not None and s["overall"] is not None else ""))
        add(f"Based on {s['measured']} of 5 outcomes measured. This is arithmetic over measured facts, not a forecast and not a ranking against other companies.")
        for c in s["caps"]: add("  Note: " + c)
        add("")
        add("ARE WE COVERED?")
        for k, p in s["outcomes"].items(): add(f"  {k}. {p['name']}: {p['score'] if p['score'] is not None else 'not measured'}. {p['why']}")
        add(""); add("WHAT IS OPEN?")
        for x in items[:5]: add(f"  [{x.tier}] {x.title} on {x.entity_name}" + (f" ({'overdue' if x.overdue else 'within deadline'}, {x.age_days:.0f} days)" if x.status != "accepted_risk" else " (risk accepted)") + (f" — {x.note}" if x.note else ""))
        if len(items) > 5: add(f"  ...and {len(items) - 5} more, in the ranked list.")
        if not items: add("  Nothing open that Halvard can see.")
        add(""); add("WHAT DID WE STOP?")
        stopped = self._stopped()
        for line in stopped or ["Nothing recorded in this period."]: add("  " + line)
        add(""); add("WHAT EVIDENCE CAN WE HAND OVER?")
        ev = self.evidence.report(); n, d = self.evidence.proven_share()
        add(f"  The Ledger {'verifies' if self.ledger.verify()[0] else 'does NOT verify'}. {n} of {d} controls have been seen working; an auditor can export evidence for any one of them without receiving employee content.")
        for x in [e for e in ev if e["status"] in ("never_fired", "stale")][:5]: add(f"  Not yet seen working: {x['name']} ({x['control']}).")
        add(""); add("Not measured: backup restore tests, cloud accounts other than the connected one, and anything on machines without an agent.")
        return "\n".join(L)

    def _stopped(self):
        from collections import Counter
        c = Counter()
        for rec in self.ledger.entries():
            k = rec["kind"]
            if k == "relay.action_executed" and rec["public"].get("pattern") in ("cloud_exposure_revert", "mail_clawback", "identity_takeover_containment", "malicious_mail_containment"): c[rec["public"]["pattern"]] += 1
        txt = {"cloud_exposure_revert": "cloud exposures closed automatically", "mail_clawback": "harmful messages pulled from inboxes", "identity_takeover_containment": "account takeovers contained", "malicious_mail_containment": "harmful-mail cases contained"}
        out = [f"{n} {txt[k]}" for k, n in sorted(c.items())]
        dev = sum(len(a.incidents) for a in self.fleet.agents.values())
        if dev: out.append(f"{dev} bulk-encryption attempt(s) stopped on devices")
        blocks = sum(1 for a in self.fleet.agents.values() for r in a.spool.entries() if r["kind"] == "ward.exec_verdict" and r["public"].get("decision") == "block")
        if blocks: out.append(f"{blocks} program(s) blocked before they could run")
        return out
