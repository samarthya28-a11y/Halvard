"""Coverage is an incident, not a chart (F121). Any entity that should be protected and has no fresh Ward heartbeat
raises a coverage_gap finding; a crown-jewel gap is incident-level and is never silenced by a change window (F122)."""
from dataclasses import dataclass


@dataclass
class Gap:
    entity_id: str
    name: str
    severity: str        # incident | gap
    reason: str


class CoverageMonitor:
    def __init__(self, store, ctx, clock, audit=None):
        self.store, self.ctx, self.clock, self.audit = store, ctx, clock, audit
        self.rows = []

    def record(self, device, reason, when=None):
        """One row a person can read: which device, why coverage failed, and when."""
        row = {"device": device, "reason": reason, "time": self.clock.now() if when is None else when}
        self.rows.append(row)
        if self.audit:
            self.audit.append("coverage.row", "halvard:coverage", "system", device, dict(row), controls=("WARD.COVERAGE",))
        return row

    def resolve(self, device, reason):
        """A later heartbeat means this device is checking in again. Drop the open rows of this reason. A pending drop stays until someone restores the file."""
        kept, gone = [], 0
        for row in self.rows:
            if row["device"] == device and row["reason"] == reason:
                gone += 1
            else:
                kept.append(row)
        self.rows = kept
        if gone and self.audit:
            self.audit.append("coverage.cleared", "halvard:coverage", "system", device, {"device": device, "reason": reason, "cleared": gone}, controls=("WARD.COVERAGE",))
        return gone

    def evaluate(self, change_windows=None, record=True):
        now, gaps = self.clock.now(), []
        change_windows = change_windows or {}
        for e in self.store.protected_entities(self.ctx):
            if e["sensor_id"] is None:
                reason = "No Halvard agent is installed here."
            elif now - e["last_heartbeat"] > e["promised_interval_s"]:
                reason = f"The agent last checked in {int((now - e['last_heartbeat']) // 60)} minutes ago (promised every {e['promised_interval_s'] // 60})."
            else:
                continue
            crown = e["criticality"] == "crown_jewel"
            win = change_windows.get(e["entity_id"])
            if win and win[0] <= now < win[1] and not crown:
                continue    # a change window may quiet an ordinary gap, never a crown-jewel one
            g = Gap(e["entity_id"], e["display_name"], "incident" if crown else "gap", reason)
            gaps.append(g)
            if not record: continue
            self.store.add_finding(self.ctx, f"cov-{e['entity_id']}", e["entity_id"], "coverage_gap", "Ward",
                                   1.0, [reason], now)
            if self.audit:
                self.audit.append("coverage.gap_raised", "halvard:coverage", "system", e["entity_id"],
                                  {"severity": g.severity, "reason": reason}, controls=("WARD.COVERAGE",))
        return gaps
