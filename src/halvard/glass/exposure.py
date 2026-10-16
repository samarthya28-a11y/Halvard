"""Ranking (F093). One rule, shown in full on every item: exploitability x reach x asset value x severity, each an ORDINAL weight.

The product orders the list. It is not a probability and not a loss estimate, and the page says so. The tier (fix now / this week / schedule)
comes from plain rules on the same facts, not from the number, so a person can predict it. Defaults below are Halvard's; a customer may
change the SLA days. They are not derived from data and are labelled as defaults.
"""
from dataclasses import dataclass, field

EXPLOIT_W = {"exploited_in_wild": 4.0, "public_exploit": 2.0, "none": 1.0}
EXPLOIT_TXT = {"exploited_in_wild": "known to be used in attacks", "public_exploit": "a working exploit is public", "none": "no known exploit"}
REACH_W = {"internet": 3.0, "network": 1.5, "local": 1.0}
REACH_TXT = {"internet": "reachable from the internet", "network": "reachable from inside the network", "local": "needs a foothold on the machine first"}
CRIT_W = {"crown_jewel": 4.0, "high": 2.5, None: 1.5, "normal": 1.5, "low": 1.0}
SEV_W = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3}
TIERS = ("now", "soon", "scheduled")
TIER_TXT = {"now": "Fix now", "soon": "Fix this fortnight", "scheduled": "Schedule"}
DEFAULT_SLA_DAYS = {"now": 2, "soon": 14, "scheduled": 60}


def value_weight(criticality, sensitivity, asset_class):
    w = CRIT_W.get(criticality, 1.5)
    if sensitivity in ("regulated", "confidential"): w *= 1.5
    if asset_class in ("production", "clinical", "privileged"): w *= 1.25
    return round(w, 3)


def tier_of(exploit, reach, value_w, sev_w, compensated=False):
    if exploit == "exploited_in_wild" and (reach == "internet" or value_w >= 4): t = "now"
    elif reach == "internet" and sev_w >= 0.8 and value_w >= 4: t = "now"
    elif exploit != "none" or reach == "internet" or (value_w >= 4 and sev_w >= 0.7): t = "soon"
    else: t = "scheduled"
    if compensated and t == "now": t = "soon"           # a live temporary protection steps "now" down one level; nothing else
    return t


@dataclass
class Exposure:
    id: str
    kind: str                  # vulnerability | misconfiguration
    entity: str
    entity_name: str
    title: str
    exploit: str
    reach: str
    value_w: float
    sev_w: float
    score: float
    tier: str
    sla_days: int
    first_seen: float
    now: float
    status: str = "open"       # open | compensated | compensation_expired | accepted_risk
    advisory: str | None = None
    product: str | None = None
    version: str | None = None
    fixed_in: str | None = None
    fix: str = ""
    fix_params: dict = field(default_factory=dict)
    workaround: str | None = None
    why: list = field(default_factory=list)
    note: str = ""

    @property
    def age_days(self): return (self.now - self.first_seen) / 86400
    @property
    def overdue(self): return self.status != "accepted_risk" and self.age_days > self.sla_days

    def explain(self):
        return (f"{TIER_TXT[self.tier]}: {self.title} on {self.entity_name}. {EXPLOIT_TXT[self.exploit].capitalize()}; {REACH_TXT[self.reach]}. "
                f"Ordering number {self.score:g} = exploit {EXPLOIT_W[self.exploit]:g} x reach {REACH_W[self.reach]:g} x asset value {self.value_w:g} x severity {self.sev_w:g}; "
                "weights are ordinal defaults, not a probability.")


def make(id, kind, entity, entity_name, title, exploit, reach, value_w, sev_w, first_seen, now, sla=None, compensated=False, **kw):
    t = tier_of(exploit, reach, value_w, sev_w, compensated)
    return Exposure(id, kind, entity, entity_name, title, exploit, reach, value_w, sev_w, round(EXPLOIT_W[exploit] * REACH_W[reach] * value_w * sev_w, 3), t,
                    (sla or DEFAULT_SLA_DAYS)[t], first_seen, now, **kw)
