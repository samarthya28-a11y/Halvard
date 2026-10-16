"""Governed custom-detection library (F022, F023, F036).

Lifecycle: draft -> in_review -> active -> (expired | retired). Rules that cannot be shown to work do not ship:
  * a rule needs at least one positive and one negative example and must pass them,
  * a seven-day backtest over stored telemetry must stay under the rule's noise cap,
  * a different person must approve it (authors cannot self-approve),
  * every rule expires (default maximum 180 days); renewing means a new version and a new review,
  * ATT&CK tags are validated against the bundled technique list.
Active rules ship to devices as a signed content pack and are evaluated on the device, so they work offline.
"""
import hashlib, hmac, json, re
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from pathlib import Path

from ..hunt import ql

ATTACK = json.loads((Path(__file__).resolve().parents[3] / "policy" / "attack_techniques.json").read_text())
SEVERITIES = ("low", "medium", "high", "critical")
MAX_EXPIRY_DAYS = 180
AUTHOR_ROLES = {"analyst", "it_admin"}
DAY = 86400.0


class RuleError(ValueError):
    pass


def _canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class Rule:
    id: str
    name: str
    description: str
    query: str
    techniques: list
    severity: str
    confidence: float                  # set by the author; labelled as such everywhere it is shown
    expires_at: float
    author: str
    version: int = 1
    status: str = "draft"
    reviewer: str | None = None
    threshold: dict | None = None      # {"count": n, "window_s": s, "by": "device"}
    max_hits_per_day: int = 500
    tests: dict = field(default_factory=lambda: {"positive": [], "negative": []})
    created_at: float = 0.0
    review_note: str = ""


class DetectionLibrary:
    def __init__(self, clock, audit=None, events=None):
        self.clock, self.audit, self.events = clock, audit, events
        self.rules: dict[str, dict[int, Rule]] = defaultdict(dict)    # id -> version -> Rule
        self.pack_version = 0

    # ---------- helpers ----------
    def _log(self, kind, who, rule, data=None):
        if self.audit:
            self.audit.append(kind, who.id, who.role, rule.id, {"version": rule.version, "status": rule.status, **(data or {})},
                              controls=("DETECT.GOVERNANCE",))

    def _get(self, rid, version=None):
        vs = self.rules.get(rid)
        if not vs: raise KeyError(rid)
        return vs[version if version else max(vs)]

    def active(self, rid):
        vs = [r for r in self.rules.get(rid, {}).values() if r.status == "active"]
        return max(vs, key=lambda r: r.version) if vs else None

    # ---------- authoring ----------
    def create(self, author, spec: dict, rid=None) -> Rule:
        if author.role not in AUTHOR_ROLES: raise PermissionError(f"role {author.role} cannot author detections")
        q = ql.parse(spec["query"])
        if q.stages: raise RuleError("a detection is a filter; remove the | stages (use threshold for counting)")
        if q.ast is None: raise RuleError("an empty query would match everything")
        techs = list(spec.get("techniques", []))
        if not techs: raise RuleError("tag at least one ATT&CK technique")
        for t in techs:
            if t not in ATTACK["techniques"]: raise RuleError(f"{t} is not in the bundled ATT&CK list (a content update may add it)")
        if spec.get("severity") not in SEVERITIES: raise RuleError(f"severity must be one of {SEVERITIES}")
        now = self.clock.now()
        exp = spec["expires_at"]
        if exp <= now: raise RuleError("expiry is in the past")
        if exp > now + MAX_EXPIRY_DAYS * DAY: raise RuleError(f"rules expire within {MAX_EXPIRY_DAYS} days; renew through review")
        th = spec.get("threshold")
        if th and (th.get("count", 0) < 2 or th.get("window_s", 0) <= 0 or th.get("by") not in ql.FIELDS):
            raise RuleError("threshold needs count >= 2, window_s > 0 and a valid 'by' field")
        rid = rid or "R-" + hashlib.sha256((spec["name"] + str(now)).encode()).hexdigest()[:8]
        version = (max(self.rules[rid]) + 1) if rid in self.rules else 1
        r = Rule(rid, spec["name"], spec.get("description", ""), spec["query"], techs, spec["severity"],
                 float(spec.get("confidence", 0.5)), exp, author.id, version, "draft", None, th,
                 int(spec.get("max_hits_per_day", 500)), spec.get("tests", {"positive": [], "negative": []}), now)
        self.rules[rid][version] = r
        self._log("detect.rule_created", author, r); return r

    def run_tests(self, r: Rule):
        ast = ql.parse(r.query).ast; fails = []
        if not r.tests["positive"] or not r.tests["negative"]:
            fails.append("needs at least one positive and one negative example")
        for i, e in enumerate(r.tests["positive"]):
            if not ql.matches(ast, e): fails.append(f"positive example {i} does not match")
        for i, e in enumerate(r.tests["negative"]):
            if ql.matches(ast, e): fails.append(f"negative example {i} matches (rule is too broad)")
        return fails

    def backtest(self, ctx, r: Rule, days=7):
        if not self.events: return None
        now = self.clock.now()
        rows, trunc = self.events.query_rows(ctx, ql.parse(r.query).ast, now - days * DAY, now, True)
        return {"matches": len(rows), "per_day": round(len(rows) / days, 1), "truncated": trunc}

    def submit(self, r: Rule, by, ctx=None):
        if by.id != r.author: raise PermissionError("only the author submits a draft")
        fails = self.run_tests(r)
        bt = self.backtest(ctx, r) if ctx else None
        if bt and bt["per_day"] > r.max_hits_per_day:
            fails.append(f"too noisy: {bt['per_day']} matches/day over the last 7 days (cap {r.max_hits_per_day}); narrow the query")
        self._log("detect.rule_submitted", by, r, {"failures": len(fails), "backtest_matches": (bt or {}).get("matches")})
        if fails: return {"ok": False, "failures": fails, "backtest": bt}
        r.status = "in_review"; return {"ok": True, "failures": [], "backtest": bt}

    def approve(self, r: Rule, reviewer, note=""):
        if reviewer.role not in AUTHOR_ROLES: raise PermissionError("reviewer must be an analyst or administrator")
        if reviewer.id == r.author: raise PermissionError("authors cannot approve their own detection")
        if r.status != "in_review": raise RuleError(f"rule is {r.status}, not in review")
        if r.expires_at <= self.clock.now(): raise RuleError("expired before approval")
        for old in self.rules[r.id].values():
            if old.status == "active": old.status = "retired"
        r.status, r.reviewer, r.review_note = "active", reviewer.id, note
        self._log("detect.rule_approved", reviewer, r, {"author": r.author}); return r

    def reject(self, r: Rule, reviewer, reason):
        if reviewer.id == r.author: raise PermissionError("authors cannot review their own detection")
        r.status, r.review_note = "draft", reason; self._log("detect.rule_rejected", reviewer, r, {"reason": reason})

    def retire(self, rid, by):
        r = self.active(rid)
        if r: r.status = "retired"; self._log("detect.rule_retired", by, r)

    def rollback(self, rid, to_version, by):
        """Re-activate an earlier APPROVED version (it keeps its original reviewer and must still be unexpired)."""
        old = self._get(rid, to_version)
        if not old.reviewer: raise RuleError("that version was never approved")
        if old.expires_at <= self.clock.now(): raise RuleError("that version has expired; submit a new version")
        for r in self.rules[rid].values():
            if r.status == "active": r.status = "retired"
        old.status = "active"; self._log("detect.rule_rolled_back", by, old); return old

    def sweep(self):
        """Expire rules past their date. Returns the ids expired."""
        now, out = self.clock.now(), []
        for vs in self.rules.values():
            for r in vs.values():
                if r.status in ("active", "in_review", "draft") and r.expires_at <= now:
                    was = r.status; r.status = "expired"; out.append(r.id)
                    if self.audit:
                        self.audit.append("detect.rule_expired", "halvard:sweeper", "system", r.id, {"version": r.version, "was": was},
                                          controls=("DETECT.GOVERNANCE",))
        return out

    # ---------- distribution (F036) ----------
    def build_pack(self, key: bytes):
        self.pack_version += 1
        rules = [asdict(r) for rid in self.rules for r in [self.active(rid)] if r]
        body = {"version": self.pack_version, "issued_at": self.clock.now(), "rules": rules,
                "attack_techniques": sorted(ATTACK["techniques"])}
        return {**body, "signature": hmac.new(key, _canon(body), "sha256").hexdigest()}


class PackError(ValueError):
    pass


def verify_pack(pack: dict, key: bytes, current_version: int):
    body = {k: v for k, v in pack.items() if k != "signature"}
    if not hmac.compare_digest(hmac.new(key, _canon(body), "sha256").hexdigest(), pack.get("signature", "")):
        raise PackError("content pack signature invalid; keeping current detections")
    if pack["version"] <= current_version: raise PackError("content pack is not newer; refusing rollback")
    return pack


class Runtime:
    """Device-side evaluator over a verified pack. No network, no cloud."""
    def __init__(self, clock):
        self.clock, self.version, self.rules = clock, 0, []
        self.windows = defaultdict(deque)

    def load(self, pack):
        self.version = pack["version"]
        self.rules = [(r, ql.parse(r["query"]).ast) for r in pack["rules"]]
        self.windows.clear()

    def on_event(self, ev, suppressor=None):
        if not self.rules: return []
        now, hits = self.clock.now(), []
        for r, ast in self.rules:
            if r["expires_at"] <= now: continue          # expiry is enforced on the device, not only in the console
            if not ql.matches(ast, ev): continue
            th = r.get("threshold")
            if th:
                key = (r["id"], ev.get(th["by"])); w = self.windows[key]; w.append(now)
                while w and now - w[0] > th["window_s"]: w.popleft()
                if len(w) < th["count"]: continue
                w.clear()
            hit = {"rule_id": r["id"], "version": r["version"], "name": r["name"], "techniques": r["techniques"],
                   "severity": r["severity"], "confidence": r["confidence"], "confidence_source": "author-set",
                   "device": ev.get("device"), "event": ev}
            if suppressor and suppressor(hit): continue
            hits.append(hit)
        return hits
