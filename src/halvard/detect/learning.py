"""Tenant-specific false-positive learning (F029) that an administrator can see, bound and reverse.

Nothing is learned silently. Repeated "this was fine" feedback only produces a SUGGESTED exception. A person approves
it after seeing a preview that replays history. Guard rails:
  * an exception is narrow: detection + program hash (+ optional folder, devices), and it expires (max 90 days),
  * it cannot be approved if it would also hide something an analyst already confirmed as malicious,
  * known-bad hash blocks can never be excepted,
  * for bulk-encryption behavior the effect is 'observe only': Ward stops freezing/stopping that program but still
    journals every write and records every event, so a wrong exception remains recoverable,
  * revoking brings back full protection at once and lists everything that was suppressed so it can be re-triaged.
"""
import hashlib
from dataclasses import dataclass, field, asdict

DAY = 86400.0
MAX_DAYS = 90
NEVER = {"known_bad_hash"}
SUGGEST_MARKS, SUGGEST_DEVICES = 3, 2
APPROVER_ROLES = {"analyst", "it_admin"}


@dataclass
class Exception_:
    id: str
    detection_id: str
    exe_sha256: str
    proc: str
    created_by: str
    created_at: float
    expires_at: float
    dir_prefix: str | None = None
    devices: list | None = None
    effect: str = "suppress_alert"       # or observe_only (Ward behavior)
    status: str = "suggested"
    approved_by: str | None = None
    reason: str = ""
    evidence: list = field(default_factory=list)
    revoked_by: str | None = None


class LearningError(ValueError):
    pass


def fingerprint(item):
    """Content-free identity of a finding: which detection, which program (by hash), where."""
    ev = item.get("event", {})
    return (item.get("rule_id") or item.get("detection_id"), item.get("exe_sha256") or ev.get("exe_sha256"),
            item.get("proc") or ev.get("proc"), item.get("device") or ev.get("device"),
            item.get("path") or ev.get("path"))


class LearningStore:
    def __init__(self, clock, audit=None):
        self.clock, self.audit = clock, audit
        self.marks, self.exceptions, self.suppressed, self._n = [], {}, [], 0

    def _log(self, kind, who, ex, data=None):
        if self.audit:
            self.audit.append(kind, getattr(who, "id", who), getattr(who, "role", "system"), ex.id,
                              {"detection": ex.detection_id, "status": ex.status, **(data or {})}, controls=("DETECT.FP_LEARNING",))

    # ---- feedback ----
    def mark(self, item, verdict, by):
        if verdict not in ("benign", "malicious"): raise LearningError("verdict is benign or malicious")
        if by.role not in APPROVER_ROLES: raise PermissionError("only analysts and administrators give feedback")
        det, sha, proc, dev, path = fingerprint(item)
        m = {"id": len(self.marks) + 1, "ts": self.clock.now(), "verdict": verdict, "detection": det, "exe_sha256": sha,
             "proc": proc, "device": dev, "path": path, "by": by.id}
        self.marks.append(m)
        if self.audit:
            self.audit.append("learning.feedback", by.id, by.role, str(det), {"verdict": verdict, "proc": proc, "device": dev, "path": path},
                              controls=("DETECT.FP_LEARNING",))
        return self._suggest(det, sha, proc)

    def _suggest(self, det, sha, proc):
        if not sha or det in NEVER: return None
        benign = [m for m in self.marks if m["verdict"] == "benign" and m["detection"] == det and m["exe_sha256"] == sha]
        if any(m["verdict"] == "malicious" and m["detection"] == det and m["exe_sha256"] == sha for m in self.marks): return None
        if len(benign) < SUGGEST_MARKS or len({m["device"] for m in benign}) < SUGGEST_DEVICES: return None
        for e in self.exceptions.values():
            if e.detection_id == det and e.exe_sha256 == sha and e.status in ("suggested", "active"): return e
        return self.propose("halvard:learning", det, sha, proc, f"{len(benign)} benign marks on {len({m['device'] for m in benign})} devices",
                            evidence=[m["id"] for m in benign])

    # ---- lifecycle ----
    def propose(self, by, det, sha, proc, reason, dir_prefix=None, devices=None, days=30, evidence=()):
        if det in NEVER: raise LearningError("known-bad blocks can never be excepted")
        if not sha: raise LearningError("an exception must name the program by its hash")
        if not 1 <= days <= MAX_DAYS: raise LearningError(f"exceptions last 1 to {MAX_DAYS} days")
        self._n += 1; now = self.clock.now()
        ward = det == "ward.bulk_encryption"
        e = Exception_(f"X-{self._n}", det, sha, proc, getattr(by, "id", by), now, now + days * DAY, dir_prefix, devices,
                       "observe_only" if ward else "suppress_alert", "suggested", None, reason, list(evidence))
        self.exceptions[e.id] = e; self._log("learning.exception_proposed", by if hasattr(by, "id") else "halvard:learning", e, {"reason": reason}); return e

    def preview(self, ex, history):
        """history: past hits/incidents (dicts). Says what this exception would have hidden."""
        would = [h for h in history if self._matches(ex, h, ignore_status=True)]
        mal = [m for m in self.marks if m["verdict"] == "malicious" and m["detection"] == ex.detection_id and
               (m["exe_sha256"] == ex.exe_sha256 or m["proc"] == ex.proc)]
        return {"would_suppress": len(would), "conflicts_with_confirmed_malicious": len(mal),
                "effect": ex.effect, "expires_in_days": round((ex.expires_at - self.clock.now()) / DAY, 1)}

    def approve(self, ex, approver, history=()):
        if approver.role not in APPROVER_ROLES: raise PermissionError("only analysts and administrators approve exceptions")
        if ex.status != "suggested": raise LearningError(f"exception is {ex.status}")
        if approver.id == ex.created_by: raise PermissionError("someone other than the proposer approves")
        pv = self.preview(ex, list(history))
        if pv["conflicts_with_confirmed_malicious"]:
            raise LearningError("refused: this would also hide a finding an analyst confirmed as malicious")
        ex.status, ex.approved_by = "active", approver.id; self._log("learning.exception_approved", approver, ex, pv); return ex

    def revoke(self, ex, by, reason=""):
        if by.role not in APPROVER_ROLES: raise PermissionError("only analysts and administrators revoke exceptions")
        ex.status, ex.revoked_by = "revoked", by.id
        reopened = [s for s in self.suppressed if s["exception"] == ex.id]
        self._log("learning.exception_revoked", by, ex, {"reason": reason, "to_retriage": len(reopened)})
        return reopened

    # ---- matching (device side uses the same code with exported entries) ----
    def _matches(self, ex, item, ignore_status=False):
        if not ignore_status and (ex.status != "active" or ex.expires_at <= self.clock.now()): return False
        det, sha, proc, dev, path = fingerprint(item)
        if det != ex.detection_id or sha != ex.exe_sha256: return False
        if ex.devices is not None and dev not in ex.devices: return False
        if ex.dir_prefix and not (path or "").lower().startswith(ex.dir_prefix.lower()): return False
        return True

    def check(self, item):
        for ex in self.exceptions.values():
            if self._matches(ex, item):
                s = {"ts": self.clock.now(), "exception": ex.id, "detection": ex.detection_id, "device": fingerprint(item)[3], "item": fingerprint(item)}
                self.suppressed.append(s); return ex
        return None

    def sweep(self):
        out = []
        for e in self.exceptions.values():
            if e.status == "active" and e.expires_at <= self.clock.now(): e.status = "expired"; out.append(e.id); self._log("learning.exception_expired", "halvard:sweeper", e)
        return out

    def export_active(self):
        return [asdict(e) for e in self.exceptions.values() if e.status == "active"]


class DeviceMatcher:
    """Device-side copy: applies exported entries, enforces expiry locally, keeps a local log for the spool."""
    def __init__(self, clock, entries=()):
        s = LearningStore(clock)
        for d in entries:
            e = Exception_(**d); s.exceptions[e.id] = e
        self.store = s

    def match(self, item): return self.store.check(item)
