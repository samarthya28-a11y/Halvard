"""The gate in front of content inspection, and the catalog of what it found.

Looking inside files and messages is the most invasive thing a data-protection product does, so it is OFF until the customer turns it
on, and it can only run where the customer said it may, for the purpose they stated, after their notice to staff has taken effect.
Personal folders are excluded. The catalog keeps labels and counts only: never the matched values and never a snippet.
"""
import fnmatch, hashlib
from dataclasses import dataclass, field

from .classifiers import Classifier, Classification


class InspectionNotAllowed(PermissionError):
    pass


@dataclass
class InspectionPolicy:
    enabled: bool = False
    purpose: str = ""                                  # e.g. "prevent card data leaving the company"
    scope: list = field(default_factory=list)          # path globs on devices, "mail:outbound", "s3:<bucket>" or "s3:*"
    exclude: list = field(default_factory=lambda: ["*/personal/*", "*/Personal/*", "*/private/*", "*/.ssh/*", "*/Pictures/*", "*/Photos/*"])
    notice_id: str | None = None
    notice_effective_at: float | None = None
    max_file_bytes: int = 20 << 20

    def check(self, target: str, now: float):
        """(allowed, plain reason). Reasons are shown to administrators so they can see what is missing."""
        if not self.enabled: return False, "Content inspection is off. Turn it on in Data protection settings."
        if not self.purpose.strip(): return False, "A stated purpose is required before content can be inspected."
        if not self.notice_id or self.notice_effective_at is None: return False, "Staff notice has not been issued. Content inspection starts after the notice takes effect."
        if now < self.notice_effective_at: return False, "Staff notice has been issued but has not taken effect yet."
        norm = target.replace("\\", "/")
        if any(fnmatch.fnmatch(norm, g) or fnmatch.fnmatch(norm.lower(), g.lower()) for g in self.exclude): return False, "This location is excluded from inspection (personal or private)."
        if not any(fnmatch.fnmatch(norm, g) or norm == g or (g.endswith("*") and norm.startswith(g[:-1])) for g in self.scope): return False, "This location is outside the inspection scope."
        return True, ""


@dataclass
class CatalogEntry:
    source: str                  # device id, "mail:outbound", "s3:<bucket>"
    ref_hash: str                # hash of the path/key: the readable path is kept only in the private audit field
    labels: dict                 # label -> count
    sensitivity: str
    ts: float
    unscannable: str | None = None


class Inspector:
    def __init__(self, policy: InspectionPolicy, clock, classifier: Classifier | None = None, audit=None, source="device"):
        self.policy, self.clock, self.classifier, self.audit, self.source = policy, clock, classifier or Classifier(), audit, source
        self.catalog, self._cache = [], {}

    def inspect(self, target: str, name: str, data: bytes, who="system") -> Classification:
        ok, why = self.policy.check(target, self.clock.now())
        if not ok:
            if self.audit:
                self.audit.append("vaultline.inspection_refused", who, "system", self.source, {"why": why, "path": target}, controls=("VAULTLINE.INSPECTION_GATE",))
            raise InspectionNotAllowed(why)
        if len(data) > self.policy.max_file_bytes: data = data[: self.policy.max_file_bytes]
        key = hashlib.sha256(data).hexdigest()
        if key in self._cache: return self._cache[key]
        c = self.classifier.classify(name, data); self._cache[key] = c
        self.catalog.append(CatalogEntry(self.source, hashlib.sha256(target.encode()).hexdigest()[:16], {k: v["count"] for k, v in c.labels.items()}, c.sensitivity, self.clock.now(), c.unscannable))
        if self.audit:
            self.audit.append("vaultline.inspected", who, "system", self.source, {"labels": {k: v["count"] for k, v in c.labels.items()}, "sensitivity": c.sensitivity, "unscannable": c.unscannable, "path": target},
                              controls=("VAULTLINE.CLASSIFICATION",))
        return c
