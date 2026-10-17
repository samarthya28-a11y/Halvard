"""Signed policy bundle: the device's decision cache. Works with no connectivity (F004).

Reference limitation: signed with HMAC-SHA256 using the device's enrolled key. Production verifies an asymmetric
signature from the tenant's policy key. Version numbers only move forward (rollback of policy is refused).
"""
import hashlib, hmac, json
from dataclasses import dataclass, field, asdict


class BundleError(ValueError):
    pass


def _canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class PolicyBundle:
    tenant: str
    version: int
    prevention: dict = field(default_factory=lambda: {"bulk_encryption": "enforce", "known_bad": "enforce"})
    known_bad_sha256: list = field(default_factory=list)
    mgmt_endpoints: list = field(default_factory=lambda: ["mgmt.halvard.example"])
    accepted_patterns: list = field(default_factory=list)
    overrides: dict = field(default_factory=dict)
    trusted_writers: list = field(default_factory=list)      # publisher + image hash; a bare name matches only when the process has no image hash
    journal_quota_mb: int = 2048
    # Paths whose pre-images are not journaled (caches, temp files, logs, app databases). They are still observed
    # by the detector. Ransomware targets documents, so the journal spends its quota on user work.
    journal_exclude: list | None = None      # None = the platform profile's default list
    platform: str = "windows"
    dlp: dict = field(default_factory=dict)       # data protection: inspection gate, rules, USB approvals, partner and SaaS lists (see vaultline/)
    tripwires: list = field(default_factory=list)       # [{id, path, kind: encryption|decoy_file|credential_lure, lure_text?}] placed by Hearth; see hearth/
    tripwire_exempt: list = field(default_factory=list)  # publisher + image hash; a bare name matches only when the process has no image hash
    blocked_apps: list = field(default_factory=list)   # publisher + image hash, or a name-only Glass stand-in when no hash is known yet
    learned_exceptions: list = field(default_factory=list)   # active entries from the console's learning store (device enforces expiry)
    retention_days_after_uninstall: int = 30
    asset_class: str = "standard"
    signature: str = ""

    def body(self):
        d = asdict(self); d.pop("signature"); return d

    def sign(self, key):
        body = _canon(self.body())
        if hasattr(key, "sign_bytes"): self.signature = key.sign_bytes(body)
        else: self.signature = hmac.new(key, body, "sha256").hexdigest()
        return self


def load_bundle(raw: dict, key, current_version: int = 0) -> PolicyBundle:
    b = PolicyBundle(**raw)
    body = _canon(b.body())
    if hasattr(key, "verify_bytes"):
        if getattr(key, "revoked", False) or not key.verify_bytes(body, b.signature):
            raise BundleError("policy bundle signature invalid; keeping the last good policy")
    else:
        good = hmac.new(key, body, "sha256").hexdigest()
        if not hmac.compare_digest(good, b.signature):
            raise BundleError("policy bundle signature invalid; keeping the last good policy")
    if b.version <= current_version:
        raise BundleError(f"policy version {b.version} is not newer than {current_version}; refusing rollback")
    return b
