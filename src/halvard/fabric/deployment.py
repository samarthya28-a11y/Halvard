"""Deployment profiles (F118) and the signed offline bundle that updates a site with no connection to Halvard.

Profiles: cloud (Halvard-operated), customer_cloud (in the customer's own cloud account), private (customer's cluster, no standing outbound access),
disconnected (a site with no link; local decision cache, store-and-forward, updates by signed bundle).
What changes is stated, not hidden: `dependencies()` lists every outside service a module would use and what it does instead when that is not allowed.
"""
import hashlib, hmac, json, os
from dataclasses import dataclass
from pathlib import Path

PROFILES = {
    "cloud":          {"remote_staff": True,  "keeper": True,  "egress": "allowed",   "updates": "online"},
    "customer_cloud": {"remote_staff": True,  "keeper": True,  "egress": "allowed",   "updates": "online"},
    "private":        {"remote_staff": False, "keeper": False, "egress": "allowlist", "updates": "signed bundle or an internal mirror"},
    "disconnected":   {"remote_staff": False, "keeper": False, "egress": "none",      "updates": "signed bundle carried in"},
}

DEPENDENCIES = [
    ("Ward", "cloud reputation lookup for unknown files", "the signed policy bundle and a local reputation cache; unknown files are judged on the device"),
    ("Ward", "agent and detection-content updates", "signed offline bundle; the device verifies it and refuses rollbacks"),
    ("Glass", "vulnerability advisory feed", "advisory feed inside the signed offline bundle (the sample feed is synthetic)"),
    ("Lumen", "AI tool catalog", "the customer's own catalog, edited in place"),
    ("Hearth", "canary token callback", "a callback hosted inside the customer's network; tokens that cannot reach one never fire"),
    ("Courier", "link reputation", "static analysis only (already the case)"),
    ("Keeper", "remote crew access", "not available; the customer's own people work cases"),
    ("Support", "Halvard staff access", "none unless the customer opens a break-glass grant and the profile allows it"),
]


class EgressDenied(PermissionError):
    pass


class EgressPolicy:
    def __init__(self, profile, allow=(), audit=None, tenant=""):
        self.profile, self.allow, self.audit, self.tenant = profile, set(allow), audit, tenant

    def check(self, dest, purpose):
        mode = PROFILES[self.profile]["egress"]
        ok = mode == "allowed" or (mode == "allowlist" and dest in self.allow)
        if not ok:
            if self.audit: self.audit.append("fabric.egress_refused", "halvard:fabric", "system", self.tenant, {"purpose": purpose, "mode": mode, "dst": dest}, controls=("FABRIC.DEPLOYMENT",))
            raise EgressDenied(f"{self.profile} deployment does not call out ({mode}); {purpose} was not attempted.")
        return True


def dependencies(profile):
    p = PROFILES[profile]; out = []
    for m, u, sub in DEPENDENCIES:
        available = {"Keeper": p["keeper"], "Support": p["remote_staff"]}.get(m, p["egress"] == "allowed")
        out.append({"module": m, "uses": u, "status": "online" if available else "substitute", "instead": "" if available else sub})
    return out


# ---------------- signed offline bundle ----------------
class BundleError(ValueError):
    pass


def _canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def build_bundle(path, version, key, created, advisories=None, ai_catalog=None, iocs=None):
    """Write a bundle directory: parts as JSON files plus a manifest carrying their hashes and a signature. Built by Halvard (or the customer's mirror), carried in by hand."""
    d = Path(path); d.mkdir(parents=True, exist_ok=True); parts = {}
    for name, obj in (("advisories", advisories), ("ai_catalog", ai_catalog), ("iocs", iocs)):
        if obj is None: continue
        b = _canon(obj); (d / f"{name}.json").write_bytes(b); parts[name] = hashlib.sha256(b).hexdigest()
    man = {"version": version, "created": created, "parts": parts}
    (d / "manifest.json").write_bytes(_canon({**man, "signature": hmac.new(key, _canon(man), "sha256").hexdigest()})); return man


def read_bundle(path, key, current_version):
    d = Path(path)
    try: m = json.loads((d / "manifest.json").read_bytes())
    except (OSError, ValueError): raise BundleError("no readable manifest")
    sig = m.pop("signature", "")
    if not hmac.compare_digest(sig, hmac.new(key, _canon(m), "sha256").hexdigest()): raise BundleError("the bundle's signature does not verify; nothing was applied")
    if m["version"] <= current_version: raise BundleError(f"bundle version {m['version']} is not newer than {current_version}; rollback refused")
    out = {}
    for name, h in m["parts"].items():
        b = (d / f"{name}.json").read_bytes() if (d / f"{name}.json").exists() else b""
        if hashlib.sha256(b).hexdigest() != h: raise BundleError(f"{name} does not match the manifest; nothing was applied")
        out[name] = json.loads(b)
    return m, out
