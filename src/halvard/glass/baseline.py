"""Configuration baselines and drift (F098). A baseline says what should be true of a device; drift is a measured difference, not a score.

Exceptions are explicit, owned, reasoned and expire. A baseline value that is not reported by the device is 'unknown', never silently 'fine'.
"""
from dataclasses import dataclass

DEFAULT_BASELINE = {
    "disk_encryption": {"expect": True, "severity": "high", "label": "Disk encryption", "fix": "Turn on full-disk encryption and keep the recovery key with IT."},
    "firewall_enabled": {"expect": True, "severity": "medium", "label": "Host firewall", "fix": "Turn the host firewall on."},
    "automatic_updates": {"expect": True, "severity": "medium", "label": "Automatic updates", "fix": "Turn automatic updates on, or place the device in a patch ring."},
    "screen_lock_minutes": {"max": 15, "severity": "low", "label": "Screen lock", "fix": "Lock the screen after 15 minutes or less."},
}


@dataclass
class Drift:
    device: str
    key: str
    expected: str
    observed: object
    severity: str
    label: str
    fix: str


def check(device, settings, baseline=None, exceptions=None, now=0):
    out = []
    for key, rule in (baseline or DEFAULT_BASELINE).items():
        if (device, key) in (exceptions or {}) and exceptions[(device, key)]["until"] > now: continue
        v = settings.get(key)
        if "expect" in rule: ok, exp = (v == rule["expect"]) if v is not None else None, str(rule["expect"])
        else: ok, exp = (v <= rule["max"]) if v is not None else None, f"at most {rule['max']}"
        if ok is True: continue
        out.append(Drift(device, key, exp, "not reported" if ok is None else v, rule["severity"], rule["label"], rule["fix"]))
    return out
