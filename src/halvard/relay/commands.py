"""Signed, expiring, single-use commands from the control plane to a device.

The device does not trust the network: it verifies the signature, the target device, the expiry and a one-time nonce,
and it re-checks the approvals against its OWN copy of the authority matrix for its OWN asset class. A compromised or
careless control plane therefore cannot talk a clinical or production device into an action that needs more approvals
than the command carries. Reference limitation: HMAC with a per-device key; production uses an asymmetric signature.
"""
import hmac, json, secrets

from .authority import ORDER

REMOTE_ACTIONS = {"isolate_host", "release_isolation", "stop_process", "quarantine_file", "legal_hold", "install_update", "rollback_update"}


def _canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def sign(key: bytes, *, device, action, params, reason, case, approvals, rule, issuer, now, ttl=6 * 3600):
    body = {"id": "cmd-" + secrets.token_hex(5), "device": device, "action": action, "params": params, "reason": reason, "case": case,
            "approvals": approvals, "rule": rule, "issuer": issuer, "issued": now, "expires": now + ttl, "nonce": secrets.token_hex(8)}
    return {**body, "signature": hmac.new(key, _canon(body), "sha256").hexdigest()}


def verify(cmd, key: bytes, device, now, seen_nonces: set, authority, asset_class):
    body = {k: v for k, v in cmd.items() if k != "signature"}
    if not hmac.compare_digest(hmac.new(key, _canon(body), "sha256").hexdigest(), cmd.get("signature", "")): return False, "signature invalid"
    if cmd["device"] != device: return False, "command is for another device"
    if now > cmd["expires"]: return False, "command expired before it could run"
    if cmd["nonce"] in seen_nonces: return False, "command already used"
    if cmd["action"] not in REMOTE_ACTIONS: return False, f"{cmd['action']} cannot be sent remotely"
    need = authority.requirement(cmd["action"], asset_class)
    if ORDER[cmd["rule"]] < ORDER[need.level]: return False, f"this device requires '{need.level}' for {cmd['action']}; the command carries '{cmd['rule']}'"
    people = {a["id"] for a in cmd["approvals"]}
    if len(people) < need.approvals_needed: return False, f"needs {need.approvals_needed} different approvers, command carries {len(people)}"
    return True, "ok"
