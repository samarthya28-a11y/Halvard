"""Connector fixture signatures.

The reference connectors seal each event with an HMAC key they hold. Automatic containment
accepts an event only when that seal verifies. HMAC is the reference stand-in for the
connector's key, not a customer KMS and not the asymmetric policy key.
"""
import hashlib, hmac, json, secrets

# A new secret for this process. The old published string is not a key: resealing with it does not verify.
# This is still a reference HMAC in this process, not a customer KMS.
CONNECTOR_KEY = secrets.token_bytes(32)
PUBLISHED_STAND_IN = b"halvard-reference-connector-v1"


def _canon(event):
    body = {k: v for k, v in event.items() if k != "connector_sig"}
    return json.dumps(body, sort_keys=True, default=str, separators=(",", ":")).encode()


def seal(event, key=CONNECTOR_KEY):
    event["connector_sig"] = hmac.new(key, _canon(event), hashlib.sha256).hexdigest()
    return event


def verified(event, key=CONNECTOR_KEY):
    sig = event.get("connector_sig") if isinstance(event, dict) else None
    if not isinstance(sig, str):
        return False
    try:
        good = hmac.new(key, _canon(event), hashlib.sha256).hexdigest()
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(good, sig)


def mark(finding, ok):
    finding.details["connector_signed"] = bool(ok)
    if not ok:
        finding.details["reference_model"] = True
    return finding
