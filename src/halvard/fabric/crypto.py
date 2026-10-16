"""Customer-managed keys (F117) for a tenant's stored objects.

Shape: each tenant has a DATA key that encrypts its objects. The data key is kept only in WRAPPED form, wrapped by a customer master key (CMK) that
lives in the customer's own key service (ReferenceKMS here). Halvard never holds the CMK. The customer can revoke it: the tenant becomes unreadable at once
(its data key cannot be unwrapped), and restoring access restores it. Destroying the CMK is a crypto-shred and cannot be undone.

REFERENCE LIMITATION, stated plainly: the cipher below is encrypt-then-MAC with a keystream built from HMAC-SHA256 in counter mode, because the standard library has
no AES. It demonstrates the key hierarchy, revocation and tamper detection. It is NOT production cryptography; production uses AES-256-GCM from a vetted library and a hardware-backed KMS.
"""
import hashlib, hmac, secrets


class KeyUnavailable(PermissionError):
    pass


class ReferenceKMS:
    """The customer's key service. It wraps and unwraps data keys; the master key never leaves it."""
    def __init__(self, clock, name="customer-kms"):
        self.clock, self.name, self._master, self.revoked, self.destroyed, self.log = clock, name, secrets.token_bytes(32), False, False, []

    def _check(self, op):
        if self.destroyed: self.log.append((self.clock.now(), op, "denied: key destroyed")); raise KeyUnavailable("the customer master key was destroyed")
        if self.revoked: self.log.append((self.clock.now(), op, "denied: access revoked")); raise KeyUnavailable("the customer has revoked Halvard's access to the master key")

    def wrap(self, data_key: bytes):
        self._check("wrap"); nonce = secrets.token_bytes(16); ks = _stream(self._master, nonce, len(data_key)); body = bytes(a ^ b for a, b in zip(data_key, ks))
        tag = hmac.new(self._master, nonce + body, "sha256").digest(); self.log.append((self.clock.now(), "wrap", "ok")); return nonce + body + tag

    def unwrap(self, wrapped: bytes):
        self._check("unwrap"); nonce, body, tag = wrapped[:16], wrapped[16:-32], wrapped[-32:]
        if not hmac.compare_digest(tag, hmac.new(self._master, nonce + body, "sha256").digest()): raise KeyUnavailable("wrapped key does not verify")
        self.log.append((self.clock.now(), "unwrap", "ok")); return bytes(a ^ b for a, b in zip(body, _stream(self._master, nonce, len(body))))

    def revoke(self): self.revoked = True
    def restore(self):
        if self.destroyed: raise KeyUnavailable("a destroyed key cannot be restored")
        self.revoked = False
    def destroy(self): self.destroyed = True; self._master = b""


def _stream(key, nonce, n):
    out, i = b"", 0
    while len(out) < n: out += hmac.new(key, nonce + i.to_bytes(8, "big"), "sha256").digest(); i += 1
    return out[:n]


class ObjectCipher:
    def __init__(self, data_key: bytes): self._k = data_key

    def seal(self, data: bytes):
        nonce = secrets.token_bytes(16); body = bytes(a ^ b for a, b in zip(data, _stream(self._k, nonce, len(data))))
        return b"HV1" + nonce + body + hmac.new(self._k, nonce + body, "sha256").digest()

    def unseal(self, raw: bytes):
        if raw[:3] != b"HV1": raise KeyUnavailable("object is not in the sealed format")
        nonce, body, tag = raw[3:19], raw[19:-32], raw[-32:]
        if not hmac.compare_digest(tag, hmac.new(self._k, nonce + body, "sha256").digest()): raise KeyUnavailable("object failed its integrity check (tampered, or the wrong key)")
        return bytes(a ^ b for a, b in zip(body, _stream(self._k, nonce, len(body))))


class LockedCipher:
    """What a tenant's store holds while its key cannot be obtained: every read and write fails closed."""
    def __init__(self, why): self.why = why
    def seal(self, data): raise KeyUnavailable(f"tenant data is locked: {self.why}")
    def unseal(self, raw): raise KeyUnavailable(f"tenant data is locked: {self.why}")


class TenantKeys:
    """Holds the wrapped data key; unlocks it through the customer's KMS. The plain data key exists only in memory while unlocked."""
    def __init__(self, kms: ReferenceKMS):
        self.kms = kms; self.wrapped = kms.wrap(secrets.token_bytes(32)); self.cipher = None

    def unlock(self):
        try: self.cipher = ObjectCipher(self.kms.unwrap(self.wrapped)); return self.cipher
        except KeyUnavailable as e: self.cipher = LockedCipher(str(e)); return self.cipher

    def lock(self, why="locked by the platform"): self.cipher = LockedCipher(why); return self.cipher
