"""Reference signatures for policy bundles, device commands, and ledger entries.

The customer private exponent lives only on CustomerSigner. WardAgent is given CustomerVerifier (n, e) and cannot produce a signature.
This is a labelled reference RSA (PKCS#1 v1.5, SHA-256, a fixed 511-bit modulus). It is not a hardware key and not a production KMS.
HMAC stays in ReferenceKMS, which is the cipher stand-in, and on the older shared-secret path used by the rest of this reference model.
"""
import hashlib

# Fixed key so tests do not hunt for primes. n = p*q, both primes, e = 65537.
_N = 6143604998046967541489210381352467507623069098318942782257589891757478314597113064257091375297031243118552146618887874484253559584964791321910911059802131
_E = 65537
_D = 899928406568059087207171821428867480555738946608203773588550940092951948061869734983499529453179315014248957807122483111392903472152625115614519839644673
_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


class KeyRevoked(PermissionError):
    pass


class _State:
    revoked = False


def restore_reference_key():
    """Tests that revoke the reference key put it back so later tests still sign."""
    _State.revoked = False


def _emsa(data: bytes, k: int) -> int:
    t = _PREFIX + hashlib.sha256(data).digest()
    if k < len(t) + 11: raise ValueError("modulus too small")
    em = b"\x00\x01" + (b"\xff" * (k - len(t) - 3)) + b"\x00" + t
    return int.from_bytes(em, "big")


def _k() -> int:
    return (_N.bit_length() + 7) // 8


class CustomerSigner:
    """Holds the private exponent. Do not put this object on the agent."""

    def sign_bytes(self, data: bytes) -> str:
        if _State.revoked: raise KeyRevoked("the customer signing key is revoked")
        s = pow(_emsa(data, _k()), _D, _N)
        return s.to_bytes(_k(), "big").hex()

    def revoke(self):
        _State.revoked = True

    @property
    def revoked(self):
        return _State.revoked


class CustomerVerifier:
    """Public half only: modulus and exponent. Revocation is the customer's, visible here, not a copy of the private key."""

    def verify_bytes(self, data: bytes, signature: str) -> bool:
        if _State.revoked or not signature: return False
        try: s = int(signature, 16)
        except ValueError: return False
        if s <= 0 or s >= _N: return False
        try: em = pow(s, _E, _N)
        except Exception: return False
        try: return em == _emsa(data, _k())
        except ValueError: return False

    def revoke(self):
        _State.revoked = True

    @property
    def revoked(self):
        return _State.revoked

    @property
    def private_exponent(self):
        raise AttributeError("the verifier does not hold the customer private key")


def customer_signer() -> CustomerSigner:
    return CustomerSigner()


def customer_verifier() -> CustomerVerifier:
    return CustomerVerifier()
