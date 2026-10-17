"""Tamper protection (F016): integrity of the agent's files and config, and a gated stop/uninstall path."""
import hashlib, hmac, json, os, secrets
from pathlib import Path


class TamperGuard:
    def __init__(self, install_dir, uninstall_key: bytes, clock, ledger, device_id, retention_days):
        self.dir = Path(install_dir); self.key, self.clock, self.ledger = uninstall_key, clock, ledger
        self.device_id, self.retention = device_id, retention_days
        self.manifest, self.golden = {}, {}
        self.used_tokens = set()

    def seal(self):
        for f in sorted(self.dir.rglob("*")):
            if f.is_file() and f.name != "manifest.json":
                b = f.read_bytes(); self.manifest[str(f)] = hashlib.sha256(b).hexdigest(); self.golden[str(f)] = b

    def check(self):
        """Verify and self-heal. Returns list of tampered paths (restored from the protected copy)."""
        bad = []
        for p, h in self.manifest.items():
            f = Path(p)
            if not f.exists() or hashlib.sha256(f.read_bytes()).hexdigest() != h:
                bad.append(p); f.parent.mkdir(parents=True, exist_ok=True); f.write_bytes(self.golden[p])
        if bad:
            self.ledger.append("ward.tamper_detected", "system", "system", self.device_id,
                               {"files": len(bad), "paths": bad, "restored": True}, controls=("WARD.TAMPER_PROTECTION",))
        return bad

    # console-issued, single-use, time-boxed
    def issue_uninstall_token(self, issued_by, minutes=30):
        exp = int(self.clock.now() + minutes * 60); nonce = secrets.token_hex(8)
        sig = hmac.new(self.key, f"{self.device_id}|{exp}|{nonce}".encode(), "sha256").hexdigest()
        self.ledger.append("ward.uninstall_authorized", issued_by, "it_admin", self.device_id, {"expires": exp},
                           controls=("WARD.TAMPER_PROTECTION",))
        return f"{exp}.{nonce}.{sig}"

    def _valid(self, token):
        try:
            exp, nonce, sig = token.split(".")
        except (ValueError, AttributeError):
            return False
        good = hmac.new(self.key, f"{self.device_id}|{exp}|{nonce}".encode(), "sha256").hexdigest()
        return hmac.compare_digest(good, sig) and float(exp) > self.clock.now() and nonce not in self.used_tokens

    def stop_or_uninstall(self, token, what="uninstall"):
        if getattr(self.ledger, "pinned", False):
            raise PermissionError("legal hold: the spool and its anchor cannot be removed")
        if not self._valid(token):
            self.ledger.append("ward.tamper_attempt", "unknown", "unknown", self.device_id, {"attempt": what},
                               controls=("WARD.TAMPER_PROTECTION",))
            raise PermissionError("Refused: this needs an uninstall code from your Halvard console. Nothing was changed.")
        self.used_tokens.add(token.split(".")[1])
        stmt = (f"Agent removed. Telemetry already sent to your tenant stays for your configured retention "
                f"({self.retention} days) and can be exported or deleted from Ledger. Local journal and quarantine "
                f"are kept for {self.retention} days unless you delete them.")
        self.ledger.append("ward.uninstalled", "console", "it_admin", self.device_id, {"statement": stmt},
                           controls=("WARD.TAMPER_PROTECTION",))
        return stmt
