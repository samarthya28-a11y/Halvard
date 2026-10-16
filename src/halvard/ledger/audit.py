"""Ledger: append-only, hash-chained, sealed audit record.

Design points
  * Each entry commits to its predecessor (hash chain) and is sealed with an HMAC key held outside the log.
  * Personal fields (paths, user ids, hostnames, commands) live in a `private` block committed by digest with a
    per-entry nonce. An auditor export reveals only the digest plus a per-export pseudonym token, so the chain
    can still be verified while employee-identifying content never leaves.
  * Raw content keys (document text, keystrokes, ...) are refused at write time.
  * The head is anchored in a separate sealed file, so truncating the tail is detected.
Reference limitation: the seal is HMAC-SHA256. Production uses an asymmetric signature from a customer-managed key (F117).
"""
import hashlib, hmac, json, os, secrets, threading
from pathlib import Path

PII_KEYS = {"path", "paths", "user", "upn", "host", "hostname", "file", "files", "target_user", "command",
            "src", "dst", "email", "ip", "justification",
            # free text and path lists written by actions and detectors: they can carry a person's name or a file name, so they live in the private half (found by the cross-check)
            "reason", "summary", "targets", "preview", "sample_paths", "process"}
FORBIDDEN_KEYS = {"content", "contents", "body", "text", "keystrokes", "document", "clipboard",
                  "screenshot", "audio", "webcam", "message"}
MAX_STR = 1024
EMAIL_RE = __import__("re").compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def scrub(o):
    """Defence in depth: an email address never survives in a public field, whatever a handler wrote into a summary or scope."""
    if isinstance(o, str): return EMAIL_RE.sub("[address]", o)
    if isinstance(o, dict): return {k: scrub(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)): return [scrub(v) for v in o]
    return o


def opaque(entity: str) -> str:
    """Stable pseudonymous id for a person-linked entity (mailbox, account), so the audit subject never carries an address."""
    return "e-" + _h(entity.encode())[:12]


class ContentNotAllowed(ValueError):
    pass


def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _check(o, path="data"):
    if isinstance(o, dict):
        for k, v in o.items():
            if str(k).lower() in FORBIDDEN_KEYS:
                raise ContentNotAllowed(f"{path}.{k}: raw content is never written to the audit record")
            _check(v, f"{path}.{k}")
    elif isinstance(o, (list, tuple)):
        for i, v in enumerate(o):
            _check(v, f"{path}[{i}]")
    elif isinstance(o, str):
        if len(o) > MAX_STR:
            raise ContentNotAllowed(f"{path}: string over {MAX_STR} chars looks like content; store a digest instead")
    elif o is not None and not isinstance(o, (int, float, bool)):
        raise ContentNotAllowed(f"{path}: unsupported type {type(o).__name__}")


def _entry_hash(prev, head, pub_digest, priv_digest):
    return _h(prev.encode() + _canon(head) + pub_digest.encode() + priv_digest.encode())


class AuditLog:
    GENESIS = "0" * 64

    def __init__(self, path, tenant: str, key: bytes, clock=None):
        self.path = Path(path)
        self.anchor = self.path.with_suffix(".head")
        self.tenant, self._key = tenant, key
        self.clock = clock
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._seq, self._head = self._load_tail()

    # ---- write path (the only mutation is append) ----
    def append(self, kind, actor, actor_role, subject, data=None, controls=(), controls_fired=()):
        data = dict(data or {})
        _check(data)
        with self._lock:
            pub = scrub({k: v for k, v in data.items() if k not in PII_KEYS})
            priv = {k: v for k, v in data.items() if k in PII_KEYS}
            priv["_actor"] = actor
            priv["_nonce"] = secrets.token_hex(8)
            seq = self._seq + 1
            ts = self.clock.now() if self.clock else __import__("time").time()
            head = {"seq": seq, "ts": round(ts, 3), "tenant": self.tenant, "kind": kind,
                    "actor_role": actor_role, "subject": subject, "controls": sorted(controls)}
            pd, vd = _h(_canon(pub)), _h(_canon(priv))
            hh = _entry_hash(self._head, head, pd, vd)
            rec = {**head, "public": pub, "private": priv, "prev": self._head, "hash": hh,
                   "seal": hmac.new(self._key, hh.encode(), "sha256").hexdigest()}
            with open(self.path, "ab") as f:
                f.write(_canon(rec) + b"\n")
                f.flush(); os.fsync(f.fileno())
            self._seq, self._head = seq, hh
            self._write_anchor()
            return rec

    def seal_bytes(self, data: bytes) -> str:
        """HMAC with the ledger key, so other evidence (e.g. a forensic manifest) is sealed by the same authority."""
        return hmac.new(self._key, data, "sha256").hexdigest()

    def _write_anchor(self):
        body = {"seq": self._seq, "hash": self._head}
        body["seal"] = hmac.new(self._key, _canon(body), "sha256").hexdigest()
        tmp = self.anchor.with_suffix(".tmp")
        tmp.write_bytes(_canon(body)); os.replace(tmp, self.anchor)

    def _load_tail(self):
        seq, head = 0, self.GENESIS
        for rec in self.entries():
            seq, head = rec["seq"], rec["hash"]
        return seq, head

    # ---- read path ----
    def entries(self):
        with open(self.path, "rb") as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)

    @property
    def head(self):
        return self._seq, self._head

    def verify(self):
        """Return (ok, problems). Detects edits, deletions, reordering, bad seals and tail truncation."""
        problems, prev, n = [], self.GENESIS, 0
        for rec in self.entries():
            n += 1
            head = {k: rec[k] for k in ("seq", "ts", "tenant", "kind", "actor_role", "subject", "controls")}
            exp = _entry_hash(rec["prev"], head, _h(_canon(rec["public"])), _h(_canon(rec["private"])))
            if rec["prev"] != prev:
                problems.append(f"seq {rec['seq']}: chain broken (entry removed, inserted or reordered)")
            if rec["seq"] != n:
                problems.append(f"seq {rec['seq']}: expected {n}")
            if exp != rec["hash"]:
                problems.append(f"seq {rec['seq']}: content changed after it was written")
            if not hmac.compare_digest(hmac.new(self._key, rec["hash"].encode(), "sha256").hexdigest(), rec["seal"]):
                problems.append(f"seq {rec['seq']}: seal invalid")
            prev = rec["hash"]
        try:
            a = json.loads(self.anchor.read_text(encoding="utf-8"))
            seal = a.pop("seal")
            if not hmac.compare_digest(hmac.new(self._key, _canon(a), "sha256").hexdigest(), seal):
                problems.append("head anchor seal invalid")
            elif a["seq"] != n or a["hash"] != prev:
                problems.append(f"log ends at seq {n} but the sealed head says seq {a['seq']}: tail truncated or replaced")
        except FileNotFoundError:
            if n:
                problems.append("head anchor missing")
        return (not problems), problems

    # ---- sharing ----
    def export_for_control(self, control_id, since=0, until=float("inf"), salt=None):
        """Auditor export: entries tagged with the control, personal fields replaced by pseudonym tokens."""
        salt = salt or secrets.token_bytes(16)
        tok = lambda v: hmac.new(salt, str(v).encode(), "sha256").hexdigest()[:10]
        out, last_visible = [], None
        for rec in self.entries():
            if control_id in rec["controls"] and since <= rec["ts"] <= until:
                head = {k: rec[k] for k in ("seq", "ts", "tenant", "kind", "actor_role", "subject", "controls")}
                priv = rec["private"]
                out.append({"head": head, "public": rec["public"], "prev": rec["prev"], "hash": rec["hash"],
                            "actor_token": tok(priv["_actor"]),
                            "private_fields": {k: tok(v) if not isinstance(v, (list, dict)) else tok(_canon(v))
                                               for k, v in priv.items() if not k.startswith("_")},
                            "private_digest": _h(_canon(priv))})
            else:
                out.append({"elided": True, "seq": rec["seq"], "prev": rec["prev"], "hash": rec["hash"]})
        seq, head = self.head
        return {"format": "halvard-evidence/1", "control": control_id, "tenant": self.tenant,
                "head": {"seq": seq, "hash": head}, "entries": out,
                "notes": ["Personal fields appear as per-export tokens; the same person has the same token within this export only.",
                          "Elided entries belong to other controls; their hashes prove nothing was removed between visible entries.",
                          "No document contents, keystrokes or message bodies are ever in this record."]}

    def ingest_segment(self, device_id, device_log: "AuditLog"):
        """Store-and-forward: verify a device's spool chain and record its head in the tenant ledger."""
        ok, problems = device_log.verify()
        if not ok:
            return self.append("ledger.spool_rejected", "halvard:ledger", "system", device_id,
                               {"problems": problems[:5]}, controls=("LEDGER.INTEGRITY",))
        seq, head = device_log.head
        seg_dir = self.path.parent / "segments"; seg_dir.mkdir(exist_ok=True)
        (seg_dir / f"{device_id}.jsonl").write_bytes(device_log.path.read_bytes())
        return self.append("ledger.spool_ingested", "halvard:ledger", "system", device_id,
                           {"device_entries": seq, "device_head": head}, controls=("LEDGER.INTEGRITY", "WARD.OFFLINE_PREVENTION"))


def verify_export(exp):
    """Auditor-side check that needs no key: every visible entry is self-consistent and links form one chain."""
    problems, prev_hash = [], None
    for e in exp["entries"]:
        if prev_hash is not None and e["prev"] != prev_hash:
            problems.append(f"link broken before seq {e.get('seq', e.get('head', {}).get('seq'))}")
        if not e.get("elided"):
            calc = _entry_hash(e["prev"], e["head"], _h(_canon(e["public"])), e["private_digest"])
            if calc != e["hash"]:
                problems.append(f"seq {e['head']['seq']}: entry does not match its hash")
        prev_hash = e["hash"]
    if exp["entries"] and exp["entries"][-1]["hash"] != exp["head"]["hash"]:
        problems.append("export does not end at the stated head")
    return (not problems), problems
