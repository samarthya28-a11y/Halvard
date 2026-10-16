"""Pre-execution verdict (F006): local known-bad cache + optional cloud reputation + a transparent baseline scorer.

HONEST SCOPE: the scorer below is a hand-weighted static-feature baseline, not a trained model, and it makes no
detection-rate claim. The `Model` protocol is where a trained model plugs in; its measured results (including
misses) belong in the public detection-test report (F129), which does not exist yet.
The EICAR string is the industry-standard harmless test file and is always treated as known-bad.
"""
import hashlib
from .detect import entropy

# A harmless marker that is NOT on any antivirus list. Real antivirus on a developer's machine removes the EICAR file the moment it is written, so anything that has to
# put a test file on disk (the setup guide, the tests) uses this instead. EICAR is still recognised when it is only held in memory.
TEST_MARKER = b"HALVARD-HARMLESS-KNOWN-BAD-TEST-FILE-DO-NOT-RUN-0001"
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class Verdict:
    def __init__(self, decision, score, reasons, source):
        self.decision, self.score, self.reasons, self.source = decision, score, reasons, source

    def __repr__(self): return f"Verdict({self.decision},{self.score:.2f},{self.source})"


class BaselineModel:
    def score(self, data: bytes, name: str):
        reasons, s = [], 0.0
        e = entropy(data[:65536])
        if data[:2] == b"MZ" and e > 7.2:
            s += 0.35; reasons.append("executable with packed-looking content")
        hits = sum(1 for w in (b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread") if w in data)
        if hits >= 2:
            s += 0.3; reasons.append("imports process-injection APIs")
        if name.lower().endswith((".exe", ".scr", ".js", ".vbs")) and name.lower().count(".") >= 2:
            s += 0.15; reasons.append("double extension")
        return min(s, 0.95), reasons


class VerdictEngine:
    def __init__(self, known_bad=(), model=None, reputation=None, block_at=0.7, ask_at=0.4):
        self.known_bad = set(known_bad); self.model = model or BaselineModel()
        self.reputation, self.block_at, self.ask_at = reputation, block_at, ask_at

    def evaluate(self, data: bytes, name: str, online: bool) -> Verdict:
        d = hashlib.sha256(data).hexdigest()
        if d in self.known_bad or EICAR in data or TEST_MARKER in data:
            return Verdict("block", 1.0, ["matches a known-bad file"], "local_cache")
        if online and self.reputation:
            r = self.reputation(d)
            if r == "bad":
                return Verdict("block", 0.99, ["cloud reputation: known malicious"], "cloud")
        score, reasons = self.model.score(data, name)
        src = "local_model" if not online else "local_model+cloud"
        if score >= self.block_at: return Verdict("block", score, reasons, src)
        if score >= self.ask_at: return Verdict("ask", score, reasons, src)
        return Verdict("allow", score, reasons, src)
