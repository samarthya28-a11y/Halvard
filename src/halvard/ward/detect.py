"""Behavioral detector for bulk encryption (F007). Pure function of file events; no network, no cloud.

Per-file signals (computed by the file hook from header bytes + a 4 KB sample, never stored):
  magic_destroyed  the old content had a recognizable file signature and the new content does not
  entropy_jump     low-entropy old content became near-random
  ext_changed      rename to an extension that is not a normal save pattern
A process is stopped when enough distinct existing files show destroying signals inside the window.
Legitimate bulk writers (compressors, backups, builds, photo exports) create new files or keep signatures, so they
do not reach the threshold; tests cover them.
"""
import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field

MAGICS = (b"PK\x03\x04", b"%PDF", b"\xff\xd8\xff", b"\x89PNG", b"GIF8", b"\xd0\xcf\x11\xe0", b"MZ", b"SQLite format 3",
          b"{\\rtf", b"RIFF", b"ID3", b"\x1f\x8b", b"7z\xbc\xaf", b"Rar!")


def entropy(sample: bytes) -> float:
    if not sample:
        return 0.0
    n = len(sample)
    return -sum((c / n) * math.log2(c / n) for c in Counter(sample).values())


def has_magic(head: bytes) -> bool:
    return any(head.startswith(m) for m in MAGICS) or (len(head) > 0 and _looks_text(head))


def _looks_text(head: bytes) -> bool:
    s = head[:256]
    return bool(s) and sum(1 for b in s if 9 <= b <= 13 or 32 <= b < 127) / len(s) > 0.95


@dataclass
class FileSignal:
    ts: float
    pid: int
    path: str
    directory: str
    signals: tuple


@dataclass
class Verdict:
    pid: int
    confidence: float
    reasons: list
    files: list


class BulkEncryptionDetector:
    def __init__(self, window_s=30.0, min_files=8, min_dirs=1):
        self.window, self.min_files, self.min_dirs = window_s, min_files, min_dirs
        self.events = defaultdict(deque)
        self.fired = set()

    def classify(self, before_head, after_sample, renamed_ext_change=False):
        sig = []
        if before_head is not None:
            if has_magic(after_sample[:256]):          # cheap exit: still a recognizable file (normal save)
                pass
            else:
                e_after = entropy(after_sample)
                if e_after > 7.0 and has_magic(before_head):
                    sig.append("magic_destroyed")
                elif e_after > 7.5 and entropy(before_head) < 6.5:
                    sig.append("entropy_jump")
        if renamed_ext_change:
            sig.append("ext_changed")
        return tuple(sig)

    def observe(self, ts, pid, path, signals):
        """Feed one per-file result. Returns a Verdict the first time a process crosses the threshold."""
        if pid in self.fired:
            return None
        destroying = [s for s in signals if s in ("magic_destroyed", "entropy_jump")]
        if not destroying:
            return None
        q = self.events[pid]
        q.append(FileSignal(ts, pid, path, path.rsplit("/", 1)[0] if "/" in path else "", tuple(signals)))
        while q and ts - q[0].ts > self.window:
            q.popleft()
        files = {e.path for e in q}
        dirs = {e.directory for e in q}
        if len(files) >= self.min_files and len(dirs) >= self.min_dirs:
            conf = min(0.99, 0.6 + 0.04 * (len(files) - self.min_files) + (0.1 if any("ext_changed" in e.signals for e in q) else 0))
            self.fired.add(pid)
            return Verdict(pid, round(conf, 2),
                           [f"{len(files)} existing files overwritten with unrecognizable data in {int(ts - q[0].ts)}s",
                            "original file signatures were destroyed"], sorted(files))
        return None

    def reset(self, pid):
        self.fired.discard(pid); self.events.pop(pid, None)
