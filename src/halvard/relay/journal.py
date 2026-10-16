"""Halvard file journal: pre-image capture at write time, independent of any shadow copy.

The Ward file hook calls `before()` ahead of each risky write/rename/delete and `after()` once the new state is on
disk. Rollback replays records for the given process(es) in reverse order, so the oldest pre-image wins. Files a
different process changed after the incident are NOT overwritten; they are reported. When the quota or per-file
cap stops capture, the record says so and the recovery note lists those files as not restorable.
"""
import hashlib, os, shutil, sqlite3, threading
from dataclasses import dataclass, field
from pathlib import Path


FULL_HASH_LIMIT = 4 << 20        # files up to this size are compared by their whole content; larger ones by size, start, end and modification time
SAMPLE = 64 << 10


def fingerprint(path, read=True):
    """Post-state marker used to decide whether someone changed a file after the incident. Content decides, not the clock: a later edit that keeps the same
    size and modification time is still an edit, and a pure timestamp touch is not. (Files above FULL_HASH_LIMIT use size, the first and last 64 KiB, and the
    modification time, which can miss an edit confined to the middle that also resets the time; that limit is stated, not hidden.)"""
    st = os.stat(path); h = hashlib.sha256()
    if not read: return f"stat:{st.st_size}:{st.st_mtime_ns}"     # a kernel-hook sensor must not open files it is judging (that deadlocks the hook), so it records the weaker size+time marker and says so
    with open(path, "rb") as f:
        if st.st_size <= FULL_HASH_LIMIT: h.update(f.read()); return f"{st.st_size}:{h.hexdigest()[:32]}"
        h.update(f.read(SAMPLE)); f.seek(max(0, st.st_size - SAMPLE)); h.update(f.read(SAMPLE))
    return f"{st.st_size}:{st.st_mtime_ns}:{h.hexdigest()[:32]}"


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class RollbackReport:
    restored: list = field(default_factory=list)
    removed_created: list = field(default_factory=list)
    renamed_back: list = field(default_factory=list)
    skipped_changed_after: list = field(default_factory=list)
    not_restorable: list = field(default_factory=list)   # (path, reason)
    snapshot_id: str | None = None

    @property
    def complete(self):
        return not self.skipped_changed_after and not self.not_restorable


class Journal:
    def __init__(self, root, clock, quota_bytes=2 << 30, max_file_bytes=256 << 20, min_interval_s=30):
        self.root = Path(root); (self.root / "blobs").mkdir(parents=True, exist_ok=True)
        self.clock, self.quota, self.max_file, self.min_interval = clock, quota_bytes, max_file_bytes, min_interval_s
        self.db = sqlite3.connect(self.root / "index.db", check_same_thread=False)
        # WAL + NORMAL: a commit survives an agent crash and costs no fsync; only a power cut can lose the last
        # few index rows (blobs are already on disk). Documented in the threat model.
        self.db.execute("PRAGMA journal_mode=WAL"); self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS rec(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, pid INTEGER,
            op TEXT, path TEXT, dst TEXT, pre TEXT, post TEXT, note TEXT)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS rec_pid ON rec(pid, ts)")
        self._lock = threading.RLock()
        self._last_cap = {}   # path key -> (ts, blob, pid)
        self.key = lambda p: p   # platform profile swaps in a case-folding key for case-insensitive filesystems
        self.used = sum(f.stat().st_size for f in (self.root / "blobs").iterdir())
        self._known = {f.name for f in (self.root / "blobs").iterdir()}   # avoids a stat per capture

    # ---- capture ----
    SMALL = 8 << 20

    def _store(self, path, data=None):
        """Copy a file into the content-addressed store with ONE open. Returns (digest|None, note|None, head).
        `data` lets a sensor that already holds the file's bytes (e.g. a fanotify event fd) avoid re-opening the path."""
        try:
            if data is not None:
                size = len(data); head = data[:512]
            else:
                with open(path, "rb") as f:
                    size = os.fstat(f.fileno()).st_size
                    if size > self.SMALL:
                        head = f.read(512); data = None
                    else:
                        data = f.read(); head = data[:512]
        except FileNotFoundError:
            return None, None, None            # nothing to preserve (file does not exist yet)
        except OSError:
            return None, "unreadable", None
        if size > self.max_file:
            return None, "file larger than per-file journal cap", head
        d = hashlib.sha256(data).hexdigest() if data is not None else sha(path)
        if d not in self._known:
            if self.used + size > self.quota:
                return None, "journal quota reached", head
            blob = self.root / "blobs" / d
            if data is not None:
                with open(blob, "wb") as f: f.write(data)
            else:
                shutil.copyfile(path, blob)
            self.used += size; self._known.add(d)
        return d, None, head

    def recently_captured(self, pid, path):
        last = self._last_cap.get(self.key(path))
        return bool(last and last[2] == pid and self.clock.now() - last[0] < self.min_interval)

    def before(self, pid, op, path, dst=None, data=None, head=None, forced_note=None, no_open=False):
        """op in write|delete|rename|create. Returns (record id for after(), head bytes of the pre-image or None)."""
        path = str(path); dst = str(dst) if dst is not None else None
        with self._lock:
            pre = note = head = None; reused = False
            if op in ("write", "delete", "rename", "open"):
                last = self._last_cap.get(self.key(path))
                now = self.clock.now()
                # rate-limit: if this pid's pre-image of the path was captured within min_interval, reuse it
                if op in ("write", "open") and last and last[2] == pid and now - last[0] < self.min_interval:
                    pre, reused = last[1], True    # head stays None: this pid already rewrote the file once
                elif forced_note:
                    note = forced_note      # sensor already knows why a pre-image cannot be kept (e.g. too large)
                elif no_open and data is None:
                    note = "pre-image unavailable (capture raced with the rate limit)"   # a sensor must never re-open the path
                else:
                    pre, note, h2 = self._store(path, data)
                    head = head or h2
                    if pre:
                        self._last_cap[self.key(path)] = (now, pre, pid)
            cur = self.db.execute("INSERT INTO rec(ts,pid,op,path,dst,pre,note) VALUES(?,?,?,?,?,?,?)",
                                  (self.clock.now(), pid, op, path, dst, pre, note))
            if not reused:      # re-writes of an already-captured path are committed with the next capture
                self.db.commit()
            return cur.lastrowid, head

    def _locked(fn):
        def w(self, *a, **k):
            with self._lock:
                return fn(self, *a, **k)
        return w

    @_locked
    def mark_written(self, rec_id):
        """A sensor that sees open-for-anything before it knows intent upgrades the record when a write close arrives."""
        self.db.execute("UPDATE rec SET op='write' WHERE id=? AND op='open'", (rec_id,))

    @_locked
    def after(self, rec_id, final_path, read=True, content=None):
        try:
            if content is not None and len(content) <= FULL_HASH_LIMIT and os.path.isfile(final_path): post = f"{len(content)}:{hashlib.sha256(content).hexdigest()[:32]}"      # the caller already holds the bytes it wrote: no second read
            else: post = fingerprint(final_path, read) if os.path.isfile(final_path) else None
        except OSError:
            post = None          # renamed or removed between the check and the stat: an asynchronous sensor can lose that race
        self.db.execute("UPDATE rec SET post=? WHERE id=?", (post, rec_id))   # committed with the next record or on flush

    # ---- rollback ----
    @_locked
    def rollback(self, pids, since=0.0, snapshot_dir=None, dry_run=False) -> RollbackReport:
        rep = RollbackReport()
        self.db.commit()
        qs = ",".join("?" * len(pids))
        rows = self.db.execute(f"SELECT id,ts,pid,op,path,dst,pre,post,note FROM rec WHERE pid IN ({qs}) AND ts>=? "
                               f"ORDER BY id DESC", (*pids, since)).fetchall()
        # forward-replay the expected end state of every path the incident touched
        expected = {}
        for (_id, _ts, _pid, op, path, dst, pre, post, note) in reversed(rows):
            if op == "open":
                continue     # read-only so far: nothing to compare; restored below only if the file vanished
            if op == "rename":
                expected[path] = None; expected[dst] = post
            elif op == "delete":
                expected[path] = None
            else:
                expected[path] = post
        tainted = set()
        for p, exp in expected.items():
            cur = fingerprint(p, read=not str(exp).startswith("stat:")) if os.path.isfile(p) else None      # compare like with like
            if cur != exp:
                tainted.add(p)    # changed by something else after the incident: do not overwrite
        rep.skipped_changed_after = sorted(tainted)
        snap = None
        if snapshot_dir and not dry_run:   # keep current state so the rollback itself can be undone (F045)
            snap = Path(snapshot_dir); snap.mkdir(parents=True, exist_ok=True)
            rep.snapshot_id = snap.name
        for (_id, _ts, _pid, op, path, dst, pre, post, note) in rows:
            final = dst if op == "rename" else path
            if path in tainted or final in tainted:
                continue
            if note and op in ("write", "delete", "rename"):
                rep.not_restorable.append((path, note)); continue
            if snap and not dry_run and os.path.isfile(final):
                tgt = snap / hashlib.sha256(final.encode()).hexdigest()
                if not tgt.exists():
                    shutil.copyfile(final, tgt)
                    (snap / (tgt.name + ".path")).write_text(final, encoding="utf-8")
            if op == "create":
                if os.path.isfile(path):
                    if not dry_run: os.remove(path)
                    rep.removed_created.append(path)
            elif op == "rename":
                if os.path.exists(dst) and not os.path.exists(path):
                    if not dry_run: os.replace(dst, path)
                    rep.renamed_back.append(path)
                if pre:
                    if not dry_run: self._restore(pre, path)
                    rep.restored.append(path)
            elif op in ("write", "delete"):
                if pre:
                    if not dry_run: self._restore(pre, path)
                    rep.restored.append(path)
                elif op == "delete" and not any(r[4] == path and r[6] for r in rows):
                    rep.not_restorable.append((path, "deleted without a pre-image: the program never opened it first"))
            elif op == "open":
                # opened by the incident process, never seen written. If the file has since vanished (delete/move we
                # could not attribute) bring it back; if it is still there, it is untouched and left alone.
                if pre and not os.path.exists(path) and path not in tainted:
                    if not dry_run: self._restore(pre, path)
                    rep.restored.append(path)
        rep.not_restorable = sorted(set(rep.not_restorable))
        rep.restored = sorted(set(rep.restored)); rep.removed_created = sorted(set(rep.removed_created))
        return rep

    def _restore(self, digest, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        tmp = str(path) + ".halvard-restore"
        shutil.copyfile(self.root / "blobs" / digest, tmp); os.replace(tmp, path)

    @_locked
    def pids_since(self, since):
        return [r[0] for r in self.db.execute("SELECT DISTINCT pid FROM rec WHERE ts>=?", (since,))]

    @_locked
    def compact(self, older_than_s, pinned_pids=()):
        """Drop records and unreferenced blobs past retention, except those for pinned incident pids."""
        cutoff = self.clock.now() - older_than_s
        qs = ",".join("?" * len(pinned_pids)) or "NULL"
        self.db.execute(f"DELETE FROM rec WHERE ts<? AND pid NOT IN ({qs})", (cutoff, *pinned_pids)); self.db.commit()
        live = {r[0] for r in self.db.execute("SELECT DISTINCT pre FROM rec WHERE pre IS NOT NULL")}
        for f in (self.root / "blobs").iterdir():
            if f.name not in live:
                self.used -= f.stat().st_size; f.unlink(); self._known.discard(f.name)
