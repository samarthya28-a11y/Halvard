"""Linux sensor (F001): a REAL kernel-notification sensor built on fanotify, plus a /proc-backed host.

What it does (needs root / CAP_SYS_ADMIN; the tests run it on a private tmpfs mount):
  * permission group (FAN_OPEN_PERM, FAN_OPEN_EXEC_PERM, FAN_CLOSE_*): before a file is opened, keep a pre-image in the
    journal; before an executable runs, run the pre-execution verdict and DENY known-bad; DENY all opens by a process
    Ward has frozen. Events from this process are always allowed so the sensor cannot deadlock itself.
  * notification group (FAN_RENAME, FAN_DELETE with directory file handles): exact, pid-attributed rename and delete
    events, so `rename to .locked` and `delete the original` are journaled and rolled back.
Honest limits
  * Intent is unknown at open time, so a pre-image is taken on any open of an existing file (rate-limited per process and
    path, deduplicated by content, bounded by the journal quota). Cost: more journal churn than a write-intent hook.
  * Files larger than the per-file cap are not preserved (reported as not restorable). 2 GB+ files are not supported.
  * A mount mark covers one mount. A service mark per mount is needed in production.
  * exec events carry the executable and its hash, not the argument list (it is not final at permission time).
  * If this process stops, the kernel auto-allows pending permission events; a dead sensor fails OPEN, and sensor
    health/coverage alerts (F121) are the control for that.
"""
import ctypes, hashlib, os, queue, select, signal, stat, struct, threading, time
from pathlib import Path

from ..relay.host import SimHost

import sys
libc = ctypes.CDLL(None, use_errno=True) if sys.platform.startswith("linux") else None      # importable everywhere; usable only on Linux
FAN_CLOEXEC, FAN_NONBLOCK, FAN_CLASS_NOTIF, FAN_CLASS_CONTENT = 0x1, 0x2, 0x0, 0x4
FAN_REPORT_DFID_NAME = 0x400 | 0x800
FAN_CLOSE_WRITE, FAN_CLOSE_NOWRITE, FAN_OPEN_PERM, FAN_OPEN_EXEC_PERM = 0x8, 0x10, 0x10000, 0x40000
FAN_DELETE, FAN_RENAME = 0x200, 0x10000000
FAN_MARK_ADD, FAN_MARK_MOUNT, FAN_MARK_FILESYSTEM = 0x1, 0x10, 0x100
FAN_ALLOW, FAN_DENY = 1, 2
INFO_DFID_NAME, INFO_OLD_DFID_NAME, INFO_NEW_DFID_NAME = 2, 10, 12
AT_FDCWD = -100
HDR = struct.Struct("<IBBHQii")      # event_len, vers, reserved, metadata_len, mask, fd, pid


def available():
    """True when this process can run the sensor (root + fanotify). Used to skip privileged tests cleanly."""
    if os.geteuid() != 0: return False
    fd = libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, os.O_RDONLY)
    if fd < 0: return False
    os.close(fd); return True


class LinuxHost(SimHost):
    """Process control and triage from /proc. Isolation is recorded, not applied: rules are rendered in relay.isolation."""
    PROTECTED = {0, 1, 2}      # 2 is kthreadd: signalling it (or its children, the kernel threads) can hang the machine

    def proc(self, pid):
        try:
            stat_txt = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
            comm = Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()
            ppid = int(stat_txt.rsplit(")", 1)[1].split()[1])
            state = stat_txt.rsplit(")", 1)[1].split()[0]
            uid = next(l.split()[1] for l in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines() if l.startswith("Uid:"))
            try: cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
            except OSError: cmd = None
            exe = None
            try: exe = os.readlink(f"/proc/{pid}/exe")
            except OSError: pass
        except (OSError, ValueError, StopIteration):
            return self.procs.get(pid)
        return {"name": comm, "user": uid, "state": {"T": "suspended", "Z": "terminated", "X": "terminated"}.get(state, "running"),
                "exe_sha256": None, "cmdline": cmd, "ppid": ppid, "exe": exe}

    @staticmethod
    def _is_kernel_thread(pid):
        """Kernel threads are children of kthreadd (pid 2) and have no executable. Never freeze or kill one."""
        try:
            stat_txt = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
            return int(stat_txt.rsplit(")", 1)[1].split()[1]) == 2
        except (OSError, ValueError, IndexError):
            return False

    def _signal(self, pid, sig):
        if pid in self.PROTECTED or pid == os.getpid() or pid == os.getppid() or self._is_kernel_thread(pid):
            raise PermissionError(f"refusing to signal pid {pid}")
        try: os.kill(pid, sig)
        except ProcessLookupError: pass

    def suspend(self, pid): self._signal(pid, signal.SIGSTOP)
    def resume(self, pid): self._signal(pid, signal.SIGCONT)

    def terminate(self, pid):
        self._signal(pid, signal.SIGCONT)      # a stopped process must be continued for SIGKILL delivery to complete promptly
        self._signal(pid, signal.SIGKILL)

    def triage(self):
        procs = []
        for d in sorted(Path("/proc").iterdir(), key=lambda p: p.name):
            if d.name.isdigit():
                i = self.proc(int(d.name))
                if i: procs.append({"pid": int(d.name), **{k: i[k] for k in ("name", "user", "state", "cmdline", "ppid")}})
        conns = []
        for f, proto in (("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6")):
            try: lines = Path(f).read_text(encoding="utf-8").splitlines()[1:]
            except OSError: continue
            for l in lines:
                c = l.split(); ip, port = c[2].split(":")
                if proto == "tcp":
                    ipn = ".".join(str(int(ip[i:i + 2], 16)) for i in (6, 4, 2, 0))
                else: ipn = ip
                conns.append({"proto": proto, "dst_ip": ipn, "dst_port": int(port, 16), "state": c[3]})
        pers = {}
        for loc in ("/etc/crontab", "/etc/rc.local", "/etc/ld.so.preload"):
            if os.path.exists(loc): pers[loc] = hashlib.sha256(Path(loc).read_bytes()).hexdigest()
        return {"processes": procs, "connections": conns, "persistence": pers, "isolated": self.isolated}

    def read_memory(self, pid, max_bytes):
        out, left = [], max_bytes
        with open(f"/proc/{pid}/maps") as maps, open(f"/proc/{pid}/mem", "rb", 0) as mem:
            for line in maps:
                rng, perms = line.split()[:2]
                if "r" not in perms or "[vvar" in line or "[vsyscall" in line: continue
                a, b = (int(x, 16) for x in rng.split("-"))
                n = min(b - a, left)
                if n <= 0: break
                try: mem.seek(a); out.append(mem.read(n)); left -= n
                except (OSError, ValueError): continue
        return b"".join(out)


class FanotifySensor:
    def __init__(self, agent, mount, exec_protection=True):
        self.agent, self.mount = agent, os.path.realpath(mount)
        self.exec_protection = exec_protection
        self.me = os.getpid()
        self.pending, self.opened = {}, {}
        self.work = queue.Queue(); self.stop_ev = threading.Event(); self.threads = []
        self.stats = {"open_perm": 0, "exec_perm": 0, "denied": 0, "close": 0, "rename": 0, "delete": 0, "errors": 0}
        self.errors = []
        self._busy_notify = False

    # ---------------- lifecycle ----------------
    def start(self):
        self.mount_fd = os.open(self.mount, os.O_RDONLY)
        self.pfd = libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, os.O_RDONLY)
        self.nfd = libc.fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_DFID_NAME, os.O_RDONLY)
        if self.pfd < 0 or self.nfd < 0:
            raise OSError(ctypes.get_errno(), "fanotify_init failed (needs root)")
        mask = FAN_OPEN_PERM | FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE | (FAN_OPEN_EXEC_PERM if self.exec_protection else 0)
        if libc.fanotify_mark(self.pfd, FAN_MARK_ADD | FAN_MARK_MOUNT, ctypes.c_uint64(mask), AT_FDCWD, self.mount.encode()) < 0:
            raise OSError(ctypes.get_errno(), "fanotify_mark(perm) failed")
        if libc.fanotify_mark(self.nfd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, ctypes.c_uint64(FAN_RENAME | FAN_DELETE), AT_FDCWD, self.mount.encode()) < 0:
            raise OSError(ctypes.get_errno(), "fanotify_mark(fid) failed")
        for fn in (self._perm_loop, self._notify_loop, self._worker):
            t = threading.Thread(target=fn, daemon=True, name=f"halvard-{fn.__name__}"); t.start(); self.threads.append(t)
        return self

    def stop(self):
        self.stop_ev.set()
        for t in self.threads: t.join(timeout=3)
        for fd in (self.pfd, self.nfd, self.mount_fd):
            try: os.close(fd)      # closing the permission group makes the kernel allow anything still pending
            except OSError: pass

    def settle(self, quiet=0.25, limit=3.0):
        """Before rolling back, let the kernel's already-generated rename/delete events reach us (they are asynchronous)."""
        end = time.time() + limit; last = time.time()
        while time.time() < end:
            r, _, _ = select.select([self.nfd], [], [], 0.05)
            if r or self._busy_notify: last = time.time()
            elif time.time() - last >= quiet: return
        return

    def drain(self, timeout=5.0):
        """Wait until queued responses (rollback etc.) have finished. Tests use this; production does not need it."""
        end = time.time() + timeout
        while time.time() < end and self.work.unfinished_tasks: time.sleep(0.02)

    # ---------------- threads ----------------
    def _worker(self):
        while not self.stop_ev.is_set():
            try: fn = self.work.get(timeout=0.1)
            except queue.Empty: continue
            try: fn()
            except Exception as e:      # a response that fails must be visible, never silent
                self.stats["errors"] += 1; self.errors.append(repr(e))
            finally: self.work.task_done()

    def _perm_loop(self):
        while not self.stop_ev.is_set():
            r, _, _ = select.select([self.pfd], [], [], 0.1)
            if not r: continue
            try: buf = os.read(self.pfd, 262144)
            except BlockingIOError: continue
            off = 0
            while off + HDR.size <= len(buf):
                elen, vers, _, mlen, mask, fd, pid = HDR.unpack_from(buf, off)
                if elen < HDR.size:      # a malformed length would leave the offset where it is and spin forever: stop reading this buffer, visibly
                    self.stats["errors"] += 1; self.errors.append(f"fanotify event with impossible length {elen}"); break
                off += elen
                if fd < 0: continue
                try: self._perm_event(mask, fd, pid)
                except Exception as e:
                    self.stats["errors"] += 1; self.errors.append(repr(e))
                    if mask & (FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM): self._reply(fd, FAN_ALLOW)      # sensor faults fail open, visibly
                finally:
                    try: os.close(fd)
                    except OSError: pass

    def _reply(self, fd, resp):
        os.write(self.pfd, struct.pack("<ii", fd, resp))

    def _perm_event(self, mask, fd, pid):
        a = self.agent
        try: path = os.readlink(f"/proc/self/fd/{fd}")
        except OSError: path = ""
        perm = mask & (FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM)
        if pid == self.me:
            if perm: self._reply(fd, FAN_ALLOW)
            return
        if perm:
            decision = self._on_exec(pid, fd, path) if mask & FAN_OPEN_EXEC_PERM else self._on_open(pid, fd, path)
            if decision == FAN_DENY: self.stats["denied"] += 1
            self._reply(fd, decision)
        else:
            self._on_close(pid, fd, path, bool(mask & FAN_CLOSE_WRITE))

    # ---------------- permission events ----------------
    def _on_open(self, pid, fd, path):
        a = self.agent; self.stats["open_perm"] += 1
        if pid in a.blocked: return FAN_DENY
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode): return FAN_ALLOW
        if a._trusted(pid) or self._excluded(path): return FAN_ALLOW
        j = a.journal
        if st.st_size == 0:
            rid, head = j.before(pid, "create", path)
        elif st.st_size > j.max_file:
            rid, head = j.before(pid, "open", path, head=os.pread(fd, 512, 0), forced_note="file larger than per-file journal cap")
        elif j.recently_captured(pid, path):
            rid, head = j.before(pid, "open", path, no_open=True)
        else:
            data = os.pread(fd, st.st_size, 0)
            rid, head = j.before(pid, "open", path, data=data, no_open=True)
        seen = self.opened.setdefault(pid, {})
        head = head or seen.get(path)            # a rate-limited re-open reuses the head from the first open of this file
        if len(self.pending) > 50_000:
            self.pending.pop(next(iter(self.pending))); self.stats["pending_dropped"] = self.stats.get("pending_dropped", 0) + 1      # an open whose close we may never match: counted so a gap is visible, not silent
        self.pending[(pid, st.st_dev, st.st_ino)] = (rid, head, st.st_size == 0)     # keyed by file identity: it may be renamed while open
        if head and len(seen) < 5000: seen[path] = head
        return FAN_ALLOW

    def _on_exec(self, pid, fd, path):
        a = self.agent; self.stats["exec_perm"] += 1
        if pid in a.blocked: return FAN_DENY
        st = os.fstat(fd)
        data = os.pread(fd, min(st.st_size, 8 << 20), 0)
        v = a.verdicts.evaluate(data, os.path.basename(path), a.online)
        digest = hashlib.sha256(data).hexdigest()
        if v.decision == "block" and a.bundle.prevention.get("known_bad", "enforce") == "enforce":
            a.spool.append("ward.exec_verdict", "system", "system", a.device_id,
                           {"decision": "block", "score": round(v.score, 2), "source": v.source, "reasons": v.reasons, "path": path,
                            "sha256": digest, "mode": "enforce", "online": a.online, "platform": "linux"},
                           controls=("WARD.PRE_EXECUTION_VERDICT",) + (("WARD.OFFLINE_PREVENTION",) if not a.online else ()))
            self.work.put(lambda: a.engine.request(__import__("halvard.relay.actions", fromlist=["x"]).ActionRequest(
                "quarantine_file", __import__("halvard.ward.agent", fromlist=["x"]).SYSTEM, [path], f"pre-execution verdict: {'; '.join(v.reasons)}",
                automatic=True, pattern="malware_quarantine")))
            return FAN_DENY
        a.emit("process", "exec", pid, path)
        return FAN_ALLOW

    def _excluded(self, path):
        import fnmatch
        p = path.replace("\\", "/").lower()
        return any(fnmatch.fnmatch(p, g) for g in self.agent.exclude)

    # ---------------- close events (no reply needed) ----------------
    def _on_close(self, pid, fd, path, wrote):
        a = self.agent; self.stats["close"] += 1
        st = os.fstat(fd)
        rec = self.pending.pop((pid, st.st_dev, st.st_ino), None)
        if not wrote or rec is None: return
        rid, head, was_empty = rec
        sample = os.pread(fd, 4096, 0)
        j = a.journal
        if rid:
            j.mark_written(rid); j.after(rid, path, read=False)
        if was_empty or not head:
            from ..ward.detect import entropy, has_magic
            a.emit("file", "create", pid, path)
            if len(sample) >= 64 and not has_magic(sample[:256]) and entropy(sample) > 7.5:
                a.recent_highent.setdefault(pid, []).append((a.clock.now(), path))
                d, base = os.path.split(path)
                for orig, ohead in list(self.opened.get(pid, {}).items()):
                    od, ob = os.path.split(orig)
                    if od == d and orig != path and base.startswith(os.path.splitext(ob)[0]):
                        self._observe(pid, orig, ("magic_destroyed",))     # a recognizable original was replaced by random-looking data
        else:
            sig = a.detector.classify(head, sample)
            a.emit("file", "write", pid, path, sig)
            self._observe(pid, path, sig)

    def _observe(self, pid, path, sig):
        a = self.agent
        if a._trusted(pid): return
        v = a.detector.observe(a.clock.now(), pid, path, sig)
        if v:
            if a.bundle.prevention.get("bulk_encryption", "enforce") == "enforce":
                a.blocked.add(pid)      # opens by this pid are denied from now on, before the slower response runs
            a.handle_verdict(v, defer=lambda fn: self.work.put(lambda: (self.settle(), fn())))

    # ---------------- rename/delete (FID group) ----------------
    def _notify_loop(self):
        while not self.stop_ev.is_set():
            r, _, _ = select.select([self.nfd], [], [], 0.1)
            if not r: continue
            try: buf = os.read(self.nfd, 262144)
            except BlockingIOError: continue
            off = 0; self._busy_notify = True
            while off + HDR.size <= len(buf):
                elen, vers, _, mlen, mask, fd, pid = HDR.unpack_from(buf, off)
                if elen < HDR.size:
                    self.stats["errors"] += 1; self.errors.append(f"fanotify event with impossible length {elen}"); break
                names = {}
                p = off + mlen
                while p < off + elen:
                    itype, _, ilen = struct.unpack_from("<BBH", buf, p)
                    if ilen < 4:      # an info record shorter than its own header would never advance: skip the rest of this event, visibly
                        self.stats["errors"] += 1; self.errors.append(f"fanotify info record with impossible length {ilen}"); break
                    if itype in (INFO_DFID_NAME, INFO_OLD_DFID_NAME, INFO_NEW_DFID_NAME):
                        names[itype] = self._decode(buf, p, ilen)
                    p += ilen
                off += elen
                try: self._notify_event(mask, pid, names)
                except Exception as e:
                    self.stats["errors"] += 1; self.errors.append(repr(e))
            self._busy_notify = False

    def _decode(self, buf, p, ilen):
        hb, = struct.unpack_from("<I", buf, p + 12)
        fh = bytes(buf[p + 12: p + 20 + hb])
        name = bytes(buf[p + 20 + hb: p + ilen]).split(b"\0")[0].decode(errors="replace")
        h = ctypes.create_string_buffer(fh, len(fh))
        dfd = libc.open_by_handle_at(self.mount_fd, h, os.O_PATH)
        if dfd < 0: return None
        try: d = os.readlink(f"/proc/self/fd/{dfd}")
        finally: os.close(dfd)
        return os.path.join(d, name)

    def _notify_event(self, mask, pid, names):
        a = self.agent
        if pid == self.me or a._trusted(pid): return
        j = a.journal
        if mask & FAN_RENAME:
            src, dst = names.get(INFO_OLD_DFID_NAME), names.get(INFO_NEW_DFID_NAME)
            if not (src and dst): return
            self.stats["rename"] += 1
            rid, _ = j.before(pid, "rename", src, dst); j.after(rid, dst, read=False)
            ext = os.path.splitext(src)[1] != os.path.splitext(dst)[1]
            a.emit("file", "rename", pid, src, ("ext_changed",) if ext else (), dst_path=dst)
            self._observe(pid, dst, ("ext_changed",) if ext else ())
        elif mask & FAN_DELETE:
            path = names.get(INFO_DFID_NAME)
            if not path: return
            self.stats["delete"] += 1
            rid, _ = j.before(pid, "delete", path); j.after(rid, path, read=False)
            a.emit("file", "delete", pid, path)
