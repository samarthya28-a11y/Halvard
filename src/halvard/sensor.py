"""Sensor interface v1 (M0 of the Windows client, docs/25).

A native sensor (ETW + tripwires now, minifilter later) is only an event source and an enforcer. It reports file operations in the
event format below and applies the answer (allow or deny). Every decision is made by the policy brain (WardAgent via ProtectedFS).
The same fixture files are replayed here against the Python reference; the native service must give the same answers on the same events.

Fixture file (JSON lines). Line 1 is the header, every other line is one event.
  header: {"fixture": 1, "name", "description", "processes": {"<pid>": "name.exe"}, "seed_files": [{"path", "kind", "size"}],
           "tripwires": [{"id", "path", "kind"}], "offline": bool, "expect": {...}, "golden": "AAAD..."}
  golden: one letter per event, A = allowed, D = denied, recorded from the Python reference by tools/gen_sensor_fixtures.py.
          Every sensor implementation (Python, Rust) must reproduce it exactly.
  event:  {"seq", "t_ms", "pid", "op": create|write|rename|delete|read|ads|delete_on_close, "path", "dst"?, "stream"?, "data"?: {"kind": text|random|magic, "size", "seed"}}
Paths are relative to the root folder the replay is given. `\\\\?\\` and a leading drive letter are the same file. An 8.3 name in the header's short_names is the long file. An ads event keeps the main bytes and records path:stream (this reference has no NTFS). Decision answers: "allow" or "deny".
"""
import hashlib, json, os
from pathlib import Path

SCHEMA_VERSION = 1
OPS = ("create", "write", "rename", "delete", "read", "ads", "delete_on_close")


def load(path):
    lines = [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]
    header, events = lines[0], lines[1:]
    if header.get("fixture") != SCHEMA_VERSION: raise ValueError(f"{path}: unsupported fixture version {header.get('fixture')}")
    for e in events:
        if e["op"] not in OPS: raise ValueError(f"{path}: unknown op {e['op']!r}")
    return header, events


def materialize(spec, ext=""):
    """Deterministic bytes for a data spec, so fixtures stay small text files."""
    size, seed = int(spec.get("size", 1000)), int(spec.get("seed", 0))
    kind = spec.get("kind", "text")
    if kind == "random": return b"".join(hashlib.sha256(f"{seed}:{i}".encode()).digest() for i in range((size + 31) // 32))[:size]    # SHA-256 counter stream: any language reproduces it
    if kind == "zeros": return bytes(size)
    if kind == "magic": return (b"\xff\xd8\xff" + bytes(range(256)) * (size // 256 + 1))[:size]
    return ((b"Meeting notes %d. " % seed) * (size // 12 + 1))[:size]


def seed(root, header):
    out = {}
    for i, f in enumerate(header.get("seed_files", [])):
        p = Path(root, f["path"]); p.parent.mkdir(parents=True, exist_ok=True)
        data = materialize({"kind": f.get("kind", "text"), "size": f.get("size", 3000), "seed": i}); p.write_bytes(data); out[str(p)] = hashlib.sha256(data).hexdigest()
    return out


def tripwire_specs(root, header):
    return [{"id": t["id"], "kind": t["kind"], "path": str(Path(root, t["path"]))} for t in header.get("tripwires", [])]


def normalize(path, header=None):
    """The path a native sensor must decide on. `\\\\?\\` is the same file. A drive letter is the volume, not a folder. An 8.3 name is the long file."""
    p = str(path).replace("\\", "/")
    if p.startswith("//?/"):
        p = p[4:]
    if len(p) >= 2 and p[1] == ":":
        p = p[2:].lstrip("/")
    shorts = {k.upper(): v.replace("\\", "/") for k, v in ((header or {}).get("short_names") or {}).items()}
    long = shorts.get(os.path.basename(p).upper())
    if long:
        p = long
    return p


def replay(fs, events, root, clock=None, header=None):
    """Apply events through the file-hook contract. Returns [(seq, "allow"|"deny")]. Stops nothing itself: a denied event is just recorded. With a ManualClock, advances it by each event's t_ms."""
    from .ward.agent import Blocked
    out = []
    last_ms = 0
    header = header or {}
    for e in events:
        if clock is not None:      # events carry their own time: the detector's 30 s window must see it
            clock.advance((e.get("t_ms", last_ms) - last_ms) / 1000.0); last_ms = e.get("t_ms", last_ms)
        p = os.path.join(root, normalize(e["path"], header)); pid = e["pid"]
        try:
            if e["op"] == "create": fs.create(pid, p, materialize(e.get("data", {})))
            elif e["op"] == "write": fs.overwrite(pid, p, materialize(e.get("data", {})))
            elif e["op"] == "rename": fs.rename(pid, p, os.path.join(root, normalize(e["dst"], header)))
            elif e["op"] == "delete": fs.delete(pid, p)
            elif e["op"] == "read": fs.read(pid, p)
            elif e["op"] == "ads": fs.ads(pid, p, e["stream"], materialize(e.get("data", {})))
            elif e["op"] == "delete_on_close": fs.delete_on_close(pid, p)
            out.append((e["seq"], "allow"))
        except Blocked:
            out.append((e["seq"], "deny"))
        except FileNotFoundError:
            out.append((e["seq"], "allow"))      # the operation itself failed (file missing); the sensor reports it as allowed, the OS reports the error
    return out


BUDGET_KEYS = ("idle_cpu_percent_of_one_core_max", "memory_mb_max", "added_latency_p50_microseconds_max", "added_latency_p99_microseconds_max",
               "install_footprint_mb_max")


def check_budget(measured: dict, budget: dict) -> list:
    """Compare a measurement report (from the native service or any stand-in) with a budget section. Returns a list of breaches; a missing measurement is a breach."""
    out = []
    for k in BUDGET_KEYS:
        if k not in budget: continue
        mk = k[:-4]            # strip "_max"
        if mk not in measured: out.append(f"{mk}: not measured"); continue
        if measured[mk] > budget[k]: out.append(f"{mk}: {measured[mk]} exceeds {budget[k]}")
    return out
