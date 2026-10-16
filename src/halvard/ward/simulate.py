"""Safe, scoped control-validation simulations (customer-authorized, modeled on commercial control-validation tools).

A simulation runs only inside a directory the customer has marked with an authorization file. It performs ordinary
file operations on test files that the harness itself created: overwrite with random bytes, rename, or
copy-and-delete. There is no cryptography, no key handling, no network, no persistence and no spreading.
"""
import os, random
from pathlib import Path

MARKER = ".halvard-simulation-authorized"


class SimulationNotAuthorized(PermissionError):
    pass


def authorize(root):
    Path(root).mkdir(parents=True, exist_ok=True); (Path(root) / MARKER).write_text("customer-authorized simulation root\n", encoding="utf-8")


def seed_files(root, n=40, seed=7, dirs=3):
    """Create ordinary-looking test documents (text, zip-like, pdf-like)."""
    rnd = random.Random(seed); paths = []
    for i in range(n):
        d = Path(root) / f"dept{i % dirs}"; d.mkdir(parents=True, exist_ok=True)
        kind = i % 3
        if kind == 0: body = b"Quarterly notes line %d\n" % i * 200
        elif kind == 1: body = b"%PDF-1.4\n" + (b"BT /F1 12 Tf (report %d) Tj ET\n" % i) * 150
        else: body = b"PK\x03\x04" + bytes(rnd.getrandbits(8) for _ in range(40)) + b"word/document.xml " * 100
        p = d / f"file{i:03d}.{['txt','pdf','docx'][kind]}"; p.write_bytes(body); paths.append(str(p))
    return paths


def run_simulation(fs, pid, root, style="overwrite_rename", limit=None):
    """Drive a ransomware-like burst through the ProtectedFS. Stops when Ward blocks the process. Returns files touched."""
    root = Path(root)
    if not (root / MARKER).exists():
        raise SimulationNotAuthorized(f"{root} is not an authorized simulation root")
    from .agent import Blocked
    touched = 0
    targets = sorted(str(p) for p in root.rglob("*") if p.is_file() and p.name != MARKER and not p.name.endswith(".locked"))
    for p in targets[: limit or len(targets)]:
        try:
            noise = os.urandom(1500)
            if style == "overwrite_rename":
                fs.overwrite(pid, p, noise); fs.rename(pid, p, p + ".locked")
            elif style == "copy_delete":
                fs.create(pid, p + ".locked", noise); fs.delete(pid, p)
            touched += 1
        except Blocked:
            break
    return touched


def main(argv=None):
    """Plain-syscall burst for the privileged Linux lane: `python -m halvard.ward.simulate ROOT STYLE`.
    Same authorization rule as run_simulation: refuses a directory without the marker. Exit 3 when the OS denies
    further writes (that is Ward working), 2 when unauthorized."""
    import sys
    root, style = (argv or sys.argv[1:])[:2]
    r = Path(root)
    if not (r / MARKER).exists():
        print("not an authorized simulation root", file=sys.stderr); return 2
    files = sorted(str(p) for p in r.rglob("*") if p.is_file() and p.name != MARKER and not p.name.endswith(".locked"))
    done = 0
    pace = float(os.environ.get("HALVARD_SIM_PACE_MS", "0")) / 1000.0     # real encryption costs time per file; 0 = fastest possible burst
    import time
    try:
        for p in files:
            data = open(p, "rb").read()          # ransomware reads the original first
            noise = os.urandom(max(1500, len(data)))
            if style == "overwrite_rename":
                with open(p, "wb") as f: f.write(noise)
                os.rename(p, p + ".locked")
            else:
                with open(p + ".locked", "wb") as f: f.write(noise)
                os.remove(p)
            done += 1
            if pace: time.sleep(pace)
    except PermissionError:
        print(f"denied after {done} files", file=sys.stderr); return 3
    print(f"finished {done} files"); return 0


if __name__ == "__main__":
    raise SystemExit(main())
