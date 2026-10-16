"""Host adapter boundary. Relay handlers act on a Host; the reference build ships SimHost, which keeps state in
memory plus real files on disk so behavior is testable anywhere. Real-OS adapters (Windows/macOS/Linux) implement
the same interface; their isolation rules are rendered by relay.isolation and are NOT executed in this build."""
import hashlib, os, shutil
from pathlib import Path


class SimHost:
    def __init__(self, name, root, mgmt_endpoints=("mgmt.halvard.example",)):
        self.name, self.root = name, Path(root); (self.root / "quarantine").mkdir(parents=True, exist_ok=True)
        self.mgmt = set(mgmt_endpoints)
        self.isolated = False
        self.procs = {}          # pid -> dict(name,user,state)
        self.persistence = {}    # key -> value (stand-in for run keys / launch agents / cron / services)
        self.commands_run = []
        self.connections = []    # dicts: pid, dst_ip, dst_port, state
        self.memory = {}         # pid -> bytes (stand-in for a process image in simulations)
        self.mounts = {}         # mount path -> {removable, encrypted, vendor, serial}
        self.system_encrypted = True
        self.macs, self.ip = [], None      # network interface addresses, reported by the inventory so the network sensor can tell managed from unknown
        self.software = {}       # product -> version, as reported by the inventory (names and versions only)
        self.settings = {}       # configuration key -> value (firewall, screen lock, ...), for baseline checks
        self.update_defects = {} # (product, version) -> services that version breaks; a stand-in for a bad update

    # processes
    def spawn(self, pid, name, user="user1", exe_sha256=None, cmdline=None, ppid=None):
        self.procs[pid] = {"name": name, "user": user, "state": "running", "exe_sha256": exe_sha256, "cmdline": cmdline, "ppid": ppid}

    def suspend(self, pid):
        if pid in self.procs: self.procs[pid]["state"] = "suspended"

    def resume(self, pid):
        if pid in self.procs: self.procs[pid]["state"] = "running"

    def terminate(self, pid):
        if pid in self.procs: self.procs[pid]["state"] = "terminated"

    def proc(self, pid):
        return self.procs.get(pid)

    # network
    def isolate(self): self.isolated = True
    def release(self): self.isolated = False

    def can_reach(self, dest):
        return (not self.isolated) or dest in self.mgmt or dest == "127.0.0.1"

    # quarantine
    def quarantine(self, path):
        data = Path(path).read_bytes(); d = hashlib.sha256(data).hexdigest()
        qid = f"q-{d[:16]}"
        dest = self.root / "quarantine" / qid
        shutil.move(path, dest); (self.root / "quarantine" / (qid + ".meta")).write_text(str(path))
        return qid

    def restore_quarantine(self, qid):
        src = self.root / "quarantine" / qid
        orig = (self.root / "quarantine" / (qid + ".meta")).read_text()
        Path(orig).parent.mkdir(parents=True, exist_ok=True); shutil.move(src, orig)
        (self.root / "quarantine" / (qid + ".meta")).unlink()
        return orig

    # persistence / config
    def snapshot_config(self): return dict(self.persistence)
    def restore_config(self, snap): self.persistence = dict(snap)

    def run_command(self, command):
        self.commands_run.append(command); return f"ran: {len(command)} chars"

    def install_update(self, product, version):
        prev = self.software.get(product); self.software[product] = version; return prev

    def broken_services(self):
        return sorted({s for (p, v), svcs in self.update_defects.items() if self.software.get(p) == v for s in svcs})

    def mount_of(self, path):
        """The mount a path lives on (longest prefix), or None for the ordinary system volume."""
        p = str(path); best = None
        for m, info in self.mounts.items():
            if (p == m or p.startswith(m.rstrip("/") + "/")) and (best is None or len(m) > len(best[0])): best = (m, info)
        return {**best[1], "mount": best[0]} if best else None

    def encryption_status(self):
        return {"system": self.system_encrypted, "removable": {m: i["encrypted"] for m, i in self.mounts.items() if i.get("removable")}}

    # ---- forensic reads (metadata by default; memory only on explicit request) ----
    def triage(self):
        return {"processes": [{"pid": p, **{k: v for k, v in i.items() if k in ("name", "user", "state", "exe_sha256", "cmdline", "ppid")}}
                              for p, i in sorted(self.procs.items())],
                "connections": list(self.connections), "persistence": dict(self.persistence), "isolated": self.isolated}

    def read_memory(self, pid, max_bytes):
        if pid not in self.memory:
            raise LookupError(f"no readable memory for pid {pid}")
        return self.memory[pid][:max_bytes]
