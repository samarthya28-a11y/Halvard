"""On-demand evidence collection (F026): authorized, scoped, hashed, sealed and logged.

Profiles
  triage  metadata only: process list, connections, persistence entries. Default. No file or memory contents.
  files   copies of NAMED paths. The scope is the list the approver saw.
  memory  process memory for NAMED pids. Needs an explicit personal-data acknowledgement; memory can hold passwords,
          messages and documents, so it is capped, labelled, and kept only for the stated retention.
Every collection writes a manifest (what, how big, SHA-256, who requested, who approved, why, retention) sealed with the
tenant ledger key, so later tampering with the evidence is detectable. Contents never enter the ledger; only counts,
hashes and the manifest digest do.
"""
import hashlib, json, os, shutil
from pathlib import Path

CAPS = {"files_total": 512 << 20, "memory_per_pid": 256 << 20}
PROFILES = ("triage", "files", "memory")


class CollectionError(ValueError):
    pass


def preview(host, params):
    prof = params.get("profile", "triage")
    if prof not in PROFILES: raise CollectionError(f"profile must be one of {PROFILES}")
    items, notes, personal = ["process list, network connections and startup entries (metadata only)"], [], False
    if prof == "files":
        paths = params.get("paths") or []
        if not paths: raise CollectionError("name the files to collect")
        size = sum(os.path.getsize(p) for p in paths if os.path.isfile(p))   # missing paths are reported as skipped at collection time
        items.append(f"copies of {len(paths)} named file(s), about {size} bytes"); personal = True
        notes.append("Files may contain personal or confidential data.")
    if prof == "memory":
        if not params.get("personal_data_ack"):
            raise CollectionError("memory collection needs personal_data_ack=True: memory can contain passwords and private content")
        pids = params.get("pids") or []
        if not pids: raise CollectionError("name the process ids to collect")
        items.append(f"memory of {len(pids)} process(es), up to {CAPS['memory_per_pid'] >> 20} MB each"); personal = True
        notes.append("Memory may contain credentials and private content; it is kept only for the retention shown.")
    return {"summary": "Collect: " + "; ".join(items) + f". Kept {params.get('retention_days', 30)} days. " + " ".join(notes),
            "personal_data": personal, "cannot_undo": ["a collection can be deleted, but anyone who already read it has seen it"]}


def collect(host, params, dest: Path, meta: dict, seal) -> dict:
    prof = params.get("profile", "triage"); dest.mkdir(parents=True, exist_ok=True)
    items = []

    def put(kind, name, data: bytes, rel):
        p = dest / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data)
        items.append({"kind": kind, "name": name, "file": rel, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})

    put("triage", "triage.json", json.dumps(host.triage(), sort_keys=True, indent=1).encode(), "triage.json")
    truncated = []
    if prof == "files":
        total = 0
        for i, src in enumerate(params["paths"]):
            if not os.path.isfile(src): truncated.append((src, "not found")); continue
            sz = os.path.getsize(src)
            if total + sz > CAPS["files_total"]: truncated.append((src, "over the collection size cap")); continue
            total += sz; put("file", src, Path(src).read_bytes(), f"files/{i:04d}")
    if prof == "memory":
        for pid in params["pids"]:
            try:
                data = host.read_memory(pid, CAPS["memory_per_pid"])
            except (LookupError, OSError, PermissionError) as e:
                truncated.append((f"pid {pid}", str(e))); continue
            put("memory", f"pid {pid}", data, f"memory/{pid}.bin")
    manifest = {**meta, "profile": prof, "items": items, "skipped": truncated,
                "personal_data": prof in ("files", "memory"), "retention_days": params.get("retention_days", 30)}
    body = json.dumps(manifest, sort_keys=True).encode()
    (dest / "manifest.json").write_text(json.dumps({"manifest": manifest, "seal": seal(body)}, sort_keys=True, indent=1))
    return {"manifest": manifest, "digest": hashlib.sha256(body).hexdigest(), "dir": str(dest)}


def verify_collection(dest: Path, seal):
    doc = json.loads((Path(dest) / "manifest.json").read_text()); problems = []
    if seal(json.dumps(doc["manifest"], sort_keys=True).encode()) != doc["seal"]: problems.append("manifest seal invalid")
    for it in doc["manifest"]["items"]:
        f = Path(dest) / it["file"]
        if not f.exists(): problems.append(f"{it['file']} missing")
        elif hashlib.sha256(f.read_bytes()).hexdigest() != it["sha256"]: problems.append(f"{it['file']} changed")
    return (not problems), problems
