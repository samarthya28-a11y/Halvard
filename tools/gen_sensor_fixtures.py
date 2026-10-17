"""Regenerate tests/fixtures/sensor/*.jsonl (deterministic). Recordings from the native sensor must replay to the same answers."""
import json, random
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sensor"


def golden(header, events):
    """Replay through the Python reference and record what it decided: 'A' allowed, 'D' denied, one letter per event."""
    import os, sys, tempfile
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests")); sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from helpers import make_agent
    from halvard import sensor
    tmp = tempfile.mkdtemp(); root = os.path.join(tmp, "work"); os.makedirs(root)
    specs = sensor.tripwire_specs(root, header)
    a, host, clock, fs = make_agent(tmp, **({"tripwires": specs} if specs else {}))
    a.set_online(not header.get("offline", False))
    for pid, n in header["processes"].items(): host.spawn(int(pid), n)
    sensor.seed(root, header)
    if specs: a._place_tripwires()
    res = sensor.replay(fs, [dict(seq=i + 1, **e) for i, e in enumerate(events)], root, clock=clock)
    return "".join("A" if d == "allow" else "D" for _, d in res)


def write(name, header, events):
    header = {"fixture": 1, "name": name, **header}
    header["golden"] = golden(header, [dict(e) for e in events])
    lines = [json.dumps(header)] + [json.dumps({"seq": i + 1, "t_ms": e.pop("t_ms", i * 40), **e}) for i, e in enumerate(events)]
    (OUT / f"{name}.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def docs(n, kind="text"): return [{"path": f"docs/file{i}.docx", "kind": kind, "size": 3000} for i in range(n)]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    write("ransomware_overwrite_rename",
          {"description": "Unknown program overwrites each document with random data and renames it .locked; must be stopped after a handful and every file restored.",
           "processes": {"4242": "burst.exe"}, "seed_files": docs(40), "offline": True,
           "expect": {"deny_pids": [4242], "max_allowed_changes": 20, "files_restored": True, "no_locked_files": True}},
          [ev for i in range(40) for ev in ({"pid": 4242, "op": "write", "path": f"docs/file{i}.docx", "data": {"kind": "random", "size": 3000, "seed": i}},
                                            {"pid": 4242, "op": "rename", "path": f"docs/file{i}.docx", "dst": f"docs/file{i}.docx.locked"})])
    write("tripwire_first_touch",
          {"description": "A tripwire sits first in the folder; the very first write to it stops the program before any real file changes.",
           "processes": {"4243": "burst.exe"}, "seed_files": docs(20), "tripwires": [{"id": "tw-1", "path": "docs/!000-budget.xlsx", "kind": "encryption"}], "offline": True,
           "expect": {"deny_pids": [4243], "first_deny_seq": 1, "max_allowed_changes": 0, "files_restored": True}},
          [{"pid": 4243, "op": "write", "path": "docs/!000-budget.xlsx", "data": {"kind": "random", "size": 2000, "seed": 1}}] +
          [{"pid": 4243, "op": "write", "path": f"docs/file{i}.docx", "data": {"kind": "random", "size": 3000, "seed": i}} for i in range(20)])
    rnd = random.Random(5); ev = []
    for i in range(60):
        r = rnd.random(); k = rnd.randrange(20)
        if r < .4: ev.append({"pid": 100, "op": "write", "path": f"docs/file{k}.docx", "data": {"kind": "text", "size": 3000, "seed": i}})
        elif r < .6: ev += [{"pid": 100, "op": "create", "path": f"docs/new{i}.tmp", "data": {"kind": "text", "size": 2000, "seed": i}},
                            {"pid": 100, "op": "rename", "path": f"docs/new{i}.tmp", "dst": f"docs/new{i}.docx"}]
        elif r < .8: ev.append({"pid": 100, "op": "read", "path": f"docs/file{k}.docx"})
        else: ev += [{"pid": 100, "op": "create", "path": f"docs/scratch{i}.dat", "data": {"kind": "text", "size": 500, "seed": i}}, {"pid": 100, "op": "delete", "path": f"docs/scratch{i}.dat"}]
    write("benign_office_session", {"description": "A word processor autosaves, saves via temp-and-rename, reads and cleans up scratch files; nothing may be blocked.",
          "processes": {"100": "winword.exe"}, "seed_files": docs(20), "offline": True, "expect": {"deny_pids": [], "all_allowed": True}}, ev)
    write("benign_compressor", {"description": "A compressor reads many documents and creates NEW archives; honest bulk work must not be stopped.",
          "processes": {"11": "7z.exe"}, "seed_files": docs(30), "offline": True, "expect": {"deny_pids": [], "all_allowed": True}},
          [e for i in range(30) for e in ({"pid": 11, "op": "read", "path": f"docs/file{i}.docx"},
                                          {"pid": 11, "op": "create", "path": f"docs/file{i}.docx.zip.part", "data": {"kind": "random", "size": 2000, "seed": i}},
                                          {"pid": 11, "op": "rename", "path": f"docs/file{i}.docx.zip.part", "dst": f"docs/file{i}.docx.zip"})])


def more():
    """Paths through the detector the first four fixtures do not reach."""
    rnd = lambda i: {"kind": "random", "size": 3000, "seed": i}
    write("ransomware_copy_delete",
          {"description": "Writes an encrypted sibling next to each document and deletes the original; stopped after eight originals are gone.",
           "processes": {"4300": "locker.exe"}, "seed_files": docs(20), "offline": True, "expect": {"deny_pids": [4300], "max_allowed_changes": 17}},
          [ev for i in range(20) for ev in ({"pid": 4300, "op": "create", "path": f"docs/file{i}.docx.enc", "data": rnd(i)}, {"pid": 4300, "op": "delete", "path": f"docs/file{i}.docx"})])
    write("ransomware_entropy_jump",
          {"description": "Documents that were mostly empty (no recognizable signature) are overwritten with random data: the entropy-jump signal.",
           "processes": {"4301": "burst.exe"}, "seed_files": docs(20, "zeros"), "offline": True, "expect": {"deny_pids": [4301], "max_allowed_changes": 8}},
          [{"pid": 4301, "op": "write", "path": f"docs/file{i}.docx", "data": rnd(i)} for i in range(20)])
    write("below_threshold",
          {"description": "Seven documents overwritten with random data: under the eight-file threshold, so nothing is stopped (the documented trade-off).",
           "processes": {"4302": "oddtool.exe"}, "seed_files": docs(20), "offline": True, "expect": {"deny_pids": [], "all_allowed": True}},
          [{"pid": 4302, "op": "write", "path": f"docs/file{i}.docx", "data": rnd(i)} for i in range(7)])
    write("slow_burn",
          {"description": "Twelve documents overwritten with random data, five seconds apart: never eight inside the 30 s window, so not stopped (a known limit).",
           "processes": {"4303": "slow.exe"}, "seed_files": docs(20), "offline": True, "expect": {"deny_pids": [], "all_allowed": True}},
          [{"pid": 4303, "op": "write", "path": f"docs/file{i}.docx", "data": rnd(i), "t_ms": i * 5000} for i in range(12)])
    mixed = []
    for i in range(12):
        mixed += [{"pid": 100, "op": "write", "path": f"docs/file{i + 10}.docx", "data": {"kind": "text", "size": 3000, "seed": i}},
                  {"pid": 4304, "op": "write", "path": f"docs/file{i}.docx", "data": rnd(i)}]
    write("mixed_processes",
          {"description": "A word processor and a ransomware program work in the same folder at once; only the ransomware is stopped.",
           "processes": {"100": "winword.exe", "4304": "burst.exe"}, "seed_files": docs(25), "offline": True, "expect": {"deny_pids": [4304], "max_allowed_changes": 24}}, mixed)


if __name__ == "__main__":
    main()
    more()
