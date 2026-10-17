"""Regenerate tests/fixtures/sensor/*.jsonl (deterministic). Recordings from the native sensor must replay to the same answers."""
import json, random
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sensor"


def write(name, header, events):
    header = {"fixture": 1, "name": name, **header}
    lines = [json.dumps(header)] + [json.dumps({"seq": i + 1, "t_ms": e.pop("t_ms", i * 40), **e}) for i, e in enumerate(events)]
    (OUT / f"{name}.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def docs(n): return [{"path": f"docs/file{i}.docx", "kind": "text", "size": 3000} for i in range(n)]


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


if __name__ == "__main__":
    main()
