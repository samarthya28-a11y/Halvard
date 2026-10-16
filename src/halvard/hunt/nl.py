"""Natural-language hunt (F027): a transparent phrase translator, NOT a language model.

It understands a fixed set of everyday phrasings, always returns the structured query it built plus a plain
explanation, and says so when it cannot understand. Nothing runs until the user (or API caller) runs the shown query.
"""
import re

UNITS = {"minute": 60, "minutes": 60, "hour": 3600, "hours": 3600, "day": 86400, "days": 86400, "week": 604800, "weeks": 604800}
EXAMPLES = ["powershell with encoded commands in the last 24 hours", "files renamed on LT-17 in the last 2 hours",
            "processes run by jsmith today", "connections to 203.0.113.9", "files deleted under C:/Finance in the last day",
            "count processes named 7z by device in the last week"]


def translate(text, now):
    t = " " + text.strip().lower() + " "
    conds, notes, since, stages = [], [], None, []
    m = re.search(r"last (\d+) (minutes?|hours?|days?|weeks?)", t)
    if m: since = now - int(m.group(1)) * UNITS[m.group(2)]; notes.append(f"last {m.group(1)} {m.group(2)}")
    elif re.search(r"\blast (hour|day|week)\b", t):
        u = re.search(r"\blast (hour|day|week)\b", t).group(1); since = now - UNITS[u]; notes.append(f"last {u}")
    elif " today " in t: since = now - (now % 86400); notes.append("since midnight UTC")
    m = re.search(r"\bon ([a-z0-9][\w.-]*)", text, re.I)
    if m and m.group(1).lower() not in ("the", "any", "all"): conds.append(f'device="{m.group(1)}"'); notes.append(f"device {m.group(1)}")
    m = re.search(r"\b(?:by|as|user) ([a-z0-9][\w.-]*)", text, re.I)
    if m and m.group(1).lower() not in ("device", "process", "user", "path", "count") and not re.search(r"count .* by " + re.escape(m.group(1)), t):
        conds.append(f'user="{m.group(1)}"'); notes.append(f"user {m.group(1)}")
    m = re.search(r"\b(?:named|called|process) ([\w.*-]+)", text, re.I)
    if "powershell" in t: conds += ['proc~"powershell*"']; notes.append("PowerShell")
    elif m and m.group(1).lower() not in ("run", "by"): conds.append(f'proc~"{m.group(1)}*"'); notes.append(f"process starting {m.group(1)}")
    if "encoded" in t or "-enc" in t: conds.append('cmdline contains "-enc"'); notes.append("encoded command")
    ops = {"renamed": "rename", "deleted": "delete", "removed": "delete", "created": "create", "written": "write", "modified": "write", "changed": "write"}
    for w, op in ops.items():
        if f" {w} " in t: conds.append(f'kind=file AND op={op}'); notes.append(f"file {op}"); break
    else:
        if re.search(r"\bfiles?\b", t): conds.append("kind=file"); notes.append("file activity")
        elif re.search(r"\b(processes|process|commands?|run)\b", t) or "powershell" in t: conds.insert(0, "kind=process"); notes.append("process starts")
    if "connections" in t or "connected" in t: conds.append("kind=net"); notes.append("network connections")
    m = re.search(r"\bto (\d{1,3}(?:\.\d{1,3}){3})", t)
    if m: conds.append(f'dst_ip="{m.group(1)}"'); notes.append(f"to {m.group(1)}")
    m = re.search(r"\b(?:under|in|inside|touching|path) ((?:[a-z]:)?[/\\][\w./\\ -]*[\w.-])", text, re.I)
    if m: conds.append(f'path contains "{m.group(1).strip()}"'); notes.append(f"path containing {m.group(1).strip()}")
    m = re.search(r"count .*? by (device|user|proc|path|op)", t)
    if m: stages.append(f"count by {m.group(1)}")
    elif t.strip().startswith("count"): stages.append("count")
    if not conds:
        return None, {"understood": False, "message": "I could not turn that into a query. Try one like: " + "; ".join(EXAMPLES)}
    seen, uniq = set(), []
    for c in conds:
        if c not in seen: seen.add(c); uniq.append(c)
    q = " AND ".join(uniq) + "".join(f" | {s}" for s in stages)
    return {"query": q, "since": since}, {"understood": True, "explanation": "Looking for " + ", ".join(notes) + ".", "editable": True}
