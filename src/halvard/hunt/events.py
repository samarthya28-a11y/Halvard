"""Telemetry store (F019, F033): metadata about process and file activity, per tenant, with hot and cold tiers.

Collected: who ran what (process name, hash, command line), which paths were created/changed/renamed/deleted and the
detector's content-free signals, network metadata. NOT collected: file contents, keystrokes, screenshots, audio.
Command lines can hold secrets, so the simple search never returns them (see hunt.service).
"""
import json, sqlite3, time
from dataclasses import dataclass

from . import ql
from ..tenancy import TenantContext

COLS = ["ts", "device", "kind", "op", "pid", "ppid", "proc", "exe_sha256", "cmdline", "user", "path", "dst_path",
        "dst_ip", "dst_port", "signals", "file_sha256", "parent_proc"]
FORBIDDEN = {"content", "contents", "body", "text", "keystrokes", "clipboard", "screenshot", "audio", "webcam"}
DAY = 86400.0


@dataclass
class Retention:
    hot_days: int = 30
    cold_days: int = 365      # total age kept, including hot

    def __post_init__(self):
        if self.hot_days < 1 or self.cold_days < self.hot_days:
            raise ValueError("retention: hot_days >= 1 and cold_days >= hot_days")


class EventStore:
    def __init__(self, tenants, path=":memory:", clock=None):
        self.tenants, self.clock = tenants, clock
        self.db = sqlite3.connect(path, check_same_thread=False)
        for tier in ("hot", "cold"):
            self.db.execute(f"""CREATE TABLE IF NOT EXISTS ev_{tier}(tenant_id TEXT NOT NULL, id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, device TEXT, kind TEXT, op TEXT, pid INTEGER, ppid INTEGER, proc TEXT, exe_sha256 TEXT, cmdline TEXT,
                user TEXT, path TEXT, dst_path TEXT, dst_ip TEXT, dst_port INTEGER, signals TEXT, file_sha256 TEXT, parent_proc TEXT)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS hot_t ON ev_hot(tenant_id, ts)")
        self.db.execute("CREATE INDEX IF NOT EXISTS hot_dev ON ev_hot(tenant_id, device, ts)")
        self.policies = {}

    def now(self): return self.clock.now() if self.clock else time.time()

    def set_retention(self, ctx, r: Retention):
        self.tenants._guard(ctx); self.policies[ctx.tenant_id] = r

    def retention(self, ctx): return self.policies.get(ctx.tenant_id, Retention())

    def add(self, ctx: TenantContext, events):
        self.tenants._guard(ctx)
        rows = []
        for e in events:
            bad = set(e) - set(COLS)
            if bad:
                raise ValueError(f"fields not allowed in telemetry: {sorted(bad)}" +
                                 (" (content is never collected)" if bad & FORBIDDEN else ""))
            sig = e.get("signals"); sig = " ".join(sig) if isinstance(sig, (list, tuple)) else sig
            rows.append((ctx.tenant_id, e.get("ts", self.now()), e.get("device"), e.get("kind"), e.get("op"), e.get("pid"),
                         e.get("ppid"), e.get("proc"), e.get("exe_sha256"), (e.get("cmdline") or None) and e["cmdline"][:1024],
                         e.get("user"), e.get("path"), e.get("dst_path"), e.get("dst_ip"), e.get("dst_port"), sig, e.get("file_sha256"), e.get("parent_proc")))
        self.db.executemany("INSERT INTO ev_hot(tenant_id,ts,device,kind,op,pid,ppid,proc,exe_sha256,cmdline,user,path,dst_path,dst_ip,dst_port,signals,file_sha256,parent_proc)"
                            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        self.db.commit(); return len(rows)

    def roll(self, ctx):
        """Move events past the hot window to cold; delete past the cold window. Returns (moved, purged)."""
        self.tenants._guard(ctx); r = self.retention(ctx); now = self.now()
        cols = ",".join(["tenant_id"] + COLS)
        cur = self.db.execute(f"INSERT INTO ev_cold({cols}) SELECT {cols} FROM ev_hot WHERE tenant_id=? AND ts<?", (ctx.tenant_id, now - r.hot_days * DAY))
        moved = cur.rowcount
        self.db.execute("DELETE FROM ev_hot WHERE tenant_id=? AND ts<?", (ctx.tenant_id, now - r.hot_days * DAY))
        purged = self.db.execute("DELETE FROM ev_cold WHERE tenant_id=? AND ts<?", (ctx.tenant_id, now - r.cold_days * DAY)).rowcount
        self.db.commit(); return moved, purged

    def query_rows(self, ctx, ast, since=0.0, until=None, include_cold=False, limit=ql.MAX_ROWS, devices=None):
        self.tenants._guard(ctx)
        where, params = ql.to_sql(ast)
        until = until if until is not None else self.now() + 1
        out, truncated = [], False
        for tier in (("hot", "cold") if include_cold else ("hot",)):
            sql = f"SELECT {','.join(['id'] + COLS)} FROM ev_{tier} WHERE tenant_id=? AND ts>=? AND ts<=? AND ({where})"
            args = [ctx.tenant_id, since, until] + params
            if devices is not None:
                sql += f" AND device IN ({','.join('?' * len(devices))})"; args += list(devices)
            sql += " ORDER BY ts LIMIT ?"; args.append(limit + 1)
            cur = self.db.execute(sql, args)
            names = [c[0] for c in cur.description]
            out += [dict(zip(names, r), tier=tier) for r in cur.fetchall()]
        if len(out) > limit: out, truncated = out[:limit], True
        return out, truncated

    def counts(self, ctx):
        self.tenants._guard(ctx)
        return {t: self.db.execute(f"SELECT COUNT(*) FROM ev_{t} WHERE tenant_id=?", (ctx.tenant_id,)).fetchone()[0] for t in ("hot", "cold")}

    def export(self, ctx, include_cold=True):
        """Customer data export in a documented format: JSON Lines, one event per line, field names = COLS (F128)."""
        rows, _ = self.query_rows(ctx, None, include_cold=include_cold)
        return "\n".join(json.dumps({k: r[k] for k in COLS}, sort_keys=True) for r in rows) + ("\n" if rows else "")
