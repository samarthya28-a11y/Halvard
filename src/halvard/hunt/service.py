"""Hunt service: who may see what (F034), with every search audited.

  analyst      full HQL, natural language, cold tier, raw fields incl. command lines and users
  it_admin     simple search only: fixed fields, recent window, no command lines, no user names
  service_desk device_status() only: "is this laptop okay?" - no raw telemetry at all
  others       refused (site_manager, auditor, owner see cases/evidence, not telemetry)
"""
import re

from . import ql, nl
from ..tenancy import TenantIsolationError

SIMPLE_FIELDS = ["ts", "device", "kind", "op", "proc", "path", "dst_ip"]
SIMPLE_WINDOW_S = 7 * 86400
HQL_ROLES = {"analyst"}


class HuntDenied(PermissionError):
    pass


class HuntService:
    def __init__(self, events, audit=None, cases=None):
        self.events, self.audit, self.cases = events, audit, cases or {}

    def _log(self, ctx, kind, data, controls=("HUNT.ACCESS",)):
        if self.audit:
            self.audit.append(kind, ctx.principal, ctx.role, ctx.tenant_id, data, controls=controls)

    def _deny(self, ctx, what):
        self._log(ctx, "hunt.denied", {"what": what})
        raise HuntDenied(f"role {ctx.role} may not {what}")

    def hql(self, ctx, text, since=None, until=None, include_cold=False, devices=None):
        if ctx.role not in HQL_ROLES: self._deny(ctx, "run structured hunts")
        q = ql.parse(text)
        rows, trunc = self.events.query_rows(ctx, q.ast, since or 0.0, until, include_cold, devices=devices)
        rows = ql.run_stages(rows, q.stages)
        self._log(ctx, "hunt.query", {"query": text, "rows": len(rows), "cold": include_cold, "truncated": trunc})
        return {"rows": rows, "truncated": trunc, "query": text}

    def natural(self, ctx, text, run=False):
        if ctx.role not in HQL_ROLES: self._deny(ctx, "run structured hunts")
        built, info = nl.translate(text, self.events.now())
        self._log(ctx, "hunt.natural_language", {"understood": info["understood"], "query": (built or {}).get("query", "")})
        if not built or not run:
            return {**info, **(built or {})}
        res = self.hql(ctx, built["query"], since=built["since"])
        return {**info, **built, **res}

    def simple(self, ctx, words, days=7):
        """Keyword search for IT staff. Fixed columns only; never command lines or user names."""
        if ctx.role not in HQL_ROLES | {"it_admin"}: self._deny(ctx, "search telemetry")
        terms = [w for w in re.split(r"\s+", words.strip()) if w][:5]
        if not terms: return {"rows": [], "message": "Type a device name, a program name or part of a file path."}
        since = self.events.now() - min(days * 86400, SIMPLE_WINDOW_S)
        ast = None
        for t in terms:
            c = ("or", ("or", ("or", ("cmp", "device", "=", t), ("cmp", "proc", "contains", t)), ("cmp", "path", "contains", t)), ("cmp", "dst_ip", "=", t))
            ast = c if ast is None else ("and", ast, c)
        rows, trunc = self.events.query_rows(self.ctx_for(ctx), ast, since, limit=200)
        out = [{k: r[k] for k in SIMPLE_FIELDS} for r in rows]
        self._log(ctx, "hunt.simple_search", {"terms": len(terms), "rows": len(out)})
        return {"rows": out, "truncated": trunc, "message": "" if out else "Nothing matched in the last 7 days. Older events are available to analysts."}

    @staticmethod
    def ctx_for(ctx): return ctx

    def device_status(self, ctx, device):
        """Service desk: a plain answer, no raw telemetry."""
        if ctx.role not in HQL_ROLES | {"it_admin", "service_desk"}: self._deny(ctx, "see device status")
        open_cases = [c for c in self.cases.get(ctx.tenant_id, []) if c["device"] == device and c["status"] != "closed"]
        res = {"device": device, "ok": not open_cases,
               "message": "No open problems. Halvard is protecting this computer." if not open_cases else
               f"{len(open_cases)} open case(s) on this computer. Ask an analyst before handing it back.",
               "open_cases": [{"title": c["title"], "status": c["status"]} for c in open_cases]}
        self._log(ctx, "hunt.device_status", {"device": device, "ok": res["ok"]})
        return res
