"""Inventory of AI tools people use, sanctioned and not (F103), and the rule for which data may go to which tool (F104).

Discovery sources: web-proxy or DNS logs (who, which domain, how much was sent), the identity provider's OAuth grants, and software names
that devices report. A tool is `sanctioned` only when an IT admin says so, with a tier: `enterprise` (customer has read the vendor's terms and
attests no training on inputs and an enterprise agreement) or `standard`. Everything else that is found is `shadow`.
Vendor facts (trains on inputs, retention) are what the CUSTOMER attests. Halvard does not verify vendor claims and shows 'unknown' as unknown.
"""
import json
from dataclasses import dataclass, field
from pathlib import Path

TIERS = ("enterprise", "standard")


@dataclass
class AITool:
    key: str
    name: str
    kind: str
    domains: list
    products: list = field(default_factory=list)
    trains_on_inputs: bool | None = None
    retention_days: int | None = None
    enterprise_tier: bool = False


@dataclass
class Found:
    tool: AITool
    state: str = "shadow"               # shadow | sanctioned
    tier: str | None = None
    users: set = field(default_factory=set)
    uploaded_bytes: int = 0
    sources: set = field(default_factory=set)
    devices: set = field(default_factory=set)
    scopes: set = field(default_factory=set)


def load_catalog(path):
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    return [AITool(**t) for t in d["tools"]]


class AIInventory:
    def __init__(self, catalog, audit=None, clock=None):
        self.catalog, self.audit, self.clock = list(catalog), audit, clock
        self.sanctioned = {}          # key -> tier
        self.found = {}

    def _log(self, kind, subject, data): 
        if self.audit: self.audit.append(kind, "halvard:lumen", "system", subject, data, controls=("LUMEN.AI_INVENTORY",))

    def tool_for_domain(self, domain):
        d = (domain or "").lower()
        return next((t for t in self.catalog if any(d == x or d.endswith("." + x) for x in t.domains)), None)

    def _rec(self, tool):
        f = self.found.setdefault(tool.key, Found(tool)); f.state, f.tier = ("sanctioned", self.sanctioned[tool.key]) if tool.key in self.sanctioned else ("shadow", None); return f

    # ---- sources ----
    def from_proxy(self, rows):
        """rows: dicts {user, domain, bytes_out, device}. Only the domain and volume are used; no URLs, no content."""
        for r in rows:
            t = self.tool_for_domain(r["domain"])
            if not t: continue
            f = self._rec(t); f.users.add(r["user"]); f.uploaded_bytes += int(r.get("bytes_out", 0)); f.sources.add("web proxy"); 
            if r.get("device"): f.devices.add(r["device"])

    def from_idp(self, idp):
        for g in idp.grants:
            if g.get("revoked"): continue
            app = idp.apps.get(g.get("app"))
            t = next((t for t in self.catalog if app and (t.key == app.app_id or t.name.split(" (")[0].lower() == app.name.lower())), None)
            if t: f = self._rec(t); f.users.add(g["user"]); f.sources.add("sign-in provider grant"); f.scopes |= set(g.get("scopes", []))

    def from_devices(self, reports):
        for d, rep in reports.items():
            for p in rep.get("software", {}):
                t = next((t for t in self.catalog if p in t.products), None)
                if t: f = self._rec(t); f.devices.add(d); f.sources.add("installed on a device")

    # ---- decisions by people ----
    def sanction(self, principal, key, tier):
        if principal.role not in ("it_admin", "owner"): raise PermissionError("Approving an AI tool needs it_admin or owner")
        if tier not in TIERS: raise ValueError(f"tier must be one of {TIERS}")
        t = next((t for t in self.catalog if t.key == key), None)
        if not t: raise KeyError(key)
        if tier == "enterprise" and not (t.enterprise_tier and t.trains_on_inputs is False):
            raise ValueError(f"{t.name} cannot be the enterprise tier: the record must show an enterprise agreement and 'does not train on inputs' (attested by the customer)")
        self.sanctioned[key] = tier; self._rec(t); self._log("lumen.tool_sanctioned", key, {"tool": key, "tier": tier, "by": principal.id})

    def unsanction(self, principal, key):
        if principal.role not in ("it_admin", "owner"): raise PermissionError("Withdrawing approval of an AI tool needs it_admin or owner")
        self.sanctioned.pop(key, None); t = next(t for t in self.catalog if t.key == key); self._rec(t); self._log("lumen.tool_unsanctioned", key, {"tool": key, "by": principal.id})

    # ---- the list ----
    def rate(self, f: Found):
        why, pts = [], 0
        if f.state == "shadow": pts += 2; why.append("not approved by IT")
        t = f.tool
        if t.trains_on_inputs is True: pts += 2; why.append("customer record says the vendor trains on inputs")
        elif t.trains_on_inputs is None: pts += 1; why.append("whether the vendor trains on inputs is unknown")
        if t.retention_days is None: pts += 1; why.append("how long the vendor keeps inputs is unknown")
        if f.uploaded_bytes > 20 << 20: pts += 1; why.append(f"{f.uploaded_bytes >> 20} MB sent")
        if len(f.users) >= 5 and f.state == "shadow": pts += 1; why.append(f"{len(f.users)} people use it")
        return {"rating": "high" if pts >= 5 else "medium" if pts >= 3 else "low", "reasons": why or ["nothing notable"]}

    def report(self):
        out = [{"key": f.tool.key, "name": f.tool.name, "kind": f.tool.kind, "state": f.state, "tier": f.tier, "users": len(f.users), "devices": len(f.devices), "sent_mb": round(f.uploaded_bytes / (1 << 20), 1),
                "sources": sorted(f.sources), **self.rate(f)} for f in self.found.values()]
        return sorted(out, key=lambda x: (x["state"] != "shadow", {"high": 0, "medium": 1, "low": 2}[x["rating"]], x["key"]))

    def dlp_map(self):
        """Domain -> class table the devices use offline. Unknown AI domains are never listed here: a device treats an AI domain it does not know as shadow."""
        m = {}
        for t in self.catalog:
            cls = {"enterprise": "ai_enterprise", "standard": "ai_standard"}.get(self.sanctioned.get(t.key), "ai_shadow")
            for d in t.domains: m[d] = cls
        return m
