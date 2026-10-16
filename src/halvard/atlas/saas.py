"""SaaS discovery and app risk rating (F081, F082).

Two honest sources: apps people have signed in to or granted access through the identity provider, and a web-proxy/DNS log the customer
feeds in (domain, user, bytes uploaded). Apps are sanctioned, personal-storage or unsanctioned, by the customer's list. The rating is a
short rubric with its reasons shown; it is not a vendor risk assessment and does not look inside the service.
"""
from collections import defaultdict
from dataclasses import dataclass, field

from ..signet.idp import HIGH_RISK_SCOPES


@dataclass
class AppRecord:
    key: str
    name: str
    state: str                     # sanctioned | personal | unsanctioned
    users: set = field(default_factory=set)
    uploaded_bytes: int = 0
    scopes: set = field(default_factory=set)
    publisher_verified: bool | None = None
    age_days: float | None = None
    sources: set = field(default_factory=set)


class SaasCatalog:
    def __init__(self, sanctioned=(), personal=()):
        self.sanctioned, self.personal = {s.lower() for s in sanctioned}, {p.lower() for p in personal}

    def state_of(self, key):
        k = key.lower()
        if any(k == s or k.endswith("." + s) for s in self.sanctioned): return "sanctioned"
        if any(k == p or k.endswith("." + p) for p in self.personal): return "personal"
        return "unsanctioned"

    def discover(self, idp=None, proxy_log=()):
        apps = {}
        def rec(key, name):
            return apps.setdefault(key, AppRecord(key, name, self.state_of(key)))
        if idp is not None:
            now = idp.clock.now()
            for g in idp.grants:
                if g["revoked"]: continue
                a = idp.apps.get(g["app"]); r = rec(g["app"], a.name if a else g["app"]); r.users.add(g["user"]); r.scopes |= set(g["scopes"]); r.sources.add("identity provider")
                if a: r.publisher_verified, r.age_days = a.publisher_verified, (now - a.created_at) / 86400
        for user, domain, up in proxy_log:
            r = rec(domain, domain); r.users.add(user); r.uploaded_bytes += up; r.sources.add("web proxy log")
        return sorted(apps.values(), key=lambda r: (r.state == "sanctioned", -len(r.users)))

    @staticmethod
    def rate(r: AppRecord):
        pts, why = 0, []
        if r.state == "unsanctioned": pts += 1; why.append("not on the approved list")
        if r.state == "personal": pts += 2; why.append("personal storage: data leaves company control")
        risky = sorted(r.scopes & HIGH_RISK_SCOPES)
        if risky: pts += 2; why.append("can " + ("read and write mail and files" if len(risky) > 1 else "access " + risky[0]) + f" ({', '.join(risky[:3])})")
        if r.publisher_verified is False: pts += 2; why.append("publisher is not verified")
        if r.age_days is not None and r.age_days < 14: pts += 1; why.append("registered less than two weeks ago")
        if r.uploaded_bytes > 50 << 20: pts += 1; why.append(f"{r.uploaded_bytes >> 20} MB uploaded")
        if len(r.users) >= 10 and r.state == "unsanctioned": pts += 1; why.append(f"{len(r.users)} people use it")
        return {"rating": "high" if pts >= 4 else "medium" if pts >= 2 else "low", "reasons": why or ["nothing notable"]}

    def dlp_map(self, extra=None):
        """The destination-class table devices use to apply upload rules offline."""
        m = {s: "sanctioned" for s in self.sanctioned}; m.update({p: "personal" for p in self.personal}); m.update(extra or {}); return m
