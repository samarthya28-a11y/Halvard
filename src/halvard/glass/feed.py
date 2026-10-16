"""Advisory feed: which product versions are affected, whether a flaw is known to be used in attacks, and how the attacker reaches it.

The reference build ships a SYNTHETIC sample (policy/advisories_sample.json, ids start HLV-SAMPLE). Halvard does not claim a vulnerability
database here. The 'exploit' field has three values the feed must supply: exploited_in_wild, public_exploit, none. Halvard never guesses it.
"""
import json
from dataclasses import dataclass
from pathlib import Path

EXPLOIT = ("none", "public_exploit", "exploited_in_wild")


def vkey(v):
    parts = []
    for p in str(v).split("."):
        digits = "".join(ch for ch in p if ch.isdigit()); parts.append(int(digits) if digits else 0)
    return tuple(parts)


@dataclass(frozen=True)
class Advisory:
    id: str
    product: str
    affected_below: str
    base_severity: float
    exploit: str
    surface: str              # network | local
    port: int | None
    summary: str
    workaround: str | None = None

    def affects(self, product, version): return product == self.product and vkey(version) < vkey(self.affected_below)


class VulnFeed:
    def __init__(self, advisories=(), synced_with_upstream=None):
        self.advisories, self.synced_with_upstream = list(advisories), synced_with_upstream
        for a in self.advisories:
            if a.exploit not in EXPLOIT: raise ValueError(f"{a.id}: exploit state must be one of {EXPLOIT}")

    @classmethod
    def load(cls, path):
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls([Advisory(x["id"], x["product"], x["affected_below"], float(x["base_severity"]), x["exploit"], x["surface"], x.get("port"), x["summary"], x.get("workaround")) for x in d["advisories"]], d.get("synced_with_upstream"))

    def matching(self, product, version): return [a for a in self.advisories if a.affects(product, version)]
    def get(self, aid): return next((a for a in self.advisories if a.id == aid), None)


def feed_from_dict(d):
    return VulnFeed([Advisory(x["id"], x["product"], x["affected_below"], float(x["base_severity"]), x["exploit"], x["surface"], x.get("port"), x["summary"], x.get("workaround")) for x in d["advisories"]], d.get("synced_with_upstream"))
