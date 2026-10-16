"""Cases: findings from different sources grouped around the same person, with an honest score (F030, F031, F020/F021 in spirit).

Grouping is by the assurance graph: a cloud account, a directory account, the person who owns them and the devices they use
are one neighbourhood. Findings in one neighbourhood within a time window become one case.

Scoring (a documented heuristic, NOT a calibrated probability):
  confidence = 1 - product(1 - c) over distinct (source, family) groups, using the highest c in each group.
               Two independent sources agreeing is worth more than one detector repeating itself.
  impact     = highest factor among involved assets: crown_jewel 1.0, high 0.85, normal 0.7, low 0.5; privileged accounts count as high.
  priority   = confidence x impact, used only to order work. Both numbers and the reasoning are shown.
"""
import time
from collections import deque
from dataclasses import dataclass, field

IMPACT = {"crown_jewel": 1.0, "high": 0.85, "normal": 0.7, "low": 0.5, None: 0.7}
REL = {"acts_for", "uses"}


@dataclass
class CaseFinding:
    id: str
    source: str                  # signet | ward
    family: str
    entity_id: str               # graph entity
    confidence: float
    summary: str
    why: str
    ts: float
    technique: str | None = None
    details: dict = field(default_factory=dict)


@dataclass
class Case:
    id: str
    findings: list = field(default_factory=list)
    entities: set = field(default_factory=set)
    status: str = "open"                     # open | contained | recovering | closed
    opened_at: float = 0.0
    updated_at: float = 0.0
    actions: list = field(default_factory=list)      # (ts, what, status, detail)
    pending: list = field(default_factory=list)      # things a human must do
    notes: list = field(default_factory=list)
    campaigns: set = field(default_factory=set)       # one campaign hitting several people is one story (F021)


class CaseEngine:
    def __init__(self, store, ctx, clock, audit=None, window_s=4 * 3600, reach=None):
        self.store, self.ctx, self.clock, self.audit, self.window = store, ctx, clock, audit, window_s
        self.reach = reach          # callable(identity_entity_id) -> list of access paths to crown jewels (Signet.access_paths)
        self.cases, self._n = {}, 0

    # ---------- graph neighbourhood ----------
    def shared_devices(self):
        """Devices that two or more different people use (a jump box, a kiosk). They are where people meet, not a reason to treat those people as one story."""
        kinds = {e["entity_id"]: e["kind"] for e in self.store.entities(self.ctx)}; users = {}
        for s, r, d, _ in self.store.edges(self.ctx):
            if r in REL and kinds.get(s) == "person" and kinds.get(d) == "device": users.setdefault(d, set()).add(s)
        return {d for d, u in users.items() if len(u) >= 2}

    def related(self, entity_id, depth=3):
        adj = {}
        for s, r, d, _ in self.store.edges(self.ctx):
            if r in REL: adj.setdefault(s, set()).add(d); adj.setdefault(d, set()).add(s)
        shared = self.shared_devices()
        seen, q = {entity_id}, deque([(entity_id, 0)])
        while q:
            n, k = q.popleft()
            if k >= depth or n in shared: continue          # the walk never continues through a shared device
            for m in adj.get(n, ()):
                if m not in seen: seen.add(m); q.append((m, k + 1))
        return seen

    # ---------- grouping ----------
    def add(self, f: CaseFinding) -> Case:
        hood = self.related(f.entity_id)
        camp = f.details.get("campaign")
        shared = self.shared_devices(); key = (hood - shared) | {f.entity_id}      # a shared device only joins findings that are directly about that device
        def case_key(c): return (c.entities - shared) | {x.entity_id for x in c.findings}
        hits = [c for c in self.cases.values() if c.status != "closed" and f.ts - c.updated_at <= self.window and (case_key(c) & key or (camp and camp in c.campaigns))]
        if not hits:
            self._n += 1; c = Case(f"C-{self._n}", opened_at=f.ts); self.cases[c.id] = c
        else:
            c = hits[0]
            for other in hits[1:]:       # one finding can join two cases: merge them
                c.findings += other.findings; c.entities |= other.entities; c.actions += other.actions; c.campaigns |= other.campaigns; del self.cases[other.id]
        if all(x.id != f.id for x in c.findings): c.findings.append(f)
        c.entities |= hood; c.updated_at = max(c.updated_at, f.ts)
        if camp: c.campaigns.add(camp)
        c.findings.sort(key=lambda x: x.ts)
        try: self.store.set_finding_case(self.ctx, f.id, c.id)
        except Exception: pass
        if self.audit:
            conf, _ = self.confidence(c)
            self.audit.append("case.updated", "halvard:cases", "system", c.id, {"finding": f.id, "source": f.source, "family": f.family, "confidence": conf, "findings": len(c.findings)}, controls=("CASES.GROUPING",))
        return c

    # ---------- score ----------
    def confidence(self, c: Case):
        groups = {}
        for f in c.findings: groups[(f.source, f.family)] = max(groups.get((f.source, f.family), 0), f.confidence)
        p = 1.0
        for v in groups.values(): p *= (1 - v)
        conf = round(min(0.99, 1 - p), 2)
        parts = ", ".join(f"{src}/{fam} {v:.2f}" for (src, fam), v in sorted(groups.items()))
        return conf, (f"{len(groups)} independent group(s): {parts}. Combined as 1 - product(1 - c). Heuristic, not a calibrated probability.")

    def impact(self, c: Case):
        ents = {e["entity_id"]: e for e in self.store.entities(self.ctx)}; best, why = 0.0, "no asset information"
        # Weigh what was actually touched, not everyone who merely received a message: people whose device, account or mailbox shows a finding
        # beyond "a harmful message arrived".
        scope = self._focus_scope(c)
        for eid in sorted(c.entities & scope, key=lambda i: (ents.get(i, {}).get("kind") != "data_store", i)):          # what the data is comes before who can reach it
            e = ents.get(eid)
            if not e: continue
            crit = e["criticality"] or ("high" if e["asset_class"] == "privileged" else None)
            if IMPACT[crit] > best: best, why = IMPACT[crit], f"{e['display_name']} is {crit or 'normal'}" + (" (privileged account)" if e["asset_class"] == "privileged" else "")
            sens = e["sensitivity"] or e["suggested_sensitivity"]
            if e["kind"] == "data_store" and sens in ("regulated", "confidential") and {"regulated": 1.0, "confidential": 0.85}[sens] > best:
                best, why = {"regulated": 1.0, "confidential": 0.85}[sens], f"{e['display_name']} holds {sens} data" + ("" if e["sensitivity"] else " (Halvard's suggestion)")
            if self.reach and e["kind"] == "identity" and e["attrs"].get("type") in ("user", "service"):
                paths = self.reach(eid)
                if paths and IMPACT["crown_jewel"] > best:
                    target = paths[0].split(" ")[-1]; best, why = IMPACT["crown_jewel"], f"{e['display_name']} can reach {ents[target]['display_name'] if target in ents else target} (marked crown jewel)"
        return (best or IMPACT[None]), why

    def priority(self, c: Case):
        conf, _ = self.confidence(c); imp, _ = self.impact(c); return round(conf * imp, 2)

    # ---------- narrative ----------
    def story(self, c: Case):
        t0 = c.findings[0].ts if c.findings else 0; out, seen = [], {}
        for f in c.findings:
            key = (f.source, f.summary)
            if key in seen: out[seen[key]][1] += 1; continue
            seen[key] = len(out); out.append([f"+{int((f.ts - t0) // 60)} min  [{ {'ward': 'device', 'courier': 'mail', 'aws': 'cloud', 'lumen': 'AI agent', 'hearth': 'tripwire', 'harbor': 'network'}.get(f.source, 'identity') }] {f.summary}", 1])
        return [t + (f" (seen {n} times)" if n > 1 else "") for t, n in out]

    def _focus_scope(self, c: Case):
        quiet = {"malicious_mail", "suspicious_mail"}
        focus = {f.entity_id for f in c.findings if not (f.source == "courier" and f.details.get("detector") in quiet)}
        return set().union(*[self.related(x) for x in focus]) if focus else set(c.entities)

    def names(self, c: Case):
        """kind -> display names, with those that merely received a harmful message marked separately from those with a real finding."""
        ents = {e["entity_id"]: e for e in self.store.entities(self.ctx)}; scope = self._focus_scope(c)
        out = {}
        for k in ("person", "identity", "device", "mailbox"):
            ids = [i for i in sorted(c.entities) if i in ents and ents[i]["kind"] == k]
            out[k] = [ents[i]["display_name"] + ("" if i in scope else " (only received it)") for i in ids]
        return out

    def owners(self, c: Case):
        ents = {e["entity_id"]: e for e in self.store.entities(self.ctx)}
        return sorted({ents[s]["display_name"] for s, r, d, _ in self.store.edges(self.ctx, "owns") if d in c.entities and s in ents})

    def page(self, c: Case):
        conf, why = self.confidence(c); imp, imp_why = self.impact(c); n = self.names(c)
        L = [f"Case {c.id}: {c.findings[0].summary if c.findings else 'no findings'}", f"Status: {c.status}", "",
             "WHAT IS HAPPENING"] + ["  " + s for s in self.story(c)] + [f"  Confidence {conf:.2f}. {why}", "",
             "WHO AND WHAT IS INVOLVED",
             f"  People: {', '.join(n['person']) or 'none'}", f"  Accounts: {', '.join(n['identity']) or 'none'}", f"  Devices: {', '.join(n['device']) or 'none'}", f"  Mailboxes: {', '.join(n['mailbox']) or 'none'}", *([f"  Owner (from the resource's tag): {', '.join(self.owners(c))}"] if self.owners(c) else []), "",
             "WHAT HALVARD ALREADY DID"] + (["  " + f"{what}: {status}. {detail}" for _, what, status, detail in c.actions] or ["  Nothing yet."]) + ["", "WHAT NEEDS A PERSON"]
        L += ["  " + p for p in c.pending] or ["  Nothing urgent."]
        L += ["", "BUSINESS IMPACT", f"  Impact weight {imp:.2f} ({imp_why}). Priority {self.priority(c):.2f} (confidence x impact; used only to order work)."]
        return "\n".join(L)


def ward_hit_to_finding(device_id, hit, i=0):
    """A Ward custom detection or bulk-encryption incident as a case finding."""
    fam = "credential_theft" if any(t in ("T1539", "T1555", "T1003", "T1552.001") for t in hit.get("techniques", [])) else "endpoint_activity"
    return CaseFinding(f"W-{hit['rule_id']}-{hit['event']['ts']:.0f}-{i}", "ward", fam, device_id, hit["confidence"],
                       f"{hit['name']} on {device_id}", f"rule {hit['rule_id']} v{hit['version']} (confidence is author-set)", hit["event"]["ts"],
                       (hit.get("techniques") or [None])[0], {"rule": hit["rule_id"]})
