"""Hearth: tripwires the customer places in the customer's own environment (F109, F110, F111). Nothing here attacks anything.

What is placed, and the rules that keep it safe:
  * encryption tripwires and decoy files on devices: generated filler only, never over an existing file, never in an operating-system folder
  * decoy accounts and keys: they hold NO privilege (refused if they would), exist only to be tried
  * decoy shares: fake files on a share nobody has business opening
  * canary tokens: a unique address in a document or repository the customer chooses
Every placement is a recorded decision by a named IT admin. Where decoys are is sensitive (an intruder who knows avoids them), so only IT and analysts can list them.
Confidence on a touch is rule-assigned, not calibrated: nothing legitimate uses these things, so a touch is strong evidence; scanners and backups are the known exceptions and
are handled by recorded, expiring exemptions.
"""
import secrets
from dataclasses import dataclass, field

from ..cases import CaseFinding
from ..signet.service import idp_id, ad_id

ROLE_OPS = {"place": {"it_admin"}, "view": {"it_admin", "analyst"}, "mint": {"it_admin"}, "exempt": {"it_admin"}}
MAX_EXEMPT_DAYS = 90
FIND_TECH = {"encryption": "T1486", "credential_lure": "T1552.001", "decoy_file": "T1083", "decoy_account": "T1078", "decoy_key": "T1078.004", "decoy_share": "T1039", "canary": None}


@dataclass
class Decoy:
    id: str
    kind: str                # idp_user | ad_user | aws_key | share | canary
    ref: str                 # upn / sam / key id / share name / token id
    created_by: str
    created_at: float
    detail: dict = field(default_factory=dict)


class HearthService:
    def __init__(self, store, ctx, clock, audit, fleet, idp, ad, aws, fileserver, canary, push, atlas=None):
        self.store, self.ctx, self.clock, self.audit, self.fleet, self.idp, self.ad, self.aws, self.fs, self.canary, self.push, self.atlas = store, ctx, clock, audit, fleet, idp, ad, aws, fileserver, canary, push, atlas
        self.decoys, self.specs, self.exempt_procs, self.exempt_accounts = {}, {}, {}, {}
        self.cur = {"idp": 0, "ad": 0, "aws": 0, "fs": 0, "canary": 0}; self._hits_seen, self._n, self._fn, self.informational = {}, 0, 0, []

    def _log(self, kind, subject, data, controls=("HEARTH.TRIPWIRES",)):
        if self.audit: self.audit.append(kind, "halvard:hearth", "system", subject, data, controls=controls)

    def require(self, principal, op):
        if principal.role not in ROLE_OPS[op]:
            self._log("hearth.denied", principal.id, {"op": op, "role": principal.role}, ("HEARTH.AUTHORIZATION",))
            raise PermissionError(f"{op} needs one of: {', '.join(sorted(ROLE_OPS[op]))}")

    def catalog(self, principal):
        """Where the decoys are. IT and analysts only: this list is what an intruder would most like to read."""
        self.require(principal, "view")
        return {"devices": {d: [{"id": s["id"], "path": s["path"], "kind": s["kind"]} for s in v] for d, v in self.specs.items()}, "decoys": [{"id": d.id, "kind": d.kind, "ref": d.ref, "created_at": d.created_at} for d in self.decoys.values()],
                "canaries": [{"id": t.id, "label": t.label, "placed_in": t.placed_in, "limits": "fires only if opened by software that loads remote content"} for t in self.canary.tokens.values()]}

    # ---------------- device tripwires ----------------
    def set_specs(self, device, specs, replace_ids=None):
        cur = [s for s in self.specs.get(device, []) if s["id"] not in (replace_ids or [])]
        ids = {s["id"] for s in cur}
        for s in specs:
            if s["id"] in ids: raise ValueError(f"tripwire id {s['id']} already exists on {device}")
            if s["kind"] not in ("encryption", "decoy_file", "credential_lure"): raise ValueError(f"unknown tripwire kind {s['kind']}")
        self.specs[device] = cur + [dict(s) for s in specs]
        return self.push(device, self.specs[device], self.exempt_procs)

    def remove_specs(self, device, ids):
        self.specs[device] = [s for s in self.specs.get(device, []) if s["id"] not in ids]
        return self.push(device, self.specs[device], self.exempt_procs)

    def new_id(self, prefix="tw"): self._n += 1; return f"{prefix}-{self._n}"

    def exempt_process(self, principal, device, name, reason):
        self.require(principal, "exempt")
        if not reason.strip(): raise ValueError("a reason is required")
        self.exempt_procs.setdefault(device, set()).add(name)
        self._log("hearth.process_exempted", device, {"device": device, "process": name, "justification": reason, "by": principal.id})
        return self.push(device, self.specs.get(device, []), self.exempt_procs)

    # ---------------- decoy identities ----------------
    def create_decoy_identity(self, kind, name, by):
        if kind == "idp_user":
            if name in self.idp.users: raise ValueError(f"{name} already exists; a decoy never reuses a real name")
            self.idp.add_user(name, name.split("@")[0], password=secrets.token_urlsafe(18), mfa_enrolled=False); ref = name
            u = self.idp.users[name]; assert not u.roles and not u.groups
        elif kind == "ad_user":
            if name in self.ad.users: raise ValueError(f"{name} already exists; a decoy never reuses a real name")
            self.ad.add_user(name); ref = name
        elif kind == "aws_key":
            if name in self.aws.users: raise ValueError(f"{name} already exists; a decoy never reuses a real name")
            kid = "AKIA" + secrets.token_hex(8).upper()
            self.aws.add_user(name, keys=[{"id": kid, "created": self.clock.now(), "last_used": None, "active": True}]); ref = kid
            if self.atlas: self.atlas.suppressed.add(f"cloud:user:{name}")
        else: raise ValueError(f"unknown decoy kind {kind}")
        self._fn += 1; d = Decoy(f"decoy-{self._fn}", kind, ref, by, self.clock.now(), {"name": name}); self.decoys[d.id] = d
        self._log("hearth.decoy_created", d.id, {"decoy": d.id, "kind": kind, "by": by}); return d

    def remove_decoy(self, decoy_id, by):
        d = self.decoys.pop(decoy_id)
        if d.kind == "idp_user": self.idp.users.pop(d.ref, None)
        elif d.kind == "ad_user": self.ad.users.pop(d.ref, None)
        elif d.kind == "aws_key": self.aws.users.pop(d.detail["name"], None)
        elif d.kind == "share": self.fs.shares.pop(d.ref, None)
        self._log("hearth.decoy_removed", decoy_id, {"decoy": decoy_id, "kind": d.kind, "by": by})

    def lure_text(self, decoy_id):
        """The text of a credentials file that tempts an intruder: the decoy account's name and its (unused) password. Safe by construction: the account has no rights."""
        d = self.decoys[decoy_id]
        if d.kind == "idp_user": return f"# service login (legacy)\nuser={d.ref}\npassword={self.idp.users[d.ref].password}\n"
        if d.kind == "ad_user": return f"# service login (legacy)\nuser={d.ref}\n"
        if d.kind == "aws_key": return f"[backup]\naws_access_key_id={d.ref}\naws_secret_access_key={secrets.token_urlsafe(30)}\n"
        raise ValueError("only accounts and keys can be used as bait")

    # ---------------- decoy shares and canary tokens ----------------
    def create_decoy_share(self, principal, share, files):
        self.require(principal, "place")
        if share in self.fs.shares: raise ValueError(f"{share} already exists")
        self.fs.add_share(share, files); self._fn += 1; d = Decoy(f"decoy-{self._fn}", "share", share, principal.id, self.clock.now(), {"files": len(files)}); self.decoys[d.id] = d
        self._log("hearth.decoy_created", d.id, {"decoy": d.id, "kind": "share", "files": len(files), "by": principal.id}); return d

    def mint_canary(self, principal, kind, label, placed_in):
        self.require(principal, "mint")
        t = self.canary.mint(kind, label, placed_in, principal.id)
        self._log("hearth.canary_minted", t.id, {"token": t.id, "kind": kind, "placed_in": placed_in, "by": principal.id}, ("HEARTH.CANARY_TOKENS",)); return t

    def exempt_account(self, principal, account, reason, days):
        self.require(principal, "exempt")
        if not reason.strip(): raise ValueError("a reason is required")
        if not 0 < days <= MAX_EXEMPT_DAYS: raise ValueError(f"an exemption lasts at most {MAX_EXEMPT_DAYS} days")
        self.exempt_accounts[account] = self.clock.now() + days * 86400
        self._log("hearth.account_exempted", account, {"account": account, "days": days, "justification": reason, "by": principal.id}, ("HEARTH.DECOY_SHARES",))

    def _exempt(self, account): return self.exempt_accounts.get(account, 0) > self.clock.now()

    # ---------------- the alarms ----------------
    def _entity(self, *cands):
        have = {e["entity_id"] for e in self.store.entities(self.ctx)}
        return next((c for c in cands if c and c in have), None)

    def _anchor(self):
        """Where an alarm lands when it concerns no entity the graph knows (a decoy key on a cloud user that has not synced yet, a token in an unregistered repository)."""
        if not self.store.has_entity(self.ctx, "hearth:decoys"): self.store.put_entity(self.ctx, "hearth:decoys", "application", "Hearth decoys and canaries", self.clock.now(), should_be_protected=0, attrs={"type": "hearth"})
        return "hearth:decoys"

    def _f(self, kind, conf, summary, why, entities, technique, ts, details):
        self._fn += 1; out = []
        entities = [e for e in entities if e] or [self._anchor()]
        for i, e in enumerate(entities):
            out.append(CaseFinding(f"hearth-{self._fn}-{i}", "hearth", "tripwire", e, conf if i == 0 else min(conf, 0.9), summary, why, ts, technique, {"detector": kind, **details}))
        if out and self.audit:
            self.audit.append("hearth.alarm", "halvard:hearth", "system", out[0].entity_id, {"kind": kind, "confidence": conf, "technique": technique, **{k: v for k, v in details.items() if k in ("decoy", "tripwire", "op", "stopped", "token", "process", "email", "ip", "user", "path")}}, controls=("HEARTH.TRIPWIRES",))
        return out

    def poll(self):
        out, ds = [], list(self.decoys.values())
        by_kind = {k: {d.ref: d for d in ds if d.kind == k} for k in ("idp_user", "ad_user", "aws_key", "share")}
        evs, self.cur["idp"] = self.idp.events_since(self.cur["idp"])
        for ev in evs:
            d = by_kind["idp_user"].get(ev["user"])
            if d:
                dev = self._entity(ev.get("device_id"))
                out += self._f("decoy_account_used", 0.95, "Someone tried to sign in with an account that exists only as a decoy.", "No person or system is meant to use this account, so any attempt is strong evidence that someone is trying credentials they found.",
                               [e for e in (self._entity(idp_id(ev["user"])), dev) if e], FIND_TECH["decoy_account"], ev["ts"], {"decoy": d.id, "campaign": f"bait:{d.id}", "user": ev["user"], "ip": ev.get("ip"), "result": ev["result"], "device": ev.get("device_id")})
        evs, self.cur["ad"] = self.ad.events_since(self.cur["ad"])
        for ev in evs:
            d = by_kind["ad_user"].get(ev.get("account"))
            if d:
                out += self._f("decoy_account_used", 0.95, "Someone used (or tried) a directory account that exists only as a decoy.", "No person or system is meant to use this account.",
                               [e for e in (self._entity(ad_id(ev["account"])), self._entity(ev.get("workstation"))) if e], FIND_TECH["decoy_account"], ev["ts"], {"decoy": d.id, "campaign": f"bait:{d.id}", "user": ev["account"], "ip": ev.get("src_ip"), "event_id": ev["event_id"]})
        evs, self.cur["aws"] = self.aws.events_since(self.cur["aws"])
        for ev in evs:
            d = by_kind["aws_key"].get(ev.get("key"))
            if d and ev["kind"] in ("api_call", "api_call_denied"):
                out += self._f("decoy_key_used", 0.97, "A cloud access key that exists only as a decoy was used.", "The key has no permissions and no legitimate user; someone found it in a file or repository and tried it.",
                               [self._entity(f"cloud:user:{d.detail['name']}")], FIND_TECH["decoy_key"], ev["ts"], {"decoy": d.id, "campaign": f"bait:{d.id}", "ip": ev.get("ip"), "action": ev.get("action")})
        evs, self.cur["fs"] = self.fs.events_since(self.cur["fs"])
        for ev in evs:
            d = by_kind["share"].get(ev["share"])
            if d and not self._exempt(ev["account"]):
                opened = ev["kind"] == "smb_open"
                out += self._f("decoy_share_touched", 0.9 if opened else 0.5, "Someone opened a file on a decoy share." if opened else "Someone browsed a decoy share.",
                               "Nobody has business in this share. Opening a file is strong evidence; only listing it can be curiosity." , [e for e in (self._entity(ad_id(ev["account"])), self._entity(ev["workstation"])) if e],
                               FIND_TECH["decoy_share"], ev["ts"], {"decoy": d.id, "user": ev["account"], "ip": ev["src_ip"], "path": ev["path"], "op": "open" if opened else "list"})
        evs, self.cur["canary"] = self.canary.events_since(self.cur["canary"])
        for ev in evs:
            t = self.canary.tokens[ev["token"]]
            ent = self._entity(t.placed_in)
            out += self._f("canary_fetched", 0.85, f"A canary token placed in '{t.label}' was fetched.", "Something opened the file or repository and loaded its hidden link. Scanners and previewers can also do this, so confidence is not higher.", [ent], None, ev["ts"], {"token": t.id, "ip": ev["ip"], "user": ev["user_agent"][:80] if ev.get("user_agent") else ""})
        for d, a in self.fleet.agents.items():
            if a.online: a.verify_tripwires()
            seen = self._hits_seen.get(d, 0)
            for h in a.tripwire_hits[seen:]:
                if h["confidence"] < 0.5: self.informational.append((d, h)); continue
                enc = h["kind"] == "encryption"
                msg = (f"A program changed a ransomware tripwire on {d}" + (" and was stopped before real files were touched." if h["stopped"] else ".")) if enc and h["op"] in ("write", "rename", "delete", "create") else f"A tripwire file on {d} was touched ({h['op']})."
                spec = next((x for x in self.specs.get(d, []) if x["id"] == h["tripwire"]), {}); camp = {"campaign": f"bait:{spec['bait']}"} if spec.get("bait") else {}
                out += self._f("tripwire_touched", h["confidence"], msg, "Nothing legitimate uses this file." + (" Reads by backup or search programs are expected and are listed separately." if enc else ""), [d], FIND_TECH.get(h["kind"], "T1083"), h["ts"],
                               {"tripwire": h["tripwire"], "op": h["op"], "process": h["process"], "user": h["user"], "path": h["path"], "stopped": h["stopped"], "device": d, **camp})
            self._hits_seen[d] = len(a.tripwire_hits)
        return out
