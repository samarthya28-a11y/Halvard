"""Courier service: mail events -> verdicts -> findings, exposure reports, retro-hunt to find where an attachment landed (F063-F066, F069-F070).

Privacy: bodies are read in memory to analyse and never stored. Records keep ids, hashes, the sender address and domain, link hosts,
the verdict and its reasons. The audit record never holds a subject or body. A service-desk listing shows sender, time, reasons and
the first 40 characters of the subject so a person can recognise the message; that text is not written anywhere by Halvard.
"""
import hashlib, re
from dataclasses import dataclass, field

from ..signet.detectors import Finding
from ..ledger.audit import opaque
from . import analysis
from .analysis import AttachmentAnalyzer, LinkAnalyzer, Intel, ReferenceWeb, BRANDS
from .auth import DomainAuthMonitor
from .impersonation import ImpersonationDetector

SENSITIVE_WORDS = ("invoice", "payment", "bank", "wire", "security", "password", "mfa", "verification", "remittance")


def mbx_id(addr): return f"mbx:{addr}"


@dataclass
class MsgRecord:
    mailbox: str
    msg_id: str
    sender: str
    sender_domain: str
    delivered_at: float
    verdict: str = "allow"
    score: float = 0.0
    reasons: list = field(default_factory=list)
    attachment_hashes: list = field(default_factory=list)
    link_hosts: list = field(default_factory=list)
    campaign: str = ""
    verdict_at: float = 0.0
    subject_hint: str = ""        # first 40 characters, held in memory only for the service-desk view
    evidence: list = field(default_factory=list)
    auto_quarantined: bool = False


class CourierService:
    def __init__(self, store, ctx, clock, mail, hr, intel, web, own_domains, partner_domains=(), events=None, audit=None, dns=None, supplier_ibans=None, ip_flagged=None):
        self.store, self.ctx, self.clock, self.mail, self.hr, self.intel, self.events, self.audit = store, ctx, clock, mail, hr, intel, events, audit
        self.own, self.partners = {d.lower() for d in own_domains}, {d.lower() for d in partner_domains}
        self.att = AttachmentAnalyzer(intel); self.links = LinkAnalyzer(intel, web, self.own | self.partners)
        self.imp = ImpersonationDetector(hr, self.own, self.partners, supplier_ibans)
        from .auth import ReferenceDNS
        self.dmarc = DomainAuthMonitor(self.own, dns or ReferenceDNS())
        self.records, self.cursor, self.findings, self._n = {}, 0, [], 0
        self.ip_flagged = ip_flagged or (lambda ip: False)
        self.reported = []; self.last_content_score = 0.0

    # ---------------- graph ----------------
    def sync_graph(self):
        now = self.clock.now()
        for addr, mb in self.mail.mailboxes.items():
            self.store.put_entity(self.ctx, mbx_id(addr), "mailbox", addr, now, attrs={"owner": mb.owner_upn})
            r = self.hr.by_upn(mb.owner_upn) if mb.owner_upn else None
            if r: self.store.put_edge(self.ctx, mbx_id(addr), "acts_for", r.person, now)

    # ---------------- findings ----------------
    def _f(self, ts, detector, family, entity, technique, conf, why, summary, evidence, **details):
        self._n += 1
        f = Finding(f"F-{detector}-{self._n}", detector, family, entity, technique, round(conf, 2), why, summary, evidence, ts, "mail", details)
        self.findings.append(f)
        if self.audit:
            self.audit.append("courier.finding", "halvard:courier", "system", opaque(entity), {"detector": detector, "technique": technique, "confidence": f.confidence, "why": why, "campaign": details.get("campaign"), "email": entity},
                              controls=("COURIER.DETECTION",))
        return f

    # ---------------- analysis ----------------
    @staticmethod
    def campaign_key(msg, att_hashes):
        if att_hashes: return att_hashes[0]
        norm = re.sub(r"\d+", "#", msg.subject.lower())
        return "c:" + hashlib.sha256(f"{msg.sender_domain}|{norm}".encode()).hexdigest()[:16]

    def analyze_message(self, msg, mailbox):
        comps, reasons, ev = [], [], "static"
        hashes, hosts = [], []
        for a in msg.attachments:
            v = self.att.analyze(a.name, a.data); hashes.append(a.sha256)
            if v.score >= 0.4: comps.append(("attachment", v.score)); reasons += [f"attachment {a.sha256[:8]}: {r}" for r in v.reasons]
        for text, href in msg.links:
            v = self.links.analyze(text, href); hosts.append(v.indicators.get("host", ""))
            if v.score >= 0.4: comps.append(("link", v.score)); reasons += [f"link {v.indicators.get('host')}: {r}" for r in v.reasons]; ev = v.evidence
        sigs = self.imp.analyze(msg, mailbox)
        for s in sigs: comps.append(("sender", s.confidence)); reasons.append(s.why)
        score = max([c[1] for c in comps] or [0.0])
        if len({c[0] for c in comps}) > 1: score = min(0.99, score + 0.05)          # independent kinds of evidence agreeing
        decision = "malicious" if score >= 0.85 else "suspicious" if score >= 0.4 else "allow"
        self.last_content_score = max([c[1] for c in comps if c[0] in ("attachment", "link")] or [0.0])        # how harmful the CONTENT is, apart from who sent it
        return decision, round(score, 2), reasons, hashes, hosts, sigs, ev

    def _record(self, mailbox, msg, ts):
        dec, score, reasons, hashes, hosts, sigs, ev = self.analyze_message(msg, mailbox)
        rec = MsgRecord(mailbox, msg.id, msg.sender, msg.sender_domain, ts, dec, score, reasons, hashes, hosts, self.campaign_key(msg, hashes), self.clock.now(), msg.subject[:40], [ev])
        self.records[(mailbox, msg.id)] = rec; self.imp.remember(mailbox, msg.sender); self.dmarc.ingest(msg)
        return rec, sigs

    # ---------------- polling ----------------
    def poll(self):
        out = []
        evs, self.cursor = self.mail.events_since(self.cursor)
        for e in evs:
            k = e["kind"]
            if k == "delivered": out += self._on_delivered(e)
            elif k == "attachment_open": out += self._on_open(e)
            elif k == "link_click": out += self._on_click(e)
            elif k in ("rule_create", "forwarding_set", "delegate_add"): out += self._on_tamper(e)
            elif k == "user_report": out += self._on_report(e)
        return out

    def _on_delivered(self, e):
        msg = self.mail.messages[e["msg_id"]]; rec, sigs = self._record(e["mailbox"], msg, e["delivered_at"]); out = []
        ent = mbx_id(e["mailbox"]); ref = [f"mail:{msg.id}"]
        if rec.verdict == "malicious" and self.last_content_score >= 0.85:          # a harmful attachment or link; sender-only fraud is reported as impersonation
            out.append(self._f(e["delivered_at"], "malicious_mail", "malicious_mail", ent, "T1566.001" if rec.attachment_hashes else "T1566.002", rec.score,
                               "; ".join(rec.reasons[:3]), f"A harmful message from {msg.sender} was delivered to {e['mailbox']}.", ref, campaign=rec.campaign, msg_id=msg.id, sender=msg.sender))
        elif rec.verdict == "suspicious" and not sigs:
            out.append(self._f(e["delivered_at"], "suspicious_mail", "suspicious_mail", ent, "T1566", rec.score, "; ".join(rec.reasons[:3]), f"A suspicious message from {msg.sender} reached {e['mailbox']}.", ref, campaign=rec.campaign, msg_id=msg.id))
        for s in sigs:
            out.append(self._f(e["delivered_at"], s.kind, "impersonation", ent, s.technique, s.confidence, s.why, s.summary, ref, campaign=rec.campaign, msg_id=msg.id, sender=msg.sender))
        return out

    def _device_entity(self, device_id):
        return device_id if device_id and device_id in {x["entity_id"] for x in self.store.entities(self.ctx)} else None

    def _on_open(self, e):
        rec = self.records.get((e["mailbox"], e["msg_id"]))
        if not rec or rec.verdict != "malicious": return []
        out = [self._f(e["ts"], "opened_malicious_attachment", "malicious_mail", mbx_id(e["mailbox"]), "T1204.002", min(0.99, rec.score + 0.05), "the recipient opened an attachment judged harmful", f"{e['mailbox']} opened the harmful attachment {e['name']}.", [f"mail:{e['msg_id']}"], campaign=rec.campaign, device=e.get("device_id"))]
        dev = self._device_entity(e.get("device_id"))
        if dev: out.append(self._f(e["ts"], "malicious_attachment_on_device", "malicious_mail", dev, "T1204.002", min(0.99, rec.score + 0.05), "the mail client reports the attachment was opened on this device", f"The harmful attachment was opened on {dev}.", [f"mail:{e['msg_id']}"], campaign=rec.campaign))
        return out

    def _on_click(self, e):
        rec = self.records.get((e["mailbox"], e["msg_id"]))
        if not rec or rec.verdict not in ("malicious", "suspicious") or not rec.link_hosts: return []
        return [self._f(e["ts"], "clicked_harmful_link", "credential_phish", mbx_id(e["mailbox"]), "T1204.001", min(0.95, rec.score), "the recipient clicked a link judged harmful", f"{e['mailbox']} clicked a link to {rec.link_hosts[0]}, which looks like a sign-in trap.", [f"mail:{e['msg_id']}"], campaign=rec.campaign, device=e.get("device_id"))]

    def _on_tamper(self, e):
        ent, ts, out = mbx_id(e["mailbox"]), e["ts"], []
        flagged = bool(e.get("ip") and self.ip_flagged(e["ip"])); why_extra = "; created from an address already flagged for attacking this account" if flagged else ""
        if e["kind"] == "forwarding_set" and e["external"]:
            out.append(self._f(ts, "external_forwarding", "mailbox_tampering", ent, "T1114.003", 0.95 if flagged else 0.8, "all mail is being copied to an outside address" + why_extra, f"{e['mailbox']} now forwards every message to {e['to']}.", [f"mail:{e['kind']}"], to=e["to"], ip=e.get("ip")))
        elif e["kind"] == "rule_create":
            w, t = e["when"], e["then"]; ext = t.get("forward_to") and t["forward_to"].rsplit("@", 1)[-1].lower() not in self.own
            hides = (t.get("delete") or t.get("move_to") or t.get("mark_read")) and any(k in SENSITIVE_WORDS for k in [x.lower() for x in w.get("subject_contains", [])])
            if ext: out.append(self._f(ts, "forwarding_rule", "mailbox_tampering", ent, "T1114.003", 0.95 if flagged else 0.8, f"a rule forwards matching mail to {t['forward_to']}" + why_extra, f"A rule on {e['mailbox']} sends copies of mail to {t['forward_to']}.", [f"mail:{e['rule']}"], rule=e["rule"], ip=e.get("ip")))
            if hides: out.append(self._f(ts, "hiding_rule", "mailbox_tampering", ent, "T1564.008", 0.9 if flagged else 0.75, "a rule hides mail about " + ", ".join(w["subject_contains"]) + " from the owner" + why_extra, f"A rule on {e['mailbox']} hides messages about {', '.join(w['subject_contains'])}.", [f"mail:{e['rule']}"], rule=e["rule"], ip=e.get("ip")))
        elif e["kind"] == "delegate_add" and e["delegate"].rsplit("@", 1)[-1].lower() not in self.own:
            out.append(self._f(ts, "outside_delegate", "mailbox_tampering", ent, "T1114.003", 0.7, "an outside address was given access to the mailbox", f"{e['delegate']} was given access to {e['mailbox']}.", [f"mail:{e['kind']}"]))
        return out

    def _on_report(self, e):
        self.reported.append((e["mailbox"], e["msg_id"])); rec = self.records.get((e["mailbox"], e["msg_id"]))
        if rec and rec.verdict != "allow":
            return [self._f(e["ts"], "user_reported", rec.verdict == "malicious" and "malicious_mail" or "suspicious_mail", mbx_id(e["mailbox"]), "T1566", max(rec.score, 0.5), "reported by the recipient, and Halvard's own checks agree: " + "; ".join(rec.reasons[:2]), f"{e['mailbox']} reported a message that Halvard also finds suspicious.", [f"mail:{e['msg_id']}"], campaign=rec.campaign)]
        return []

    # ---------------- delayed verdicts ----------------
    def rescan(self):
        """Intel changed (a new bad hash, a domain on a block list): re-judge what was delivered. Returns findings for messages that turned malicious."""
        out = []
        for (mbx, mid), rec in list(self.records.items()):
            if rec.verdict == "malicious": continue
            msg = self.mail.messages.get(mid)
            if not msg: continue
            dec, score, reasons, hashes, hosts, sigs, ev = self.analyze_message(msg, mbx)
            if dec == "malicious":
                rec.verdict, rec.score, rec.reasons, rec.verdict_at = dec, score, reasons, self.clock.now()
                if self.last_content_score < 0.85: continue
                out.append(self._f(self.clock.now(), "malicious_mail", "malicious_mail", mbx_id(mbx), "T1566.001" if hashes else "T1566.002", score, "; ".join(reasons[:3]) + " (verdict changed after delivery)",
                                   f"A message delivered to {mbx} {int((self.clock.now() - rec.delivered_at) // 60)} minutes ago is now known to be harmful.", [f"mail:{mid}"], campaign=rec.campaign, msg_id=mid, delayed=True, exposure_s=int(self.clock.now() - rec.delivered_at)))
        return out

    # ---------------- exposure and landing ----------------
    def exposure(self, key):
        rows = []
        for a, mid, folder in self.mail.copies(key):
            st = sorted(self.mail.mailboxes[a].state.get(mid, set())); rows.append({"mailbox": a, "msg_id": mid, "folder": folder, "state": st,
                       "at_risk": bool(set(st) & {"attachment_opened", "clicked", "replied", "forwarded"})})
        return rows

    def landings(self, sha256, since=0.0):
        """Retro-hunt: where did a file with this hash appear on a device? (needs the telemetry store)"""
        if not self.events: return []
        from ..hunt import ql
        rows, _ = self.events.query_rows(self.ctx, ql.parse(f'file_sha256="{sha256}"').ast, since, include_cold=True)
        return [{"device": r["device"], "path": r["path"], "ts": r["ts"], "proc": r["proc"]} for r in rows]

    # ---------------- service-desk view (F070) ----------------
    def quarantined_for(self, mailbox):
        out = []
        for mid in self.mail.mailboxes[mailbox].folders["quarantine"]:
            rec = self.records.get((mailbox, mid))
            out.append({"msg_id": mid, "sender": rec.sender if rec else self.mail.messages[mid].sender, "when": rec.delivered_at if rec else None, "verdict": rec.verdict if rec else "unknown",
                        "why": rec.reasons[:3] if rec else [], "subject_hint": rec.subject_hint if rec else "", "needs_analyst": bool(rec and rec.verdict == "malicious")})
        return out
