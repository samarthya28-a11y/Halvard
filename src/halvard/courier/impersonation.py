"""Impersonation and payment-fraud detection (F064). Header and wording facts only; a verdict never rests on one weak clue.

Signals: display name of a known executive or colleague on an outside address; a sender domain that imitates the company's or a
partner's; Reply-To pointing somewhere else; failed authentication while claiming the company's own domain; first contact from
that sender; payment wording; and a bank account that differs from the one on file for that supplier (compared by hash).
"""
import hashlib, re
from dataclasses import dataclass, field

from .analysis import lookalike_of

PAYMENT = re.compile(r"\b(wire transfer|bank details|new bank account|updated? (?:our )?(?:bank|payment)|change(?:d)? (?:of )?(?:bank|account)|urgent payment|gift cards?|payment (?:is )?overdue|invoice attached|iban)\b", re.I)
IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
URGENCY = re.compile(r"\b(urgent|immediately|asap|today|confidential|do not tell|don't tell|before (?:noon|close of business))\b", re.I)


def iban_hash(s): return hashlib.sha256(re.sub(r"\s", "", s).upper().encode()).hexdigest()


@dataclass
class Signal:
    kind: str
    confidence: float
    why: str
    summary: str
    technique: str = "T1566"   # phishing; payment fraud has no clean ATT&CK id
    details: dict = field(default_factory=dict)


class ImpersonationDetector:
    def __init__(self, hr, own_domains, partner_domains=(), supplier_ibans=None, vip_names=()):
        self.hr, self.own, self.partners = hr, {d.lower() for d in own_domains}, {d.lower() for d in partner_domains}
        self.supplier_ibans = supplier_ibans or {}        # supplier domain -> set(iban hashes)
        self.vip_names = {n.lower() for n in vip_names}
        self.seen = {}                                     # recipient -> set(sender addresses) already contacted before
        self.trusted = self.own | self.partners

    @property
    def names(self):
        """Read from HR every time: people join and leave, and a snapshot taken at start-up goes stale."""
        return {r.name.lower() for r in self.hr.records.values()} | self.vip_names

    def remember(self, recipient, sender): self.seen.setdefault(recipient, set()).add(sender.lower())

    def analyze(self, msg, recipient):
        out, dom = [], msg.sender_domain
        first_time = msg.sender.lower() not in self.seen.get(recipient, set())
        outside = dom not in self.own and not any(dom.endswith("." + o) for o in self.own)
        text = f"{msg.subject}\n{msg.body}"; pay = bool(PAYMENT.search(text)); urgent = bool(URGENCY.search(text))
        spoof_name = outside and msg.display_name.lower() in self.names and dom not in self.partners
        look = lookalike_of(dom, self.own | self.partners)
        reply_diff = bool(msg.reply_to and msg.reply_to.rsplit("@", 1)[-1].lower() != dom)
        claims_own_failed = (dom in self.own) and msg.auth.get("dmarc") != "pass"
        if claims_own_failed:
            out.append(Signal("spoofed_own_domain", 0.9, f"the message says it is from {dom} but failed sender checks (SPF {msg.auth['spf']}, DKIM {msg.auth['dkim']}, DMARC {msg.auth['dmarc']})",
                              f"Someone is sending mail pretending to be {msg.sender}.", "T1566", {"auth": msg.auth}))
        if look:
            c = 0.85 + (0.05 if pay else 0) + (0.03 if reply_diff else 0)
            out.append(Signal("lookalike_domain", min(c, 0.95), f"{dom} imitates {look}" + ("; the text asks for a payment" if pay else "") + ("; replies go to a different address" if reply_diff else ""),
                              f"The sender's address {msg.sender} imitates {look}.", "T1566", {"imitates": look}))
        if spoof_name:
            c = 0.75 + (0.1 if reply_diff else 0) + (0.05 if urgent else 0) + (0.05 if pay else 0)
            out.append(Signal("display_name_spoof", min(c, 0.95), "the display name is a known colleague's, but the address is outside the company" + ("; replies go elsewhere" if reply_diff else "") + ("; urgent wording" if urgent else ""),
                              f"A message uses {msg.display_name}'s name from an outside address.", "T1566", {"name": msg.display_name}))
        ibans = {iban_hash(m) for m in IBAN.findall(msg.body.replace(" ", "")) } | {iban_hash(m) for m in IBAN.findall(msg.body)}
        known = self.supplier_ibans.get(dom)
        if pay and ibans:
            if known is not None and not (ibans & known):
                out.append(Signal("bank_details_changed", 0.95, f"the message gives a bank account that is not the one on file for {dom}", f"{dom} asks to pay a bank account we have never paid.", "T1566", {"supplier": dom}))
            elif known is None and (first_time or look or spoof_name):
                out.append(Signal("payment_request_unknown_account", 0.7, "a payment request with bank details from a sender we have no account on file for", "A first-time sender asks for a payment to new bank details.", "T1566", {}))
        if pay and first_time and not out and dom not in self.partners:
            out.append(Signal("payment_wording_first_contact", 0.45, "payment wording from a sender this person has not heard from before", "A first-time sender is asking about a payment.", "T1566", {}))
        if reply_diff and first_time and not out and urgent:
            out.append(Signal("reply_to_mismatch", 0.5, "urgent message whose replies would go to a different address than it came from", "Replies to this message would go to a different address.", "T1566", {}))
        return out
