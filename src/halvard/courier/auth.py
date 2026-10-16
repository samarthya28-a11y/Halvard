"""Sender authentication monitoring (F069): what the world sees of the company's domain, and who is imitating it.

Two views. (1) Inbound: authentication results seen on mail, grouped by sending domain, plus spoofing attempts against the
company's own domain. (2) Posture: the company's published SPF/DKIM/DMARC records, read from DNS (a model here), with a staged path
from monitoring to enforcement; moving to reject before the company's own mail is aligned would block its own invoices.
"""
import re
from collections import Counter, defaultdict
from dataclasses import dataclass


class ReferenceDNS:
    def __init__(self, records=None): self.records = records or {}       # name -> list of TXT strings
    def txt(self, name): return list(self.records.get(name.lower(), []))


@dataclass
class DomainFinding:
    domain: str
    severity: str
    summary: str
    action: str


def spf_lookups(dns, record, depth=0):
    """Count DNS lookups SPF would make (limit is 10). Includes are followed in the model."""
    n = 0
    for term in record.split()[1:]:
        t = term.lstrip("+-~?")
        if t.startswith("include:"):
            n += 1
            if depth < 5:
                for r in dns.txt(t[8:]):
                    if r.startswith("v=spf1"): n += spf_lookups(dns, r, depth + 1)
        elif t.startswith(("a", "mx", "ptr", "exists:", "redirect=")): n += 1
    return n


class DomainAuthMonitor:
    def __init__(self, own_domains, dns: ReferenceDNS):
        self.own, self.dns = [d.lower() for d in own_domains], dns
        self.by_domain = defaultdict(Counter); self.spoof_attempts = []

    def ingest(self, msg):
        d = msg.sender_domain
        for k in ("spf", "dkim", "dmarc"): self.by_domain[d][f"{k}_{msg.auth.get(k, 'none')}"] += 1
        self.by_domain[d]["total"] += 1
        if d in self.own and msg.auth.get("dmarc") != "pass": self.spoof_attempts.append((msg.ts, msg.sender, msg.id))

    def alignment(self, domain):
        c = self.by_domain.get(domain, Counter()); t = c["total"] or 1
        return {"messages": c["total"], "dmarc_pass_rate": round(c["dmarc_pass"] / t, 2), "spf_pass_rate": round(c["spf_pass"] / t, 2), "dkim_pass_rate": round(c["dkim_pass"] / t, 2)}

    def posture(self, dkim_selectors=()):
        out = []
        for d in self.own:
            spf = next((r for r in self.dns.txt(d) if r.startswith("v=spf1")), None)
            if not spf: out.append(DomainFinding(d, "high", f"{d} publishes no SPF record, so anyone can claim to send for it without a check.", "Publish an SPF record listing your real senders."))
            else:
                end = spf.split()[-1]
                if end in ("+all", "all"): out.append(DomainFinding(d, "high", f"{d}'s SPF record allows every sender ({end}).", "Change the ending to -all or ~all after listing real senders."))
                elif end == "?all": out.append(DomainFinding(d, "medium", f"{d}'s SPF record says 'neutral' for everyone else (?all).", "Move to ~all, then -all."))
                n = spf_lookups(self.dns, spf)
                if n > 10: out.append(DomainFinding(d, "high", f"{d}'s SPF record needs {n} lookups; over 10 it fails and mail may be rejected.", "Flatten includes or remove unused services."))
            dm = next((r for r in self.dns.txt("_dmarc." + d) if r.startswith("v=DMARC1")), None)
            if not dm: out.append(DomainFinding(d, "high", f"{d} has no DMARC policy.", "Publish p=none with a report address, watch reports, then tighten."))
            else:
                pol = (re.search(r"\bp=(\w+)", dm) or [None, "none"])[1]; rua = "rua=" in dm
                if not rua: out.append(DomainFinding(d, "medium", f"{d}'s DMARC policy has no report address, so you cannot see who sends as you.", "Add rua=mailto:..."))
                al = self.alignment(d)
                if pol == "none": out.append(DomainFinding(d, "medium", f"{d}'s DMARC policy is p=none: spoofed mail is not stopped.", "Move to quarantine" + (f" (your own mail passes DMARC {int(al['dmarc_pass_rate'] * 100)}% of the time in what Halvard has seen)" if al["messages"] else "") + " when your own senders are aligned."))
                elif pol == "quarantine" and al["messages"] >= 20 and al["dmarc_pass_rate"] >= 0.98: out.append(DomainFinding(d, "low", f"{d} is at p=quarantine and aligned mail passes {int(al['dmarc_pass_rate'] * 100)}%.", "You can move to p=reject."))
            for sel in dkim_selectors:
                if not self.dns.txt(f"{sel}._domainkey.{d}"): out.append(DomainFinding(d, "medium", f"No DKIM key is published for selector '{sel}' on {d}.", "Publish the key or remove the selector from your sending service."))
        return out
