"""External attack surface of the company's OWN internet-facing assets (F096) and expiry warnings (F097).

Authorization: Halvard probes only addresses the customer owns. Ownership is shown one of two ways: the address belongs to the customer's own
cloud account (read from the cloud API), or it is where a domain resolves AND that domain passed a DNS ownership challenge. Anything else is
refused before a packet is sent, and the refusal is recorded. The probe is a plain connection and a banner/certificate read: no exploit, no
password guessing, no payload. The 'internet' here is a reference model (ReferenceInternet); a real scan is not performed by this build.
"""
import secrets
from dataclasses import dataclass, field

from .feed import vkey

ADMIN = {22: "SSH", 3389: "Remote Desktop", 5900: "VNC", 23: "Telnet"}
DATA = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}
PROBE_PORTS = sorted({80, 443, 8443, *ADMIN, *DATA})
CERT_WARN_DAYS = (30, 14, 7, 1)


class ScopeError(PermissionError):
    pass


class ReferenceInternet:
    """What the outside world sees. Hosts have services and certificates; domains resolve and may carry a verification TXT record."""
    def __init__(self, clock):
        self.clock, self.hosts, self.dns, self.txt, self.probes = clock, {}, {}, {}, []

    def add_host(self, ip, services=None, certs=None): self.hosts[ip] = {"services": dict(services or {}), "certs": dict(certs or {})}
    def point(self, name, *ips): self.dns[name] = list(ips)
    def resolve(self, name): return list(self.dns.get(name, []))
    def txt_records(self, name): return list(self.txt.get(name, []))

    def connect(self, ip, port):
        self.probes.append((ip, port)); h = self.hosts.get(ip)
        if not h or port not in h["services"]: return None
        s = dict(h["services"][port]); c = h["certs"].get(port)
        return {**s, "cert": dict(c) if c else None}


def _need(role, allowed, what):
    if role not in allowed: raise PermissionError(f"{what} needs one of: {', '.join(sorted(allowed))}")


class ExternalSurface:
    def __init__(self, internet, clock, audit, cloud_ips, feed):
        self.net, self.clock, self.audit, self.cloud_ips, self.feed = internet, clock, audit, cloud_ips, feed
        self.domains, self.observed, self.temp, self._warned, self.confirmed = {}, {}, {}, set(), set()

    def _log(self, kind, subject, data, controls=("GLASS.SURFACE",)):
        if self.audit: self.audit.append(kind, "halvard:glass", "system", subject, data, controls=controls)

    # ---- ownership ----
    def declare_domain(self, principal, name):
        _need(principal.role, {"it_admin"}, "Declaring a domain")
        token = "halvard-verify=" + secrets.token_hex(8); self.domains[name.lower()] = {"token": token, "verified": False}
        self._log("glass.domain_declared", name.lower(), {"domain": name.lower(), "by": principal.id})
        return {"domain": name.lower(), "record": f"_halvard-challenge.{name.lower()}", "value": token}

    def verify_domain(self, principal, name):
        _need(principal.role, {"it_admin"}, "Verifying a domain")
        d = self.domains.get(name.lower())
        if not d: raise KeyError(f"{name} was not declared")
        ok = d["token"] in self.net.txt_records(f"_halvard-challenge.{name.lower()}"); d["verified"] = ok
        self._log("glass.domain_verified" if ok else "glass.domain_verification_failed", name.lower(), {"domain": name.lower()})
        return ok

    def candidates(self):
        """Addresses a verified domain points to that nobody has confirmed as the company's own. A domain can point at a vendor's shared server; Halvard does not probe it on DNS alone."""
        ips = set()
        for n, d in self.domains.items():
            if d["verified"]: ips |= set(self.net.resolve(n))
        return ips - self.scope()

    def confirm_address(self, principal, ip, note):
        _need(principal.role, {"it_admin"}, "Confirming an address")
        if ip not in self.candidates(): raise ValueError(f"{ip} is not an address a verified domain points to, or it is already in scope")
        if not note.strip(): raise ValueError("a note saying why this address is yours is required")
        self.confirmed.add(ip); self._log("glass.address_confirmed", ip, {"ip": ip, "justification": note, "by": principal.id})

    def remove_address(self, principal, ip):
        _need(principal.role, {"it_admin"}, "Removing an address")
        self.confirmed.discard(ip); self.observed = {k: v for k, v in self.observed.items() if k[0] != ip}; self._log("glass.address_removed", ip, {"ip": ip, "by": principal.id})

    def scope(self):
        return set(self.cloud_ips()) | self.confirmed

    # ---- scanning ----
    def probe(self, ip, port):
        if ip not in self.scope():
            self._log("glass.probe_refused", ip, {"ip": ip, "port": port, "why": "not an address the customer owns"}); raise ScopeError(f"{ip} is not in your verified scope; nothing was sent.")
        return self.net.connect(ip, port)

    def scan(self, principal):
        _need(principal.role, {"it_admin", "analyst"}, "Scanning the external surface")
        obs = {}
        for ip in sorted(self.scope()):
            for port in PROBE_PORTS:
                r = self.probe(ip, port)
                if r: obs[(ip, port)] = r
        self.observed = obs
        self._log("glass.surface_scanned", "external", {"addresses": len(self.scope()), "open_services": len(obs), "by": principal.id})
        return obs

    def approve_temporary_exposure(self, principal, ip, port, days, reason):
        _need(principal.role, {"it_admin"}, "Approving a temporary exposure")
        if not reason.strip(): raise ValueError("a reason is required")
        if not 0 < days <= 30: raise ValueError("a temporary exposure lasts at most 30 days")
        until = self.clock.now() + days * 86400; self.temp[(ip, port)] = {"until": until, "reason": reason, "by": principal.id}
        self._log("glass.temporary_exposure_approved", ip, {"ip": ip, "port": port, "days": days, "justification": reason, "by": principal.id})
        return until

    # ---- findings ----
    def findings(self, known_ips=()):
        now, out = self.clock.now(), []
        for (ip, port), s in sorted(self.observed.items()):
            tmp = self.temp.get((ip, port))
            if port in ADMIN or port in DATA:
                kind = "remote administration" if port in ADMIN else "database"; name = (ADMIN | DATA)[port]
                if tmp and tmp["until"] > now: pass
                else:
                    expired = bool(tmp)
                    out.append({"kind": "admin_exposed" if port in ADMIN else "data_exposed", "ip": ip, "port": port, "severity": "critical" if port in DATA or expired else "high",
                                "title": f"{name} ({kind}) is open to the internet at {ip}:{port}" + (" after its approved window ended" if expired else ""),
                                "why": ["anyone can try to reach it"] + (["it was approved only until the date shown on the record, and it is still open"] if expired else [])})
            if ip not in set(known_ips) and ip not in set(self.cloud_ips()):
                out.append({"kind": "unknown_asset", "ip": ip, "port": port, "severity": "medium", "title": f"{ip} answers on port {port} for one of your domains but is not in your inventory",
                            "why": ["it may be a forgotten server, a vendor-hosted site, or something unapproved"]})
            for a in self.feed.matching(s.get("product", ""), s.get("version", "0")):
                if a.surface == "network" and (a.port is None or a.port == port):
                    out.append({"kind": "vulnerable_service", "ip": ip, "port": port, "severity": "critical" if a.base_severity >= 9 else "high" if a.base_severity >= 7 else "medium",
                                "title": f"{s['product']} {s['version']} at {ip}:{port} is affected: {a.summary}", "advisory": a, "product": s["product"], "version": s["version"],
                                "why": [f"advisory {a.id}"]})
        seen = set()
        out = [f for f in out if not ((f["kind"], f["ip"], f["port"]) in seen or seen.add((f["kind"], f["ip"], f["port"])))]
        return out

    def expiries(self):
        """Certificates and time-boxed exposures that end soon or already have, soonest first. Each threshold is recorded once."""
        now, out = self.clock.now(), []
        for (ip, port), s in sorted(self.observed.items()):
            c = s.get("cert")
            if c:
                days = (c["not_after"] - now) / 86400
                if days <= CERT_WARN_DAYS[0]:
                    out.append({"kind": "certificate", "ip": ip, "port": port, "name": ", ".join(c.get("names", [])) or ip, "days_left": round(days, 1), "level": "expired" if days <= 0 else "urgent" if days <= 7 else "soon"})
        for (ip, port), t in sorted(self.temp.items()):
            days = (t["until"] - now) / 86400
            if days <= 3: out.append({"kind": "temporary_exposure", "ip": ip, "port": port, "name": f"{ip}:{port}", "days_left": round(days, 1), "level": "expired" if days <= 0 else "urgent"})
        out.sort(key=lambda x: x["days_left"])
        for x in out:
            key = (x["kind"], x["ip"], x["port"], x["level"])
            if key not in self._warned:
                self._warned.add(key); self._log("glass.expiry_warning", x["ip"], {k: x[k] for k in ("kind", "ip", "port", "level", "days_left")}, controls=("GLASS.EXPIRY_WARNINGS",))
        return out
