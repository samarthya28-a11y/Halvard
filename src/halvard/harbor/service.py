"""Harbor: what is on each site's network, whether Halvard knows it, what is talking sideways, and what to tighten (F071, F072, F076).

Rogue-device discovery (F072): every hardware address a sensor sees is matched against what is known: devices that report their own addresses (Ward), devices IT
adopted, and things IT said to expect (a printer, a camera) with an expiry. Everything else is UNKNOWN, with a confidence built from stated reasons (new, in a sensitive
zone, talking to a crown jewel). Halvard never blocks a device by itself: it asks, and a blocking request goes to the customer's own network tool as a change request.
East-west (F071): fan-out of administration protocols and flows that cross a zone boundary the site's policy does not allow. Metadata only.
Segmentation advice (F076): rules that allow flows nobody used during an observation window long enough to mean something; sent as a change request, never applied.
"""
from dataclasses import dataclass, field

from ..cases import CaseFinding

ADMIN_PORTS = {22, 445, 3389, 5985, 5986}
OBSERVATION_DAYS = 14
FANOUT = 15
SENSITIVE_ZONES = {"servers", "ot", "finance", "clinical"}
WORKSTATION_HINTS = ("MSFT 5.0", "dhcpcd", "Apple")
ROLE_OPS = {"register": {"it_admin"}, "classify": {"it_admin"}, "view": {"it_admin", "analyst"}, "advise": {"it_admin", "analyst"}}
MAX_EXPECT_DAYS = 365


@dataclass
class Seen:
    mac: str
    site: str
    first: float
    last: float
    ips: set = field(default_factory=set)
    hostnames: set = field(default_factory=set)
    vendor_class: str | None = None
    vlans: set = field(default_factory=set)
    talked_to: set = field(default_factory=set)       # (dst_ip, port)


class ReferenceChangeTool:
    """The customer's existing network tool or ticket queue. Halvard files change requests here; a person implements them."""
    def __init__(self, clock): self.clock, self.tickets, self._n = clock, {}, 0

    def submit(self, cr):
        self._n += 1; tid = f"CHG-{1000 + self._n}"; self.tickets[tid] = {"cr": cr, "status": "open", "ts": self.clock.now()}; return tid

    def withdraw(self, tid): self.tickets[tid]["status"] = "withdrawn"


class HarborService:
    def __init__(self, store, ctx, clock, audit, fleet, sensor_interval_s=900):
        self.store, self.ctx, self.clock, self.audit, self.fleet, self.interval = store, ctx, clock, audit, fleet, sensor_interval_s
        self.sites, self.devices, self.expected, self.adopted, self.last_seen, self.gaps = {}, {}, {}, {}, {}, []
        self.flows, self.findings, self._n, self._fan, self._flagged, self.first_obs = [], [], 0, {}, set(), {}
        self.pending_cr = {}

    def _log(self, kind, subject, data, controls=("HARBOR.DISCOVERY",)):
        if self.audit: self.audit.append(kind, "halvard:harbor", "system", subject, data, controls=controls)

    def require(self, principal, op):
        if principal.role not in ROLE_OPS[op]:
            self._log("harbor.denied", principal.id, {"op": op, "role": principal.role}, ("HARBOR.AUTHORIZATION",))
            raise PermissionError(f"{op} needs one of: {', '.join(sorted(ROLE_OPS[op]))}")

    # ---------------- sites ----------------
    def register_site(self, principal, site, name, zones, allow, crown_ips=()):
        """zones: {vlan: zone}. allow: [(from_zone, to_zone, port or '*')] flows the site's policy permits across zones. Same-zone traffic is always allowed."""
        self.require(principal, "register")
        self.sites[site] = {"name": name, "zones": dict(zones), "allow": [tuple(a) for a in allow], "crown_ips": set(crown_ips)}
        eid = f"site:{site}"
        if not self.store.has_entity(self.ctx, eid): self.store.put_entity(self.ctx, eid, "site", name, self.clock.now(), should_be_protected=0, attrs={"zones": sorted(set(zones.values()))})
        self._log("harbor.site_registered", site, {"site": site, "zones": len(set(zones.values())), "by": principal.id})

    # ---------------- ingest ----------------
    def ingest(self, site, records, lost=0, lost_since=None):
        now = self.clock.now()
        if site not in self.sites: raise KeyError(f"{site} is not registered")
        self.last_seen[site] = now; self.first_obs.setdefault(site, records[0]["ts"] if records else now)
        if lost:
            self.gaps.append({"site": site, "lost": lost, "since": lost_since, "until": now}); self._log("harbor.sensor_gap", site, {"site": site, "records_lost": lost})
        for r in records:
            if r["kind"] == "seen": self._saw(site, r)
            else: self._flow(site, r)
        self._log("harbor.ingested", site, {"site": site, "records": len(records), "lost": lost})

    def _saw(self, site, r):
        d = self.devices.get(r["mac"])
        if d is None: d = self.devices[r["mac"]] = Seen(r["mac"], site, r["ts"], r["ts"])
        d.last = r["ts"]; d.ips.add(r["ip"]); d.vlans.add(r.get("vlan"))
        if r.get("hostname"): d.hostnames.add(r["hostname"])
        if r.get("vendor_class"): d.vendor_class = r["vendor_class"]

    def _flow(self, site, r):
        self.flows.append(r)
        by_ip = {ip: m for m, d in self.devices.items() for ip in d.ips}
        m = by_ip.get(r["src_ip"])
        if m: self.devices[m].talked_to.add((r["dst_ip"], r["dst_port"]))
        if r["dst_port"] in ADMIN_PORTS:
            q = self._fan.setdefault((site, r["src_ip"]), {}); q[r["dst_ip"]] = r["ts"]
            for ip in [i for i, t in q.items() if r["ts"] - t > 300]: q.pop(ip)

    # ---------------- what is known ----------------
    def known_macs(self):
        k = {}
        for d, rep in ((d, a.inventory()) for d, a in self.fleet.agents.items()):
            for m in rep.get("macs", []): k[m.lower()] = ("managed", d)
        for e in self.store.entities(self.ctx):
            m = (e["attrs"] or {}).get("mac")
            if m: k.setdefault(m.lower(), ("recorded", e["entity_id"]))
        now = self.clock.now()
        for m, x in self.expected.items():
            if x["until"] > now: k[m] = ("expected", x["kind"])
        return k

    def _device_for_ip(self, ip):
        for d, a in self.fleet.agents.items():
            if a.inventory().get("ip") == ip: return d
        for e in self.store.entities(self.ctx):
            if (e["attrs"] or {}).get("ip") == ip: return e["entity_id"]
        return None

    def unknown(self):
        """Hardware addresses seen on a site that nobody has accounted for, strongest reasons first. Confidence is rule-assigned from the reasons shown."""
        known, now, out = self.known_macs(), self.clock.now(), []
        for m, d in self.devices.items():
            if m in known: continue
            site = self.sites[d.site]; zones = {site["zones"].get(v) for v in d.vlans if v in site["zones"]}
            why, conf = ["no agent, record or exception accounts for this hardware address"], 0.4
            if now - d.first < 86400: conf += 0.1; why.append("first seen in the last 24 hours")
            if zones & SENSITIVE_ZONES: conf += 0.2; why.append(f"it is on the {', '.join(sorted(zones & SENSITIVE_ZONES))} network, where only managed machines should be")
            if any(ip in site["crown_ips"] for ip, _ in d.talked_to): conf += 0.2; why.append("it has talked to a crown-jewel system")
            if any(h in (d.vendor_class or "") for h in WORKSTATION_HINTS): why.append("it announces itself as a general-purpose computer, which should have an agent")
            out.append({"mac": m, "site": d.site, "ips": sorted(d.ips), "hostnames": sorted(d.hostnames), "vendor_class": d.vendor_class, "zones": sorted(z for z in zones if z), "confidence": round(min(conf, 0.9), 2), "why": why, "first_seen": d.first})
        return sorted(out, key=lambda x: -x["confidence"])

    # ---------------- decisions by people ----------------
    def adopt(self, principal, mac, name, owner, should_be_protected=True, criticality=None):
        self.require(principal, "classify"); mac = mac.lower(); d = self.devices.get(mac)
        if d is None: raise KeyError(f"{mac} has not been seen")
        eid = f"dev:{mac.replace(':', '')}"
        self.store.put_entity(self.ctx, eid, "device", name, self.clock.now(), should_be_protected=1 if should_be_protected else 0, criticality=criticality, attrs={"mac": mac, "ip": sorted(d.ips)[0], "adopted": True})
        if owner and self.store.has_entity(self.ctx, owner): self.store.put_edge(self.ctx, owner, "uses", eid, self.clock.now())
        self.adopted[mac] = {"entity": eid, "by": principal.id}; self._log("harbor.device_adopted", eid, {"device": eid, "protected": should_be_protected, "by": principal.id})
        return eid

    def expect(self, principal, mac, kind, reason, days):
        self.require(principal, "classify")
        if not reason.strip(): raise ValueError("a reason is required")
        if not 0 < days <= MAX_EXPECT_DAYS: raise ValueError(f"an exception lasts at most {MAX_EXPECT_DAYS} days")
        self.expected[mac.lower()] = {"kind": kind, "until": self.clock.now() + days * 86400, "by": principal.id}
        self._log("harbor.device_expected", mac.lower(), {"kind": kind, "days": days, "justification": reason, "by": principal.id})

    # ---------------- findings ----------------
    def poll(self):
        out, now = [], self.clock.now()
        for u in self.unknown():
            if u["mac"] in self._flagged or u["confidence"] < 0.6: continue
            self._flagged.add(u["mac"]); eid = f"site:{u['site']}"; self._n += 1
            out.append(CaseFinding(f"harbor-{self._n}", "harbor", "unknown_device", eid, u["confidence"], f"An unknown device ({u['ips'][0] if u['ips'] else u['mac']}{', ' + u['hostnames'][0] if u['hostnames'] else ''}) appeared on the {', '.join(u['zones']) or 'a'} network at {self.sites[u['site']]['name']}" + (" and has talked to a crown-jewel system." if any('crown-jewel' in x for x in u['why']) else "."), "; ".join(u["why"]), now, None, {"detector": "unknown_device", "mac": u["mac"], "ip": u["ips"][0] if u["ips"] else None}))
        for (site, ip), q in list(self._fan.items()):
            if len(q) >= FANOUT and (site, ip, "fan") not in self._flagged:
                self._flagged.add((site, ip, "fan")); self._n += 1; ent = self._device_for_ip(ip) or f"site:{site}"
                out.append(CaseFinding(f"harbor-{self._n}", "harbor", "lateral_movement", ent, 0.6, f"One machine reached administration services on {len(q)} different machines within five minutes.", "A single computer contacting many others on remote-administration ports looks like scanning or lateral movement. Backup and patch servers do this legitimately and can be exempted.", now, "T1021", {"detector": "admin_fanout", "ip": ip, "targets": len(q)}))
        for r in self.flows:
            site = self.sites[r["site"]]; sz, dz = r.get("src_zone"), r.get("dst_zone")
            if not sz or not dz or sz == dz: continue
            if any(a[0] == sz and a[1] == dz and a[2] in ("*", r["dst_port"]) for a in site["allow"]): continue
            key = (r["site"], sz, dz, r["dst_port"])
            if key in self._flagged: continue
            self._flagged.add(key); self._n += 1; ent = self._device_for_ip(r["src_ip"]) or f"site:{r['site']}"
            out.append(CaseFinding(f"harbor-{self._n}", "harbor", "zone_violation", ent, 0.5, f"Traffic crossed from the {sz} network to the {dz} network on port {r['dst_port']}, which the site's policy does not allow.", "Either the policy is out of date or something is where it should not be.", now, None, {"detector": "zone_violation", "from": sz, "to": dz, "port": r["dst_port"]}))
        self.findings += out; return out

    def coverage_gaps(self):
        """A site whose sensor has gone quiet is a gap, not a quiet network."""
        now = self.clock.now()
        return [{"site": s, "reason": "no sensor has ever reported" if s not in self.last_seen else f"the sensor last reported {int((now - self.last_seen[s]) // 60)} minutes ago (promised every {self.interval // 60})"}
                for s in self.sites if s not in self.last_seen or now - self.last_seen[s] > self.interval]

    # ---------------- F076: segmentation advice as a change request ----------------
    def advice(self, principal, site):
        self.require(principal, "advise"); s = self.sites[site]; now = self.clock.now()
        have = (now - self.first_obs[site]) / 86400 if site in self.first_obs else 0
        if have < OBSERVATION_DAYS:
            return {"site": site, "status": "not_enough_observation", "message": f"Advice needs at least {OBSERVATION_DAYS} days of observation; the sensor has {have:.1f}. Nothing is proposed.", "changes": []}
        flows = [r for r in self.flows if r["site"] == site and r.get("src_zone") and r.get("dst_zone") and r["src_zone"] != r["dst_zone"]]
        changes = []
        for rule in s["allow"]:
            used = [r for r in flows if r["src_zone"] == rule[0] and r["dst_zone"] == rule[1] and rule[2] in ("*", r["dst_port"])]
            if not used: changes.append({"op": "remove", "rule": rule, "observed_flows": 0, "would_break": 0, "why": f"no {rule[0]} to {rule[1]} traffic on {rule[2]} in {have:.0f} days"})
            elif rule[2] == "*":
                ports = sorted({r["dst_port"] for r in used}); changes.append({"op": "narrow", "rule": rule, "to_ports": ports, "observed_flows": len(used), "would_break": 0, "why": f"only ports {ports} were used between these zones in {have:.0f} days"})
        cr = {"site": site, "created": now, "observation_days": round(have, 1), "changes": changes, "caveat": "Rare but legitimate flows (quarter-end jobs, disaster recovery) may not appear in a short window. Review before implementing."}
        return {"site": site, "status": "draft", "message": f"{len(changes)} proposed change(s). Nothing has been changed; submit it as a change request to your network team.", "changes": changes, "change_request": cr}
