"""Harbor's network sensor (F071) as the platform sees it: METADATA only (who talked to whom on which port, how much), plus address-resolution and DHCP sightings that say which
hardware address showed up where. No payloads, no URLs, no names beyond what DHCP announces.

A site sensor keeps working when its link to the platform is down: it buffers (bounded), and when the link returns it forwards. If the buffer overflowed, the loss is COUNTED and
reported as a gap; it is never hidden. The real sensor is a separate native component; this is the contract it satisfies.
"""
from collections import deque


class SiteSensor:
    def __init__(self, site, clock, buffer=5000):
        self.site, self.clock, self.buf, self.max, self.lost, self.online = site, clock, deque(), buffer, 0, True
        self.lost_from = None

    def seen(self, mac, ip, hostname=None, vendor_class=None, vlan=None):
        self._add({"kind": "seen", "mac": mac.lower(), "ip": ip, "hostname": hostname, "vendor_class": vendor_class, "vlan": vlan})

    def flow(self, src_ip, dst_ip, dst_port, proto="tcp", nbytes=0, src_zone=None, dst_zone=None):
        self._add({"kind": "flow", "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port, "proto": proto, "bytes": nbytes, "src_zone": src_zone, "dst_zone": dst_zone})

    def _add(self, rec):
        rec = {**rec, "ts": self.clock.now(), "site": self.site}
        if len(self.buf) >= self.max:
            self.buf.popleft(); self.lost += 1; self.lost_from = self.lost_from or self.clock.now()
        self.buf.append(rec)

    def flush(self, ingest):
        """Forward everything buffered. Returns how many records went and how many were lost while the link was down."""
        if not self.online: return {"sent": 0, "lost": self.lost, "queued": len(self.buf)}
        recs, lost, since = list(self.buf), self.lost, self.lost_from; self.buf.clear(); self.lost, self.lost_from = 0, None
        ingest(self.site, recs, lost=lost, lost_since=since); return {"sent": len(recs), "lost": lost, "queued": 0}
