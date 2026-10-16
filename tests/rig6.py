import os
from rig5 import *
from halvard.glass.surface import ReferenceInternet
from halvard.relay.actions import ActionRequest

OWNER, ADM, ADM2, AN, SD, AUD = (Principal("u-own", "owner"), Principal("u-adm", "it_admin"), Principal("u-adm2", "it_admin"),
                                 Principal("u-an", "analyst"), Principal("u-sd", "service_desk"), Principal("u-aud", "auditor"))
DAY = 86400


class World6(World5):
    """World5 plus software inventories, two cloud servers with Ward on them (one production crown jewel), and an internet the company can be seen from."""
    def __init__(self, **kw):
        super().__init__(**kw)
        cp = self.cp
        cp.engine.auth.policy.accepted_patterns |= {"patch_failure_rollback"}
        self.host.software.update({"pdfviewer": "11.1", "vpnclient": "5.0.0", "officesuite": "16.9"})
        self.host2.software.update({"pdfviewer": "11.1", "officesuite": "16.5"})
        self.host.settings.update({"firewall_enabled": True, "automatic_updates": True, "screen_lock_minutes": 10})
        self.host2.settings.update({"firewall_enabled": True, "automatic_updates": True, "screen_lock_minutes": 10})
        self.web = self._server("i-web", "production", {"webserver": "2.4.50", "sshd": "9.3"})
        self.bastion = self._server("i-bastion", "standard", {"sshd": "9.1"})
        cp.glass.assign_ring(ADM, "LT-22", "pilot")
        cp.atlas.sync_graph(); cp.atlas.run_posture(); cp.glass.evaluate()
        self.net = cp.internet
        self.net.add_host("198.51.100.80", {443: {"service": "https", "product": "webserver", "version": "2.4.50"}}, {443: {"names": ["www.acme.com"], "not_after": self.clock.now() + 400 * DAY}})
        self.net.add_host("198.51.100.81", {22: {"service": "ssh", "product": "sshd", "version": "9.1"}})
        self.net.add_host("203.0.113.50", {8443: {"service": "https", "product": "legacy-portal", "version": "1.0"}}, {8443: {"names": ["old.acme.com"], "not_after": self.clock.now() + 20 * DAY}})
        self.net.add_host("192.0.2.99", {22: {"service": "ssh", "product": "sshd", "version": "9.1"}})            # someone else's server
        self.net.point("www.acme.com", "198.51.100.80"); self.net.point("old.acme.com", "203.0.113.50"); self.net.point("vendor-hosted.example", "192.0.2.99")

    def _server(self, iid, klass, software):
        a, h, _, fs = make_agent(os.path.join(self.tmp, iid), asset_class=klass, accepted=("ransomware_stop", "malware_quarantine", "undo"))
        a.device_id = iid; a.clock = self.clock; a.engine.clock = self.clock; a.spool.clock = self.clock; a.journal.clock = self.clock; a.engine.device_id = iid
        h.software.update(software); h.settings.update({"firewall_enabled": True, "automatic_updates": True, "screen_lock_minutes": 5})
        self.cp.fleet.register(a); self.cp.atlas.enroll_workload(iid, a)
        return a

    def verify_scope(self, confirm=None):
        """Prove the domain, then confirm the addresses it points to that really are the company's (not the vendor-hosted one)."""
        cp = self.cp; self.net.dns.setdefault("acme.com", ["203.0.113.50"])
        rec = cp.surface.declare_domain(ADM, "acme.com"); self.net.txt[rec["record"]] = [rec["value"]]
        assert cp.surface.verify_domain(ADM, "acme.com")
        for ip in (confirm if confirm is not None else sorted(cp.surface.candidates() - {"192.0.2.99"})): cp.surface.confirm_address(ADM, ip, "our colocation rack")
        cp.surface.scan(ADM)

    def checkin(self):
        """Every agent phones home (the device's own heartbeat), then the control plane takes it in."""
        for a in self.cp.fleet.agents.values():
            if a.online: a.heartbeat()
        self.cp.process()
