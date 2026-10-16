import dataclasses, os
from rig4 import *
from halvard.vaultline.inspection import InspectionPolicy
from halvard.vaultline.classifiers import Classifier
from halvard.atlas.aws import ReferenceAWS

VISA, MC = "4111111111111111", "5555555555554444"
CARD_CSV = f"name,card,exp\nA Customer,{VISA},12/28\nB Customer,{MC},01/29\nC,378282246310005,11/27\n".encode()
SECRET_ENV = b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\napi_key=q8Zr2LmX9vB4nT7pW1sD6yK3\n"
PLAIN = b"Meeting notes: agenda for Tuesday. Nothing sensitive here.\n"


def inspection(now, scope):
    return dataclasses.asdict(InspectionPolicy(enabled=True, purpose="prevent regulated customer data leaving the company", scope=scope, notice_id="NOTICE-2026-04", notice_effective_at=now - 86400))


class World5(World4):
    def __init__(self, dlp_on=True, **kw):
        super().__init__(**kw)
        cp, aws = self.cp, self.cp.aws
        cp.engine.auth.policy.accepted_patterns |= {"cloud_exposure_revert"}
        # devices: removable drives
        for h in (self.host, self.host2):
            h.mounts["/mnt/usb-approved-enc"] = {"removable": True, "encrypted": True, "vendor": "Kingston", "serial": "SN-APPROVED"}
            h.mounts["/mnt/usb-approved-plain"] = {"removable": True, "encrypted": False, "vendor": "Kingston", "serial": "SN-APPROVED"}
            h.mounts["/mnt/usb-stranger"] = {"removable": True, "encrypted": False, "vendor": "NoName", "serial": "SN-777"}
        self.dlp = {"inspection": inspection(self.clock.now(), [f"{self.tmp}/*", "s3:*", "mail:outbound"]) if dlp_on else {"enabled": False},
                    "usb": {"approved": [{"vendor": "Kingston", "serial": "SN-APPROVED"}], "unapproved_mode": "read_only"},
                    "partners": ["globex-supplies.com"], "saas": {"files.acme-approved.example": "sanctioned", "dropbox.com": "personal"}}
        cp.vault.policy.__dict__.update(inspection(self.clock.now(), ["s3:*", "mail:outbound"])) if dlp_on else None
        cp.vault.partners = {"globex-supplies.com"}
        cp.push_dlp(self.dlp)
        # cloud account
        aws.add_sg("sg-web", [{"port": 443, "cidr": "0.0.0.0/0", "proto": "tcp"}]); aws.add_sg("sg-admin", [{"port": 22, "cidr": "0.0.0.0/0", "proto": "tcp"}])
        aws.add_bucket("cust-exports", tags={"env": "dev", "owner": "p:alice"}); aws.put_object("cust-exports", "2026/orders.csv", CARD_CSV); aws.put_object("cust-exports", "notes.txt", PLAIN)
        aws.add_bucket("prod-ledgers", tags={"env": "prod", "criticality": "crown_jewel", "owner": "p:maria"}); aws.put_object("prod-ledgers", "q1.csv", CARD_CSV)
        aws.add_bucket("public-site", tags={"env": "prod", "website": "true"}); aws.put_object("public-site", "index.html", b"<html>hello</html>"); aws.make_bucket_public("public-site", "web-deployer")
        aws.add_role("web-role", buckets={"cust-exports"}); aws.add_role("admin-role", admin=True)
        aws.add_instance("i-web", {"env": "prod", "name": "web", "criticality": "crown_jewel"}, ["sg-web"], public_ip="198.51.100.80", role="web-role", imds_v2_required=False)
        aws.add_instance("i-bastion", {"env": "dev", "name": "bastion"}, ["sg-admin"], public_ip="198.51.100.81", role="admin-role")
        aws.add_user("deploy", console=True, mfa=False, keys=[{"id": "AKIAOLDKEY0000001", "created": self.clock.now() - 200 * 86400, "last_used": None, "active": True}])
        aws.log.clear()
        cp.atlas.sync_graph(); cp.atlas.cursor = 0; cp.process()

    def scan_all(self):
        return [self.cp.vault.scan_bucket(b) for b in ("cust-exports", "prod-ledgers")]
