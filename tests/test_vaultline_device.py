import hashlib, json, os, pathlib, unittest
from helpers import *
from rig5 import *
from halvard.ward.agent import EgressBlocked, NeedsJustification, Blocked
from halvard.vaultline.inspection import InspectionNotAllowed


class DeviceEgress(unittest.TestCase):
    def setUp(self):
        self.w = World5(); self.w.agent.set_online(False)           # every decision below is made on the device with no connection
        self.src = os.path.join(self.w.tmp, "work", "orders.csv"); pathlib.Path(self.src).parent.mkdir(parents=True, exist_ok=True); pathlib.Path(self.src).write_bytes(CARD_CSV)
        self.plain = os.path.join(self.w.tmp, "work", "notes.txt"); pathlib.Path(self.plain).write_bytes(PLAIN); self.fs, self.host, self.agent = self.w.fs, self.w.host, self.w.agent
        self.host.spawn(300, "explorer.exe")

    def dst(self, mount, name="orders.csv"): return os.path.join(self.w.tmp, "mnt", mount.split("/")[-1], name)

    def mount_at(self, name):
        real = os.path.join(self.w.tmp, "mnt", name); os.makedirs(real, exist_ok=True)
        info = {"usb-approved-enc": ("Kingston", "SN-APPROVED", True), "usb-approved-plain": ("Kingston", "SN-APPROVED", False), "usb-stranger": ("NoName", "SN-777", False)}[name]
        self.host.mounts[real] = {"removable": True, "encrypted": info[2], "vendor": info[0], "serial": info[1]}; return real

    def test_regulated_data_to_each_kind_of_drive(self):
        stranger, plain, enc = self.mount_at("usb-stranger"), self.mount_at("usb-approved-plain"), self.mount_at("usb-approved-enc")
        with self.assertRaises(EgressBlocked) as e: self.fs.copy_out(300, self.src, os.path.join(stranger, "o.csv"))
        self.assertIn("read-only", str(e.exception)); self.assertEqual(e.exception.decision.rule, "usb-device-readonly")
        with self.assertRaises(EgressBlocked) as e: self.fs.copy_out(300, self.src, os.path.join(plain, "o.csv"))
        self.assertIn("regulated data", str(e.exception)); self.assertFalse(os.path.exists(os.path.join(plain, "o.csv")))
        self.assertTrue(self.fs.copy_out(300, self.src, os.path.join(enc, "o.csv"))); self.assertTrue(os.path.exists(os.path.join(enc, "o.csv")))

    def test_a_plain_document_goes_to_an_approved_drive_but_an_unapproved_drive_is_read_only_for_everything(self):
        plain, stranger = self.mount_at("usb-approved-plain"), self.mount_at("usb-stranger")
        self.assertTrue(self.fs.copy_out(300, self.plain, os.path.join(plain, "n.txt")))
        with self.assertRaises(EgressBlocked): self.fs.copy_out(300, self.plain, os.path.join(stranger, "n.txt"))            # device rule, not content: no inspection needed

    def test_decisions_are_logged_with_labels_and_the_offline_tag_but_no_values_or_paths(self):
        enc, plain = self.mount_at("usb-approved-enc"), self.mount_at("usb-approved-plain")
        self.fs.copy_out(300, self.src, os.path.join(enc, "o.csv"))
        with self.assertRaises(EgressBlocked): self.fs.copy_out(300, self.src, os.path.join(plain, "o.csv"))
        rows = [e for e in self.agent.spool.entries() if e["kind"] == "ward.egress_decision"]; self.assertEqual([r["public"]["decision"] for r in rows], ["allow", "block"])
        for r in rows: self.assertIn("WARD.OFFLINE_PREVENTION", r["controls"]); self.assertIn("VAULTLINE.USB_CONTROL", r["controls"]); self.assertEqual(r["public"]["labels"], {"pci_card": 3})
        blob = json.dumps(rows); self.assertNotIn(VISA, blob); self.assertNotIn(self.src, json.dumps([r["public"] for r in rows]))
        self.assertTrue(self.agent.spool.verify()[0])
        ev = [e for e in self.agent.outbox if e["kind"] == "egress"]; self.assertEqual([e["op"] for e in ev], ["allowed", "block"]); self.assertNotIn(VISA, str(ev))

    def test_confidential_data_needs_a_reason_which_is_recorded_time_boxed_and_specific(self):
        sec_free = b"PROJECT-ATLAS-0001 PROJECT-ATLAS-0002 roadmap"; f = os.path.join(self.w.tmp, "work", "road.txt"); pathlib.Path(f).write_bytes(sec_free)
        self.w.cp.push_dlp({**self.w.dlp, "custom_labels": [{"label": "project_atlas", "regex": r"PROJECT-ATLAS-\d{4}", "min_count": 1}]}); self.w.cp.fleet.reconnect("LT-17"); self.agent.set_online(False); plain = self.mount_at("usb-approved-plain")
        with self.assertRaises(NeedsJustification) as e: self.fs.copy_out(300, f, os.path.join(plain, "r.txt"))
        dest = {"mount": self.host.mount_of(plain)}
        with self.assertRaises(ValueError): self.agent.justify("usb", f, sec_free, dest, "short")
        self.agent.justify("usb", f, sec_free, dest, "Handing the roadmap to the printer vendor on site")
        self.assertTrue(self.fs.copy_out(300, f, os.path.join(plain, "r.txt")))                                         # allowed now
        self.w.clock.advance(3601)
        with self.assertRaises(NeedsJustification): self.fs.copy_out(300, f, os.path.join(plain, "r2.txt"))             # an hour later: asked again
        other = os.path.join(self.w.tmp, "work", "other.txt"); pathlib.Path(other).write_bytes(sec_free + b" v2")
        self.agent.justify("usb", f, sec_free, dest, "Handing the roadmap to the printer vendor on site")
        with self.assertRaises(NeedsJustification): self.fs.copy_out(300, other, os.path.join(plain, "o.txt"))            # a different file is a different question
        j = [e for e in self.agent.spool.entries() if e["kind"] == "ward.egress_justified"]; self.assertEqual(len(j), 2)
        self.assertIn("printer vendor", j[0]["private"]["justification"]); self.assertNotIn("printer vendor", json.dumps(j[0]["public"]))

    def test_secrets_cannot_be_unlocked_by_a_reason(self):
        f = os.path.join(self.w.tmp, "work", "creds.env"); pathlib.Path(f).write_bytes(SECRET_ENV); enc = self.mount_at("usb-approved-enc")
        with self.assertRaises(EgressBlocked) as e: self.fs.copy_out(300, f, os.path.join(enc, "c.env"))                  # not even to an approved encrypted drive
        self.assertFalse(e.exception.decision.justifiable); self.assertIn("secret manager", str(e.exception))
        with self.assertRaises(PermissionError): self.agent.justify("usb", f, SECRET_ENV, {"mount": self.host.mount_of(enc)}, "I really need this one please")

    def test_printing_and_uploading(self):
        with self.assertRaises(NeedsJustification): self.fs.send_out(300, "print", self.src, {"printer": "floor-2"})
        self.assertEqual(self.fs.send_out(300, "print", self.plain, {"printer": "floor-2"}).action, "allow")
        for domain, want in (("files.acme-approved.example", "allow"), ("dropbox.com", "block"), ("random-share.example", "block")):
            if want == "block":
                with self.assertRaises(EgressBlocked): self.fs.send_out(300, "upload", self.src, {"domain": domain})
            else: self.assertEqual(self.fs.send_out(300, "upload", self.src, {"domain": domain}).action, "allow")
        self.assertEqual(self.fs.send_out(300, "upload", self.plain, {"domain": "random-share.example"}).action, "allow")      # plain notes may go anywhere

    def test_blocked_process_cannot_use_the_channel_at_all(self):
        self.agent.blocked.add(300); enc = self.mount_at("usb-approved-enc")
        with self.assertRaises(Blocked): self.fs.copy_out(300, self.plain, os.path.join(enc, "n.txt"))


class InspectionGate(unittest.TestCase):
    def test_content_inspection_is_off_by_default_and_content_rules_do_nothing_until_it_is_on(self):
        w = World5(dlp_on=False); w.agent.set_online(False); src = os.path.join(w.tmp, "w", "o.csv"); pathlib.Path(src).parent.mkdir(parents=True, exist_ok=True); pathlib.Path(src).write_bytes(CARD_CSV)
        real = os.path.join(w.tmp, "mnt", "plain"); os.makedirs(real); w.host.mounts[real] = {"removable": True, "encrypted": False, "vendor": "Kingston", "serial": "SN-APPROVED"}; w.host.spawn(300, "explorer.exe")
        d = w.agent.check_egress(300, "usb", src, CARD_CSV, {"mount": w.host.mount_of(real)}); self.assertFalse(d.inspected); self.assertEqual(d.action, "allow")
        refused = [e for e in w.agent.spool.entries() if e["kind"] == "vaultline.inspection_refused"]; self.assertIn("off", refused[0]["public"]["why"])

    def test_each_precondition_is_required_and_the_reason_says_which(self):
        ok = lambda **kw: InspectionPolicy(**{**dict(enabled=True, purpose="p", scope=["/data/*"], notice_id="N", notice_effective_at=100.0), **kw}).check("/data/a.csv", 200.0)
        self.assertTrue(ok()[0])
        for kw, word in (({"enabled": False}, "off"), ({"purpose": " "}, "purpose"), ({"notice_id": None}, "notice"), ({"notice_effective_at": 300.0}, "not taken effect"), ({"scope": ["/other/*"]}, "outside")):
            r = ok(**kw); self.assertFalse(r[0], kw); self.assertIn(word, r[1], kw)
        self.assertIn("excluded", InspectionPolicy(enabled=True, purpose="p", scope=["/data/*"], notice_id="N", notice_effective_at=1.0).check("/data/personal/diary.txt", 200.0)[1])

    def test_personal_folders_are_never_read(self):
        w = World5(); personal = os.path.join(w.tmp, "personal", "cards.csv"); pathlib.Path(personal).parent.mkdir(parents=True, exist_ok=True); pathlib.Path(personal).write_bytes(CARD_CSV)
        with self.assertRaises(InspectionNotAllowed): w.agent.inspector.inspect(personal, "cards.csv", CARD_CSV)
        self.assertEqual(w.agent.inspector.catalog, [])

    def test_catalog_keeps_labels_and_counts_and_the_control_plane_learns_only_that(self):
        w = World5(); f = os.path.join(w.tmp, "docs", "o.csv"); pathlib.Path(f).parent.mkdir(parents=True, exist_ok=True); pathlib.Path(f).write_bytes(CARD_CSV)
        c = w.agent.inspector.inspect(f, "o.csv", CARD_CSV); self.assertEqual(w.agent.inspector.catalog[0].labels, {"pci_card": 3})
        r = w.cp.vault.ingest_catalog("LT-17", w.agent.inspector.catalog); self.assertEqual(r["sensitivity"], "regulated")
        e = next(x for x in w.cp.store.entities(w.cp.ctx) if x["entity_id"] == "LT-17"); self.assertEqual((e["suggested_sensitivity"], e["sensitivity"]), ("regulated", None)); self.assertNotIn(VISA, json.dumps(e)); self.assertEqual(e["attrs"]["data_labels"], {"pci_card": 3})
        self.assertNotIn(VISA, str(w.agent.inspector.catalog)); self.assertNotIn(f, str(w.agent.inspector.catalog))

    def test_encryption_status_and_device_health(self):
        w = World5(); self.assertEqual(w.agent.encryption_report()["issues"], []); w.host.system_encrypted = False
        self.assertEqual(w.agent.encryption_report()["issues"], ["The disk is not encrypted."]); h = w.cp.signet.push_device_health(w.agent); self.assertIn("disk not encrypted", h["reasons"]); self.assertFalse(w.cp.idp.devices["LT-17"]["compliant"])


class DlpPolicyDelivery(unittest.TestCase):
    def test_offline_device_gets_the_policy_when_it_returns_and_unsigned_policy_is_refused(self):
        w = World5(); w.agent2.set_online(False); new = {**w.dlp, "usb": {"approved": [], "unapproved_mode": "block"}}; out = w.cp.push_dlp(new); self.assertEqual(out["LT-22"], "queued")
        self.assertEqual(w.agent2.usb_cfg["unapproved_mode"], "read_only"); w.cp.fleet.reconnect("LT-22"); self.assertEqual(w.agent2.usb_cfg["unapproved_mode"], "block")
        from halvard.ward.policy import PolicyBundle
        forged = dataclasses.replace(w.agent.bundle, version=99, dlp={"inspection": {"enabled": False}}).__dict__.copy(); self.assertFalse(w.agent.apply_bundle(forged, POLICY_KEY))      # unsigned
        self.assertTrue(w.agent.inspector.policy.enabled)


if __name__ == "__main__":
    unittest.main()
