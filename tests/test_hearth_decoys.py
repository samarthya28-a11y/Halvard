import os, unittest
from helpers import *
from rig7 import *
from halvard.hearth import canary as C
from halvard.vaultline.classifiers import extract_text
from halvard.signet.idp import AuthError

DECOY = "svc-backup-old@acme.com"


def make(w, kind, name, actor=ADM):
    r = w.cp.engine.request(ActionRequest("create_decoy_identity", actor, [name], "decoy account", None, {"kind": kind})); return r


def approve(w, r, who=ADM2): return w.cp.engine.approve(r.action_id, who) if r.status == "pending_approval" else r


class DecoyIdentityTests(unittest.TestCase):
    def test_a_decoy_has_no_rights_refuses_real_names_and_needs_an_approver(self):
        w = World7(); r = make(w, "idp_user", DECOY); self.assertEqual(r.status, "pending_approval"); self.assertNotIn(DECOY, w.cp.idp.users); r = approve(w, r); self.assertEqual(r.status, "executed")
        u = w.cp.idp.users[DECOY]; self.assertEqual((u.roles, u.groups, u.is_service), ({}, set(), False))
        with self.assertRaises(ValueError): w.cp.hearth.create_decoy_identity("idp_user", "alice@acme.com", "x")
        with self.assertRaises(ValueError): w.cp.hearth.create_decoy_identity("aws_key", "deploy", "x")
        self.assertEqual(make(w, "idp_user", "x@acme.com", actor=SD).status, "denied")
        u = w.cp.engine.undo(r.action_id, ADM); u = approve(w, u); self.assertEqual(u.status, "executed"); self.assertNotIn(DECOY, w.cp.idp.users)

    def test_trying_a_decoy_account_raises_one_strong_alarm_from_the_first_attempt_and_names_the_device(self):
        w = World7(); approve(w, make(w, "idp_user", DECOY)); w.cp.signet.sync_graph(); w.cp.hearth.poll()
        pw = w.cp.idp.users[DECOY].password
        with self.assertRaises(AuthError): w.cp.idp.sign_in(DECOY, "Summer2024!", "203.0.113.9", dict(country="RU", lat=55, lon=37), device_id="LT-17")
        fs = w.cp.hearth.poll(); self.assertEqual({f.entity_id for f in fs}, {"id:idp:" + DECOY, "LT-17"}); f = fs[0]
        self.assertEqual((f.family, f.confidence, f.technique), ("tripwire", 0.95, "T1078")); self.assertIn("exists only as a decoy", f.summary); self.assertEqual(f.details["result"], "failure")

    def test_a_decoy_cloud_key_is_denied_everything_but_every_use_is_an_alarm_and_it_is_not_a_posture_problem(self):
        w = World7(); r = approve(w, make(w, "aws_key", "svc-legacy-backup")); kid = next(d.ref for d in w.cp.hearth.decoys.values())
        for act in ("s3:ListBuckets", "iam:ListUsers"):
            with self.assertRaises(PermissionError): w.cp.aws.api_call(kid, act, "198.51.100.200")
        w.cp.atlas.sync_graph(); fs = w.cp.hearth.poll(); self.assertEqual(len(fs), 2); self.assertEqual((fs[0].confidence, fs[0].technique), (0.97, "T1078.004")); self.assertEqual(fs[0].details["ip"], "198.51.100.200")
        w.clock.advance(200 * DAY); w.cp.atlas.sync_graph(); w.cp.atlas.run_posture()
        self.assertTrue([f for f in w.cp.atlas.posture_findings if "deploy" in f.resource])                       # an ordinary user with an old unused key IS reported...
        self.assertFalse([f for f in w.cp.atlas.posture_findings if "svc-legacy-backup" in f.resource]); self.assertFalse([x for x in w.cp.glass.evaluate() if "svc-legacy-backup" in x.id])


class ShareAndLureTests(unittest.TestCase):
    def test_a_decoy_share_alarms_strongly_on_open_weakly_on_browse_and_not_for_a_scanner_that_is_exempt(self):
        w = World7(); h = w.cp.hearth
        with self.assertRaises(PermissionError): h.create_decoy_share(AN, "Finance-Archive-Old", {"/q3.xlsx": b"fake"})
        h.create_decoy_share(ADM, "Finance-Archive-Old", {"/q3.xlsx": b"generated filler"}); h.poll()
        w.cp.fileserver.list("alice", "10.0.0.7", "LT-17", "Finance-Archive-Old"); w.cp.fileserver.read("alice", "10.0.0.7", "LT-17", "Finance-Archive-Old", "/q3.xlsx")
        fs = h.poll(); self.assertEqual([(f.confidence, f.details["op"]) for f in fs if f.entity_id == "LT-17"], [(0.5, "list"), (0.9, "open")])
        with self.assertRaises(ValueError): h.exempt_account(ADM, "svc-scan", "", 30)
        with self.assertRaises(ValueError): h.exempt_account(ADM, "svc-scan", "weekly inventory scan", 91)
        with self.assertRaises(PermissionError): h.exempt_account(AN, "svc-scan", "weekly inventory scan", 30)
        h.exempt_account(ADM, "svc-scan", "weekly inventory scan", 30); w.cp.fileserver.read("svc-scan", "10.0.0.9", "SCAN01", "Finance-Archive-Old", "/q3.xlsx"); self.assertEqual(h.poll(), [])
        w.clock.advance(31 * DAY); w.cp.fileserver.read("svc-scan", "10.0.0.9", "SCAN01", "Finance-Archive-Old", "/q3.xlsx"); self.assertEqual(len(h.poll()), 1)       # exemptions end

    def test_a_credentials_lure_on_a_laptop_then_the_decoy_account_being_tried_is_one_story_not_two_alerts(self):
        w = World7(); h = w.cp.hearth; approve(w, make(w, "idp_user", DECOY)); w.cp.signet.sync_graph(); did = next(iter(h.decoys))
        root = os.path.join(w.tmp, "docs"); os.makedirs(root); lure = os.path.join(root, "vpn-login.txt")
        place = w.cp.engine.request(ActionRequest("place_tripwires", ADM, ["LT-17"], "credential lure", None, {"specs": [{"id": "lure1", "path": lure, "kind": "credential_lure", "lure_text": h.lure_text(did), "bait": did}]})); self.assertEqual(place.status, "executed")
        self.assertIn(DECOY, open(lure).read()); w.cp.process()
        w.host.spawn(960, "infostealer.exe"); w.fs.read(960, lure)                                                         # the intruder opens the bait on the laptop...
        with self.assertRaises(AuthError): w.cp.idp.sign_in(DECOY, "wrong", "203.0.113.9", dict(country="RU", lat=55, lon=37), device_id="LT-17")   # ...and tries the account
        w.cp.process(); cases = [c for c in w.cp.cases.cases.values() if any(f.source == "hearth" for f in c.findings)]
        self.assertEqual(len(cases), 1); c = cases[0]; self.assertEqual({f.details["detector"] for f in c.findings if f.source == "hearth"}, {"tripwire_touched", "decoy_account_used"})
        conf, why = w.cp.cases.confidence(c); self.assertEqual(conf, 0.95); self.assertIn("LT-17", c.entities); self.assertIn("id:idp:" + DECOY, c.entities)       # one source: the score does not pretend two decoys are independent evidence

    def test_the_catalog_of_decoys_is_visible_only_to_it_and_analysts_and_refusals_are_recorded(self):
        w = World7(); h = w.cp.hearth; h.create_decoy_share(ADM, "Archive-Old", {"/a.txt": b"x"}); h.mint_canary(ADM, "doc_url", "board pack", "srv-fin")
        cat = h.catalog(AN); self.assertEqual([d["ref"] for d in cat["decoys"]], ["Archive-Old"]); self.assertIn("fires only if opened", cat["canaries"][0]["limits"])
        for p in (SD, OWNER, AUD):
            with self.assertRaises(PermissionError): h.catalog(p)
        with self.assertRaises(PermissionError): h.mint_canary(AN, "doc_url", "x", "srv-fin")
        self.assertEqual(sum(1 for e in w.cp.ledger.entries() if e["kind"] == "hearth.denied"), 4)


class CanaryTests(unittest.TestCase):
    def test_a_canary_document_still_reads_as_a_document_carries_the_beacon_and_fires_when_fetched_with_its_limits(self):
        w = World7(); h = w.cp.hearth; t = h.mint_canary(ADM, "doc_url", "Board pack Q3", "srv-fin")
        docx = C.canary_docx(t, ["Board pack, quarter three.", "Revenue discussion."]); text, why = extract_text("board.docx", docx); self.assertIn("Revenue discussion.", text)
        import zipfile, io; rels = zipfile.ZipFile(io.BytesIO(docx)).read("word/_rels/document.xml.rels").decode(); self.assertIn(t.url, rels); self.assertIn('TargetMode="External"', rels)
        self.assertIn(t.url, C.embed_text(t, "<p>notes</p>")); self.assertFalse(w.cp.canary.hit("c-unknown", "198.51.100.5", "ua")); self.assertEqual(h.poll(), [])
        self.assertTrue(w.cp.canary.hit(t.id, "198.51.100.77", "Mozilla/5.0 (X11)")); fs = h.poll()
        self.assertEqual(len(fs), 1); f = fs[0]; self.assertEqual((f.entity_id, f.confidence), ("srv-fin", 0.85)); self.assertIn("Board pack Q3", f.summary); self.assertIn("Scanners and previewers can also", f.why)
        e = next(x for x in w.cp.ledger.entries() if x["kind"] == "hearth.alarm"); self.assertNotIn("198.51.100.77", str(e["public"])); self.assertIn("198.51.100.77", str(e["private"]))

    def test_an_alarm_with_no_known_entity_lands_on_a_hearth_anchor_and_is_never_lost(self):
        w = World7(); t = w.cp.hearth.mint_canary(ADM, "repo_url", "billing-service repo", "git:billing"); w.cp.canary.hit(t.id, "198.51.100.1", "git/2.40")
        fs = w.cp.hearth.poll(); self.assertEqual([f.entity_id for f in fs], ["hearth:decoys"]); self.assertTrue(w.cp.store.has_entity(w.cp.ctx, "hearth:decoys"))

    def test_a_repository_bait_key_that_is_used_is_one_alarm_with_the_source_address(self):
        w = World7(); h = w.cp.hearth; approve(w, make(w, "aws_key", "svc-ci-legacy")); did = next(iter(h.decoys)); bait = h.lure_text(did); self.assertIn("aws_access_key_id=AKIA", bait)
        kid = h.decoys[did].ref
        with self.assertRaises(PermissionError): w.cp.aws.api_call(kid, "s3:GetObject", "198.51.100.66")
        self.assertEqual([f.confidence for f in h.poll()], [0.97])


if __name__ == "__main__":
    unittest.main()
