import unittest
from helpers import *
from rig5 import *
from halvard.atlas.saas import SaasCatalog


class SaasTests(unittest.TestCase):
    def test_discovery_from_the_identity_provider_and_the_proxy_log_with_reasons(self):
        w = World5(); idp = w.cp.idp; idp.add_app("evil", "Shiny Mail Tool", publisher_verified=False, created_at=w.clock.now() - 2 * 86400); idp.grant_consent("alice@acme.com", "evil", ["Mail.Read", "Files.ReadWrite.All"]); idp.grant_consent("alice@acme.com", "mail", ["User.Read"]); idp.grant_consent("bob@acme.com", "evil", ["Mail.Read"])
        cat = SaasCatalog(sanctioned=["files.acme-approved.example", "mail"], personal=["dropbox.com"])
        apps = cat.discover(idp, [("alice", "dropbox.com", 80 << 20), ("bob", "dropbox.com", 1 << 20), ("alice", "files.acme-approved.example", 10), ("carol", "random-share.example", 5)])
        by = {a.key: a for a in apps}; self.assertEqual(by["dropbox.com"].state, "personal"); self.assertEqual(by["dropbox.com"].users, {"alice", "bob"}); self.assertEqual(by["evil"].users, {"alice@acme.com", "bob@acme.com"})
        ev = cat.rate(by["evil"]); self.assertEqual(ev["rating"], "high"); self.assertTrue(any("publisher is not verified" in r for r in ev["reasons"]) and any("read and write mail and files" in r for r in ev["reasons"]))
        dp = cat.rate(by["dropbox.com"]); self.assertEqual(dp["rating"], "medium"); self.assertTrue("personal storage" in " ".join(dp["reasons"]) and "81 MB uploaded" in " ".join(dp["reasons"]) or "80 MB uploaded" in " ".join(dp["reasons"]), dp)
        self.assertEqual(cat.rate(by["files.acme-approved.example"])["rating"], "low"); self.assertEqual(apps[-1].state, "sanctioned")                    # unapproved apps are listed first

    def test_a_revoked_grant_stops_counting_and_the_table_feeds_device_upload_rules(self):
        w = World5(); w.cp.idp.add_app("evil", "Shiny Mail Tool", publisher_verified=False); w.cp.idp.grant_consent("alice@acme.com", "evil", ["Mail.Read"]); w.cp.idp.revoke_grant("alice@acme.com", "evil"); cat = SaasCatalog(sanctioned=["a.example"], personal=["dropbox.com"])
        self.assertNotIn("evil", {a.key for a in cat.discover(w.cp.idp)}); m = cat.dlp_map({"x.example": "sanctioned"}); self.assertEqual((m["a.example"], m["dropbox.com"], m["x.example"]), ("sanctioned", "personal", "sanctioned"))
        self.assertEqual(cat.state_of("sub.dropbox.com"), "personal"); self.assertEqual(cat.state_of("notdropbox.com"), "unsanctioned")


class RatingTests(unittest.TestCase):
    def test_an_unverified_publisher_raises_the_rating_and_says_why(self):
        from halvard.atlas.saas import AppRecord, SaasCatalog
        base = dict(key="x", name="X", state="unsanctioned")
        a = SaasCatalog.rate(AppRecord(**base, publisher_verified=True)); b = SaasCatalog.rate(AppRecord(**base, publisher_verified=False))
        self.assertEqual((a["rating"], b["rating"]), ("low", "medium")); self.assertIn("publisher is not verified", b["reasons"])


if __name__ == "__main__":
    unittest.main()
