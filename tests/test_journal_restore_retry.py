"""A restore that meets a file Windows is briefly holding (virus scanner, indexer) must retry, and a file that stays unavailable must be reported without stopping the rest.
Found when the full suite on Windows failed at random with PermissionError inside rollback (the same cause the ledger anchor already retries for)."""
import os, tempfile, unittest, unittest.mock as m
from pathlib import Path
from helpers import *


class RestoreRetry(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.a, self.host, self.clock, self.fs = make_agent(self.tmp)
        self.work = Path(self.tmp) / "docs"; self.work.mkdir(); self.a.set_online(False); self.host.spawn(4242, "burst.exe")
        self.files = {}
        for name in ("a.txt", "locked.txt", "c.txt"):
            p = self.work / name; p.write_bytes(b"ORIGINAL-" + name.encode()); self.files[name] = p
            self.fs.overwrite(4242, str(p), b"ENCRYPTED")

    def replace_that_fails(self, target, times):
        real, state = os.replace, {"n": 0}
        def wrapper(src, dst, *a, **k):
            if str(dst).endswith(target) and state["n"] < times:
                state["n"] += 1; raise PermissionError(13, "Access is denied")
            return real(src, dst, *a, **k)
        return wrapper

    def test_a_file_that_is_briefly_locked_is_still_restored(self):
        with m.patch("os.replace", self.replace_that_fails("locked.txt", 4)), m.patch("halvard.relay.journal.time.sleep"):
            rep = self.a.journal.rollback([4242])
        self.assertEqual(self.files["locked.txt"].read_bytes(), b"ORIGINAL-locked.txt")
        self.assertTrue(rep.complete, rep)

    def test_a_file_that_stays_locked_is_reported_and_the_others_are_still_restored(self):
        with m.patch("os.replace", self.replace_that_fails("locked.txt", 10**6)), m.patch("halvard.relay.journal.time.sleep"):
            rep = self.a.journal.rollback([4242])
        self.assertEqual(self.files["a.txt"].read_bytes(), b"ORIGINAL-a.txt")
        self.assertEqual(self.files["c.txt"].read_bytes(), b"ORIGINAL-c.txt")
        self.assertEqual(self.files["locked.txt"].read_bytes(), b"ENCRYPTED")
        named = {Path(p).name: why for p, why in rep.not_restorable}
        self.assertIn("locked.txt", named); self.assertIn("could not be restored", named["locked.txt"])
        self.assertNotIn(str(self.files["locked.txt"]), rep.restored)
        self.assertFalse(rep.complete)
        self.assertEqual([p.name for p in self.work.iterdir() if p.name.endswith(".halvard-restore")], [], "no temporary file is left behind")


if __name__ == "__main__":
    unittest.main()
