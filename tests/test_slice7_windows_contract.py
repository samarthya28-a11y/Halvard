"""Slice 7: the Windows sensor contract and the installer manifests. Neither component is built here."""
import hashlib, os, unittest
from pathlib import Path
from helpers import *
from halvard import sensor
from halvard.install.manifest import INSTALL_MANIFEST, UPDATE_MANIFEST
from test_sensor_conformance import FIX, ReplayTests

WIN = ("win_prefix", "short_name", "ads_document", "ads_tripwire", "delete_on_close", "delete_on_close_tripwire")


class WindowsSensorContract(unittest.TestCase):
    def replay(self, name):
        return ReplayTests().run_fixture(name)

    def test_a_win_prefix_write_changes_the_named_file(self):
        header, events, res, _, root, seeded = self.replay("win_prefix")
        self.assertEqual([d for _, d in res], ["allow"])
        target = os.path.join(root, "docs", "budget.xlsx")
        self.assertEqual(Path(target).read_bytes(), sensor.materialize(events[0]["data"]))
        self.assertEqual(hashlib.sha256(Path(target).read_bytes()).hexdigest(), hashlib.sha256(sensor.materialize(events[0]["data"])).hexdigest())
        self.assertFalse(any("?" in p.name for p in Path(root).rglob("*")))

    def test_a_short_name_is_the_long_file(self):
        _, events, res, _, root, _ = self.replay("short_name")
        self.assertEqual([d for _, d in res], ["allow"])
        long = Path(root, "docs", "quarter-budget.xlsx")
        self.assertEqual(long.read_bytes(), sensor.materialize(events[0]["data"]))
        self.assertFalse((Path(root) / "docs" / "BUDGET~1.XLS").exists())

    def test_an_alternate_stream_does_not_replace_the_file_and_a_tripwire_stream_is_stopped(self):
        _, events, res, _, root, seeded = self.replay("ads_document")
        self.assertEqual([d for _, d in res], ["allow"])
        main = Path(root, "docs", "notes.docx")
        self.assertEqual(hashlib.sha256(main.read_bytes()).hexdigest(), seeded[str(main)])
        self.assertEqual((Path(str(main) + ":Zone.Identifier")).read_bytes(), sensor.materialize(events[0]["data"]))
        _, _, res2, _, root2, _ = self.replay("ads_tripwire")
        self.assertEqual([d for _, d in res2], ["deny"])
        tw = Path(root2, "docs", "!000-budget.xlsx")
        self.assertTrue(tw.exists())
        self.assertFalse(Path(str(tw) + ":Zone.Identifier").exists())

    def test_delete_on_close_removes_an_ordinary_file_and_stops_on_a_tripwire(self):
        _, _, res, _, root, _ = self.replay("delete_on_close")
        self.assertEqual([d for _, d in res], ["allow"])
        self.assertFalse((Path(root) / "docs" / "notes.docx").exists())
        _, _, res2, _, root2, _ = self.replay("delete_on_close_tripwire")
        self.assertEqual([d for _, d in res2], ["deny"])
        self.assertTrue((Path(root2) / "docs" / "!000-budget.xlsx").exists())

    def test_each_windows_fixture_matches_its_golden_and_is_in_the_folder(self):
        names = sorted(p.stem for p in FIX.glob("*.jsonl"))
        for n in WIN:
            self.assertIn(n, names)
            header, _, res, _, _, _ = self.replay(n)
            self.assertEqual("".join("A" if d == "allow" else "D" for _, d in res), header["golden"], n)


class InstallerManifestTests(unittest.TestCase):
    def test_the_install_and_update_manifests_name_the_service_the_files_and_the_rollback_rules(self):
        for m in (INSTALL_MANIFEST, UPDATE_MANIFEST):
            self.assertEqual(m["service_name"], "HalvardGuard")
            self.assertIn("halvard-svc.exe", m["files"])
            self.assertEqual(m["decoys_removed_by"], "remove")
            self.assertEqual(m["configure_failure"], "rollback")
            self.assertFalse(m["built"])
        root = Path(__file__).resolve().parent.parent
        wxs = (root / "native" / "installer" / "halvard.wxs").read_text(encoding="utf-8")
        service = (root / "native" / "halvard-svc" / "src" / "service.rs").read_text(encoding="utf-8")
        self.assertIn('Name="HalvardGuard"', wxs)
        self.assertNotIn("halvard.conf", wxs)
        self.assertNotIn("halvard.conf", service)
        self.assertIn("service.json", service)
        for m in (INSTALL_MANIFEST, UPDATE_MANIFEST):
            self.assertNotIn("halvard.conf", m["files"])
            self.assertEqual(m["files"], ["halvard-svc.exe"])
        self.assertEqual(INSTALL_MANIFEST["kind"], "install")
        self.assertEqual(UPDATE_MANIFEST["kind"], "update")
        self.assertNotEqual(INSTALL_MANIFEST["files"], [])


if __name__ == "__main__":
    unittest.main()
