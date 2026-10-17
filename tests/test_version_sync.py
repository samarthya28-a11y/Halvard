"""One product version everywhere: the Python package, the Rust service (it prints this version and the MSI is named after the Python one), and the changelog."""
import re, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class VersionSync(unittest.TestCase):
    def test_python_rust_and_changelog_agree(self):
        py = re.search(r'__version__\s*=\s*"([^"]+)"', (ROOT / "src" / "halvard" / "__init__.py").read_text(encoding="utf-8")).group(1)
        cargo = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "native" / "halvard-svc" / "Cargo.toml").read_text(encoding="utf-8"), re.M).group(1)
        top = re.search(r"^## (\d+\.\d+\.\d+)", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), re.M).group(1)
        self.assertEqual((cargo, top), (py, py), "bump src/halvard/__init__.py, native/halvard-svc/Cargo.toml and the top CHANGELOG entry together")


if __name__ == "__main__":
    unittest.main()
