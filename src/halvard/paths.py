"""Where the shipped policy/data files live: the repository's policy folder, or the folder bundled inside halvard.exe."""
import sys
from pathlib import Path


def policy_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "policy"
    return Path(__file__).resolve().parents[2] / "policy"
