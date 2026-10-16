"""Per-OS knowledge the same agent core needs (F001, F002): path semantics, noisy-path exclusions, persistence
locations, quarantine home, and how to render host isolation. Behavior differences live here, not in forks of the agent.

Status by platform (see docs/08): Linux has a real kernel-notification sensor (platforms/linux.py) tested in a
privileged lane. macOS and Windows have profiles and rendered rules only; their native sensors are not built here.
"""
import unicodedata
from dataclasses import dataclass

from ..relay import isolation


@dataclass(frozen=True)
class PlatformProfile:
    name: str
    case_sensitive: bool
    unicode_nfc: bool
    journal_exclude: tuple
    persistence_locations: tuple
    quarantine_dir: str
    sensor: str              # what the native sensor is, and whether it exists in this repository
    render_isolation: callable
    render_release: callable

    def path_key(self, p: str) -> str:
        """Key under which two spellings of one file must collide (case-insensitive volumes, macOS NFD/NFC)."""
        p = p.replace("\\", "/") if self.name == "windows" else p
        if self.unicode_nfc: p = unicodedata.normalize("NFC", p)
        return p if self.case_sensitive else p.lower()


WINDOWS = PlatformProfile(
    "windows", False, False,
    ("*/appdata/local/*", "*/appdata/locallow/*", "*.tmp", "*.log", "*/windows/temp/*", "*/node_modules/*"),
    ("HKLM/HKCU Run and RunOnce keys", "Scheduled tasks", "Services", "Startup folders", "WMI event subscriptions"),
    "C:/ProgramData/Halvard/quarantine", "minifilter driver + ETW (not in this repository)",
    lambda ips, dns=None: isolation.windows_rules(ips, dns), lambda: isolation.windows_release())

MACOS = PlatformProfile(
    "macos", False, True,
    ("*/library/caches/*", "*/library/logs/*", "*/.trash/*", "*/library/containers/*/data/library/caches/*", "*.tmp", "*/node_modules/*"),
    ("~/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons", "Login Items", "cron / at jobs", "shell rc files (.zshrc, .zprofile)"),
    "/Library/Application Support/Halvard/quarantine", "Endpoint Security client + system extension (not in this repository; needs Apple entitlement)",
    lambda ips, dns=None: isolation.macos_pf(ips, dns), lambda: isolation.macos_release())

LINUX = PlatformProfile(
    "linux", True, False,
    ("*/.cache/*", "/var/cache/*", "/var/tmp/*", "/proc/*", "/sys/*", "/run/*", "*.tmp", "*.log", "*/node_modules/*"),
    ("/etc/systemd/system, ~/.config/systemd/user", "/etc/cron*, user crontabs", "shell rc files (.bashrc, .profile)",
     "~/.ssh/authorized_keys", "/etc/ld.so.preload", "/etc/rc.local"),
    "/var/lib/halvard/quarantine", "fanotify permission + FID groups (platforms/linux.py; privileged test lane)",
    lambda ips, dns=None: [isolation.linux_nft(ips, dns)], lambda: [isolation.linux_release()])

PROFILES = {p.name: p for p in (WINDOWS, MACOS, LINUX)}
