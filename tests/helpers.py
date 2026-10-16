import atexit, os, sys, tempfile, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from halvard.clock import ManualClock
from halvard.ward.agent import WardAgent, ProtectedFS
from halvard.ward.policy import PolicyBundle
from halvard.relay.host import SimHost

DEV_KEY, UNINSTALL_KEY, POLICY_KEY = b"dev-key-" * 4, b"uninst-k" * 4, b"policy-k" * 4


def make_agent(tmp, asset_class="standard", accepted=("ransomware_stop", "malware_quarantine", "undo"), **bundle_kw):
    clock = ManualClock()
    host = SimHost("LT-17", os.path.join(tmp, "host"))
    b = PolicyBundle(tenant="acme", version=1, accepted_patterns=list(accepted), **bundle_kw).sign(POLICY_KEY)
    a = WardAgent("LT-17", os.path.join(tmp, "agent"), b, host, clock, DEV_KEY, UNINSTALL_KEY, asset_class=asset_class)
    a.install_files({"ward.exe": b"agent-binary", "ward.conf": b"mode=enforce"})
    return a, host, clock, ProtectedFS(a)


# Every test builds worlds in throwaway directories. Remove them when the test process ends so repeated runs (and mutation sweeps)
# cannot fill the disk. (A defect found the hard way: 140,000 leftover directories once exhausted the writable space.)
_TRACKED = []
_orig_mkdtemp = tempfile.mkdtemp


def _tracked_mkdtemp(*a, **k):
    d = _orig_mkdtemp(*a, **k); _TRACKED.append(d); return d


tempfile.mkdtemp = _tracked_mkdtemp


def _cleanup():
    for d in _TRACKED:
        shutil.rmtree(d, ignore_errors=True)


atexit.register(_cleanup)
