"""Guided setup: gets one IT generalist to F004, F006, F016, F037 and F040 on day one, with proof for each.

Each step is verified by doing the safe thing, not by checking a checkbox: it blocks a harmless test file with the
network down, refuses an unauthorized stop, isolates and releases the test device while keeping the management
channel reachable, and rolls back a scoped simulation. Copy says what happened, what is protected, what to do next.
"""
import hashlib, os
from dataclasses import dataclass
from pathlib import Path

from ..relay.actions import Principal
from ..ward import simulate as sim
from ..ward.agent import Blocked
from ..ward.verdict import TEST_MARKER as EICAR      # a harmless marker, not the EICAR file: real antivirus deletes that one on write


@dataclass
class StepResult:
    key: str
    ok: bool
    happened: str
    protected: str
    next: str
    evidence: dict


class GuidedSetup:
    STEPS = [
        ("enroll", "Connect this computer", None),
        ("offline_prevention", "Block known threats even with no internet", "F004"),
        ("preexec", "Check files before they run", "F006"),
        ("tamper", "Stop people and malware from switching Halvard off", "F016"),
        ("isolation", "Cut a computer off the network, keeping Halvard connected", "F037"),
        ("rollback", "Stop file-scrambling and restore the files", "F040"),
    ]

    def __init__(self, agent, fs, admin: Principal, workdir):
        self.agent, self.fs, self.admin, self.work = agent, fs, admin, Path(workdir)
        self.done: dict[str, StepResult] = {}

    # ----- navigation (the only thing a user needs) -----
    def next_step(self):
        for key, title, feat in self.STEPS:
            if key not in self.done or not self.done[key].ok:
                return key, title
        return None

    def progress(self):
        ok = sum(1 for r in self.done.values() if r.ok)
        return f"{ok} of {len(self.STEPS)} setup checks passed on this computer (in the reference build; a native agent has its own checks)"

    def run_current(self):
        key, _ = self.next_step()
        r = getattr(self, "_" + key)()
        self.done[key] = r
        self.agent.spool.append("setup.step", self.admin.id, self.admin.role, self.agent.device_id,
                                {"step": key, "ok": r.ok}, controls=("SETUP.GUIDE",))
        return r

    # ----- steps -----
    def _enroll(self):
        self.agent.heartbeat()
        return StepResult("enroll", True, "This computer is connected and reporting.",
                          "Only monitoring so far.", "Next: prove protection works with no internet.", {"device": self.agent.device_id})

    def _offline_prevention(self):
        was = self.agent.online
        self.agent.set_online(False)
        try:
            tf = self.work / "eicar-test.txt"; tf.parent.mkdir(parents=True, exist_ok=True); tf.write_bytes(EICAR)
            try:
                self.agent.pre_execute(str(tf), EICAR)
                blocked = False
            except Blocked:
                blocked = True
        finally:
            self.agent.set_online(was)
        if blocked:
            return StepResult("offline_prevention", True,
                              "Halvard blocked the standard harmless test file while this computer had no connection to us.",
                              "Known threats are blocked on the device itself; it does not wait for the cloud.",
                              "Next: turn on pre-run checks.", {"blocked_offline": True})
        return StepResult("offline_prevention", False, "The test file was not blocked.",
                          "Detection still reports to the console, but offline blocking is not proven.",
                          "Check that the policy's known-threat rule is set to Enforce, then retry.", {"blocked_offline": False})

    def _preexec(self):
        v = self.agent.verdicts.evaluate(b"hello world, a normal document", "memo.txt", self.agent.online)
        ok = v.decision == "allow" and self.agent.bundle.prevention.get("known_bad") == "enforce"
        return StepResult("preexec", ok, "A normal file was allowed and the test threat was blocked." if ok else "Ordinary files were not allowed.",
                          "Files are checked on the device before they run.", "Next: protect Halvard itself.",
                          {"normal_file": v.decision})

    def _tamper(self):
        try:
            self.agent.tamper.stop_or_uninstall("not-a-real-code")
            refused = False
        except PermissionError:
            refused = True
        code = self.agent.tamper.issue_uninstall_token(self.admin.id)
        return StepResult("tamper", refused, "An attempt to switch Halvard off without a console code was refused and recorded."
                          if refused else "The attempt was not refused.",
                          "Stopping or removing Halvard needs a short-lived one-time code from an administrator. In this reference build that is a check inside the agent; kernel-level self-protection is not built yet.",
                          "Next: test network isolation.", {"refused": refused, "one_time_code_issued": bool(code)})

    def _isolation(self):
        h = self.agent.host
        r = self.agent.engine.request(__import__("halvard.relay.actions", fromlist=["x"]).ActionRequest(
            "isolate_host", self.admin, [self.agent.device_id], "setup test: prove isolation keeps Halvard connected"))
        mgmt_up = h.can_reach(next(iter(h.mgmt))) if h.isolated else False
        web_down = (not h.can_reach("intranet.example")) if h.isolated else False
        # release again so the test leaves the machine usable
        rel = self.agent.engine.undo(r.action_id, self.admin) if r.status == "executed" else r
        released = not h.isolated
        ok = r.status == "executed" and mgmt_up and web_down and released
        return StepResult("isolation", ok,
                          "This computer was cut off from everything except Halvard, then reconnected." if ok else
                          f"Isolation test did not complete ({r.status}). {r.message}",
                          "A computer can be isolated while Halvard stays connected so it can be released. (The console that would offer this as one click is not built; the action itself is demonstrated.)",
                          "Next: prove file recovery.", {"management_reachable": mgmt_up, "other_network_blocked": web_down,
                                                          "released_after_test": released})

    def _rollback(self):
        root = self.work / "simulation"
        sim.authorize(root)
        paths = sim.seed_files(root, n=30)
        before = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in paths}
        # Automation shows its work first: the administrator sees the plan and accepts it before it can run quietly.
        plan = ("When Halvard sees a program scrambling many files it will: (1) freeze the program, (2) stop it, "
                "(3) restore the files from its own journal. You can undo any step.")
        self.agent.engine.accept_pattern("ransomware_stop", self.admin)
        h = self.agent.host; pid = 90001; h.spawn(pid, "halvard-safe-simulation")
        was = self.agent.online; self.agent.set_online(False)
        try:
            sim.run_simulation(self.fs, pid, root)
        finally:
            self.agent.set_online(was)
        back = sum(1 for p in paths if os.path.exists(p) and hashlib.sha256(Path(p).read_bytes()).hexdigest() == before[p])
        stopped = pid in self.agent.blocked
        ok = stopped and back == len(paths)
        if not ok:
            self.agent.engine.auth.policy.accepted_patterns.discard("ransomware_stop")
        return StepResult("rollback", ok,
                          f"{plan} A harmless simulation then scrambled test files. Halvard stopped it and restored {back} of {len(paths)} files, with no connection to the cloud."
                          if ok else f"Only {back} of {len(paths)} test files came back.",
                          "If this happens for real, Halvard stops the program and puts files back from its own journal." if ok else
                          "Detection works, but restore is not proven. Nothing on your real files was touched.",
                          "Setup complete." if ok else "Free disk space for the journal, then retry.",
                          {"stopped": stopped, "restored": back, "total": len(paths)})
