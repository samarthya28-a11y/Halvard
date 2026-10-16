"""Evidence that a control FIRED, not only that a policy says it should (F100).

A control is proven in one of two ways, and the report never mixes them:
  - real: the Ledger (or a device spool) holds entries tagged with the control, from real traffic
  - exercised: a safe, scoped simulation the customer authorized ran and the control did its job; the device entries it produced are set aside and
    are NOT counted as real firings
A control that has done neither is listed as 'never fired'. That is not a failure; it may mean nothing needed it. It does mean the
control has not been seen working.
"""
import hashlib, os

from ..ward import simulate as sim

# (control id, outcome 1..5, module, plain name)
CATALOG = [
    ("WARD.BEHAVIORAL_STOP", 2, "Ward", "Stops bulk file encryption on the device"),
    ("WARD.PRE_EXECUTION_VERDICT", 2, "Ward", "Judges a program before it runs"),
    ("WARD.OFFLINE_PREVENTION", 2, "Ward", "Keeps blocking with no internet"),
    ("WARD.TAMPER_PROTECTION", 2, "Ward", "Notices and resists tampering with the agent"),
    ("WARD.POLICY_INTEGRITY", 2, "Ward", "Accepts only signed, newer policy"),
    ("WARD.COVERAGE", 1, "Ward", "Raises an incident when a protected machine goes quiet"),
    ("RELAY.ISOLATE_HOST", 3, "Relay", "Isolates a device and keeps the management channel"),
    ("RELAY.APPROVAL_GATES", 3, "Relay", "Holds risky actions for the right approvers"),
    ("RELAY.COMMAND_CHANNEL", 3, "Relay", "Delivers signed commands to devices"),
    ("RELAY.JOURNAL_ROLLBACK", 4, "Relay", "Puts files back from Halvard's own record"),
    ("SIGNET.DETECTION", 2, "Signet", "Spots stolen or misused sign-ins"),
    ("COURIER.DETECTION", 2, "Courier", "Spots harmful or impersonating mail"),
    ("ATLAS.POSTURE", 1, "Atlas", "Finds risky cloud settings"),
    ("ATLAS.DETECTION", 2, "Atlas", "Spots risky cloud changes as they happen"),
    ("VAULTLINE.USB_CONTROL", 3, "Vaultline", "Limits regulated data on removable drives"),
    ("VAULTLINE.EMAIL_CONTROL", 3, "Vaultline", "Holds regulated data going to outside addresses"),
    ("GLASS.EXPOSURE_RANKING", 1, "Glass", "Ranks open weaknesses by what matters most"),
    ("GLASS.COMPENSATING_CONTROL", 1, "Glass", "Holds a weakness shut until a patch can land"),
    ("GLASS.PATCH_RINGS", 1, "Glass", "Rolls updates out in rings and stops a bad one"),
    ("LUMEN.AI_INVENTORY", 1, "Lumen", "Lists the AI tools people use, approved or not"),
    ("LUMEN.AI_DATA_POLICY", 3, "Lumen", "Limits which data goes to which AI tools"),
    ("LUMEN.AGENT_GATEWAY", 3, "Lumen", "Allows, asks or blocks each AI agent tool call"),
    ("HEARTH.TRIPWIRES", 2, "Hearth", "Stops ransomware early and alarms on decoys"),
    ("HARBOR.DISCOVERY", 1, "Harbor", "Finds devices on a site network that nobody accounted for"),
    ("FABRIC.DELEGATION", 3, "Platform", "Lets outsiders in only through grants the company opened"),
    ("KEEPER.CHARTER", 3, "Keeper", "Keeps the crew inside the company's written list"),
    ("FABRIC.CUSTOMER_KEYS", 3, "Platform", "Locks a company's data when its own key is withdrawn"),
    ("LEDGER.INTEGRITY", 5, "Ledger", "Keeps a tamper-evident record"),
]
OUTCOMES = {1: "Shrink what can be hit", 2: "Stop active harm", 3: "Limit the blast radius", 4: "Restore the work", 5: "Prove it"}


class ControlEvidence:
    def __init__(self, ledger, fleet, clock, window_days=90, catalog=CATALOG):
        self.ledger, self.fleet, self.clock, self.window, self.catalog = ledger, fleet, clock, window_days * 86400, catalog
        self.exercised, self._skip = {}, {}

    def _real(self):
        got = {}
        def see(rec):
            for c in rec.get("controls", ()):
                g = got.setdefault(c, {"n": 0, "last": None}); g["n"] += 1; g["last"] = max(g["last"] or 0, rec["ts"])
        for rec in self.ledger.entries(): see(rec)
        for d, a in self.fleet.agents.items():
            skip = self._skip.get(d, [])
            for rec in a.spool.entries():
                if not any(lo < rec["seq"] <= hi for lo, hi in skip): see(rec)
        return got

    def report(self):
        now, real, out = self.clock.now(), self._real(), []
        for cid, outcome, module, name in self.catalog:
            r, ex = real.get(cid), self.exercised.get(cid)
            if r and now - r["last"] <= self.window: st = "fired"
            elif ex and now - ex["ts"] <= self.window: st = "exercised"
            elif r: st = "stale"
            else: st = "never_fired"
            out.append({"control": cid, "outcome": outcome, "module": module, "name": name, "status": st, "real_firings": r["n"] if r else 0,
                        "last_real": r["last"] if r else None, "last_exercised": ex["ts"] if ex else None, "evidence": ex["evidence"] if ex and st == "exercised" else None})
        return out

    def proven_share(self):
        rep = self.report(); return sum(1 for x in rep if x["status"] in ("fired", "exercised")), len(rep)

    def exercise_ransomware_stop(self, principal, agent, fs, root, pid=9100):
        """Run a safe ransomware-style burst on test files the customer put in an authorized folder, and check that Ward stopped it and the files came back.
        The burst is plain overwrite/rename on those files only. Isolation that Ward applies is released again afterwards."""
        if principal.role not in ("it_admin", "analyst"): raise PermissionError("Running a control exercise needs it_admin or analyst")
        sim_files = sorted(str(p) for p in __import__("pathlib").Path(root).rglob("*") if p.is_file() and p.name != sim.MARKER)
        if not sim_files: raise ValueError("the authorized folder has no test files; seed some first")
        orig = {p: open(p, "rb").read() for p in sim_files}; before = {p: hashlib.sha256(b).hexdigest() for p, b in orig.items()}
        seq0 = agent.spool.head[0]; agent.host.spawn(pid, "halvard-exercise.exe", exe_sha256="ab" * 32)
        n_inc = len(agent.incidents)
        try: touched = sim.run_simulation(fs, pid, root)
        except sim.SimulationNotAuthorized: raise
        released = False
        if len(agent.incidents) > n_inc:
            for step, status, _msg, aid in agent.incidents[-1]["results"]:
                if step == "isolate_host" and status == "executed" and aid:
                    agent.engine.undo(aid, principal); released = agent.host.isolated is False
        self._skip.setdefault(agent.device_id, []).append((seq0, agent.spool.head[0]))
        stopped = len(agent.incidents) > n_inc and any(r[0] == "stop_process" and r[1] == "executed" for r in agent.incidents[-1]["results"])      # detected AND the process was actually stopped
        restored = sum(1 for p, h in before.items() if os.path.exists(p) and hashlib.sha256(open(p, "rb").read()).hexdigest() == h)
        cleaned = 0
        if restored != len(before):         # the exercise never leaves the customer's test folder damaged, whatever Ward did
            root_p = __import__("pathlib").Path(root)
            for q in root_p.rglob("*"):
                if q.is_file() and q.name != sim.MARKER and str(q) not in orig: q.unlink(); cleaned += 1
            for q, b in orig.items():
                if not os.path.exists(q) or open(q, "rb").read() != b: open(q, "wb").write(b); cleaned += 1
        ev = {"device": agent.device_id, "files_touched_before_stop": touched, "files_total": len(before), "stopped": stopped, "files_restored": restored, "isolation_released": released, "test_files_repaired_by_cleanup": cleaned}
        ok = stopped and restored == len(before)
        if ok:
            for c in ("WARD.BEHAVIORAL_STOP", "RELAY.JOURNAL_ROLLBACK"): self.exercised[c] = {"ts": self.clock.now(), "evidence": ev}
            if any(r[0] == "isolate_host" and r[1] == "executed" for r in agent.incidents[-1]["results"]): self.exercised["RELAY.ISOLATE_HOST"] = {"ts": self.clock.now(), "evidence": ev}
        self.ledger.append("glass.control_exercised", "halvard:glass", "system", agent.device_id, {**ev, "ok": ok, "by": principal.id, "simulation": True}, controls=("GLASS.CONTROL_EXERCISE",))
        return {"ok": ok, **ev}
