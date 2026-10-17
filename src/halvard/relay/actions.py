"""Action fabric. Every action has an actor, reason, scope, approval rule and reversal path, and is recorded.

Flow: request -> authorize actor -> resolve requirement from the authority matrix (strictest target class) ->
automation gate (first-run patterns must be accepted by the customer) -> maintenance/legal-hold gates ->
approvals -> preview -> apply -> ledger. Anything unclear fails closed into a pending proposal or a denial.
"""
import hashlib, json, os, shutil, time
from dataclasses import dataclass, field
from pathlib import Path

from .authority import Authority, Requirement, ORDER
from .matrix_def import BY_KEY
from .journal import RollbackReport
from ..ledger.audit import opaque


def scope_item(t):
    """What an action touched, as it may appear in the PUBLIC half of the Ledger: an entity id as is, a file path only as a stable token (the real path is in the private fields)."""
    s = str(t); return "path:" + opaque(s)[2:] if ("/" in s or "\\" in s) else s

CLEANUP = {"remove_persistence", "config_rollback", "journal_rollback", "quarantine_file", "reset_credentials"}
JIT_ROLES = {"keeper_crew", "service_provider", "halvard_support"}


@dataclass
class Principal:
    id: str
    role: str
    elevated_until: float = 0.0     # just-in-time elevation for staff/Keeper/providers


@dataclass
class ActionRequest:
    action: str
    actor: Principal
    targets: list                   # entity ids (or paths for file actions)
    reason: str
    case_id: str | None = None
    params: dict = field(default_factory=dict)
    automatic: bool = False
    pattern: str | None = None      # automation pattern id, e.g. "ransomware_stop"
    critical: bool = False          # case severity; critical cases are never delayed by windows


@dataclass
class Result:
    status: str                     # executed | pending_approval | pending_pattern_acceptance | denied | deferred | blocked
    action_id: str | None = None
    message: str = ""
    preview: dict | None = None
    requirement: Requirement | None = None
    detail: dict = field(default_factory=dict)
    cannot_undo: list = field(default_factory=list)


class ActionEngine:
    def __init__(self, authority: Authority, ledger, clock, host, journal, state_dir, asset_class_of=None,
                 device_id="device", evidence_dir=None):
        self.auth, self.ledger, self.clock, self.host, self.journal = authority, ledger, clock, host, journal
        self.state = Path(state_dir); self.state.mkdir(parents=True, exist_ok=True)
        self.class_of = asset_class_of or (lambda t: "standard")
        self.device_id = device_id
        self.evidence_dir = Path(evidence_dir or (self.state / "evidence"))
        self.pending, self.executed, self.holds, self._n = {}, {}, {}, 0
        self.deferred = {}      # actions held back by a maintenance window: id -> {req, until}; offer_due() asks again once the window has ended
        self.adapters = __import__("types").SimpleNamespace()     # identity providers, directory, fleet, notifier (control plane only)
        self.handlers = {
            "isolate_host": _Isolate(), "release_isolation": _Release(), "stop_process": _Stop(),
            "quarantine_file": _Quarantine(), "release_quarantine": _ReleaseQ(),
            "journal_rollback": _Rollback(), "config_rollback": _ConfigRollback(),
            "remove_persistence": _RemovePersistence(), "legal_hold": _LegalHold(),
            "install_update": _InstallUpdate(), "rollback_update": _RollbackUpdate(),
            "remote_command": _RemoteCommand(), "undo_action": _Undo(), "collect_forensics": _Collect(),
        }

    # ---------------------------------------------------------------- public
    def request(self, req: ActionRequest) -> Result:
        a = BY_KEY.get(req.action)
        if not a or req.action not in self.handlers:
            return self._deny(req, f"'{req.action}' is not available in this build")
        err = self._authorize_actor(req, a)
        if err:
            return self._deny(req, err)
        classes = [self.class_of(t) for t in req.targets] or ["standard"]
        reqmt = self.auth.strictest([self.auth.requirement(req.action, c) for c in classes])
        h = self.handlers[req.action]
        extra = getattr(h, "extra_requirements", None)
        if extra:       # composite actions are only as permissive as their strictest component
            reqmt = self.auth.strictest([reqmt] + extra(self, req))
        if req.actor.role == "keeper_crew" and a["keeper"] == "propose_only" and ORDER[reqmt.level] < ORDER["approve"]:
            reqmt = Requirement("approve", a["approve_roles"], 1)       # Keeper proposes; a customer approver runs it
        plan = h.preview(self, req)
        if plan.get("invalid"):
            return self._deny(req, plan["summary"])
        # gate: maintenance window (F049/F122)
        win = self._window(req)
        if win and a["destructive"] and not req.critical:
            self._n += 1; did = f"defer-{self._n}"; self.deferred[did] = {"req": req, "until": win[1]}
            self._log("relay.action_deferred", req, {"until": win[1], "deferred": did}, ("RELAY.MAINTENANCE_WINDOWS",))
            return Result("deferred", action_id=did, message=f"{req.targets[0]} is in a maintenance window until {int(win[1])}. The request is kept ({did}) and is asked again "
                          "on the first cycle after the window ends. Critical cases are never deferred.", preview=plan,
                          requirement=reqmt)
        # gate: legal hold (F048)
        if req.case_id and self.holds.get(req.case_id) == "unfrozen" and req.action in CLEANUP:
            self._log("relay.action_blocked", req, {"why": "legal hold: evidence not yet frozen"}, ("RELAY.LEGAL_HOLD",))
            return Result("blocked", message="This case is under legal hold and its evidence is not frozen yet. "
                          "Freeze the evidence, then retry; nothing was changed.", preview=plan, requirement=reqmt)
        # gate: automation must be accepted first (shows its work)
        if req.automatic and not reqmt.needs_human:
            if req.pattern not in self.auth.policy.accepted_patterns:
                return self._park(req, reqmt, plan, "pending_pattern_acceptance",
                                  "Automatic action prepared. It has not run: this pattern has not been accepted yet. "
                                  "Review the preview, then accept the pattern to let it run quietly next time.")
        if reqmt.needs_human or (req.actor.role == "keeper_crew" and a["keeper"] == "propose_only"):
            return self._park(req, reqmt, plan, "pending_approval",
                              f"Waiting for {reqmt.approvals_needed} approval(s) from: {', '.join(reqmt.approve_roles)}.")
        return self._apply(req, reqmt, plan, approvals=[])

    def offer_due(self):
        """Ask again for every deferred action whose window has ended. Called by the control plane's cycle and by the agent's heartbeat; there is no separate scheduler."""
        out = []
        for did in [d for d, v in self.deferred.items() if v["until"] <= self.clock.now()]:
            v = self.deferred.pop(did); out.append(self.request(v["req"]))
        return out

    def request_authorized(self, req: ActionRequest, cmd: dict) -> Result:
        """Run an action whose approvals were gathered by the control plane and carried in a verified command.
        Actor/approval gating is replaced by the command's authorization; maintenance and legal-hold gates still apply."""
        h = self.handlers.get(req.action)
        if h is None: return self._deny(req, f"'{req.action}' is not available on this device")
        plan = h.preview(self, req)
        if plan.get("invalid"): return self._deny(req, plan["summary"])
        if self._window(req) and BY_KEY[req.action]["destructive"] and not req.critical:
            self._log("relay.action_deferred", req, {"command": cmd["id"]}, ("RELAY.MAINTENANCE_WINDOWS",)); return Result("deferred", message="maintenance window", preview=plan)
        if req.case_id and self.holds.get(req.case_id) == "unfrozen" and req.action in CLEANUP:
            return Result("blocked", message="legal hold: freeze evidence first", preview=plan)
        approvers = [Principal(a["id"], a["role"]) for a in cmd["approvals"]]
        reqmt = Requirement(cmd["rule"], BY_KEY[req.action]["approve_roles"], len(approvers))
        return self._apply(req, reqmt, plan, approvers, pending_id=cmd["id"])

    def approve(self, pid, approver: Principal) -> Result:
        item = self.pending.get(pid)
        if not item:
            return Result("denied", message="No such pending action.")
        req, reqmt, plan = item["req"], item["reqmt"], item["plan"]
        a = BY_KEY[req.action]
        if approver.role in JIT_ROLES and not self._jit(approver):
            return self._deny(req, "approver elevation expired", approver)
        if approver.role not in a["approve_roles"] or approver.role == "keeper_crew":
            return self._deny(req, f"role {approver.role} cannot approve {req.action}", approver)
        if approver.id == req.actor.id:
            return self._deny(req, "requester cannot approve their own action", approver)
        if approver.id in {x.id for x in item["approvals"]}:
            return self._deny(req, "this person already approved", approver)
        item["approvals"].append(approver)
        self._log("relay.approval_given", req, {"pending": pid, "approver_role": approver.role,
                  "approvals": len(item["approvals"]), "needed": reqmt.approvals_needed, "user": approver.id},
                  ("RELAY.APPROVAL_GATES",), actor=approver)
        if len(item["approvals"]) >= reqmt.approvals_needed:
            del self.pending[pid]
            return self._apply(req, reqmt, plan, item["approvals"], pid)
        return Result("pending_approval", message=f"{len(item['approvals'])} of {reqmt.approvals_needed} approvals.",
                      preview=plan, requirement=reqmt)

    def accept_pattern(self, pattern, by: Principal):
        if by.role not in ("it_admin", "owner", "analyst"):
            raise PermissionError("only an administrator may accept an automation pattern")
        self.auth.policy.accepted_patterns.add(pattern)
        self.ledger.append("relay.pattern_accepted", by.id, by.role, pattern, {}, controls=("RELAY.AUTOMATION_GATE",))

    def freeze_evidence(self, case_id, paths, by: Principal):
        """Copy named items into the evidence store with hashes before cleanup (F048)."""
        d = self.evidence_dir / case_id; d.mkdir(parents=True, exist_ok=True)
        manifest = {}
        for p in paths:
            if os.path.isfile(p):
                h = hashlib.sha256(Path(p).read_bytes()).hexdigest()
                shutil.copyfile(p, d / h); manifest[str(p)] = h
        (d / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        self.holds[case_id] = "frozen"
        self.ledger.append("relay.evidence_frozen", by.id, by.role, case_id, {"items": len(manifest), "paths": list(manifest)},
                           controls=("RELAY.LEGAL_HOLD",))

    # ---------------------------------------------------------------- internals
    def _authorize_actor(self, req, a):
        p = req.actor
        if req.automatic:
            return None if p.role == "system" else "automatic requests must come from the system principal"
        if p.role in JIT_ROLES and not self._jit(p):
            return "elevation required: this role must request just-in-time access first"
        if p.role == "keeper_crew" and a["keeper"] == "never":
            return "Keeper is not permitted to perform this action"
        if p.role not in a["request_roles"] and not (p.role == "keeper_crew"):
            return f"role {p.role} may not request {req.action}"
        return None

    def _jit(self, p): return p.elevated_until > self.clock.now()

    def _window(self, req):
        for t in req.targets:
            w = self.auth.policy.maintenance_windows.get(t)
            if w and w[0] <= self.clock.now() < w[1]:
                return w

    def _park(self, req, reqmt, plan, status, msg):
        self._n += 1; pid = f"pend-{self._n}"
        self.pending[pid] = {"req": req, "reqmt": reqmt, "plan": plan, "approvals": []}
        self._log("relay.action_proposed", req, {"pending": pid, "level": reqmt.level, "status": status,
                  "preview": plan["summary"]}, ("RELAY.APPROVAL_GATES",))
        return Result(status, action_id=pid, message=msg, preview=plan, requirement=reqmt,
                      cannot_undo=plan.get("cannot_undo", []))

    def _apply(self, req, reqmt, plan, approvals, pending_id=None):
        h = self.handlers[req.action]
        req._approvals, req._reqmt = approvals, reqmt      # composite actions pass the same authorization down to each step
        outcome = h.apply(self, req, plan)
        self._n += 1; aid = f"act-{self._n}"
        undo = {"undo_with": BY_KEY[req.action]["reversal"], "data": outcome.get("undo"),
                "cannot_undo": plan.get("cannot_undo", [])}
        self.executed[aid] = {"req": req, "undo": undo, "undone": False}
        data = {"pending": pending_id, "scope": [scope_item(t) for t in req.targets], "targets": [str(t) for t in req.targets], "reason": req.reason,
                "approval_rule": reqmt.level, "approvers": [x.role for x in approvals],
                "approver_ids": [x.id for x in approvals], "reversible": BY_KEY[req.action]["reversible"],
                "reversal": undo["undo_with"], "cannot_undo": undo["cannot_undo"],
                "pattern": req.pattern, "case": req.case_id, "summary": outcome.get("summary", "")}
        data.update({k: v for k, v in outcome.get("audit", {}).items()})
        ctl = ("RELAY." + req.action.upper(),) + (("RELAY.AUTOMATION_GATE",) if req.automatic else ())
        self._log("relay.action_executed", req, data, ctl)
        if reqmt.notify:
            self._log("relay.notice_sent", req, {"to": "it_admin", "action": req.action}, ("RELAY.NOTIFY",))
        return Result("executed", action_id=aid, message=outcome.get("summary", ""), preview=plan, requirement=reqmt,
                      detail=outcome.get("detail", {}), cannot_undo=undo["cannot_undo"])

    def undo(self, action_id, actor: Principal, approvals=()):
        ex = self.executed.get(action_id)
        if not ex or ex["undone"]:
            return Result("denied", message="Nothing to undo.")
        req = ex["req"]
        if not BY_KEY[req.action]["reversible"]:
            msg = (f"{req.action} cannot be undone. " + ("Not reversible: " + "; ".join(ex["undo"]["cannot_undo"]) + ". "
                   if ex["undo"]["cannot_undo"] else "") + "Nothing was changed.")
            self._log("relay.action_denied", req, {"why": msg, "undo_of": action_id}, ("RELAY.AUTHORIZATION",), actor=actor)
            return Result("denied", message=msg, cannot_undo=ex["undo"]["cannot_undo"])
        ur = ActionRequest("undo_action", actor, req.targets, f"undo {action_id}", req.case_id,
                           {"target_action": action_id}, automatic=actor.role == "system", pattern="undo")
        res = self.request(ur)
        for ap in approvals:
            if res.status == "pending_approval":
                res = self.approve(res.action_id, ap)
        return res

    def _deny(self, req, why, actor=None):
        self._log("relay.action_denied", req, {"why": why}, ("RELAY.AUTHORIZATION",), actor=actor)
        return Result("denied", message=why)

    def _log(self, kind, req, data, controls, actor=None):
        a = actor or req.actor
        data = {"action": req.action, **data}
        return self.ledger.append(kind, a.id, a.role, self.device_id, data, controls=controls)


# ===================================================================== handlers
class _H:
    def preview(self, eng, req): raise NotImplementedError


class _Isolate(_H):
    def preview(self, eng, req):
        return {"summary": f"{req.targets[0]} will lose all network access except the Halvard management channel. "
                           "Local work continues; email, web and file shares stop until released.",
                "keeps": sorted(eng.host.mgmt), "cannot_undo": []}

    def apply(self, eng, req, plan):
        eng.host.isolate()
        return {"summary": "Isolated. Management channel is still up.", "undo": {"release": True}}


class _Release(_H):
    def preview(self, eng, req): return {"summary": "Normal network access returns.", "cannot_undo": []}
    def apply(self, eng, req, plan):
        eng.host.release()
        done = getattr(eng, "on_containment_released", None)
        if done: done()
        return {"summary": "Isolation released."}


class _Stop(_H):
    def preview(self, eng, req):
        p = eng.host.proc(req.params["pid"]) or {}
        return {"summary": f"Stop process {p.get('name','?')} (pid {req.params['pid']}, user {p.get('user','?')}). "
                           "Unsaved data in that process is lost.",
                "cannot_undo": BY_KEY["stop_process"]["cannot_undo"]}

    def apply(self, eng, req, plan):
        eng.host.terminate(req.params["pid"])
        return {"summary": "Process stopped.", "audit": {"pid": req.params["pid"]}}


class _Quarantine(_H):
    def preview(self, eng, req):
        return {"summary": f"Move {len(req.targets)} file(s) to quarantine. Nothing is deleted.", "cannot_undo": []}

    def apply(self, eng, req, plan):
        present = [p for p in req.targets if os.path.isfile(p)]
        qids = [eng.host.quarantine(p) for p in present]
        missing = len(req.targets) - len(present)
        return {"summary": f"{len(qids)} file(s) quarantined." + (f" {missing} could not be found (already gone)." if missing else ""), "undo": {"qids": qids}, "detail": {"qids": qids},
                "audit": {"paths": [str(p) for p in req.targets]}}


class _ReleaseQ(_H):
    def preview(self, eng, req): return {"summary": "Return the file to its original location.", "cannot_undo": []}
    def apply(self, eng, req, plan):
        out = [eng.host.restore_quarantine(q) for q in req.params["qids"]]
        return {"summary": f"{len(out)} file(s) released.", "audit": {"paths": out}}


class _Rollback(_H):
    def preview(self, eng, req):
        rep = eng.journal.rollback(req.params["pids"], req.params.get("since", 0.0), dry_run=True)
        return {"summary": f"Restore {len(rep.restored)} file(s) and remove {len(rep.removed_created)} file(s) the incident "
                           f"created. {len(rep.not_restorable)} cannot be restored; {len(rep.skipped_changed_after)} were "
                           "changed afterwards and will be left alone.",
                "cannot_undo": BY_KEY["journal_rollback"]["cannot_undo"], "dry_run": rep}

    def apply(self, eng, req, plan):
        snap = eng.state / "rollback-snapshots" / f"rb-{eng._n + 1}"
        rep = eng.journal.rollback(req.params["pids"], req.params.get("since", 0.0), snapshot_dir=snap)
        from .recovery import recovery_note
        note = recovery_note(rep)
        return {"summary": note["headline"], "undo": {"snapshot": str(snap)}, "detail": {"report": rep, "note": note},
                "audit": {"restored": len(rep.restored), "removed": len(rep.removed_created),
                          "not_restorable": len(rep.not_restorable), "changed_after": len(rep.skipped_changed_after),
                          "complete": rep.complete}}


class _ConfigRollback(_H):
    def preview(self, eng, req):
        return {"summary": "Restore startup, registry and security settings to the snapshot taken before the incident.",
                "cannot_undo": BY_KEY["config_rollback"]["cannot_undo"]}

    def apply(self, eng, req, plan):
        before = eng.host.snapshot_config(); eng.host.restore_config(req.params["snapshot"])
        return {"summary": "Settings restored.", "undo": {"config": before}}


class _RemovePersistence(_H):
    def preview(self, eng, req):
        return {"summary": f"Remove {len(req.params['keys'])} startup/persistence item(s). A snapshot is kept to restore them.",
                "cannot_undo": BY_KEY["remove_persistence"]["cannot_undo"]}

    def apply(self, eng, req, plan):
        before = eng.host.snapshot_config()
        for k in req.params["keys"]:
            eng.host.persistence.pop(k, None)
        return {"summary": "Persistence removed.", "undo": {"config": before}}


class _LegalHold(_H):
    def preview(self, eng, req):
        return {"summary": "Mark the case as under legal hold. Cleanup actions wait until evidence is frozen.", "cannot_undo": []}

    def apply(self, eng, req, plan):
        eng.holds[req.case_id] = "unfrozen"
        return {"summary": "Legal hold set.", "undo": {"case": req.case_id}}


class _InstallUpdate(_H):
    def preview(self, eng, req):
        p = req.params
        if not p.get("product") or not p.get("version"): return {"summary": "An update needs a product and a version.", "invalid": True, "cannot_undo": []}
        cur = eng.host.software.get(p["product"])
        return {"summary": f"Install {p['product']} {p['version']} (now {cur or 'not installed'}). The program restarts; unsaved work in it can be lost.", "cannot_undo": []}

    def apply(self, eng, req, plan):
        p = req.params; prev = eng.host.install_update(p["product"], p["version"]); broken = eng.host.broken_services()
        msg = f"{p['product']} is now {p['version']} (was {prev or 'not installed'})." + (f" After the update these stopped working: {', '.join(broken)}." if broken else " Everything checked after the update still works.")
        return {"summary": msg, "undo": {"product": p["product"], "was": prev}, "detail": {"product": p["product"], "previous": prev, "broken": broken, "healthy": not broken},
                "audit": {"product": p["product"], "from_version": prev, "to_version": p["version"], "healthy": not broken}}

    def undo(self, eng, r, d, ureq):
        eng.host.install_update(d["product"], d["was"]); return {"summary": f"{d['product']} is back on {d['was']}."}


class _RollbackUpdate(_H):
    def preview(self, eng, req):
        p = req.params
        if not p.get("product") or not p.get("to_version"): return {"summary": "A rollback needs a product and the version to go back to.", "invalid": True, "cannot_undo": []}
        return {"summary": f"Put {p['product']} back on {p['to_version']} (now {eng.host.software.get(p['product'])}). The program restarts.", "cannot_undo": []}

    def apply(self, eng, req, plan):
        p = req.params; prev = eng.host.install_update(p["product"], p["to_version"]); broken = eng.host.broken_services()
        return {"summary": f"{p['product']} is back on {p['to_version']}." + (f" Still not working: {', '.join(broken)}." if broken else ""), "undo": {"product": p["product"], "was": prev},
                "detail": {"product": p["product"], "broken": broken, "healthy": not broken}, "audit": {"product": p["product"], "to_version": p["to_version"], "healthy": not broken}}

    def undo(self, eng, r, d, ureq):
        eng.host.install_update(d["product"], d["was"]); return {"summary": f"{d['product']} is on {d['was']} again."}


class _RemoteCommand(_H):
    MAX_S = 3600

    def preview(self, eng, req):
        ttl = req.params.get("expires_in", 900)
        return {"summary": f"Run one command on {req.targets[0]}. It expires in {min(ttl, self.MAX_S)}s if not run. "
                           "The command and its output digest are recorded.", "cannot_undo": BY_KEY["remote_command"]["cannot_undo"]}

    def apply(self, eng, req, plan):
        ttl = min(req.params.get("expires_in", 900), self.MAX_S)
        if eng.clock.now() > req.params.get("requested_at", eng.clock.now()) + ttl:
            return {"summary": "Expired before it ran; nothing executed."}
        out = eng.host.run_command(req.params["command"])
        return {"summary": "Command ran.", "audit": {"command": req.params["command"],
                "output_sha256": hashlib.sha256(out.encode()).hexdigest()}}


class _Collect(_H):
    def preview(self, eng, req):
        from . import forensics
        try:
            return forensics.preview(eng.host, req.params)
        except forensics.CollectionError as e:
            return {"summary": f"Cannot collect: {e}", "invalid": True, "cannot_undo": []}

    def apply(self, eng, req, plan):
        from . import forensics
        if plan.get("invalid"):
            return {"summary": plan["summary"]}
        cid = f"col-{eng._n + 1}"
        meta = {"collection_id": cid, "case": req.case_id, "requested_by": req.actor.id, "reason": req.reason,
                "collected_at": eng.clock.now(), "device": eng.device_id}
        res = forensics.collect(eng.host, req.params, eng.evidence_dir / (req.case_id or "no-case") / cid, meta, eng.ledger.seal_bytes)
        m = res["manifest"]
        return {"summary": f"Collected {len(m['items'])} item(s); {len(m['skipped'])} skipped. Sealed manifest recorded.",
                "undo": {"dir": res["dir"]}, "detail": {"dir": res["dir"], "manifest": m},
                "audit": {"profile": m["profile"], "items": len(m["items"]), "skipped": len(m["skipped"]), "manifest_sha256": res["digest"],
                          "personal_data": m["personal_data"], "retention_days": m["retention_days"]}}


class _Undo(_H):
    def preview(self, eng, req):
        ex = eng.executed.get(req.params["target_action"])
        cu = ex["undo"]["cannot_undo"] if ex else []
        return {"summary": "Reverse the earlier action. " + ("These cannot be undone: " + "; ".join(cu) if cu else "Everything it did can be reversed."),
                "cannot_undo": cu}

    def apply(self, eng, req, plan):
        ex = eng.executed[req.params["target_action"]]
        ex["undone"] = True
        r, d, host = ex["req"], ex["undo"]["data"] or {}, eng.host
        h = eng.handlers.get(r.action)
        if h is not None and hasattr(h, "undo"):
            return h.undo(eng, r, d, req)
        if r.action == "isolate_host":
            host.release()
            done = getattr(eng, "on_containment_released", None)
            if done: done()
        elif r.action == "quarantine_file":
            for q in d["qids"]: host.restore_quarantine(q)
        elif r.action in ("remove_persistence", "config_rollback"): host.restore_config(d["config"])
        elif r.action == "journal_rollback":
            snap = Path(d["snapshot"])
            for meta in snap.glob("*.path"):
                dest = meta.read_text(encoding="utf-8"); shutil.copyfile(snap / meta.name[:-5], dest)
        elif r.action == "legal_hold": eng.holds.pop(d["case"], None)
        elif r.action == "collect_forensics":
            if r.case_id in eng.holds:
                raise PermissionError("this case is under legal hold; collected evidence cannot be deleted")
            shutil.rmtree(d["dir"], ignore_errors=True)
        elif r.action == "stop_process": raise RuntimeError("stop_process cannot be undone")
        return {"summary": f"Undid {r.action}."}
