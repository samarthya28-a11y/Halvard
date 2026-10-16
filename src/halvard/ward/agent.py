"""Ward agent (Phase 1 reference): device-side prevention that never waits for the cloud.

Everything in `on_*` / `ProtectedFS` runs from the local policy bundle, local detector, local journal and local
action engine. `online` only controls whether the spool is forwarded and whether cloud reputation is consulted.
The OS hook that feeds ProtectedFS (minifilter / Endpoint Security / fanotify) is a separate native component
that is NOT part of this build; ProtectedFS is the contract it must satisfy.
"""
import fnmatch, hashlib, os
from pathlib import Path

from ..ledger.audit import AuditLog
from ..relay.actions import ActionEngine, ActionRequest, Principal
from ..relay.authority import Authority, CustomerPolicy
from ..relay.journal import Journal
from .detect import BulkEncryptionDetector, entropy, has_magic
from .policy import PolicyBundle, load_bundle, BundleError
from .tamper import TamperGuard
from ..detect.library import Runtime, verify_pack, PackError
from ..detect.learning import DeviceMatcher
from ..platforms import PROFILES
from collections import deque
from ..vaultline.classifiers import Classifier
from ..vaultline.inspection import Inspector, InspectionPolicy, InspectionNotAllowed
from ..vaultline import dlp as dlpmod
from .verdict import VerdictEngine

SYSTEM = Principal("halvard:auto", "system")


URGENT_REMOTE = {"isolate_host", "stop_process", "quarantine_file", "legal_hold"}      # containment is never delayed by a maintenance window; updates and rollbacks are


class Blocked(PermissionError):
    pass


class EgressBlocked(Blocked):
    def __init__(self, message, decision): super().__init__(message); self.decision = decision


class NeedsJustification(Blocked):
    def __init__(self, message, decision): super().__init__(message); self.decision = decision


class WardAgent:
    def __init__(self, device_id, root, bundle: PolicyBundle, host, clock, device_key: bytes, uninstall_key: bytes,
                 asset_class="standard", reputation=None):
        self.device_id, self.root, self.clock, self.host = device_id, Path(root), clock, host
        self.root.mkdir(parents=True, exist_ok=True)
        self.key, self.online = device_key, True
        self.bundle, self.asset_class = bundle, asset_class
        self.spool = AuditLog(self.root / "spool" / "ledger.log", bundle.tenant, device_key, clock)
        self.journal = Journal(self.root / "journal", clock, quota_bytes=bundle.journal_quota_mb << 20)
        self.detector = BulkEncryptionDetector()
        self.verdicts = VerdictEngine(bundle.known_bad_sha256, reputation=reputation)
        self.profile = PROFILES[bundle.platform]
        self.journal.key = self.profile.path_key
        self.blocked, self.incidents, self.recent_highent = set(), [], {}
        self.runtime, self.detections, self.outbox = Runtime(clock), [], deque(maxlen=20000)
        self.matcher = DeviceMatcher(clock, bundle.learned_exceptions)
        self._proc_cache = {}
        self._nonces = set()
        self.tamper = TamperGuard(self.root / "install", uninstall_key, clock, self.spool, device_id,
                                  bundle.retention_days_after_uninstall)
        self.tripwires, self.tripwire_hits, self._tw_state = {}, [], {}
        self._build_engine(); self._build_dlp(); self._place_tripwires()
        self.sensors = {"heartbeat": clock.now()}

    def _build_dlp(self):
        d = self.bundle.dlp or {}
        self.inspector = Inspector(InspectionPolicy(**d.get("inspection", {})), self.clock, Classifier(d.get("custom_labels")), self.spool, source=self.device_id)
        self.dlp_rules = d.get("rules")
        self.usb_cfg = d.get("usb", {"approved": [], "unapproved_mode": "read_only"})
        self.saas = d.get("saas", {}); self.partners = {x.lower() for x in d.get("partners", [])}; self.ai_map = dict(d.get("ai", {}))
        self.justified = getattr(self, "justified", {})

    @property
    def exclude(self):
        b = self.bundle.journal_exclude
        return b if b is not None else list(self.profile.journal_exclude)

    def _build_engine(self):
        pol = CustomerPolicy(overrides=self.bundle.overrides, accepted_patterns=set(self.bundle.accepted_patterns))
        self.engine = ActionEngine(Authority(pol), self.spool, self.clock, self.host, self.journal,
                                   self.root / "relay", asset_class_of=lambda t: self.asset_class, device_id=self.device_id)

    # ---- policy ----
    def apply_bundle(self, raw: dict, key: bytes):
        try:
            nb = load_bundle(raw, key, self.bundle.version)
        except BundleError as e:
            self.spool.append("ward.policy_rejected", "system", "system", self.device_id, {"why": str(e)},
                              controls=("WARD.POLICY_INTEGRITY",))
            return False
        pending, executed, acc = self.engine.pending, self.engine.executed, self.engine.auth.policy.accepted_patterns
        self.bundle = nb; self._build_engine()
        self.engine.pending, self.engine.executed = pending, executed
        self.engine.auth.policy.accepted_patterns |= acc
        self.verdicts.known_bad = set(nb.known_bad_sha256); self._build_dlp(); self._place_tripwires()
        self.matcher = DeviceMatcher(self.clock, nb.learned_exceptions)
        self.spool.append("ward.policy_applied", "system", "system", self.device_id, {"version": nb.version},
                          controls=("WARD.POLICY_INTEGRITY",))
        return True

    # ---- tripwires (Hearth): files nobody has a reason to touch ----
    FORBIDDEN_ROOTS = ("/etc", "/usr", "/bin", "/sbin", "/boot", "/sys", "/proc", "/dev", "/lib", "/windows", "/program files", "/programdata")

    @staticmethod
    def _twkey(path): return os.path.normcase(os.path.realpath(str(path))).replace("\\", "/")      # a link to a tripwire is the tripwire

    def _decoy_bytes(self, spec):
        if spec.get("lure_text"): return spec["lure_text"].encode()
        seed = hashlib.sha256(spec["id"].encode()).digest(); ext = os.path.splitext(spec["path"])[1].lower()
        body = (b"Reference " + seed.hex().encode() + b"\n") * 40
        if ext == ".pdf": return b"%PDF-1.4\n" + body
        if ext in (".docx", ".xlsx", ".pptx"): return b"PK\x03\x04" + seed * 30 + body
        return body

    def _place_tripwires(self):
        """Create each tripwire the signed policy names. Never over an existing file, never in an operating-system folder, never twice."""
        want = {self._twkey(t["path"]): t for t in self.bundle.tripwires}
        for k in [k for k in self.tripwires if k not in want]:                 # removed from policy: take the file away if it is still ours
            tw = self.tripwires.pop(k)
            try:
                if hashlib.sha256(Path(k).read_bytes()).hexdigest() == tw["sha"]: Path(k).unlink()
            except OSError: pass
            self.spool.append("ward.tripwire_removed", "system", "system", self.device_id, {"tripwire": tw["id"]}, controls=("HEARTH.TRIPWIRES",))
        for k, t in want.items():
            if k in self.tripwires: continue
            why = None
            kk = k.lower().replace("\\", "/")
            if not (os.path.isabs(t["path"]) or str(t["path"]).replace("\\", "/").startswith("/")): why = "the path is not absolute"
            elif any(kk.startswith(r) or (len(kk) > 2 and kk[1:2] == ":" and kk[2:].startswith(r)) for r in self.FORBIDDEN_ROOTS): why = "operating-system folders are never used"
            elif os.path.lexists(k): why = "a file already exists there; Halvard never replaces an existing file"
            elif not Path(k).parent.is_dir(): why = "the folder does not exist"
            if why:
                self.spool.append("ward.tripwire_skipped", "system", "system", self.device_id, {"tripwire": t["id"], "why": why, "path": k}, controls=("HEARTH.TRIPWIRES",)); continue
            data = self._decoy_bytes(t); Path(k).write_bytes(data)
            self.tripwires[k] = {"id": t["id"], "kind": t["kind"], "sha": hashlib.sha256(data).hexdigest()}
            self.spool.append("ward.tripwire_placed", "system", "system", self.device_id, {"tripwire": t["id"], "kind": t["kind"], "path": k}, controls=("HEARTH.TRIPWIRES",))

    def tripwire_gate(self, pid, op, *paths):
        """Called by the file hook BEFORE an operation. Changing an encryption tripwire stops the process now, before any real file is lost."""
        if not self.tripwires: return          # most devices have none: the hot path pays nothing
        for p in paths:
            tw = self.tripwires.get(self._twkey(p))
            if not tw: continue
            proc = (self.host.proc(pid) or {}).get("name")
            if self._trusted(pid) or proc in self.bundle.tripwire_exempt:
                self.spool.append("ward.tripwire_exempt", "system", "system", self.device_id, {"tripwire": tw["id"], "op": op, "process": proc}, controls=("HEARTH.TRIPWIRES",)); continue
            modifying = op in ("write", "rename", "delete", "create")
            conf = 0.9 if (modifying or tw["kind"] != "encryption") else 0.3          # reading an encryption tripwire is what indexers and backups do
            hit = {"ts": self.clock.now(), "tripwire": tw["id"], "kind": tw["kind"], "op": op, "pid": pid, "process": proc, "user": (self.host.proc(pid) or {}).get("user"), "path": str(p), "confidence": conf, "stopped": False}
            self.tripwire_hits.append(hit)
            self.spool.append("ward.tripwire_touched", "system", "system", self.device_id, {k: v for k, v in hit.items() if k not in ("ts", "stopped")}, controls=("HEARTH.TRIPWIRES",) + (("WARD.OFFLINE_PREVENTION",) if not self.online else ()))
            if tw["kind"] == "encryption" and modifying and self.bundle.prevention.get("bulk_encryption", "enforce") == "enforce":
                from .detect import Verdict
                hit["stopped"] = True
                self.handle_verdict(Verdict(pid, 0.9, [f"a tripwire file ({tw['id']}) was changed by this process before any real file was"], [str(p)]))
                raise Blocked(f"Blocked: {proc or 'this program'} tried to change a file that only ransomware-like behaviour would touch. It was stopped before it reached your documents.")

    def verify_tripwires(self):
        """Tripwires removed or changed by something that bypassed the file hook (or while the agent was off). Reported once per state."""
        out = []
        for k, tw in self.tripwires.items():
            try: now_sha = hashlib.sha256(Path(k).read_bytes()).hexdigest()
            except OSError: now_sha = None
            state = "removed" if now_sha is None else "changed" if now_sha != tw["sha"] else None
            if state and self._tw_state.get(k) != state:
                self._tw_state[k] = state; h = {"ts": self.clock.now(), "tripwire": tw["id"], "kind": tw["kind"], "op": state, "pid": None, "process": None, "user": None, "path": k, "confidence": 0.8, "stopped": False}
                self.tripwire_hits.append(h); out.append(h)
                self.spool.append("ward.tripwire_" + state, "system", "system", self.device_id, {"tripwire": tw["id"], "path": k}, controls=("HEARTH.TRIPWIRES",))
        return out

    # ---- connectivity ----
    def set_online(self, online: bool):
        self.online = online

    def sync(self, tenant_ledger: AuditLog):
        """Store-and-forward: merge the device spool into the tenant ledger."""
        if not self.online:
            return None
        self.sensors["heartbeat"] = self.clock.now()
        return tenant_ledger.ingest_segment(self.device_id, self.spool)

    # ---- data leaving the device (F014, F015, F084) ----
    CONTROL = {"usb": "VAULTLINE.USB_CONTROL", "print": "VAULTLINE.PRINT_CONTROL", "upload": "VAULTLINE.UPLOAD_CONTROL", "email_external": "VAULTLINE.EMAIL_CONTROL", "cloud_share_public": "VAULTLINE.SHARING_CONTROL", "ai_prompt": "LUMEN.AI_DATA_POLICY"}

    def usb_dest_class(self, info):
        approved = any(a.get("vendor") == info.get("vendor") and a.get("serial") == info.get("serial") for a in self.usb_cfg.get("approved", []))
        return "approved_encrypted" if approved and info.get("encrypted") else "approved_plain" if approved else "unapproved"

    def upload_dest_class(self, domain):
        d = (domain or "").lower()
        return next((v for k, v in self.saas.items() if d == k or d.endswith("." + k)), "unsanctioned")

    def _dest_class(self, channel, dest):
        if channel == "usb": return self.usb_dest_class(dest["mount"])
        if channel == "upload": return self.upload_dest_class(dest.get("domain"))
        if channel == "ai_prompt":
            d = (dest.get("domain") or "").lower()
            return next((v for k, v in self.ai_map.items() if d == k or d.endswith("." + k)), "ai_shadow")      # an AI domain this device has not been told about is shadow
        return "any"

    def check_egress(self, pid, channel, path, data: bytes, dest: dict):
        """Decide, on the device and with no connection, whether this data may leave through this door. Returns a Decision."""
        dest_class = self._dest_class(channel, dest)
        h = hashlib.sha256(data).hexdigest(); name = os.path.basename(str(path))
        if channel == "usb" and dest_class == "unapproved" and self.usb_cfg.get("unapproved_mode", "read_only") in ("read_only", "block"):
            d = dlpmod.Decision("block", "usb-device-readonly", {}, "This drive is not approved for company computers, so it is read-only. Ask IT to approve it, or use an approved drive.", False, False)
        else:
            try: cls = self.inspector.inspect(str(path), name, data, who="ward")
            except InspectionNotAllowed: cls = None
            d = dlpmod.decide(cls, channel, dest_class, self.dlp_rules)
        just = False
        if d.action == "justify":
            exp = self.justified.get((h, channel, dest_class))
            if exp and exp > self.clock.now(): just = True
        self.spool.append("ward.egress_decision", "system", "system", self.device_id,
                          {"channel": channel, "dest_class": dest_class, "decision": "allow" if just else d.action, "rule": d.rule, "labels": d.labels, "inspected": d.inspected, "justified": just, "online": self.online, "path": str(path)},
                          controls=(self.CONTROL.get(channel, "VAULTLINE.EGRESS"),) + (("WARD.OFFLINE_PREVENTION",) if not self.online else ()))
        self.emit("egress", "allowed" if (just or d.action in ("allow", "warn")) else d.action, pid, str(path), tuple(d.labels))
        if just: d.action = "allow"
        return d

    def justify(self, channel, path, data: bytes, dest: dict, text: str, minutes=60):
        """The person says why. Time-boxed to this file, this door, this kind of destination. Secrets and device rules cannot be justified."""
        dest_class = self._dest_class(channel, dest)
        text = (text or "").strip()
        if not 10 <= len(text) <= 200: raise ValueError("Please give a reason of 10 to 200 characters.")
        d = self.check_egress(0, channel, path, data, dest)
        if d.action == "block" and not d.justifiable: raise PermissionError(d.message)
        if d.action != "justify": return d
        minutes = max(1, min(int(minutes), 60)); exp = self.clock.now() + minutes * 60;      # a reason unlocks at most one hour, whatever the caller asks for
        self.justified[(hashlib.sha256(data).hexdigest(), channel, dest_class)] = exp
        self.spool.append("ward.egress_justified", "user", "end_user", self.device_id, {"channel": channel, "minutes": minutes, "justification": text}, controls=(self.CONTROL.get(channel, "VAULTLINE.EGRESS"),))
        return d

    def encryption_report(self):
        s = self.host.encryption_status(); issues = []
        if not s["system"]: issues.append("The disk is not encrypted.")
        return {"system_encrypted": s["system"], "removable": s["removable"], "issues": issues}

    # ---- commands from the control plane ----
    def execute_command(self, cmd, key: bytes):
        from ..relay import commands
        ok, why = commands.verify(cmd, key, self.device_id, self.clock.now(), self._nonces, self.engine.auth, self.asset_class)
        if not ok:
            self.spool.append("ward.command_rejected", "controlplane", "system", self.device_id, {"why": why, "command": cmd.get("id")}, controls=("RELAY.COMMAND_CHANNEL",))
            return {"status": "rejected", "message": why}
        self._nonces.add(cmd["nonce"])
        targets = cmd["params"].get("paths") if cmd["action"] == "quarantine_file" else None
        req = ActionRequest(cmd["action"], Principal("controlplane", "system"), targets or [self.device_id], cmd["reason"], cmd.get("case"), cmd["params"], critical=cmd["action"] in URGENT_REMOTE)
        r = self.engine.request_authorized(req, cmd)
        return {"status": r.status, "message": r.message, "detail": r.detail}

    def inventory(self):
        """Names and versions of installed software, configuration values and health. Never file contents or user activity."""
        h = self.host
        return {"software": dict(h.software), "settings": {**h.settings, "disk_encryption": bool(h.system_encrypted)}, "broken_services": h.broken_services(), "macs": list(h.macs), "ip": h.ip, "ts": self.clock.now()}

    # ---- telemetry and custom detections (F019, F023, F036) ----
    def emit(self, kind, op, pid, path=None, signals=(), **extra):
        """One content-free telemetry event. Evaluated against device-side rules (works offline), then queued for upload."""
        p = self.host.proc(pid) or {}
        parent = (self.host.proc(p["ppid"]) or {}).get("name") if p.get("ppid") else None
        ev = {"ts": self.clock.now(), "device": self.device_id, "kind": kind, "op": op, "pid": pid, "ppid": p.get("ppid"), "parent_proc": parent,
              "proc": p.get("name"), "exe_sha256": p.get("exe_sha256"), "cmdline": p.get("cmdline"), "user": p.get("user"),
              "path": path, "signals": " ".join(signals) if signals else None, **extra}
        self.outbox.append(ev)
        if self.runtime.rules:
            for hit in self.runtime.on_event(ev, suppressor=self.matcher.match):
                self.detections.append(hit)
                self.spool.append("ward.custom_detection", "system", "system", self.device_id,
                                  {"rule": hit["rule_id"], "version": hit["version"], "name": hit["name"], "severity": hit["severity"],
                                   "confidence": hit["confidence"], "confidence_source": "author-set", "techniques": hit["techniques"],
                                   "path": path, "proc": ev["proc"], "online": self.online},
                                  controls=("DETECT.CUSTOM_RULES",) + (("WARD.OFFLINE_PREVENTION",) if not self.online else ()))
        return ev

    def apply_content(self, pack: dict, key: bytes):
        """Detection content update without an agent upgrade (F036): signed, monotonic, expiry enforced locally."""
        try:
            verify_pack(pack, key, self.runtime.version)
        except PackError as e:
            self.spool.append("ward.content_rejected", "system", "system", self.device_id, {"why": str(e)}, controls=("DETECT.CONTENT_INTEGRITY",))
            return False
        self.runtime.load(pack)
        self.spool.append("ward.content_applied", "system", "system", self.device_id,
                          {"pack_version": pack["version"], "rules": len(pack["rules"])}, controls=("DETECT.CONTENT_INTEGRITY",))
        return True

    def flush_telemetry(self, events, ctx):
        """Store-and-forward upload. Returns number sent; nothing is sent while offline."""
        if not self.online or not self.outbox: return 0
        batch = list(self.outbox); n = events.add(ctx, batch); self.outbox.clear(); return n

    # ---- pre-execution (F006) ----
    def pre_execute(self, path, data: bytes, pid=0):
        stem = os.path.splitext(os.path.basename(path))[0].lower()
        for b in self.bundle.blocked_apps:
            if b["app"].lower() == stem:
                self.spool.append("ward.exec_blocked_by_temporary_protection", "system", "system", self.device_id, {"app": stem, "why": b.get("why", ""), "control": b.get("control")},
                                  controls=("GLASS.COMPENSATING_CONTROL",) + (("WARD.OFFLINE_PREVENTION",) if not self.online else ()))
                raise Blocked(f"{stem} is switched off on this device for now: {b.get('why', 'a temporary protection is in place')}. Ask IT if you need it.")
        v = self.verdicts.evaluate(data, os.path.basename(path), self.online)
        mode = self.bundle.prevention.get("known_bad", "enforce")
        self.spool.append("ward.exec_verdict", "system", "system", self.device_id,
                          {"decision": v.decision, "score": round(v.score, 2), "source": v.source,
                           "reasons": v.reasons, "path": path, "sha256": __import__("hashlib").sha256(data).hexdigest(),
                           "mode": mode, "online": self.online},
                          controls=("WARD.PRE_EXECUTION_VERDICT",) + (("WARD.OFFLINE_PREVENTION",) if not self.online else ()))
        if v.decision == "block" and mode == "enforce":
            self.engine.request(ActionRequest("quarantine_file", SYSTEM, [path], f"pre-execution verdict: {'; '.join(v.reasons)}",
                                              automatic=True, pattern="malware_quarantine"))
            raise Blocked(f"Blocked before it could run: {', '.join(v.reasons)}. The file was moved to quarantine.")
        return v

    # ---- bulk-encryption prevention ----
    def _trusted(self, pid):
        p = self.host.proc(pid)
        return bool(p and p["name"] in self.bundle.trusted_writers)

    def handle_verdict(self, v, defer=None):
        """Decide and freeze synchronously; run the response now, or via `defer(callable)` when a sensor must keep draining events."""
        mode = self.bundle.prevention.get("bulk_encryption", "enforce")
        pinfo = self.host.proc(v.pid) or {}
        self.spool.append("ward.bulk_encryption_detected", "system", "system", self.device_id,
                          {"pid": v.pid, "process": pinfo.get("name", "?"), "confidence": v.confidence,
                           "files_affected": len(v.files), "reasons": v.reasons, "mode": mode, "online": self.online,
                           "sample_paths": v.files[:5], "technique": "T1486"},
                          controls=("WARD.BEHAVIORAL_STOP", "WARD.OFFLINE_PREVENTION") if not self.online
                          else ("WARD.BEHAVIORAL_STOP",))
        inc = {"pid": v.pid, "process": pinfo.get("name", "?"), "confidence": v.confidence, "reasons": v.reasons,
               "files_at_detection": len(v.files), "mode": mode, "online": self.online, "results": [], "ts": self.clock.now()}
        self.incidents.append(inc)
        ex = self.matcher.match({"detection_id": "ward.bulk_encryption", "exe_sha256": pinfo.get("exe_sha256"), "proc": pinfo.get("name"),
                                 "device": self.device_id, "path": v.files[0] if v.files else None})
        if ex:      # learned exception: observe only. The journal already holds every pre-image, so this stays recoverable.
            self.spool.append("ward.suppressed_by_exception", "system", "system", self.device_id,
                              {"exception": ex.id, "detection": "ward.bulk_encryption", "process": pinfo.get("name"), "confidence": v.confidence,
                               "effect": "observe_only"}, controls=("DETECT.FP_LEARNING",))
            inc["note"] = f"Not stopped: administrator-approved exception {ex.id} applies to this program. Files are still being journaled."
            inc["suppressed_by"] = ex.id
            return inc
        if mode != "enforce":
            inc["note"] = "Audit-only mode: nothing was blocked. Switch the rule to enforce to stop this automatically."
            return inc
        # Prevention: freeze the process's I/O immediately. Non-destructive, always available, reversible.
        self.host.suspend(v.pid); self.blocked.add(v.pid)
        self.spool.append("ward.io_blocked", "system", "system", self.device_id, {"pid": v.pid},
                          controls=("WARD.BEHAVIORAL_STOP",))
        run = lambda: self._respond(v, inc)
        (defer(run) if defer else run())
        return inc

    def _respond(self, v, inc):
        # Response: run through the authority matrix, in order.
        steps = [("stop_process", [self.device_id], {"pid": v.pid}),
                 ("isolate_host", [self.device_id], {}) if v.confidence >= 0.9 else None,
                 ("journal_rollback", [self.device_id], {"pids": [v.pid], "since": 0.0})]
        for s in filter(None, steps):
            r = self.engine.request(ActionRequest(s[0], SYSTEM, s[1], f"bulk encryption by pid {v.pid} (confidence {v.confidence})",
                                                  case_id=f"case-{v.pid}", params=s[2], automatic=True,
                                                  pattern="ransomware_stop", critical=True))
            inc["results"].append((s[0], r.status, r.message, r.action_id))
            if r.detail.get("note"):
                inc["recovery"] = r.detail["note"]

    # ---- tamper ----
    def install_files(self, files: dict):
        d = self.root / "install"; d.mkdir(parents=True, exist_ok=True)
        for n, b in files.items():
            (d / n).write_bytes(b)
        self.tamper.seal()

    def heartbeat(self):
        self.sensors["heartbeat"] = self.clock.now(); self.engine.offer_due()


class ProtectedFS:
    """The contract the OS file hook satisfies: call the agent before and after each operation."""
    HEAD, SAMPLE = 512, 4096
    HASH_EXT = {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pdf", ".zip", ".rar", ".7z", ".iso", ".img", ".exe", ".dll", ".js", ".vbs", ".ps1", ".lnk", ".html", ".htm", ".hta", ".msi", ".jar", ".scr"}
    HASH_MAX = 25 << 20

    def __init__(self, agent: WardAgent):
        self.a = agent

    def _gate(self, pid):
        if pid in self.a.blocked:
            raise Blocked("Halvard stopped this program from changing files because it looked like bulk encryption.")

    @staticmethod
    def _head(path, n):
        try:
            with open(path, "rb") as f:
                return f.read(n)
        except OSError:
            return None

    def _excluded(self, path):
        p = str(path).replace("\\", "/").lower()
        return any(fnmatch.fnmatch(p, g) for g in self.a.exclude)

    def _before(self, pid, op, path, dst=None):
        if self.a._trusted(pid) or (self._excluded(path) and (dst is None or self._excluded(dst))):
            return None, self._head(path, self.HEAD) if op != "create" else None
        return self.a.journal.before(pid, op, path, dst)

    def create(self, pid, path, data: bytes):
        self._gate(pid); self.a.tripwire_gate(pid, "create", path)
        rid, _ = self._before(pid, "create", path)
        Path(path).parent.mkdir(parents=True, exist_ok=True); Path(path).write_bytes(data)
        if rid: self.a.journal.after(rid, path, content=data)
        if len(data) >= 64 and not has_magic(data[:256]) and entropy(data[:self.SAMPLE]) > 7.5:
            self.a.recent_highent.setdefault(pid, []).append((self.a.clock.now(), path))
        ext = os.path.splitext(str(path))[1].lower()
        sha = hashlib.sha256(data).hexdigest() if ext in self.HASH_EXT and len(data) <= self.HASH_MAX else None   # lets a mail verdict find where an attachment landed
        self.a.emit("file", "create", pid, str(path), file_sha256=sha)

    def overwrite(self, pid, path, data: bytes):
        self._gate(pid); self.a.tripwire_gate(pid, "write", path)
        rid, before = self._before(pid, "write", path)
        Path(path).write_bytes(data)
        if rid: self.a.journal.after(rid, path, content=data)
        sig = self.a.detector.classify(before, data[:self.SAMPLE]) if before is not None else ()
        self.a.emit("file", "write", pid, str(path), sig)
        self._observe(pid, path, sig)

    def rename(self, pid, src, dst):
        self._gate(pid); self.a.tripwire_gate(pid, "rename", src, dst)
        rid, _ = self._before(pid, "rename", src, dst)
        os.replace(src, dst)
        if rid: self.a.journal.after(rid, dst)
        ext_changed = os.path.splitext(src)[1] != os.path.splitext(dst)[1]
        self.a.emit("file", "rename", pid, str(src), ("ext_changed",) if ext_changed else (), dst_path=str(dst))
        self._observe(pid, dst, ("ext_changed",) if ext_changed else ())

    def delete(self, pid, path):
        self._gate(pid); self.a.tripwire_gate(pid, "delete", path)
        rid, before = self._before(pid, "delete", path)
        os.remove(path)
        if rid: self.a.journal.after(rid, path)
        stem = os.path.splitext(os.path.basename(path))[0]
        now = self.a.clock.now()
        sig = ()
        hi = self.a.recent_highent.get(pid)
        if before is not None and hi and any(now - t < 30 and os.path.dirname(p) == os.path.dirname(str(path))
                                             and os.path.basename(p).startswith(stem) for t, p in hi):
            sig = ("magic_destroyed",)    # original replaced by a random-looking sibling
        self.a.emit("file", "delete", pid, str(path), sig)
        self._observe(pid, str(path), sig)

    def copy_out(self, pid, src, dst):
        """Copy a file; if the destination is a removable drive, the data-handling rules decide first."""
        self._gate(pid); data = Path(src).read_bytes(); info = self.a.host.mount_of(dst)
        if info and info.get("removable"):
            d = self.a.check_egress(pid, "usb", src, data, {"mount": info})
            if d.action == "block": raise EgressBlocked(d.message, d)
            if d.action == "justify": raise NeedsJustification(d.message, d)
        self.create(pid, dst, data); return True

    def send_out(self, pid, channel, src, dest):
        """Printing, uploads: the same decision, performed by the caller if allowed. Returns the Decision."""
        self._gate(pid); data = Path(src).read_bytes(); d = self.a.check_egress(pid, channel, src, data, dest)
        if d.action == "block": raise EgressBlocked(d.message, d)
        if d.action == "justify": raise NeedsJustification(d.message, d)
        return d

    def read(self, pid, path):
        self._gate(pid); self.a.tripwire_gate(pid, "read", path)
        return Path(path).read_bytes()

    def _observe(self, pid, path, sig):
        if self.a._trusted(pid):
            return
        v = self.a.detector.observe(self.a.clock.now(), pid, path, sig)
        if v:
            self.a.handle_verdict(v)
