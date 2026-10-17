"""Control plane wiring for Phase 3: one tenant's ledger, graph, IdP and AD connectors, Signet, cases, the action engine
with Signet handlers, the fleet that reaches devices, and the optional automatic response. Used by tests and the demo;
there is no network service here yet (see docs/10)."""
import os
from pathlib import Path
from .paths import policy_dir

from .cases import CaseEngine, CaseFinding, ward_hit_to_finding
from .detect.library import ATTACK  # noqa: F401  (technique list is validated where findings are produced)
from .ledger.audit import AuditLog
from .relay.actions import ActionEngine, ActionRequest, Principal
from .relay.authority import Authority, CustomerPolicy
from .relay.fleet import Fleet
from .relay.courier_actions import register_courier
from .relay.atlas_actions import register_atlas
from .relay.glass_actions import register_glass
from .relay.lumen_actions import register_lumen
from .relay.hearth_actions import register_hearth
from .relay.harbor_actions import register_harbor
from .harbor.service import HarborService, ReferenceChangeTool
from .lumen.service import LumenService
from .hearth.service import HearthService
from .hearth.fileserver import ReferenceFileServer
from .hearth.canary import CanaryService
from .glass.feed import VulnFeed
from .glass.service import GlassService
from .coverage import CoverageMonitor
from .glass.evidence import ControlEvidence
from .glass.board import Board
from .glass.surface import ExternalSurface, ReferenceInternet
from .atlas.aws import ReferenceAWS
from .atlas.service import AtlasService
from .vaultline.service import VaultlineService
from .vaultline.inspection import InspectionPolicy
from .courier.mail import ReferenceMail
from .courier.analysis import Intel, ReferenceWeb
from .courier.service import CourierService, mbx_id
from .hunt.events import EventStore
from .ward.policy import PolicyBundle
import dataclasses
from .relay.signet_actions import register_signet
from .signet.ad import ReferenceAD
from .signet.detectors import IdentityDetector
from .signet.hr import HR
from .signet.idp import ReferenceIdP
from .signet.notify import Notifier
from .signet.service import SignetService, entity_of_finding, idp_id, ad_id
from .tenancy import TenantStore, TenantContext

SYSTEM = Principal("halvard:auto", "system")
_CONNECTOR_SOURCES = {"signet", "courier", "aws"}


def _signed_connector(f):
    d = getattr(f, "details", None) or {}
    return bool(d.get("connector_signed")) and not d.get("reference_model")


def _signed_case(case):
    """Automatic containment uses Signet, Courier, and Atlas only when each of their findings was sealed by that connector."""
    external = [f for f in case.findings if f.source in _CONNECTOR_SOURCES]
    return all(_signed_connector(f) for f in external)


class ControlPlane:
    def __init__(self, tmp, clock, policy_key, tenant="acme", accepted_patterns=("identity_takeover_containment",), trusted_egress=(), auto_threshold=0.85,
                 channels=(), overrides=None, partner_domains=(), supplier_ibans=None, web_pages=None, store=None, region="eu-west", deployment="cloud", operated_by="customer", ledger_key=None, **detector_kw):
        self.clock, self.tenant, self.auto_threshold = clock, tenant, auto_threshold
        self.store = store or TenantStore(); self.store.create_tenant(tenant, tenant.title(), region=region, deployment=deployment, operated_by=operated_by)
        self.ctx = TenantContext(tenant, "controlplane", "system")
        self.ledger = AuditLog(os.path.join(tmp, "tenant-ledger.log"), tenant, ledger_key or b"tenant-ledger-key-0123456789abcd", clock)
        self.idp, self.ad, self.hr = ReferenceIdP(tenant, clock), ReferenceAD(f"{tenant}.local", clock), HR()
        self.detector = IdentityDetector(clock, trusted_egress=trusted_egress, domain_controllers=["DC01"], **detector_kw)
        self.signet = SignetService(self.store, self.ctx, clock, self.idp, self.ad, self.detector, self.hr, self.ledger)
        self.fleet = Fleet(policy_key, clock, self.ledger); self.notifier = Notifier(self.hr, channels, clock)
        policy = CustomerPolicy(overrides=overrides or {}, accepted_patterns=set(accepted_patterns))
        self.engine = ActionEngine(Authority(policy), self.ledger, clock, host=None, journal=None, state_dir=Path(tmp) / "cp-state",
                                   asset_class_of=self.class_of, device_id=tenant)
        register_signet(self.engine); register_courier(self.engine); register_atlas(self.engine); register_glass(self.engine); register_lumen(self.engine); register_hearth(self.engine); register_harbor(self.engine)
        a = self.engine.adapters; a.idp, a.ad, a.fleet, a.notifier, a.hr, a.signet = self.idp, self.ad, self.fleet, self.notifier, self.hr, self.signet
        self.events = EventStore(self.store, clock=clock)
        self.mail, self.intel, self.web = ReferenceMail(f"{tenant}.com", clock), Intel(), ReferenceWeb(web_pages or {})
        self.courier = CourierService(self.store, self.ctx, clock, self.mail, self.hr, self.intel, self.web, [f"{tenant}.com"], partner_domains, self.events, self.ledger,
                                      supplier_ibans=supplier_ibans, ip_flagged=lambda ip: any(f.details.get("ip") == ip for f in self.signet.findings))
        a.mail, a.courier = self.mail, self.courier
        self.aws = ReferenceAWS("111122223333", clock)
        self.atlas = AtlasService(self.store, self.ctx, clock, self.aws, self.ledger, ip_flagged=lambda ip: any(f.details.get("ip") == ip for f in self.signet.findings))
        self.vault = VaultlineService(self.store, self.ctx, clock, self.aws, self.mail, [f"{tenant}.com"], partner_domains, audit=self.ledger, atlas=self.atlas)
        a.aws, a.atlas, a.vault = self.aws, self.atlas, self.vault
        self.internet = ReferenceInternet(clock)
        feed = VulnFeed.load(policy_dir() / "advisories_sample.json") if (policy_dir() / "advisories_sample.json").exists() else VulnFeed()
        self.surface = ExternalSurface(self.internet, clock, self.ledger, lambda: {i.public_ip for i in self.aws.instances.values() if i.public_ip}, feed)
        self.glass = GlassService(self.store, self.ctx, clock, self.ledger, feed, self.aws, self.atlas, self.fleet, self.engine, surface=self.surface, signet=self.signet)
        self.glass.pusher = self.push_blocked; a.glass = self.glass
        self.coverage = CoverageMonitor(self.store, self.ctx, clock, self.ledger); self.evidence = ControlEvidence(self.ledger, self.fleet, clock)
        self.board = Board(self.glass, self.coverage, self.evidence, self.ledger, clock, self.fleet, store=self.store, ctx=self.ctx)
        root = policy_dir()
        self.lumen = LumenService(self.store, self.ctx, clock, self.ledger, self.idp, self.aws, self.signet, root / "ai_tools_sample.json", internal_domains=[f"{tenant}.com"])
        self.fileserver, self.canary = ReferenceFileServer(clock), CanaryService(clock)
        self.hearth = HearthService(self.store, self.ctx, clock, self.ledger, self.fleet, self.idp, self.ad, self.aws, self.fileserver, self.canary, self.push_tripwires, atlas=self.atlas)
        a.lumen, a.hearth = self.lumen, self.hearth
        self.harbor, self.change_tool = HarborService(self.store, self.ctx, clock, self.ledger, self.fleet), ReferenceChangeTool(clock); a.harbor, a.change_tool = self.harbor, self.change_tool
        self.cases = CaseEngine(self.store, self.ctx, clock, self.ledger, reach=self.signet.access_paths)
        self._ward_seen = {}; self._exposed = set(); self.auto_log = []; self.landing_paths = {}; self._landed = set(); self._clawed = set(); self._suspended = set()

    # ---------------- assets ----------------
    def class_of(self, target):
        sg = str(target).split("|")[0]
        if "|" in str(target) and sg in self.aws.sgs:      # a firewall rule is as sensitive as the most sensitive host behind it
            order = ("standard", "production", "clinical", "privileged")
            return max([self.class_of(i) for i, x in self.aws.instances.items() if sg in x.sg_ids] or ["standard"], key=order.index)
        try: return self.store.get_entity(self.ctx, target)["asset_class"]
        except KeyError: return "standard"

    def enroll_device(self, agent, owner_upn, criticality=None):
        self.idp.register_device(agent.device_id, owner_upn, compliant=True)
        self.store.put_entity(self.ctx, agent.device_id, "device", agent.device_id, self.clock.now(), asset_class=agent.asset_class, criticality=criticality)
        self.store.put_sensor(self.ctx, f"ward-{agent.device_id}", agent.device_id, "ward", self.clock.now())
        agent.coverage = self.coverage
        self.fleet.register(agent)

    # ---------------- ingest ----------------
    def process(self):
        """Poll connectors, Courier and Ward agents, group into cases, apply the automatic-response policy. Returns touched cases."""
        touched = {}
        self.engine.offer_due()
        for d, agent in self.fleet.agents.items():         # an online agent's own last check-in time is what coverage measures
            if agent.online and self.store.has_entity(self.ctx, d): self.store.heartbeat(self.ctx, f"ward-{d}", agent.sensors["heartbeat"])
        def add(cf):
            c = self.cases.add(cf); touched[c.id] = c
        for agent in self.fleet.agents.values(): agent.flush_telemetry(self.events, self.ctx)        # so Courier can hunt for where a file landed
        for f in self.signet.poll():
            eid = entity_of_finding(f)
            if eid: add(CaseFinding(f.id, "signet", f.family, eid, f.confidence, f.summary, f.why, f.ts, f.technique, f.details))
        mail_findings = self.courier.poll() + self.courier.rescan()
        for f in mail_findings + self._landing_findings(mail_findings):
            add(CaseFinding(f.id, "courier", f.family, f.entity, f.confidence, f.summary, f.why, f.ts, f.technique, {**f.details, "detector": f.detector}))
        for agent in self.fleet.agents.values():
            seen = self._ward_seen.get(agent.device_id, 0)
            for i, hit in enumerate(agent.detections[seen:], start=seen): add(ward_hit_to_finding(agent.device_id, hit, i))
            self._ward_seen[agent.device_id] = len(agent.detections)
        for f in self.atlas.poll():
            add(CaseFinding(f.id, "aws", f.family, f.entity, f.confidence, f.summary, f.why, f.ts, f.technique, {**f.details, "detector": f.detector}))
            res = self.auto_revert_exposure(f)
            if res is not None: self._record_revert(self.cases.add(CaseFinding(f.id, "aws", f.family, f.entity, f.confidence, f.summary, f.why, f.ts, f.technique, {**f.details, "detector": f.detector})), res)
        for f in self.lumen.poll() + self.hearth.poll() + self.harbor.poll():
            c = self.cases.add(f); touched[c.id] = c
            if f.source == "hearth" and f.details.get("stopped") and not any(a[1] == "stopped the program" for a in c.actions):
                c.actions.append((self.clock.now(), "stopped the program", "done", f"Ward froze {f.details.get('process') or 'the program'} on {f.entity_id} at the tripwire, before any real file was changed. Nothing needed restoring.")); c.status = "contained"
            if f.source == "lumen":
                res = self.auto_suspend_agent(f)
                if res is not None and res.status == "executed": c.actions.append((self.clock.now(), "suspended the AI agent", "done", res.message + " It can be resumed.")); c.status = "contained"
                elif res is not None: c.actions.append((self.clock.now(), "suspending the AI agent", "prepared", res.message)); c.pending.append("The AI agent is still running until an approver suspends it.")
        for f in mail_findings: self.auto_clawback(f)
        for c in list(touched.values()): self.auto_respond(c)
        return list(touched.values())

    def glass_cycle(self):
        """One exposure cycle: refresh cloud posture, re-read the external surface if one is declared, review temporary protections. Returns what changed."""
        self.atlas.posture_findings = __import__("halvard.atlas.posture", fromlist=["x"]).run_checks(self.aws, self.atlas.sensitivity_of, self.atlas.criticality_of)
        if self.surface.scope() and self.surface.observed: self.surface.scan(Principal("halvard:auto", "it_admin"))
        return self.glass.review_controls()

    def auto_suspend_agent(self, f):
        """An AI agent tried to send protected data out or move credentials: suspend it (reversible) under the accepted 'ai_agent_suspend' pattern."""
        if f.confidence < 0.8 or f.entity_id in self._suspended: return None
        self._suspended.add(f.entity_id)
        res = self.engine.request(ActionRequest("suspend_ai_agent", SYSTEM, [f.entity_id], f"{f.summary}", None, {}, automatic=True, pattern="ai_agent_suspend", critical=True))
        self.auto_log.append((f"suspend:{f.entity_id}", res.status)); return res

    def _landing_findings(self, mail_findings):
        """For each harmful attachment, ask the telemetry store which devices saw a file with that hash."""
        out = []
        for f in mail_findings:
            h = f.details.get("campaign")
            if f.family != "malicious_mail" or not h or h.startswith("c:"): continue
            for l in self.courier.landings(h):
                if (h, l["device"]) in self._landed or l["device"] not in {e["entity_id"] for e in self.store.entities(self.ctx)}: continue
                self._landed.add((h, l["device"])); self.landing_paths.setdefault(h, []).append((l["device"], l["path"]))
                landed = {"campaign": h, "path": l["path"], "connector_signed": bool(f.details.get("connector_signed"))}
                if f.details.get("reference_model"): landed["reference_model"] = True
                out.append(self.courier._f(l["ts"], "malicious_attachment_landed", "malicious_mail", l["device"], "T1204.002", min(0.99, f.confidence + 0.05),
                                           "a file with the same fingerprint as the harmful attachment was saved on this device", f"The harmful attachment was saved on {l['device']}.", [f"hash:{h[:12]}"], **landed))
        return out

    def auto_revert_exposure(self, f):
        """A bucket was opened to the internet. Put the protection back (recoverable) under the accepted 'cloud_exposure_revert' pattern;
        on production resources the matrix asks for an approver first, and the case says so."""
        if not _signed_connector(f): return None
        if f.detector != "bucket_made_public" or f.confidence < 0.9 or f.entity in self._exposed: return None
        self._exposed.add(f.entity)
        res = self.engine.request(ActionRequest("block_public_access", SYSTEM, [f.entity], f"{f.entity} was opened to the internet", None, {}, automatic=True, pattern="cloud_exposure_revert", critical=True))
        self.auto_log.append((f"revert:{f.entity}", res.status)); return res

    def _record_revert(self, case, res):
        if res.status == "executed":
            case.status = "contained"; case.actions.append((self.clock.now(), "closed the exposure", "done", res.message + " It can be undone."))
            case.pending.append("Reads made while the data was public cannot be undone. Review who accessed it in your cloud access logs.")
        elif res.status in ("pending_approval", "pending_pattern_acceptance"):
            case.actions.append((self.clock.now(), "closing the exposure", "prepared", res.message))
            case.pending.append(f"The data is still exposed until someone approves. {res.preview['summary'] if res.preview else ''}")
        else: case.actions.append((self.clock.now(), "closing the exposure", res.status, res.message)); case.pending.append(res.message)

    def _base_bundle(self, d):
        """The newest policy for a device, including one still waiting for it to come back online, so one push never undoes another."""
        raw = self.fleet.pending_policy.get(d)
        return PolicyBundle(**raw) if raw else self.fleet.agents[d].bundle

    def push_tripwires(self, device, specs, exempt=None):
        """Tripwire specs (and the program names allowed to touch them) for one device, in a signed policy bundle. The device creates the files."""
        base = self._base_bundle(device)
        b = dataclasses.replace(base, version=base.version + 1, tripwires=[dict(s) for s in specs], tripwire_exempt=sorted((exempt or {}).get(device, set())))
        return self.fleet.push_policy(device, b.sign(self.fleet.key).__dict__.copy())["status"]

    def push_blocked(self, devices, app, why, control, remove=False):
        """Add or remove a temporary 'this program will not start' protection on devices, signed and enforced on the device itself."""
        out = {}
        for d in devices:
            base = self._base_bundle(d); cur = [x for x in base.blocked_apps if x.get("control") != control]
            if not remove: cur.append({"app": app, "why": why, "control": control})
            b = dataclasses.replace(base, version=base.version + 1, blocked_apps=cur)
            out[d] = self.fleet.push_policy(d, b.sign(self.fleet.key).__dict__.copy())["status"]
        return out

    def push_dlp(self, dlp: dict):
        """Data-handling rules, USB approvals and the inspection gate, signed and pushed to every device (offline devices get it on return)."""
        out = {}
        for d, agent in self.fleet.agents.items():
            base = self._base_bundle(d); b = dataclasses.replace(base, version=base.version + 1, dlp=dlp)
            out[d] = self.fleet.push_policy(d, b.sign(self.fleet.key).__dict__.copy())["status"]
        return out

    def auto_clawback(self, f):
        """The quick, safe response: pull every copy of a message judged harmful. Needs only the accepted 'mail_clawback' pattern."""
        key = f.details.get("campaign")
        if not _signed_connector(f): return None
        if f.family not in ("malicious_mail", "impersonation") or f.confidence < 0.9 or not key or key in self._clawed or f.detector in ("opened_malicious_attachment", "malicious_attachment_on_device", "malicious_attachment_landed", "user_reported"): return None
        self._clawed.add(key)
        res = self.engine.request(ActionRequest("clawback_message", SYSTEM, [key], f"harmful message campaign {key[:12]}", None, {}, automatic=True, pattern="mail_clawback"))
        self.auto_log.append((f"clawback:{key[:8]}", res.status))
        if res.status == "executed" and f.family == "malicious_mail" and not key.startswith("c:"): self.push_ioc([key])       # block the same file on every device
        return res

    # ---------------- containment ----------------
    def containment_params(self, case):
        ents = {e["entity_id"]: e for e in self.store.entities(self.ctx)}
        fams = {f.family for f in case.findings}
        persons = sorted(i for i in case.entities if ents.get(i, {}).get("kind") == "person")
        takeover = bool(fams & {"identity_takeover", "credential_phish"})
        identities = sorted(s for s, r, d, _ in self.store.edges(self.ctx, "acts_for") if d in persons and ents.get(s, {}).get("attrs", {}).get("type") in ("user", "service")) if takeover else []
        devices = sorted(i for i in case.entities if ents.get(i, {}).get("kind") == "device" and any(f.entity_id == i for f in case.findings))
        campaigns = sorted({f.details["campaign"] for f in case.findings if f.source == "courier" and f.family == "malicious_mail" and f.details.get("campaign")})
        files = [f"{d}|{p}" for c in campaigns for d, p in self.landing_paths.get(c, []) if d in devices]
        rules = sorted({f"{f.entity_id[4:]}|{f.details['rule']}" for f in case.findings if f.details.get("detector") in ("forwarding_rule", "hiding_rule")})
        fwd = sorted({f.entity_id[4:] for f in case.findings if f.details.get("detector") == "external_forwarding"})
        return {"identities": identities, "devices": devices, "notify_person": persons[0] if persons else None, "reset_credentials": takeover, "reset_mfa": takeover,
                "messages": campaigns, "quarantine_files": files, "mailbox_rules": rules, "forwarding_mailboxes": fwd}

    def contain(self, case, actor=SYSTEM, automatic=False):
        params = self.containment_params(case)
        targets = params["identities"] + params["devices"] + params["messages"] + params["quarantine_files"] + params["mailbox_rules"] + params["forwarding_mailboxes"]
        res = self.engine.request(ActionRequest("contain_everywhere", actor, targets, f"case {case.id}: {case.findings[0].summary}", case.id, params,
                                                automatic=automatic, pattern=self.pattern_for(case) if automatic else None, critical=True))
        self._record(case, res, params); return res

    def approve(self, pending_id, approver, case=None):
        res = self.engine.approve(pending_id, approver)
        if case: self._record(case, res)
        return res

    def _record(self, case, res, params=None):
        what = "containment"
        if res.status == "executed":
            case.status = "contained" if not res.detail.get("partial") else "open"
            case.actions.append((self.clock.now(), what, "done" if not res.detail.get("partial") else "partly done", res.message))
            case.pending = [f"Finish: {s['action']} {s['target']} ({s['status']}): {s['message']}" for s in res.detail.get("steps", []) if s["status"] != "executed"]
            if params and params.get("devices") and not params.get("reset_credentials"):
                ents = {e["entity_id"]: e for e in self.store.entities(self.ctx)}
                owners = {s_ for s_, r, d, _ in self.store.edges(self.ctx, "uses") if d in params["devices"]}
                names = sorted(ents[o]["display_name"] for o in owners if o in ents)
                case.pending.append(f"Malware may have run on {', '.join(params['devices'])}. Once the device is clean, consider resetting the password and sign-in methods for {', '.join(names) or 'the user'}; that needs an approver.")
            case.pending += [f"{w['name']} can still use the old sign-in for {w['seconds'] // 60} minutes; no action needed unless it holds sensitive data." for w in res.detail.get("residual", []) if w["seconds"] > 0]
        elif res.status in ("pending_approval", "pending_pattern_acceptance"):
            case.actions.append((self.clock.now(), what, "prepared", res.message))
            case.pending.append(f"Approve containment ({res.requirement.level if res.requirement else ''}): {res.message} Preview: {res.preview['summary'] if res.preview else ''}")
        else:
            case.actions.append((self.clock.now(), what, res.status, res.message)); case.pending.append(res.message)

    @staticmethod
    def pattern_for(case):
        fams = {f.family for f in case.findings}
        return "identity_takeover_containment" if fams & {"identity_takeover"} else "malicious_mail_containment"

    def auto_respond(self, case):
        if case.status != "open" or any(a[1] == "containment" for a in case.actions): return None
        conf, _ = self.cases.confidence(case)
        fams = {f.family for f in case.findings}
        endpoint_evidence = any(x.source == "ward" or x.details.get("detector") in ("malicious_attachment_landed", "malicious_attachment_on_device") for x in case.findings)
        if not _signed_case(case): return None
        if conf < self.auto_threshold or not ("identity_takeover" in fams or ("malicious_mail" in fams and endpoint_evidence)): return None
        res = self.contain(case, SYSTEM, automatic=True); self.auto_log.append((case.id, res.status)); return res

    def push_ioc(self, hashes):
        """Tell every device that these file hashes are known-bad, so the next attempt to run one is blocked on the device itself."""
        out = {}
        for d, agent in self.fleet.agents.items():
            base = self._base_bundle(d); b = dataclasses.replace(base, version=base.version + 1, known_bad_sha256=sorted(set(base.known_bad_sha256) | set(hashes)))
            out[d] = self.fleet.push_policy(d, b.sign(self.fleet.key).__dict__.copy())["status"]
        return out
