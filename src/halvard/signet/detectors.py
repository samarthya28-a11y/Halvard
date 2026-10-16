"""Identity threat detections for a cloud IdP and on-premises Active Directory (F051, F052, F056).

Each detector says what it saw, the confidence it assigns and WHY, with references to the events (not their content).
Confidence values are rule-assigned heuristics, labelled as such; they are not calibrated probabilities. Thresholds are
plain constants a customer can change; defaults are conservative starting points, not measured optima.
"""
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .ad import DS_REPL_GET_CHANGES, DS_REPL_GET_CHANGES_ALL, PRIVILEGED_GROUPS
from .idp import PRIVILEGED_ROLES, HIGH_RISK_SCOPES

MIN = 60.0


def haversine_km(a, b):
    la1, lo1, la2, lo2 = map(math.radians, (a["lat"], a["lon"], b["lat"], b["lon"]))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 6371.0 * 2 * math.asin(math.sqrt(h))


@dataclass
class Finding:
    id: str
    detector: str
    family: str                  # for case scoring: identity_takeover, credential_attack, privilege, persistence, directory_attack
    entity: str                  # identity id (upn, or "ad:SAM")
    technique: str
    confidence: float
    why: str                     # why this confidence
    summary: str                 # one plain sentence
    evidence: list = field(default_factory=list)
    ts: float = 0.0
    source: str = "idp"
    details: dict = field(default_factory=dict)
    case_id: str | None = None


@dataclass
class Thresholds:
    spray_users: int = 10
    spray_max_attempts_per_user: int = 3
    spray_window_s: float = 30 * MIN
    mfa_denied_before_approve: int = 5
    mfa_window_s: float = 10 * MIN
    mfa_ongoing: int = 8
    travel_min_km: float = 500.0
    travel_max_kmh: float = 900.0
    kerberoast_spns: int = 5
    kerberoast_window_s: float = 10 * MIN
    new_admin_window_s: float = 3600.0


class IdentityDetector:
    def __init__(self, clock, th: Thresholds | None = None, trusted_egress=(), approved_jit=(), change_approvers=(), allowed_asrep=(), domain_controllers=(), service_accounts=()):
        self.clock, self.th = clock, th or Thresholds()
        self.trusted_egress, self.approved_jit, self.change_approvers = set(trusted_egress), set(approved_jit), set(change_approvers)
        self.allowed_asrep, self.dcs, self.service_accounts = set(allowed_asrep), set(domain_controllers), set(service_accounts)
        self._n = 0
        self.fail_by_ip = defaultdict(deque)          # ip -> (ts, user)
        self.sprayed = {}                              # ip -> set(users)
        self.mfa = defaultdict(deque)                  # user -> (ts, result)
        self.mfa_flagged = {}
        self.last_ok = {}                              # user -> (ts, geo, ip, device)
        self.sess_origin = {}                          # sid -> (device, geo)
        self.tgs = defaultdict(deque)                  # account -> (ts, spn)
        self.kerb_flagged = {}
        self.created = {}                              # sam -> ts
        self.asrep = defaultdict(set)
        self.seen = 0

    def _f(self, ev, detector, family, entity, technique, conf, why, summary, evidence, **details):
        self._n += 1
        return Finding(f"F-{detector}-{self._n}", detector, family, entity, technique, round(conf, 2), why, summary, evidence, ev["ts"], ev["source"], details)

    def ingest(self, ev):
        self.seen += 1; ev.setdefault("ref", f"{ev['source']}:{self.seen}")
        fn = getattr(self, "_" + ev["source"] + "_" + str(ev["kind"] if ev["source"] == "idp" else ev["event_id"]), None)
        return list(fn(ev) or []) if fn else []

    # ================= cloud IdP =================
    def _idp_signin(self, ev):
        out, u, ip = [], ev["user"], ev.get("ip")
        if ev["result"] == "failure" and ev["extra"].get("reason") == "bad credentials":
            q = self.fail_by_ip[ip]; q.append((ev["ts"], u))
            while q and ev["ts"] - q[0][0] > self.th.spray_window_s: q.popleft()
            users = {x[1] for x in q}; per_user = max([sum(1 for t in q if t[1] == x) for x in users] or [0])
            if len(users) >= self.th.spray_users and per_user <= self.th.spray_max_attempts_per_user and ip not in self.sprayed:
                self.sprayed[ip] = set(users)
                out.append(self._f(ev, "password_spray", "credential_attack", f"ip:{ip}", "T1110.003", 0.8,
                                   f"{len(users)} different accounts failed from one address, at most {per_user} tries each, inside {int(self.th.spray_window_s / MIN)} minutes",
                                   f"One address tried a few passwords against {len(users)} accounts.", [ev["ref"]], accounts=sorted(users), ip=ip))
        if ev["result"] == "success":
            if ip in self.sprayed and u in self.sprayed[ip]:
                out.append(self._f(ev, "spray_success", "credential_attack", u, "T1110.003", 0.95,
                                   "this account was among those sprayed from the same address and then signed in from it",
                                   f"{u} signed in from the address that was guessing passwords.", [ev["ref"]], ip=ip))
            out += self._travel(ev)
            self.sess_origin[ev["session_id"]] = (ev["device_id"], ev["geo"])
            if ev["protocol"] == "legacy":
                out.append(self._f(ev, "legacy_auth", "credential_attack", u, "T1078.004", 0.5, "legacy protocols skip MFA", f"{u} signed in with a legacy protocol.", [ev["ref"]]))
        return out

    def _travel(self, ev):
        u, geo, ip = ev["user"], ev["geo"], ev.get("ip")
        prev = self.last_ok.get(u); self.last_ok[u] = (ev["ts"], geo, ip, ev["device_id"])
        if not prev or not geo or not prev[1] or ip in self.trusted_egress or prev[2] in self.trusted_egress: return []
        km = haversine_km(prev[1], geo); hours = max((ev["ts"] - prev[0]) / 3600.0, 1e-6); kmh = km / hours
        if km >= self.th.travel_min_km and kmh > self.th.travel_max_kmh:
            new_dev = ev["device_id"] != prev[3]
            conf = 0.8 if new_dev else 0.6
            return [self._f(ev, "impossible_travel", "identity_takeover", u, "T1078.004", conf,
                            f"{int(km)} km in {hours * 60:.0f} minutes ({int(kmh)} km/h)" + ("; the second sign-in was from a different device" if new_dev else "; same device, so VPN or geolocation error is plausible"),
                            f"{u} signed in from {prev[1]['country']} and then from {geo['country']} faster than anyone can travel.", [ev["ref"]], km=int(km), kmh=int(kmh), from_country=prev[1]["country"], to_country=geo["country"])]
        return []

    def _idp_mfa_prompt(self, ev):
        u, q = ev["user"], self.mfa[ev["user"]]; q.append((ev["ts"], ev["result"]))
        while q and ev["ts"] - q[0][0] > self.th.mfa_window_s: q.popleft()
        bad = sum(1 for _, r in q if r in ("denied", "timeout"))
        key = (u, int(ev["ts"] // self.th.mfa_window_s))
        if ev["result"] == "approved" and bad >= self.th.mfa_denied_before_approve and key not in self.mfa_flagged:
            self.mfa_flagged[key] = 1
            return [self._f(ev, "mfa_fatigue", "identity_takeover", u, "T1621", 0.92, f"{bad} prompts were denied or ignored, then one was approved within {int(self.th.mfa_window_s / MIN)} minutes",
                            f"{u} was flooded with sign-in prompts and then one was approved.", [ev["ref"]], prompts=len(q))]
        if bad >= self.th.mfa_ongoing and key not in self.mfa_flagged:
            self.mfa_flagged[key] = 1
            return [self._f(ev, "mfa_fatigue", "credential_attack", u, "T1621", 0.6, f"{bad} prompts denied or ignored, none approved yet",
                            f"Someone is repeatedly sending {u} sign-in prompts.", [ev["ref"]], prompts=len(q))]
        return []

    def _idp_token_refresh(self, ev):
        if ev["result"] != "success": return []
        home_dev = ev["extra"].get("home_device"); origin = self.sess_origin.get(ev["session_id"])
        if home_dev is not None and ev["device_id"] != home_dev:
            far = bool(origin and origin[1] and ev["geo"] and origin[1]["country"] != ev["geo"]["country"])
            return [self._f(ev, "token_replay", "identity_takeover", ev["user"], "T1550.001", 0.9 if far else 0.8,
                            f"a session created on device {home_dev} was renewed from {'another country and ' if far else ''}a different device",
                            f"A sign-in session belonging to {ev['user']} is being used from somewhere else.", [ev["ref"]],
                            session_id=ev["session_id"], ip=ev["ip"], country=(ev["geo"] or {}).get("country"))]
        if home_dev is None and origin and origin[1] and ev["geo"] and origin[1]["country"] != ev["geo"]["country"] and ev.get("ip") not in self.trusted_egress:
            return [self._f(ev, "token_replay", "identity_takeover", ev["user"], "T1550.001", 0.75,
                            f"a session created in {origin[1]['country']} was renewed from {ev['geo']['country']}; the session is not tied to a device, so this is weaker evidence",
                            f"A sign-in session belonging to {ev['user']} is being used from a different country.", [ev["ref"]], session_id=ev["session_id"], ip=ev["ip"], country=ev["geo"]["country"])]
        return []

    def _idp_refresh_reuse(self, ev):
        return [self._f(ev, "refresh_reuse", "identity_takeover", ev["user"], "T1528", 0.95,
                        "a sign-in token that was already replaced was presented again, so two parties hold a copy",
                        f"A copied sign-in token for {ev['user']} was used.", [ev["ref"]], session_id=ev["session_id"], ip=ev["ip"])]

    def _idp_consent_grant(self, ev):
        x = ev["extra"]; risky = sorted(set(x["scopes"]) & HIGH_RISK_SCOPES)
        if not risky: return []
        unverified, young = not x["publisher_verified"], x["app_age_days"] < 14
        if (unverified or young) and x["consent_by"] == "user":
            return [self._f(ev, "illicit_consent", "persistence", ev["user"], "T1528", 0.85 if unverified and young else 0.75,
                            "high-risk permissions granted by the user to " + ("an unverified publisher" if unverified else "") + (" and " if unverified and young else "") + ("an app registered less than 14 days ago" if young else ""),
                            f"{ev['user']} gave an unfamiliar app access to {', '.join(risky)}.", [ev["ref"]], app=ev["app"], scopes=risky)]
        return []

    def _idp_role_assign(self, ev):
        x = ev["extra"]
        if x["role"] in PRIVILEGED_ROLES and x["mode"] == "permanent" and x.get("jit_request") not in self.approved_jit:
            self_assign = x["assigned_by"] == ev["user"]
            return [self._f(ev, "privilege_escalation", "privilege", ev["user"], "T1098.003", 0.95 if self_assign else 0.85,
                            "permanent privileged role without an approved just-in-time request" + ("; assigned by the account itself" if self_assign else ""),
                            f"{ev['user']} was given the {x['role']} role outside the approved process.", [ev["ref"]], role=x["role"], assigned_by=x["assigned_by"])]
        return []

    # ================= Active Directory =================
    def _ad_4771(self, ev): return self._ad_fail(ev)
    def _ad_4625(self, ev): return self._ad_fail(ev)

    def _ad_fail(self, ev):
        ip = ev["src_ip"]; q = self.fail_by_ip[ip]; q.append((ev["ts"], ev["account"]))
        while q and ev["ts"] - q[0][0] > self.th.spray_window_s: q.popleft()
        users = {x[1] for x in q}
        if len(users) >= self.th.spray_users and ip not in self.sprayed:
            self.sprayed[ip] = set(users)
            return [self._f(ev, "password_spray", "credential_attack", f"ip:{ip}", "T1110.003", 0.8, f"{len(users)} directory accounts failed from one address",
                            f"One address tried passwords against {len(users)} directory accounts.", [ev["ref"]], accounts=sorted(users), ip=ip)]
        return []

    def _ad_4769(self, ev):
        if ev["enc_type"] != "0x17" or ev["account"].endswith("$") or ev["service"].lower().startswith("krbtgt"): return []
        q = self.tgs[ev["account"]]; q.append((ev["ts"], ev["service"]))
        while q and ev["ts"] - q[0][0] > self.th.kerberoast_window_s: q.popleft()
        spns = {s for _, s in q}
        if len(spns) >= self.th.kerberoast_spns and ev["account"] not in self.kerb_flagged:
            self.kerb_flagged[ev["account"]] = 1
            return [self._f(ev, "kerberoasting", "directory_attack", "ad:" + ev["account"], "T1558.003", 0.9 if len(spns) >= 15 else 0.8,
                            f"{len(spns)} service tickets requested with weak (RC4) encryption in {int(self.th.kerberoast_window_s / MIN)} minutes",
                            f"{ev['account']} asked for tickets for {len(spns)} service accounts using the weakest encryption, which is how their passwords get cracked offline.",
                            [ev["ref"]], services=sorted(spns))]
        return []

    def _ad_4768(self, ev):
        if ev["preauth_type"] == 0 and ev["account"] not in self.allowed_asrep:
            self.asrep[ev["src_ip"]].add(ev["account"])
            many = len(self.asrep[ev["src_ip"]]) >= 3
            return [self._f(ev, "asrep_roasting", "directory_attack", "ad:" + ev["account"], "T1558.004", 0.85 if many else 0.75,
                            "a ticket was requested without pre-authentication" + ("; the same address did this for several accounts" if many else ""),
                            f"A login ticket for {ev['account']} was requested without proving who was asking.", [ev["ref"]])]
        return []

    def _ad_4662(self, ev):
        props = set(ev.get("properties", []))
        if {DS_REPL_GET_CHANGES, DS_REPL_GET_CHANGES_ALL} <= props and ev["account"].rstrip("$") not in {d.rstrip("$") for d in self.dcs}:
            return [self._f(ev, "dcsync", "directory_attack", "ad:" + ev["account"], "T1003.006", 0.97, "directory replication rights used by an account that is not a domain controller",
                            f"{ev['account']} copied password data from the directory as if it were a domain controller.", [ev["ref"]], src=ev.get("src_host"))]
        return []

    def _ad_4720(self, ev):
        self.created[ev["account"]] = ev["ts"]; return []

    def _group(self, ev):
        out = []
        if ev["group"] in PRIVILEGED_GROUPS and ev["by"] not in self.change_approvers:
            fresh = ev["member"] in self.created and ev["ts"] - self.created[ev["member"]] <= self.th.new_admin_window_s
            out.append(self._f(ev, "privilege_escalation", "privilege", "ad:" + ev["member"], "T1098", 0.95 if fresh else 0.9,
                               f"added to {ev['group']} by an account that is not an approved administrator" + ("; the account was created less than an hour earlier" if fresh else ""),
                               f"{ev['member']} was added to {ev['group']} outside the approved change process.", [ev["ref"]], group=ev["group"], by=ev["by"], new_account=fresh))
        return out
    _ad_4728 = _ad_4732 = _ad_4756 = _group

    def _ad_4624(self, ev):
        if ev["logon_type"] in (2, 10) and not ev["account"].endswith("$") and self._is_service(ev["account"]):
            return [self._f(ev, "service_account_interactive", "credential_attack", "ad:" + ev["account"], "T1078.002", 0.6, "service accounts normally never log on interactively",
                            f"The service account {ev['account']} was used like a person's account.", [ev["ref"]])]
        return []

    def _is_service(self, sam): return sam in self.service_accounts
