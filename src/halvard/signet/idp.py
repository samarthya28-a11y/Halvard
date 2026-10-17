"""Reference cloud identity provider (the contract Signet's connector codes against).

It is a model, not a vendor clone, but it ENFORCES what the real thing enforces, so containment tests mean something:
  * access tokens are short-lived and self-validating; a revoked session only stops them where the resource server asks
    the IdP (continuous access evaluation / introspection). Servers that do not ask keep accepting a revoked token until
    it expires. Signet reports that residual window instead of pretending revocation is instant.
  * refresh tokens rotate; presenting an old one again is a replay signal.
  * conditional access can require a compliant device; disabled users and revoked sessions cannot refresh.
  * optional token binding rejects a token used from a different device than it was issued to.
"""
import hashlib, secrets
from dataclasses import dataclass, field

GLOBAL_ADMIN = "Global Administrator"
PRIVILEGED_ROLES = {GLOBAL_ADMIN, "Privileged Role Administrator", "Exchange Administrator", "User Administrator", "Application Administrator"}
HIGH_RISK_SCOPES = {"Mail.Read", "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All", "Files.Read.All", "offline_access", "Directory.ReadWrite.All", "User.ReadWrite.All"}


class AuthError(Exception):
    def __init__(self, reason): super().__init__(reason); self.reason = reason


@dataclass
class User:
    upn: str
    display: str
    enabled: bool = True
    mfa_enrolled: bool = True
    password_version: int = 1
    mfa_version: int = 1
    roles: dict = field(default_factory=dict)      # role -> "permanent" | "jit"
    groups: set = field(default_factory=set)
    manager: str | None = None
    is_service: bool = False
    password: str = "correct-horse"
    last_password_change: float = 0.0
    ai_agent: bool = False         # the customer tagged this identity as one an AI agent runs as


@dataclass
class App:
    app_id: str
    name: str
    publisher_verified: bool = True
    created_at: float = 0.0
    cae: bool = False                  # does its resource server ask the IdP whether a token is still valid?
    first_party: bool = True


@dataclass
class Session:
    sid: str
    upn: str
    device_id: str | None
    ip: str
    geo: dict
    created: float
    revoked_at: float | None = None


class ReferenceIdP:
    def __init__(self, tenant, clock, access_ttl=3600.0, refresh_ttl=14 * 86400.0, require_compliant_device=True, token_binding=False, legacy_auth_allowed=False):
        self.tenant, self.clock = tenant, clock
        self.access_ttl, self.refresh_ttl = access_ttl, refresh_ttl
        self.require_compliant_device, self.token_binding, self.legacy_auth_allowed = require_compliant_device, token_binding, legacy_auth_allowed
        self.users, self.apps, self.devices, self.grants, self.sessions = {}, {}, {}, [], {}
        self.refresh, self.refresh_used, self.access, self.log = {}, {}, {}, []
        self.cursor_subscribers = []

    # ---------------- provisioning ----------------
    def add_user(self, upn, display=None, **kw):
        u = User(upn, display or upn, last_password_change=self.clock.now(), **kw); self.users[upn] = u; return u

    def add_app(self, app_id, name, **kw):
        a = App(app_id, name, created_at=kw.pop("created_at", self.clock.now() - 365 * 86400), **kw); self.apps[app_id] = a; return a

    def register_device(self, device_id, owner, compliant=True):
        self.devices[device_id] = {"owner": owner, "compliant": compliant}

    def _emit(self, kind, user, result, **kw):
        ev = {"ts": self.clock.now(), "source": "idp", "kind": kind, "user": user, "result": result, "protocol": kw.pop("protocol", "modern"),
              "ip": kw.pop("ip", None), "geo": kw.pop("geo", None), "device_id": kw.pop("device_id", None), "app": kw.pop("app", None),
              "session_id": kw.pop("session_id", None), "extra": kw}
        d = self.devices.get(ev["device_id"]); ev["device_compliant"] = d["compliant"] if d else None
        self.log.append(ev); return ev

    def events_since(self, cursor):
        return self.log[cursor:], len(self.log)

    # ---------------- sign-in ----------------
    def sign_in(self, upn, password, ip, geo, device_id=None, app="portal", mfa=None, protocol="modern", prompts=1):
        """mfa: 'approve' | 'deny' | None (no response). `prompts` models push spam: that many prompts are sent first."""
        key = getattr(self, "signing_key", None)
        if key is not None and getattr(key, "revoked", False):
            self._emit("signin", upn, "failure", ip=ip, geo=geo, device_id=device_id, app=app, protocol=protocol, reason="signing key revoked"); raise AuthError("signing key revoked")
        u = self.users.get(upn)
        if protocol == "legacy" and not self.legacy_auth_allowed:
            self._emit("signin", upn, "failure", ip=ip, geo=geo, device_id=device_id, app=app, protocol="legacy", reason="legacy authentication blocked"); raise AuthError("legacy_blocked")
        if not u or password != u.password:
            self._emit("signin", upn, "failure", ip=ip, geo=geo, device_id=device_id, app=app, reason="bad credentials"); raise AuthError("bad_credentials")
        if not u.enabled:
            self._emit("signin", upn, "failure", ip=ip, geo=geo, device_id=device_id, app=app, reason="account disabled"); raise AuthError("disabled")
        if self.require_compliant_device and not u.is_service:
            d = self.devices.get(device_id)
            if d is not None and not d["compliant"]:
                self._emit("signin", upn, "failure", ip=ip, geo=geo, device_id=device_id, app=app, reason="device not compliant"); raise AuthError("device_noncompliant")
        if u.mfa_enrolled and not u.is_service:
            ok = False
            for i in range(prompts):
                res = mfa if i == prompts - 1 else ("deny" if mfa == "approve" or i % 2 else None)
                self._emit("mfa_prompt", upn, {"approve": "approved", "deny": "denied", None: "timeout"}[res], ip=ip, geo=geo, device_id=device_id, app=app)
                ok = res == "approve"
            if not ok:
                self._emit("signin", upn, "failure", ip=ip, geo=geo, device_id=device_id, app=app, reason="mfa not approved"); raise AuthError("mfa_failed")
        sid = "S-" + secrets.token_hex(6); now = self.clock.now()
        self.sessions[sid] = Session(sid, upn, device_id, ip, geo, now)
        out = self._issue(sid, app, device_id)
        self._emit("signin", upn, "success", ip=ip, geo=geo, device_id=device_id, app=app, session_id=sid, protocol=protocol)
        return out

    def _issue(self, sid, app, device_id):
        now = self.clock.now(); rt, at = "RT-" + secrets.token_hex(12), "AT-" + secrets.token_hex(12)
        self.refresh[rt] = {"sid": sid, "exp": now + self.refresh_ttl, "bound": device_id}
        self.access[at] = {"sid": sid, "app": app, "exp": now + self.access_ttl, "bound": device_id}
        return {"session_id": sid, "refresh_token": rt, "access_token": at}

    # ---------------- token use ----------------
    def refresh_grant(self, refresh_token, ip, geo, device_id=None, app="portal"):
        r = self.refresh.get(refresh_token)
        if r is None:
            if refresh_token in self.refresh_used:      # a rotated-out token presented again: someone holds a copy
                sid = self.refresh_used[refresh_token]; s = self.sessions[sid]
                self._emit("refresh_reuse", s.upn, "failure", ip=ip, geo=geo, device_id=device_id, app=app, session_id=sid, reason="refresh token reuse")
                self._kill_session(sid)      # standard IdP response to reuse: end the whole token family
            raise AuthError("invalid_grant")
        s = self.sessions[r["sid"]]; u = self.users[s.upn]
        if s.revoked_at is not None or not u.enabled or self.clock.now() > r["exp"]:
            self._emit("token_refresh", s.upn, "failure", ip=ip, geo=geo, device_id=device_id, app=app, session_id=s.sid, reason="session revoked or user disabled"); raise AuthError("invalid_grant")
        if self.token_binding and r["bound"] != device_id:
            self._emit("token_refresh", s.upn, "failure", ip=ip, geo=geo, device_id=device_id, app=app, session_id=s.sid, reason="token bound to another device"); raise AuthError("binding_mismatch")
        d = self.devices.get(device_id)
        if self.require_compliant_device and d is not None and not d["compliant"]:
            self._emit("token_refresh", s.upn, "failure", ip=ip, geo=geo, device_id=device_id, app=app, session_id=s.sid, reason="device not compliant"); raise AuthError("device_noncompliant")
        del self.refresh[refresh_token]; self.refresh_used[refresh_token] = s.sid       # rotate
        out = self._issue(s.sid, app, r["bound"] if self.token_binding else device_id)
        self._emit("token_refresh", s.upn, "success", ip=ip, geo=geo, device_id=device_id, app=app, session_id=s.sid, home_device=s.device_id)
        return out

    def introspect(self, access_token):
        a = self.access.get(access_token)
        if not a or self.clock.now() > a["exp"]: return False
        s = self.sessions[a["sid"]]; return s.revoked_at is None and self.users[s.upn].enabled

    def _valid_locally(self, access_token):
        a = self.access.get(access_token); return bool(a and self.clock.now() <= a["exp"])

    # ---------------- consent and roles ----------------
    def grant_consent(self, upn, app_id, scopes, by="user"):
        self.grants.append({"user": upn, "app": app_id, "scopes": sorted(scopes), "by": by, "ts": self.clock.now(), "revoked": False})
        a = self.apps[app_id]
        self._emit("consent_grant", upn, "success", app=app_id, scopes=sorted(scopes), consent_by=by, publisher_verified=a.publisher_verified,
                   app_age_days=round((self.clock.now() - a.created_at) / 86400, 1))

    def assign_role(self, upn, role, assigned_by, mode="permanent", via_jit_request=None):
        self.users[upn].roles[role] = mode
        self._emit("role_assign", upn, "success", role=role, assigned_by=assigned_by, mode=mode, jit_request=via_jit_request)

    # ---------------- admin surface used by Signet actions ----------------
    def _kill_session(self, sid): self.sessions[sid].revoked_at = self.clock.now()

    def revoke_sessions(self, upn):
        n = 0
        for s in self.sessions.values():
            if s.upn == upn and s.revoked_at is None: self._kill_session(s.sid); n += 1
        for t in [t for t, r in self.refresh.items() if self.sessions[r["sid"]].upn == upn]: del self.refresh[t]
        self._emit("admin_action", upn, "success", action="revoke_sessions", sessions=n); return n

    def disable_user(self, upn): self.users[upn].enabled = False; self._emit("admin_action", upn, "success", action="disable_user")
    def enable_user(self, upn): self.users[upn].enabled = True; self._emit("admin_action", upn, "success", action="enable_user")

    def reset_credentials(self, upn):
        u = self.users[upn]; u.password_version += 1; u.password = "reset-" + secrets.token_hex(6); u.last_password_change = self.clock.now()
        self._emit("admin_action", upn, "success", action="reset_credentials"); return u.password

    def require_mfa_reregistration(self, upn):
        u = self.users[upn]; u.mfa_version += 1; u.mfa_enrolled = False
        self._emit("admin_action", upn, "success", action="require_mfa_reregistration")

    def complete_mfa_registration(self, upn): self.users[upn].mfa_enrolled = True

    def revoke_grant(self, upn, app_id):
        n = 0
        for g in self.grants:
            if g["user"] == upn and g["app"] == app_id and not g["revoked"]: g["revoked"] = True; n += 1
        self._emit("admin_action", upn, "success", action="revoke_grant", app=app_id); return n

    def remove_role(self, upn, role): self.users[upn].roles.pop(role, None); self._emit("admin_action", upn, "success", action="remove_role", role=role)

    def set_device_compliance(self, device_id, compliant, reason=""):
        if device_id in self.devices: self.devices[device_id]["compliant"] = compliant
        self._emit("admin_action", None, "success", action="set_device_compliance", device_id=device_id, compliant=compliant, reason=reason)

    # ---------------- inventory used by Signet ----------------
    def active_access_tokens(self, upn):
        now = self.clock.now()
        return [(t, a) for t, a in self.access.items() if self.sessions[a["sid"]].upn == upn and a["exp"] > now and self.sessions[a["sid"]].revoked_at is None]


class ResourceServer:
    """An application behind the IdP. `cae=True` means it asks the IdP on every request; otherwise it trusts the token until it expires."""
    def __init__(self, idp: ReferenceIdP, app_id):
        self.idp, self.app_id = idp, app_id
        self.cae = idp.apps[app_id].cae

    def handle(self, access_token):
        a = self.idp.access.get(access_token)
        if not a or a["app"] != self.app_id: return False, "invalid token"
        if not self.idp._valid_locally(access_token): return False, "expired"
        if self.cae and not self.idp.introspect(access_token): return False, "revoked (continuous access evaluation)"
        s = self.idp.sessions[a["sid"]]
        return True, f"served {s.upn}"
