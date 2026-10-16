"""Signet actions on the control plane (F039, F044, F055, F056, F058) and the one containment that spans device, user and token.

Each handler previews its effect (including what it can NOT stop), applies it through an adapter, and knows its own reversal.
The honest part: revoking a session does not instantly stop an access token that was already issued. Applications that
ask the IdP on every request (continuous access evaluation) stop at once; others keep honouring the token until it expires.
Preview and result both list every such application and the time it can still be used.
"""
from .actions import ActionRequest, Principal
from .matrix_def import BY_KEY

KERBEROS_NOTE = ("Active Directory has no session to revoke. Kerberos tickets already issued keep working until they expire (up to 10 hours by default). "
                 "Disabling the account and resetting its password stops new tickets. Resetting the krbtgt password twice would end all tickets, but it disrupts the whole domain, so Halvard never does it automatically.")


def split_id(eid):
    _, src, name = eid.split(":", 2); return src, name


def residual_windows(idp, upn):
    """For each live access token: can the application still be reached after revocation, and for how long?"""
    now, out = idp.clock.now(), []
    for tok, a in idp.active_access_tokens(upn):
        app = idp.apps.get(a["app"]); secs = 0.0 if (app and app.cae) else max(a["exp"] - now, 0.0)
        out.append({"app": a["app"], "name": app.name if app else a["app"], "cae": bool(app and app.cae), "seconds": round(secs)})
    merged = {}
    for w in out: merged[w["app"]] = max(merged.get(w["app"], w), w, key=lambda x: x["seconds"])
    return sorted(merged.values(), key=lambda w: -w["seconds"])


def _fmt_windows(ws):
    open_ = [w for w in ws if w["seconds"] > 0]
    if not ws: return "No live access tokens were found."
    s = f"{len(ws) - len(open_)} application(s) stop at once."
    if open_: s += " Still usable until the token expires: " + ", ".join(f"{w['name']} ({w['seconds'] // 60} min)" for w in open_) + "."
    return s


class _Base:
    def cannot(self, key): return BY_KEY[key]["cannot_undo"]


class RevokeSessions(_Base):
    def preview(self, eng, req):
        notes = []
        for t in req.targets:
            src, name = split_id(t)
            notes.append(_fmt_windows(residual_windows(eng.adapters.idp, name)) if src == "idp" else KERBEROS_NOTE)
        return {"summary": f"End all sign-in sessions for {len(req.targets)} identity(ies). " + " ".join(notes), "cannot_undo": self.cannot("revoke_sessions")}

    def apply(self, eng, req, plan):
        idp, res, n = eng.adapters.idp, [], 0
        for t in req.targets:
            src, name = split_id(t)
            if src == "idp":
                res += residual_windows(idp, name); n += idp.revoke_sessions(name)
        open_ = [w for w in res if w["seconds"] > 0]
        return {"summary": f"Ended {n} session(s). " + _fmt_windows(res), "undo": {}, "detail": {"residual": res},
                "audit": {"sessions": n, "apps_still_open": len(open_), "max_residual_s": max([w["seconds"] for w in res] or [0])}}

    def undo(self, eng, r, d, ureq): return {"summary": "Nothing to restore: the person simply signs in again."}


class DisableAccount(_Base):
    key = "disable_account"
    def preview(self, eng, req):
        extra = KERBEROS_NOTE if any(split_id(t)[0] == "ad" for t in req.targets) else ""
        return {"summary": f"Disable {len(req.targets)} account(s). The person cannot sign in until it is enabled again. {extra}".strip(), "cannot_undo": self.cannot(self.key)}

    def apply(self, eng, req, plan):
        before = {}
        for t in req.targets:
            src, name = split_id(t)
            if src == "idp": before[t] = eng.adapters.idp.users[name].enabled; eng.adapters.idp.disable_user(name)
            else: before[t] = eng.adapters.ad.users[name].enabled; eng.adapters.ad.disable(name)
        return {"summary": f"Disabled {len(req.targets)} account(s).", "undo": {"before": before}, "audit": {"accounts": len(req.targets)}}

    def undo(self, eng, r, d, ureq):
        for t, was in d["before"].items():
            src, name = split_id(t)
            if was:
                (eng.adapters.idp.enable_user(name) if src == "idp" else eng.adapters.ad.enable(name))
        return {"summary": "Accounts enabled again."}


class DisableServiceAccount(DisableAccount):
    key = "disable_service_account"
    def preview(self, eng, req):
        p = super().preview(eng, req); p["summary"] += " Jobs that use this account will fail until it is restored."; return p


class EnableAccount(_Base):
    def preview(self, eng, req): return {"summary": f"Enable {len(req.targets)} account(s).", "cannot_undo": []}

    def apply(self, eng, req, plan):
        for t in req.targets:
            src, name = split_id(t); (eng.adapters.idp.enable_user(name) if src == "idp" else eng.adapters.ad.enable(name))
        return {"summary": f"Enabled {len(req.targets)} account(s).", "undo": {"targets": list(req.targets)}}

    def undo(self, eng, r, d, ureq):
        for t in d["targets"]:
            src, name = split_id(t); (eng.adapters.idp.disable_user(name) if src == "idp" else eng.adapters.ad.disable(name))
        return {"summary": "Accounts disabled again."}


class ResetCredentials(_Base):
    def preview(self, eng, req): return {"summary": f"Invalidate the password and secrets of {len(req.targets)} account(s). The new password is delivered out of band, never written to the record.", "cannot_undo": self.cannot("reset_credentials")}

    def apply(self, eng, req, plan):
        for t in req.targets:
            src, name = split_id(t); (eng.adapters.idp.reset_credentials(name) if src == "idp" else eng.adapters.ad.reset_password(name))
        return {"summary": f"Reset credentials for {len(req.targets)} account(s).", "undo": {}}


class ForceMFA(_Base):
    def preview(self, eng, req): return {"summary": "Require the person to register their sign-in verification again. Registered phones and keys stop working until they do.", "cannot_undo": []}

    def apply(self, eng, req, plan):
        for t in req.targets:
            src, name = split_id(t)
            if src == "idp": eng.adapters.idp.require_mfa_reregistration(name)
        return {"summary": "Verification methods reset; the person re-registers at next sign-in.", "undo": {}}

    def undo(self, eng, r, d, ureq): return {"summary": "The person re-registers; there is nothing for Halvard to restore."}


class RevokeConsent(_Base):
    def preview(self, eng, req): return {"summary": f"Remove the app's access ({req.params.get('app')}) for {len(req.targets)} person(s). Data it already copied stays copied.", "cannot_undo": self.cannot("revoke_oauth_consent")}

    def apply(self, eng, req, plan):
        n = sum(eng.adapters.idp.revoke_grant(split_id(t)[1], req.params["app"]) for t in req.targets if split_id(t)[0] == "idp")
        return {"summary": f"Removed {n} permission grant(s).", "undo": {}}

    def undo(self, eng, r, d, ureq): return {"summary": "The person can grant it again if they choose; Halvard does not."}


class RemoveStanding(_Base):
    def preview(self, eng, req):
        what = req.params.get("role") or ", ".join(req.params.get("groups", [])) or "listed access"
        return {"summary": f"Remove {what} from {len(req.targets)} identity(ies). {'It can be requested just-in-time.' if req.params.get('convert_to') == 'jit' else ''}".strip(), "cannot_undo": []}

    def apply(self, eng, req, plan):
        undo = []
        for t in req.targets:
            src, name = split_id(t)
            if src == "idp" and req.params.get("role"):
                role = req.params["role"]; undo.append(("role", name, role, eng.adapters.idp.users[name].roles.get(role))); eng.adapters.idp.remove_role(name, role)
            elif src == "ad":
                for g in req.params.get("groups", []): undo.append(("group", name, g, None)); eng.adapters.ad.remove_member(g, name)
        return {"summary": f"Removed {len(undo)} standing entitlement(s).", "undo": {"items": undo}}

    def undo(self, eng, r, d, ureq):
        for kind, name, what, mode in d["items"]:
            if kind == "role": eng.adapters.idp.users[name].roles[what] = mode or "permanent"
            else: eng.adapters.ad.add_member("signet-undo", what, name)
        return {"summary": "Entitlements restored."}


class NotifyManager(_Base):
    def preview(self, eng, req): return {"summary": "Tell the person's manager, through an approved channel that is not part of the incident, in plain words.", "cannot_undo": self.cannot("notify_manager")}

    def apply(self, eng, req, plan):
        r = eng.adapters.notifier.notify_manager(req.params["person"], req.params.get("compromised", ()))
        return {"summary": r.get("message") or f"Manager notified by {r['channel']}.", "undo": {}, "detail": r,
                "audit": {"status": r["status"], "channel": r.get("channel"), "template": r.get("template"), "recipient_role": r.get("recipient_role"), "email": r.get("address")}}


class SetDeviceHealth(_Base):
    def preview(self, eng, req): return {"summary": f"Tell the identity provider that {len(req.targets)} device(s) are {'healthy' if req.params['compliant'] else 'NOT healthy'}. Sign-ins from an unhealthy device are refused.", "cannot_undo": []}

    def apply(self, eng, req, plan):
        idp, prev = eng.adapters.idp, {}
        for t in req.targets:
            prev[t] = idp.devices.get(t, {}).get("compliant"); idp.set_device_compliance(t, req.params["compliant"], req.reason)
        return {"summary": "Device health sent to the identity provider.", "undo": {"previous": prev}}

    def undo(self, eng, r, d, ureq):
        for t, was in d["previous"].items():
            if was is not None: eng.adapters.idp.set_device_compliance(t, was, "undo")
        return {"summary": "Device health restored to its earlier value."}


class ContainEverywhere(_Base):
    """One decision, many places. Identity side first (the attacker is the one with the clock), then the device, then people."""

    def steps(self, eng, req):
        p, out = req.params, []
        for k in p.get("messages", []): out.append(("clawback_message", k))          # stop the spread first: it is cheap and safe
        for i in p.get("identities", []): out.append(("revoke_sessions", i))
        for t in p.get("mailbox_rules", []): out.append(("remove_mailbox_rule", t))
        for m in p.get("forwarding_mailboxes", []): out.append(("disable_forwarding", m))
        for d in p.get("devices", []): out.append(("set_device_health_signal", d))
        for i in p.get("identities", []):
            if split_id(i)[0] == "idp" and p.get("reset_mfa", True): out.append(("force_mfa_reregistration", i))
            if p.get("reset_credentials", True): out.append(("reset_credentials", i))
            if p.get("disable", False): out.append(("disable_account", i))
        for t in p.get("quarantine_files", []): out.append(("quarantine_file", t))      # "device|path"
        for d in p.get("devices", []): out.append(("isolate_host", d))
        if p.get("notify_person"): out.append(("notify_manager", p["notify_person"]))
        return out

    def extra_requirements(self, eng, req):
        return [eng.auth.requirement(a, eng.class_of(t.split("|", 1)[0] if a == "quarantine_file" else t)) for a, t in self.steps(eng, req) if a != "notify_manager"]

    def preview(self, eng, req):
        steps, windows = self.steps(eng, req), []
        for i in req.params.get("identities", []):
            if split_id(i)[0] == "idp": windows += residual_windows(eng.adapters.idp, split_id(i)[1])
        ad = any(split_id(i)[0] == "ad" for i in req.params.get("identities", []))
        lines = [f"{a.replace('_', ' ')}: {t}" for a, t in steps]
        return {"summary": f"{len(steps)} steps across identity, device and people. " + _fmt_windows(windows) + (" " + KERBEROS_NOTE if ad else ""),
                "steps": lines, "residual": windows,
                "cannot_undo": ["passwords that were reset", "verification methods that were reset", "access already used by an application that does not recheck tokens until they expire"]}

    def apply(self, eng, req, plan):
        results, undo, a, mail_exposure = [], [], eng.adapters, []
        approvals, reqmt = getattr(req, "_approvals", []), getattr(req, "_reqmt", None)
        for action, target in self.steps(eng, req):
            sub_params = dict(req.params.get("step_params", {}).get(action, {}))
            try:
                if action == "isolate_host":
                    r = a.fleet.send(target, "isolate_host", {}, req.reason, req.case_id, approvals, reqmt.level if reqmt else "approve", issuer=req.actor.id)
                    results.append({"action": action, "target": target, "status": r["status"], "message": r["message"]})
                    if r["status"] in ("executed", "queued"): undo.append(("release_isolation", target))
                    continue
                if action == "quarantine_file":
                    dev, path = target.split("|", 1)
                    r = a.fleet.send(dev, "quarantine_file", {"paths": [path]}, req.reason, req.case_id, approvals, reqmt.level if reqmt else "approve", issuer=req.actor.id)
                    results.append({"action": action, "target": target, "status": r["status"], "message": r["message"]}); continue
                if action == "set_device_health_signal":
                    sub_params["compliant"] = False
                if action == "notify_manager":
                    sub_params.update(person=target, compromised=[split_id(i)[1] for i in req.params.get("identities", [])]); targets = []
                else: targets = [target]
                h = eng.handlers[action]
                sub = ActionRequest(action, req.actor, targets, req.reason, req.case_id, sub_params, req.automatic, req.pattern, req.critical)
                out = h.apply(eng, sub, h.preview(eng, sub))
                eng._log("relay.action_executed", sub, {"parent": "contain_everywhere", "summary": out.get("summary", ""), "scope": [str(target)]}, ("RELAY." + action.upper(),))
                results.append({"action": action, "target": target, "status": "executed", "message": out.get("summary", "")})
                if action in ("disable_account",): undo.append(("enable", target, out["undo"]["before"]))
                if action == "set_device_health_signal": undo.append(("device_health", target, out["undo"]["previous"]))
                if action == "clawback_message": undo.append(("clawback", target, out["undo"]["moved"])); mail_exposure.extend(out["detail"]["at_risk"])
                if action == "remove_mailbox_rule": undo.append(("rule", target, out["undo"]["rules"]))
                if action == "disable_forwarding": undo.append(("forward", target, out["undo"]["prev"]))
            except Exception as e:      # one failing step must not stop the others; it is reported, never hidden
                results.append({"action": action, "target": target, "status": "failed", "message": repr(e)})
        bad = [r for r in results if r["status"] not in ("executed",)]
        done = sum(1 for r in results if r["status"] == "executed")
        summary = f"{done} of {len(results)} steps done." + (" Not finished: " + "; ".join(f"{r['action']} {r['target']} ({r['status']})" for r in bad) + "." if bad else "")
        return {"summary": summary + (" " + _fmt_windows(plan.get("residual", [])) if req.params.get("identities") else ""), "undo": {"steps": undo},
                "detail": {"steps": results, "residual": plan.get("residual", []), "partial": bool(bad), "mail_exposure": mail_exposure},
                "audit": {"steps": len(results), "done": done, "not_done": len(bad), "residual_apps": sum(1 for w in plan.get("residual", []) if w["seconds"] > 0)}}

    def undo(self, eng, r, d, ureq):
        a, out = eng.adapters, []
        for step in reversed(d["steps"]):
            kind = step[0]
            if kind == "enable":
                for t, was in step[2].items():
                    if was: src, name = split_id(t); (a.idp.enable_user(name) if src == "idp" else a.ad.enable(name))
                out.append("accounts enabled")
            elif kind == "device_health":
                for t, was in step[2].items():
                    if was is not None: a.idp.set_device_compliance(t, was, "undo")
                out.append(f"{step[1]} marked healthy again")
            elif kind == "clawback":
                n = sum(1 for m in step[2] if a.mail.restore(*m)); out.append(f"{n} message(s) returned")
            elif kind == "rule":
                for t in step[2]: a.mail.restore_rule(*t.split("|", 1))
                out.append("mailbox rules restored")
            elif kind == "forward":
                for mb, to in step[2].items(): a.mail.mailboxes[mb].forwarding = to
                out.append("forwarding restored")
            elif kind == "release_isolation":
                rq = getattr(ureq, "_reqmt", None)
                res = a.fleet.send(step[1], "release_isolation", {}, "recovery", r.case_id, getattr(ureq, "_approvals", []), rq.level if rq else "approve", issuer=ureq.actor.id)
                out.append(f"{step[1]} release: {res['status']}")
        return {"summary": "Recovery steps: " + "; ".join(out) + ". Reset passwords and verification methods stay reset: the person sets new ones."}


def register_signet(engine):
    H = engine.handlers
    H.update({"revoke_sessions": RevokeSessions(), "disable_account": DisableAccount(), "enable_account": EnableAccount(), "disable_service_account": DisableServiceAccount(),
              "reset_credentials": ResetCredentials(), "force_mfa_reregistration": ForceMFA(), "revoke_oauth_consent": RevokeConsent(),
              "remove_standing_privilege": RemoveStanding(), "notify_manager": NotifyManager(), "set_device_health_signal": SetDeviceHealth(),
              "contain_everywhere": ContainEverywhere()})
