"""Identity hygiene that shrinks what can be hit (outcome 1): standing privilege (F053), service accounts (F054),
entitlement drift (F060), joiner/mover/leaver mismatches (F062). Every item names the evidence and proposes a Relay
action; nothing here changes anything. Recommendations are plain statements of fact plus a suggested next step."""
from dataclasses import dataclass, field

from .idp import PRIVILEGED_ROLES

DAY = 86400.0


@dataclass
class Recommendation:
    kind: str
    entity: str
    summary: str
    evidence: list
    proposed_action: str | None = None
    params: dict = field(default_factory=dict)
    severity: str = "medium"


def standing_privilege(idp, ad, last_seen_days=30):
    """Privileged access that is permanent rather than just-in-time, and privileged accounts nobody has used lately."""
    now, out = idp.clock.now(), []
    for upn, u in idp.users.items():
        for role, mode in u.roles.items():
            if role in PRIVILEGED_ROLES and mode == "permanent":
                last = max([s.created for s in idp.sessions.values() if s.upn == upn] or [0])
                idle = (now - last) / DAY if last else None
                if idle is None or idle > last_seen_days:
                    out.append(Recommendation("unused_privilege", f"id:idp:{upn}", f"{upn} holds {role} permanently and {'has never signed in' if idle is None else f'has not signed in for {int(idle)} days'}. Remove it.",
                                              [f"role:{role}", f"idle_days:{None if idle is None else int(idle)}"], "remove_standing_privilege", {"role": role}, "high"))
                else:
                    out.append(Recommendation("standing_privilege", f"id:idp:{upn}", f"{upn} holds {role} all the time. Make it just-in-time so it exists only while needed.",
                                              [f"role:{role}", "mode:permanent"], "remove_standing_privilege", {"role": role, "convert_to": "jit"}))
    for sam, groups in ad.privileged_members().items():
        u = ad.users.get(sam)
        if u and not u.is_service:
            idle = (now - u.last_logon) / DAY if u.last_logon else None
            if idle is None or idle > last_seen_days:
                out.append(Recommendation("unused_privilege", f"id:ad:{sam}", f"{sam} is in {', '.join(sorted(groups))} and {'has never logged on' if idle is None else f'has not logged on for {int(idle)} days'}. Remove it.",
                                          [f"groups:{sorted(groups)}"], "remove_standing_privilege", {"groups": sorted(groups)}, "high"))
    return out


def service_account_inventory(idp, ad, max_password_age_days=365, owners=None):
    """Non-human identities and what is risky about each one (F054)."""
    now, owners, out = idp.clock.now(), owners or {}, []
    rows = [(f"id:idp:{u}", u, "cloud", x.is_service, x.last_password_change, bool(set(x.roles) & PRIVILEGED_ROLES), False, u) for u, x in idp.users.items() if x.is_service]
    rows += [(f"id:ad:{s}", s, "directory", True, x.pwd_last_set, s in ad.privileged_members(), x.interactive_logon_seen, s) for s, x in ad.users.items() if x.is_service and not x.is_computer]
    for eid, name, where, _, pwd, priv, interactive, key in rows:
        risks = []
        age = (now - pwd) / DAY
        if age > max_password_age_days: risks.append(f"password {int(age)} days old")
        if priv: risks.append("holds privileged access")
        if interactive: risks.append("has been used interactively")
        if key not in owners: risks.append("no owner recorded")
        if where == "directory" and ad.users[name].spns and ad.users[name].groups & {"Domain Admins"}: risks.append("has a service principal name and Domain Admin rights (a cracked ticket gives domain control)")
        out.append({"entity": eid, "name": name, "where": where, "owner": owners.get(key), "risks": risks, "risk_count": len(risks)})
    return sorted(out, key=lambda r: -r["risk_count"])


def entitlement_drift(idp, ad, hr, role_baselines):
    """Compare what a person's accounts actually hold with what their department's template allows (F060).
    role_baselines: {dept: {"cloud_roles": set, "ad_groups": set}}"""
    out = []
    for r in hr.records.values():
        base = role_baselines.get(r.dept)
        if not base or r.status != "active": continue
        extra = []
        if r.upn in idp.users: extra += [f"cloud role {x}" for x in set(idp.users[r.upn].roles) - set(base.get("cloud_roles", ()))]
        if r.sam in ad.users: extra += [f"group {x}" for x in ad.users[r.sam].groups - set(base.get("ad_groups", ()))]
        if extra:
            out.append(Recommendation("entitlement_drift", r.person, f"{r.name} ({r.dept}) holds access outside the {r.dept} template: {', '.join(sorted(extra))}.", sorted(extra), "remove_standing_privilege", {"remove": sorted(extra)}))
    return out


def joiner_mover_leaver(idp, ad, hr, role_baselines=None, grace_days=7):
    now, out = idp.clock.now(), []
    for r in hr.records.values():
        accounts = ([("cloud", r.upn, idp.users[r.upn].enabled)] if r.upn in idp.users else []) + ([("directory", r.sam, ad.users[r.sam].enabled)] if r.sam in ad.users else [])
        if r.status == "terminated":
            for where, name, enabled in accounts:
                if enabled: out.append(Recommendation("leaver_still_enabled", r.person, f"{r.name} left but their {where} account {name} is still enabled.", [f"{where}:{name}"], "disable_account", {"identity": name}, "high"))
            sessions = [s for s in idp.sessions.values() if s.upn == r.upn and s.revoked_at is None] if r.upn else []
            if sessions: out.append(Recommendation("leaver_active_sessions", r.person, f"{r.name} left but has {len(sessions)} active sign-in session(s).", [s.sid for s in sessions], "revoke_sessions", {"identity": r.upn}, "high"))
            devs = [d for d, x in idp.devices.items() if x["owner"] == r.upn]
            if devs: out.append(Recommendation("leaver_devices", r.person, f"{r.name} left but {len(devs)} device(s) are still registered to them: {', '.join(devs)}.", devs, None, {}, "medium"))
        elif r.status == "active":
            if r.start and now - r.start > grace_days * DAY and accounts == []:
                out.append(Recommendation("joiner_without_account", r.person, f"{r.name} started {int((now - r.start) // DAY)} days ago and has no account.", [], None))
            for where, name, _ in accounts:
                if where == "cloud" and not idp.users[name].mfa_enrolled and not idp.users[name].is_service:
                    out.append(Recommendation("joiner_without_mfa", r.person, f"{name} has not registered multi-factor sign-in.", [f"cloud:{name}"], "force_mfa_reregistration", {"identity": name}))
            if role_baselines and r.dept in role_baselines and r.sam in ad.users:
                other = {g for d, b in role_baselines.items() if d != r.dept for g in b.get("ad_groups", ())} - set(role_baselines[r.dept].get("ad_groups", ()))
                held = ad.users[r.sam].groups & other
                if held: out.append(Recommendation("mover_keeps_old_access", r.person, f"{r.name} is now in {r.dept} but still belongs to groups from another department: {', '.join(sorted(held))}.", sorted(held), "remove_standing_privilege", {"groups": sorted(held)}))
    return out
