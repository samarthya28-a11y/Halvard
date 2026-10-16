# Phase 3: Signet for one cloud identity provider and Active Directory, and cross-domain containment

Evidence (generated from real runs): `docs/11-phase3-evidence.md`. Read its **Not demonstrated** section first.

## What Phase 3 adds

| Capability | Where | Features |
|---|---|---|
| Reference cloud IdP and reference Active Directory that enforce tokens, sessions, revocation, compliance, tickets and event logs | `signet/idp.py`, `signet/ad.py` | the contract connectors code against |
| Identity detections: password spray, MFA fatigue, impossible travel, token replay and refresh reuse, illicit consent, privilege escalation, legacy auth; Kerberoasting, AS-REP roasting, DCSync, privileged-group changes, service-account misuse | `signet/detectors.py` | F051, F052, F056 |
| Graph sync, connector health, access paths to crown jewels | `signet/service.py` | F061, F121 (connectors) |
| Standing-privilege and unused-privilege advice, service-account inventory, entitlement drift, joiner/mover/leaver | `signet/posture.py` | F053, F054, F060, F062 |
| Device health into the IdP | `signet/service.py`, `signet/idp.py` | F055 |
| Cases that group device and identity findings around one person, with a documented score | `cases.py` | F030, F031 (partial) |
| Signet actions: revoke sessions, disable/enable, reset credentials, MFA re-registration, revoke consent, remove standing privilege, notify manager, device-health signal | `relay/signet_actions.py` | F039, F056, F058 |
| One containment across identity, device and people, with an honest residual-exposure statement | `ContainEverywhere` | F044, F045, F046 |
| Signed, expiring, single-use device commands; store-and-forward fleet | `relay/commands.py`, `relay/fleet.py` | F037 remote, F004 |
| Automatic response policy gated on case confidence and an accepted pattern | `controlplane.py` | automation rule of section 7 |

## What "a stolen session cannot keep acting" means here, precisely

1. The IdP stops the stolen **refresh token** immediately (revoked session, rotated tokens, reset credentials, reset verification, refused device).
2. Applications that ask the IdP on every request (continuous access evaluation) stop **immediately**.
3. Applications that only check a token's signature and expiry keep honouring the **access token already issued** until it expires (one hour in the reference IdP).
   Halvard cannot shorten that from the outside. It lists each such application and the minutes left, in the preview before anything runs, in the result, and on the case page.
   The mitigations it can offer are: enable continuous access evaluation on that app, shorten token lifetime, enable token binding (the reference IdP supports it; `posture` should recommend it).
4. The compromised device is isolated with the management channel up, and is marked non-compliant at the IdP so it cannot sign in again.
5. Active Directory has no session to revoke. Tickets already issued live on (default up to 10 h). Disabling and resetting stops new ones. Rotating the krbtgt password twice would end all of them but
   disrupts the domain, so it is **never automatic**; the preview says so.

## Detection notes (confidence is a rule-assigned heuristic, with its reason shown)

| Detector | Fires when | Known false-positive sources |
|---|---|---|
| password_spray (0.8) | ≥ 10 accounts fail from one address within 30 min, ≤ 3 tries each | shared NAT/egress; vulnerability scanners |
| spray_success (0.95) | a sprayed account then signs in from the same address | none known |
| mfa_fatigue (0.92 / 0.6) | ≥ 5 denied or ignored prompts then an approval within 10 min / ≥ 8 with none approved | a broken authenticator app retrying |
| impossible_travel (0.8 new device / 0.6 same device) | ≥ 500 km at > 900 km/h between successful sign-ins | VPN, mobile carriers, geolocation errors (trusted egress is excluded) |
| token_replay (0.9 / 0.8 / 0.75) | session renewed from a different device (and country) than it was created on; weaker when the session is not tied to a device | legitimate device changes; roaming |
| refresh_reuse (0.95) | a replaced refresh token is presented again | client bugs that retry with old tokens |
| illicit_consent (0.85 / 0.75) | user grants high-risk scopes to an unverified publisher or an app younger than 14 days | legitimate new internal apps |
| privilege_escalation (0.85–0.95) | permanent privileged role without an approved JIT request, or privileged-group change by a non-approver | unrecorded emergency changes |
| kerberoasting (0.8 / 0.9) | ≥ 5 distinct services with RC4 tickets within 10 min | old software that only speaks RC4 |
| asrep_roasting (0.75 / 0.85), dcsync (0.97) | no pre-auth ticket requested; replication rights used by a non-DC | legacy apps (allow-list exists); backup tools doing replication |

Thresholds are constants in `Thresholds`, not tuned on real data. **No detection-rate or false-positive-rate is claimed.**

## Containment, approvals and automation

`contain_everywhere` is the strictest of its own row and every component action for every target's asset class. A standard user's account and laptop run under the accepted automation pattern.
A **privileged** account (Domain Admin, Global Administrator) needs **two different people** (the matrix cell); the customer can tighten but not loosen it. This adds minutes to a hijacked admin. That is deliberate.
The 24/7 approver for those minutes is Keeper (Phase 8) or the customer's on-call; until then the case shows exactly what is waiting and who can approve.
Order inside a containment is: end sessions, refuse the device, reset verification and credentials, isolate the device, tell the manager. The attacker holds the clock, so identity goes first and never waits for the device.
A step that fails or is queued is reported and left on the case; the others still run.
Recovery reverses what can be reversed (account enabled, device marked healthy, isolation released through the same command channel) and states what stays reset.

## Device command channel

Commands are signed, device-bound, expiring (default 6 h) and single-use. The device re-checks approvals against its **own** authority matrix and asset class, so a control plane that believes a clinical device is standard cannot isolate it without two approvers. Only an allow-list of actions can be sent remotely. Offline devices get the command when they reconnect, unless it has expired, in which case it is dropped and reported.
Reference limitation: HMAC with a shared key; production uses per-device asymmetric keys.

## Not built, on purpose or because it needs later phases

Real Entra/Okta/Google and real AD connectors (the reference models define the contract); a scheduler calling `process()` and `connector_health()` on a cadence; F057 decoy accounts and honeytokens (Hearth, Phase 7);
F059 privileged-session recording; F082 org-wide OAuth app risk rating (Atlas); mailbox rules and clawback (Courier, Phase 4); a console; Keeper approvers; token-binding advice in `posture` (the IdP supports the switch, the recommendation is not yet generated).
