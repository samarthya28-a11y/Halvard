# Authority matrix: Relay, Signet, Courier, Atlas and Glass

Generated from `src/halvard/relay/matrix_def.py` by `tools/gen_matrix.py`. Do not edit by hand; `tests/test_authority.py` fails if this file is stale.

**Levels:** `auto` runs alone · `notify` runs and tells a named role · `approve` one role must approve first · `two_person` two different people must approve.

**Rules:** a customer may tighten any cell. A customer may loosen a cell only down to its *floor*. Destructive actions on production, clinical and privileged assets never go below `approve`. Keeper: `within_auto` = may run only where the cell is `auto`/`notify` or a customer approver approved; `propose_only` = prepares, a customer approver runs; `never` = Keeper may not do this at all. Humans on staff or Keeper always use just-in-time elevation. No action has a shared superuser path.

## Roles

- **owner**: Risk, spend, renewals, board pack. No device actions.
- **it_admin**: Rollout, policy, exceptions, device health. Approves most Relay actions.
- **analyst**: Cases, hunting, containment. Requests and runs actions; approves within limits.
- **service_desk**: Password-safe actions, quarantine release, 'is this laptop okay?'. No raw telemetry.
- **site_manager**: Local impact only for their site. Approves maintenance windows and clinical-site actions.
- **auditor**: Read-only evidence, time-bounded. Never sees raw employee content.
- **service_provider**: Many tenants, hard walls. Acts only inside a tenant after a delegated grant.
- **keeper_crew**: Halvard crew. Bound by this matrix. Just-in-time elevation required.

## Relay

| Action | Features | Standard | Production | Clinical | Privileged | Floor (S/P/C/X) | Reversal | Cannot undo | Request | Approve | Keeper |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `isolate_host` — Isolate host (management channel stays up) | F037 | notify | approve | two_person | approve | auto/approve/approve/approve | release_isolation | — | it_admin, analyst, service_desk | it_admin, analyst | within_auto |
| `release_isolation` — Release host isolation | F037 | notify | approve | approve | approve | auto/approve/approve/approve | isolate_host | — | it_admin, analyst | it_admin, analyst | propose_only |
| `stop_process` — Stop process | F038 | auto | approve | two_person | approve | auto/approve/approve/approve | none (process restarts only if the user or a service starts it) | in-memory state of the stopped process | it_admin, analyst | it_admin, analyst | within_auto |
| `quarantine_file` — Quarantine file | F038 | auto | approve | approve | approve | auto/approve/approve/approve | release_quarantine | — | it_admin, analyst | it_admin, analyst | within_auto |
| `release_quarantine` — Release file from quarantine | F038/F070 | approve | approve | approve | approve | approve/approve/approve/approve | quarantine_file | — | it_admin, analyst, service_desk | it_admin, analyst | propose_only |
| `remove_persistence` — Remove persistence (startup items, tasks, services) | F038 | notify | approve | two_person | approve | auto/approve/approve/approve | config_rollback | anything the incident changed after the snapshot window | it_admin, analyst | it_admin, analyst | within_auto |
| `journal_rollback` — Restore files from the Halvard journal | F040 | auto | approve | approve | approve | auto/approve/approve/approve | undo_action (a pre-rollback snapshot of current files is kept for the retention window) | files changed outside the journal's quota window; files the journal skipped (reported in the recovery note) | it_admin, analyst, service_desk | it_admin, analyst | within_auto |
| `config_rollback` — Roll back registry, startup and security-config changes | F041 | notify | approve | two_person | approve | auto/approve/approve/approve | undo_action | changes made by someone else after the incident | it_admin, analyst | it_admin, analyst | within_auto |
| `remote_command` — Remote command or script (time-limited, fully recorded) | F042 | approve | approve | two_person | two_person | approve/approve/approve/approve | none (depends on the command; the command text and output are recorded) | effects of the command | analyst, it_admin | it_admin, analyst | propose_only |
| `collect_forensics` — Collect memory or disk evidence | F026 | approve | approve | approve | approve | auto/approve/approve/approve | delete_collection (after legal hold clears) | — | analyst, it_admin | it_admin, analyst | propose_only |
| `run_playbook_step` — Playbook step (inherits the step's own action rule) | F043 | approve | approve | two_person | approve | auto/approve/approve/approve | per step | per step | it_admin, analyst | it_admin, analyst | within_auto |
| `contain_everywhere` — One containment across device, user, mailbox, token, workload | F044 | notify | approve | two_person | two_person | auto/approve/approve/approve | undo_action per component | per component | it_admin, analyst | it_admin, analyst | within_auto |
| `undo_action` — Undo an earlier action | F045 | notify | approve | approve | approve | auto/approve/approve/approve | re-run original | — | it_admin, analyst | it_admin, analyst | propose_only |
| `backup_restore_signal` — Ask the backup product to restore a known-clean copy | F047 | approve | approve | two_person | approve | approve/approve/approve/approve | none (restore is performed by the backup product) | data newer than the restore point | it_admin, analyst | it_admin | propose_only |
| `legal_hold` — Freeze evidence before cleanup | F048 | auto | auto | auto | auto | auto/auto/auto/auto | release_legal_hold | — | it_admin, analyst | it_admin, analyst | within_auto |
| `release_legal_hold` — Release a legal hold | F048 | two_person | two_person | two_person | two_person | two_person/two_person/two_person/two_person | legal_hold | — | owner, it_admin | owner, it_admin | never |
| `override_maintenance_window` — Act during a maintenance window on a named system | F049 | approve | approve | approve | approve | approve/approve/approve/approve | none | — | it_admin, analyst | it_admin, site_manager | propose_only |
| `break_glass_local` — Local break-glass recovery (control plane unreachable) | F050 | two_person | two_person | two_person | two_person | two_person/two_person/two_person/two_person | record replayed to Ledger when connectivity returns | — | it_admin | it_admin, owner | never |

Notes:

- `isolate_host`: Clinical-class devices need two people because isolating a bedside or imaging system has patient impact.
- `release_quarantine`: Service desk may request; a file flagged malicious by detonation needs analyst approval.
- `remote_command`: Never auto. Expires at the time limit. Keeper may only run Halvard-signed runbook commands.
- `collect_forensics`: May contain personal data; collection scope and retention are recorded.
- `run_playbook_step`: The strictest rule among the steps applies; dangerous steps wait for the configured approver.
- `contain_everywhere`: Strictest component rule applies.
- `undo_action`: Before it runs, Halvard states what cannot be undone.
- `legal_hold`: Holding is always safe to automate. It blocks cleanup actions on the case until released.
- `override_maintenance_window`: Critical cases are never delayed by a window; this override is for disruptive actions on high-confidence-not-critical cases.
- `break_glass_local`: Two local holders; every step is written to a local sealed log and replayed into Ledger.

## Signet

| Action | Features | Standard | Production | Clinical | Privileged | Floor (S/P/C/X) | Reversal | Cannot undo | Request | Approve | Keeper |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `revoke_sessions` — Revoke sessions and tokens at the identity provider | F039 | auto | approve | approve | approve | auto/approve/approve/approve | user signs in again | work in progress in the revoked session | it_admin, analyst, service_desk | it_admin, analyst | within_auto |
| `disable_account` — Disable an account | F058 | notify | approve | approve | two_person | auto/approve/approve/approve | enable_account | — | it_admin, analyst | it_admin, analyst | within_auto |
| `enable_account` — Re-enable an account | F058 | approve | approve | approve | two_person | approve/approve/approve/approve | disable_account | — | it_admin, analyst, service_desk | it_admin, analyst | propose_only |
| `reset_credentials` — Force password reset and rotate secrets | F039 | notify | approve | approve | two_person | auto/approve/approve/approve | none (previous credential is invalidated) | the previous credential | it_admin, analyst, service_desk | it_admin, analyst | within_auto |
| `force_mfa_reregistration` — Require MFA re-registration | F056 | notify | approve | approve | approve | auto/approve/approve/approve | user re-registers | — | it_admin, analyst, service_desk | it_admin, analyst | within_auto |
| `revoke_oauth_consent` — Revoke an OAuth consent or third-party app grant | F056 | auto | approve | approve | approve | auto/approve/approve/approve | re-consent by the user | data syncs that ran under the grant | it_admin, analyst | it_admin, analyst | within_auto |
| `remove_standing_privilege` — Remove standing privilege (convert to just-in-time) | F053 | approve | approve | approve | two_person | approve/approve/approve/approve | restore_entitlement | — | it_admin, analyst | it_admin | propose_only |
| `disable_service_account` — Disable a service account or non-human identity | F054 | approve | approve | two_person | two_person | approve/approve/approve/approve | enable_account | jobs that failed while it was disabled | it_admin, analyst | it_admin | propose_only |
| `notify_manager` — Notify the person's manager through an approved channel | F058 | auto | auto | auto | auto | auto/auto/auto/auto | none | a sent notification | it_admin, analyst | it_admin, analyst | within_auto |
| `set_device_health_signal` — Publish device-health signal to the identity provider | F055 | auto | auto | auto | auto | auto/auto/auto/auto | clear signal | — | it_admin, analyst | it_admin | within_auto |
| `start_session_recording` — Record a privileged session | F059 | approve | approve | approve | approve | approve/approve/approve/approve | stop_recording; recording deleted per retention | — | analyst, it_admin | it_admin, owner | never |

Notes:

- `disable_service_account`: Service accounts break production quietly, so there is no auto route.
- `notify_manager`: Only to channels the customer pre-approved; message uses the plain-language template.
- `start_session_recording`: Precondition: policy exists, employee notice was issued, and the session is privileged. Refused otherwise.

## Courier

| Action | Features | Standard | Production | Clinical | Privileged | Floor (S/P/C/X) | Reversal | Cannot undo | Request | Approve | Keeper |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `clawback_message` — Pull a delivered message out of mailboxes (moved to recoverable quarantine, not deleted) | F065 | auto | auto | auto | auto | auto/auto/auto/auto | release_message | — | it_admin, analyst, service_desk | it_admin, analyst | within_auto |
| `release_message` — Return a quarantined message to the mailbox | F070 | notify | notify | notify | notify | auto/auto/auto/auto | clawback_message | — | it_admin, analyst, service_desk | it_admin, analyst | propose_only |
| `purge_message` — Permanently delete quarantined messages | F065 | approve | approve | two_person | approve | approve/approve/approve/approve | none (deleted) | the deleted messages | it_admin, analyst | it_admin | propose_only |
| `remove_mailbox_rule` — Remove a mailbox rule (forwarding, hiding, deleting) | F066 | auto | approve | approve | approve | auto/approve/approve/approve | restore_mailbox_rule (rule is kept for the retention window) | — | it_admin, analyst, service_desk | it_admin, analyst | within_auto |
| `disable_forwarding` — Turn off mailbox forwarding to outside addresses | F066 | auto | approve | approve | approve | auto/approve/approve/approve | re-enable forwarding | mail already forwarded | it_admin, analyst, service_desk | it_admin, analyst | within_auto |
| `block_sender` — Block a sender or look-alike domain tenant-wide | F064 | notify | approve | approve | approve | auto/approve/approve/approve | unblock_sender | — | it_admin, analyst | it_admin, analyst | within_auto |
| `release_outbound_message` — Send a message that Vaultline held before it left | F084 | approve | approve | approve | approve | approve/approve/approve/approve | none (a sent message cannot be recalled) | the message once it is sent | it_admin, analyst, service_desk | it_admin, analyst | propose_only |

Notes:

- `clawback_message`: Non-destructive by design: copies go to a recoverable quarantine. Anything already read, forwarded or saved elsewhere is not recalled; the result lists it.
- `release_message`: Service desk may release low-risk messages alone. A message with a malicious verdict also needs an analyst or administrator to approve (the handler raises the requirement).
- `purge_message`: Only after the retention window and legal-hold check. Separate from clawback so that pulling a message never destroys evidence.
- `release_outbound_message`: Someone other than the sender approves; the sender can instead give a reason when the rule allows it (that path is recorded but is not this action).

## Atlas

| Action | Features | Standard | Production | Clinical | Privileged | Floor (S/P/C/X) | Reversal | Cannot undo | Request | Approve | Keeper |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `block_public_access` — Block all public access to a storage bucket | F079 | notify | approve | approve | approve | auto/approve/approve/approve | restore the earlier public-access settings | reads that anonymous visitors made before it was blocked | it_admin, analyst | it_admin, analyst | within_auto |
| `restrict_security_group_rule` — Close a firewall rule that allows access from anywhere | F079 | notify | approve | two_person | approve | auto/approve/approve/approve | authorize the same rule again | — | it_admin, analyst | it_admin | within_auto |
| `disable_access_key` — Turn off a cloud access key | F079 | notify | approve | approve | approve | auto/approve/approve/approve | turn the key back on | jobs that failed while it was off | it_admin, analyst | it_admin | propose_only |
| `enforce_imdsv2` — Require the safer metadata service on an instance | F079 | approve | approve | approve | approve | auto/approve/approve/approve | allow the old metadata service again | software that only speaks the old service fails until updated | it_admin, analyst | it_admin | propose_only |

Notes:

- `block_public_access`: A bucket that serves a public website will stop serving it; the preview says so when the bucket is tagged as one.

## Glass

| Action | Features | Standard | Production | Clinical | Privileged | Floor (S/P/C/X) | Reversal | Cannot undo | Request | Approve | Keeper |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `install_update` — Install a software update on a device | F095 | notify | approve | two_person | approve | auto/approve/approve/approve | rollback_update | — | it_admin, analyst | it_admin | propose_only |
| `rollback_update` — Put a program back on its previous version | F095 | notify | approve | two_person | approve | auto/approve/approve/approve | install_update | work lost while the program restarted | it_admin, analyst | it_admin | propose_only |
| `apply_compensating_control` — Apply a temporary protection while a patch cannot land | F094 | notify | approve | approve | approve | auto/approve/approve/approve | remove the protection (undo) | people or jobs that relied on the closed port or the switched-off program, while it was in place | it_admin, analyst | it_admin | propose_only |

Notes:

- `install_update`: The program restarts. Production and privileged hosts wait for an approver; clinical hosts need two people. A patch ring never skips this.
- `rollback_update`: A failed pilot ring rolls back on its own only where this cell is auto or notify and the 'patch_failure_rollback' pattern was accepted.
- `apply_compensating_control`: Every temporary protection has an expiry. When it passes, the protection stays in force and the item returns to the top of the list until a person extends it, patches, or signs a risk acceptance.

## Lumen

| Action | Features | Standard | Production | Clinical | Privileged | Floor (S/P/C/X) | Reversal | Cannot undo | Request | Approve | Keeper |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `suspend_ai_agent` — Suspend an AI agent (every tool call is refused until resumed) | F106 | notify | approve | approve | approve | auto/approve/approve/approve | resume the agent (undo) | work the agent was doing for people while suspended | it_admin, analyst | it_admin | within_auto |

Notes:

- `suspend_ai_agent`: Suspending is the safe direction, so standard agents may be suspended automatically under the 'ai_agent_suspend' pattern. Agents whose asset class is production or privileged need an approver first.

## Hearth

| Action | Features | Standard | Production | Clinical | Privileged | Floor (S/P/C/X) | Reversal | Cannot undo | Request | Approve | Keeper |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `place_tripwires` — Place tripwire files on devices | F109/F111 | notify | approve | approve | approve | auto/approve/approve/approve | remove the tripwires (undo) | — | it_admin | it_admin | propose_only |
| `create_decoy_identity` — Create a decoy account or key | F109 | approve | approve | approve | approve | approve/approve/approve/approve | delete the decoy (undo) | — | it_admin | it_admin | propose_only |

Notes:

- `place_tripwires`: Creates generated filler files; never over an existing file and never in an operating-system folder. A program that changes an encryption tripwire is stopped by Ward.
- `create_decoy_identity`: The decoy gets no roles, groups or permissions. A name that already exists is refused.

## Harbor

| Action | Features | Standard | Production | Clinical | Privileged | Floor (S/P/C/X) | Reversal | Cannot undo | Request | Approve | Keeper |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `request_network_change` — File a segmentation change request in the customer's network tool | F076 | approve | approve | approve | approve | auto/approve/approve/approve | withdraw the request (undo) | anything your network team already did with it | it_admin, analyst | it_admin | propose_only |

Notes:

- `request_network_change`: Halvard only files the request; it never changes a firewall or switch. Approval is for sending it, not for applying it.
