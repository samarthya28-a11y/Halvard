"""Source of truth for the authority matrix (docs/03, policy/authority_matrix.json are generated from this).

Approval levels, loosest to strictest:
  auto        runs without a human
  notify      runs, and a named role is told
  approve     one named role must approve first
  two_person  two different people must approve (the second from a different role where possible)

Per asset class, `default` is what ships. `floor` is the loosest a customer may configure for that class; a
customer policy below the floor is rejected at load time. Destructive actions on production, clinical or
privileged assets can never be set to auto or notify.
"""

CLASSES = ("standard", "production", "clinical", "privileged")
A, N, S, T = "auto", "notify", "approve", "two_person"

ROLES = {
    "owner":            "Risk, spend, renewals, board pack. No device actions.",
    "it_admin":         "Rollout, policy, exceptions, device health. Approves most Relay actions.",
    "analyst":          "Cases, hunting, containment. Requests and runs actions; approves within limits.",
    "service_desk":     "Password-safe actions, quarantine release, 'is this laptop okay?'. No raw telemetry.",
    "site_manager":     "Local impact only for their site. Approves maintenance windows and clinical-site actions.",
    "auditor":          "Read-only evidence, time-bounded. Never sees raw employee content.",
    "service_provider": "Many tenants, hard walls. Acts only inside a tenant after a delegated grant.",
    "keeper_crew":      "Halvard crew. Bound by this matrix. Just-in-time elevation required.",
}


def _a(module, key, label, ftag, destructive, reversible, reversal, cannot_undo,
       default, floor, request, approve, keeper, note=""):
    return dict(
        key=key, module=module, label=label, features=ftag, destructive=destructive,
        reversible=reversible, reversal=reversal, cannot_undo=cannot_undo,
        approval=dict(zip(CLASSES, default)), floor=dict(zip(CLASSES, floor)),
        request_roles=request, approve_roles=approve, keeper=keeper, note=note,
    )


ALL_STAFF = ["it_admin", "analyst"]
MATRIX = [
    # ---- Relay ---------------------------------------------------------------------------------
    _a("Relay", "isolate_host", "Isolate host (management channel stays up)", "F037", True, True,
       "release_isolation", [],
       (N, S, T, S), (A, S, S, S), ALL_STAFF + ["service_desk"], ["it_admin", "analyst"], "within_auto",
       "Clinical-class devices need two people because isolating a bedside or imaging system has patient impact."),
    _a("Relay", "release_isolation", "Release host isolation", "F037", False, True,
       "isolate_host", [], (N, S, S, S), (A, S, S, S), ALL_STAFF, ["it_admin", "analyst"], "propose_only"),
    _a("Relay", "stop_process", "Stop process", "F038", True, False,
       "none (process restarts only if the user or a service starts it)", ["in-memory state of the stopped process"],
       (A, S, T, S), (A, S, S, S), ALL_STAFF, ["it_admin", "analyst"], "within_auto"),
    _a("Relay", "quarantine_file", "Quarantine file", "F038", True, True,
       "release_quarantine", [], (A, S, S, S), (A, S, S, S), ALL_STAFF, ["it_admin", "analyst"], "within_auto"),
    _a("Relay", "release_quarantine", "Release file from quarantine", "F038/F070", False, True,
       "quarantine_file", [], (S, S, S, S), (S, S, S, S), ALL_STAFF + ["service_desk"],
       ["it_admin", "analyst"], "propose_only",
       "Service desk may request; a file flagged malicious by detonation needs analyst approval."),
    _a("Relay", "remove_persistence", "Remove persistence (startup items, tasks, services)", "F038", True, True,
       "config_rollback", ["anything the incident changed after the snapshot window"],
       (N, S, T, S), (A, S, S, S), ALL_STAFF, ["it_admin", "analyst"], "within_auto"),
    _a("Relay", "journal_rollback", "Restore files from the Halvard journal", "F040", True, True,
       "undo_action (a pre-rollback snapshot of current files is kept for the retention window)",
       ["files changed outside the journal's quota window", "files the journal skipped (reported in the recovery note)"],
       (A, S, S, S), (A, S, S, S), ALL_STAFF + ["service_desk"], ["it_admin", "analyst"], "within_auto"),
    _a("Relay", "config_rollback", "Roll back registry, startup and security-config changes", "F041", True, True,
       "undo_action", ["changes made by someone else after the incident"],
       (N, S, T, S), (A, S, S, S), ALL_STAFF, ["it_admin", "analyst"], "within_auto"),
    _a("Relay", "remote_command", "Remote command or script (time-limited, fully recorded)", "F042", True, False,
       "none (depends on the command; the command text and output are recorded)", ["effects of the command"],
       (S, S, T, T), (S, S, S, S), ["analyst", "it_admin"], ["it_admin", "analyst"], "propose_only",
       "Never auto. Expires at the time limit. Keeper may only run Halvard-signed runbook commands."),
    _a("Relay", "collect_forensics", "Collect memory or disk evidence", "F026", False, True,
       "delete_collection (after legal hold clears)", [], (S, S, S, S), (A, S, S, S),
       ["analyst", "it_admin"], ["it_admin", "analyst"], "propose_only",
       "May contain personal data; collection scope and retention are recorded."),
    _a("Relay", "run_playbook_step", "Playbook step (inherits the step's own action rule)", "F043", True, True,
       "per step", ["per step"], (S, S, T, S), (A, S, S, S), ALL_STAFF, ["it_admin", "analyst"], "within_auto",
       "The strictest rule among the steps applies; dangerous steps wait for the configured approver."),
    _a("Relay", "contain_everywhere", "One containment across device, user, mailbox, token, workload", "F044", True, True,
       "undo_action per component", ["per component"], (N, S, T, T), (A, S, S, S), ALL_STAFF,
       ["it_admin", "analyst"], "within_auto", "Strictest component rule applies."),
    _a("Relay", "undo_action", "Undo an earlier action", "F045", False, True, "re-run original", [],
       (N, S, S, S), (A, S, S, S), ALL_STAFF, ["it_admin", "analyst"], "propose_only",
       "Before it runs, Halvard states what cannot be undone."),
    _a("Relay", "backup_restore_signal", "Ask the backup product to restore a known-clean copy", "F047", True, False,
       "none (restore is performed by the backup product)", ["data newer than the restore point"],
       (S, S, T, S), (S, S, S, S), ["it_admin", "analyst"], ["it_admin"], "propose_only"),
    _a("Relay", "legal_hold", "Freeze evidence before cleanup", "F048", False, True, "release_legal_hold", [],
       (A, A, A, A), (A, A, A, A), ALL_STAFF, ["it_admin", "analyst"], "within_auto",
       "Holding is always safe to automate. It blocks cleanup actions on the case until released."),
    _a("Relay", "release_legal_hold", "Release a legal hold", "F048", False, False, "legal_hold", [],
       (T, T, T, T), (T, T, T, T), ["owner", "it_admin"], ["owner", "it_admin"], "never"),
    _a("Relay", "override_maintenance_window", "Act during a maintenance window on a named system", "F049", False, True,
       "none", [], (S, S, S, S), (S, S, S, S), ALL_STAFF, ["it_admin", "site_manager"], "propose_only",
       "Critical cases are never delayed by a window; this override is for disruptive actions on high-confidence-not-critical cases."),
    _a("Relay", "break_glass_local", "Local break-glass recovery (control plane unreachable)", "F050", True, True,
       "record replayed to Ledger when connectivity returns", [],
       (T, T, T, T), (T, T, T, T), ["it_admin"], ["it_admin", "owner"], "never",
       "Two local holders; every step is written to a local sealed log and replayed into Ledger."),
    # ---- Signet --------------------------------------------------------------------------------
    _a("Signet", "revoke_sessions", "Revoke sessions and tokens at the identity provider", "F039", True, True,
       "user signs in again", ["work in progress in the revoked session"],
       (A, S, S, S), (A, S, S, S), ALL_STAFF + ["service_desk"], ["it_admin", "analyst"], "within_auto"),
    _a("Signet", "disable_account", "Disable an account", "F058", True, True, "enable_account", [],
       (N, S, S, T), (A, S, S, S), ALL_STAFF, ["it_admin", "analyst"], "within_auto"),
    _a("Signet", "enable_account", "Re-enable an account", "F058", False, True, "disable_account", [],
       (S, S, S, T), (S, S, S, S), ALL_STAFF + ["service_desk"], ["it_admin", "analyst"], "propose_only"),
    _a("Signet", "reset_credentials", "Force password reset and rotate secrets", "F039", True, False,
       "none (previous credential is invalidated)", ["the previous credential"],
       (N, S, S, T), (A, S, S, S), ALL_STAFF + ["service_desk"], ["it_admin", "analyst"], "within_auto"),
    _a("Signet", "force_mfa_reregistration", "Require MFA re-registration", "F056", True, True,
       "user re-registers", [], (N, S, S, S), (A, S, S, S), ALL_STAFF + ["service_desk"],
       ["it_admin", "analyst"], "within_auto"),
    _a("Signet", "revoke_oauth_consent", "Revoke an OAuth consent or third-party app grant", "F056", True, True,
       "re-consent by the user", ["data syncs that ran under the grant"],
       (A, S, S, S), (A, S, S, S), ALL_STAFF, ["it_admin", "analyst"], "within_auto"),
    _a("Signet", "remove_standing_privilege", "Remove standing privilege (convert to just-in-time)", "F053", True, True,
       "restore_entitlement", [], (S, S, S, T), (S, S, S, S), ["it_admin", "analyst"], ["it_admin"], "propose_only"),
    _a("Signet", "disable_service_account", "Disable a service account or non-human identity", "F054", True, True,
       "enable_account", ["jobs that failed while it was disabled"],
       (S, S, T, T), (S, S, S, S), ["it_admin", "analyst"], ["it_admin"], "propose_only",
       "Service accounts break production quietly, so there is no auto route."),
    _a("Signet", "notify_manager", "Notify the person's manager through an approved channel", "F058", False, False,
       "none", ["a sent notification"], (A, A, A, A), (A, A, A, A), ALL_STAFF, ["it_admin", "analyst"], "within_auto",
       "Only to channels the customer pre-approved; message uses the plain-language template."),
    _a("Signet", "set_device_health_signal", "Publish device-health signal to the identity provider", "F055", False, True,
       "clear signal", [], (A, A, A, A), (A, A, A, A), ALL_STAFF, ["it_admin"], "within_auto"),
    _a("Signet", "start_session_recording", "Record a privileged session", "F059", False, True,
       "stop_recording; recording deleted per retention", [], (S, S, S, S), (S, S, S, S),
       ["analyst", "it_admin"], ["it_admin", "owner"], "never",
       "Precondition: policy exists, employee notice was issued, and the session is privileged. Refused otherwise."),
    # ---- Courier ---------------------------------------------------------------------------------
    _a("Courier", "clawback_message", "Pull a delivered message out of mailboxes (moved to recoverable quarantine, not deleted)", "F065", False, True,
       "release_message", [], (A, A, A, A), (A, A, A, A), ALL_STAFF + ["service_desk"], ["it_admin", "analyst"], "within_auto",
       "Non-destructive by design: copies go to a recoverable quarantine. Anything already read, forwarded or saved elsewhere is not recalled; the result lists it."),
    _a("Courier", "release_message", "Return a quarantined message to the mailbox", "F070", False, True, "clawback_message", [],
       (N, N, N, N), (A, A, A, A), ALL_STAFF + ["service_desk"], ["it_admin", "analyst"], "propose_only",
       "Service desk may release low-risk messages alone. A message with a malicious verdict also needs an analyst or administrator to approve (the handler raises the requirement)."),
    _a("Courier", "purge_message", "Permanently delete quarantined messages", "F065", True, False, "none (deleted)", ["the deleted messages"],
       (S, S, T, S), (S, S, S, S), ["it_admin", "analyst"], ["it_admin"], "propose_only",
       "Only after the retention window and legal-hold check. Separate from clawback so that pulling a message never destroys evidence."),
    _a("Courier", "remove_mailbox_rule", "Remove a mailbox rule (forwarding, hiding, deleting)", "F066", True, True, "restore_mailbox_rule (rule is kept for the retention window)", [],
       (A, S, S, S), (A, S, S, S), ALL_STAFF + ["service_desk"], ["it_admin", "analyst"], "within_auto"),
    _a("Courier", "disable_forwarding", "Turn off mailbox forwarding to outside addresses", "F066", True, True, "re-enable forwarding", ["mail already forwarded"],
       (A, S, S, S), (A, S, S, S), ALL_STAFF + ["service_desk"], ["it_admin", "analyst"], "within_auto"),
    _a("Courier", "block_sender", "Block a sender or look-alike domain tenant-wide", "F064", True, True, "unblock_sender", [],
       (N, S, S, S), (A, S, S, S), ALL_STAFF, ["it_admin", "analyst"], "within_auto"),
    _a("Courier", "release_outbound_message", "Send a message that Vaultline held before it left", "F084", False, False, "none (a sent message cannot be recalled)", ["the message once it is sent"],
       (S, S, S, S), (S, S, S, S), ALL_STAFF + ["service_desk"], ["it_admin", "analyst"], "propose_only",
       "Someone other than the sender approves; the sender can instead give a reason when the rule allows it (that path is recorded but is not this action)."),
    # ---- Atlas -----------------------------------------------------------------------------------
    _a("Atlas", "block_public_access", "Block all public access to a storage bucket", "F079", True, True, "restore the earlier public-access settings", ["reads that anonymous visitors made before it was blocked"],
       (N, S, S, S), (A, S, S, S), ALL_STAFF, ["it_admin", "analyst"], "within_auto",
       "A bucket that serves a public website will stop serving it; the preview says so when the bucket is tagged as one."),
    _a("Atlas", "restrict_security_group_rule", "Close a firewall rule that allows access from anywhere", "F079", True, True, "authorize the same rule again", [],
       (N, S, T, S), (A, S, S, S), ALL_STAFF, ["it_admin"], "within_auto"),
    _a("Atlas", "disable_access_key", "Turn off a cloud access key", "F079", True, True, "turn the key back on", ["jobs that failed while it was off"],
       (N, S, S, S), (A, S, S, S), ALL_STAFF, ["it_admin"], "propose_only"),
    _a("Atlas", "enforce_imdsv2", "Require the safer metadata service on an instance", "F079", True, True, "allow the old metadata service again", ["software that only speaks the old service fails until updated"],
       (S, S, S, S), (A, S, S, S), ["it_admin", "analyst"], ["it_admin"], "propose_only"),
    # ---- Glass ---------------------------------------------------------------------------------
    _a("Glass", "install_update", "Install a software update on a device", "F095", True, True, "rollback_update", [],
       (N, S, T, S), (A, S, S, S), ALL_STAFF, ["it_admin"], "propose_only",
       "The program restarts. Production and privileged hosts wait for an approver; clinical hosts need two people. A patch ring never skips this."),
    _a("Glass", "rollback_update", "Put a program back on its previous version", "F095", True, True, "install_update", ["work lost while the program restarted"],
       (N, S, T, S), (A, S, S, S), ALL_STAFF, ["it_admin"], "propose_only",
       "A failed pilot ring rolls back on its own only where this cell is auto or notify and the 'patch_failure_rollback' pattern was accepted."),
    _a("Glass", "apply_compensating_control", "Apply a temporary protection while a patch cannot land", "F094", True, True, "remove the protection (undo)",
       ["people or jobs that relied on the closed port or the switched-off program, while it was in place"],
       (N, S, S, S), (A, S, S, S), ALL_STAFF, ["it_admin"], "propose_only",
       "Every temporary protection has an expiry. When it passes, the protection stays in force and the item returns to the top of the list until a person extends it, patches, or signs a risk acceptance."),
    # ---- Lumen ---------------------------------------------------------------------------------
    _a("Lumen", "suspend_ai_agent", "Suspend an AI agent (every tool call is refused until resumed)", "F106", True, True, "resume the agent (undo)",
       ["work the agent was doing for people while suspended"], (N, S, S, S), (A, S, S, S), ALL_STAFF, ["it_admin"], "within_auto",
       "Suspending is the safe direction, so standard agents may be suspended automatically under the 'ai_agent_suspend' pattern. Agents whose asset class is production or privileged need an approver first."),
    # ---- Hearth --------------------------------------------------------------------------------
    _a("Hearth", "place_tripwires", "Place tripwire files on devices", "F109/F111", False, True, "remove the tripwires (undo)", [],
       (N, S, S, S), (A, S, S, S), ["it_admin"], ["it_admin"], "propose_only",
       "Creates generated filler files; never over an existing file and never in an operating-system folder. A program that changes an encryption tripwire is stopped by Ward."),
    _a("Hearth", "create_decoy_identity", "Create a decoy account or key", "F109", False, True, "delete the decoy (undo)", [],
       (S, S, S, S), (S, S, S, S), ["it_admin"], ["it_admin"], "propose_only",
       "The decoy gets no roles, groups or permissions. A name that already exists is refused."),
    # ---- Harbor --------------------------------------------------------------------------------
    _a("Harbor", "request_network_change", "File a segmentation change request in the customer's network tool", "F076", False, True, "withdraw the request (undo)",
       ["anything your network team already did with it"], (S, S, S, S), (A, S, S, S), ["it_admin", "analyst"], ["it_admin"], "propose_only",
       "Halvard only files the request; it never changes a firewall or switch. Approval is for sending it, not for applying it."),
]

BY_KEY = {a["key"]: a for a in MATRIX}
