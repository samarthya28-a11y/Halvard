# Phase 1 test plan

Scope: Ward (Windows-first contract, tested through `ProtectedFS` on Linux), Relay isolation / quarantine / journal
rollback, Ledger audit, tenant walls, guided setup, performance ceiling. Run with
`python3 -W ignore -m unittest discover -s tests` (80+ tests, about 25 s). `python3 tools/run_acceptance.py` regenerates the evidence.
Every test below names the behavior it guards; `tools/mutation_check.py` removes each behavior in turn and requires a named test to fail.

## 1. The offline ransomware case (acceptance 1)

Fixture: 60 ordinary test files (text, PDF-like, zip-like) in an authorized folder across 3 directories. Agent offline
(`set_online(False)`), bundle already in the device decision cache. A scoped simulation process overwrites files with
random bytes, then (a) renames to `.locked` or (b) writes a `.locked` sibling and deletes the original.

| Test | Pass condition |
|---|---|
| `test_offline_burst_overwrite_rename_is_stopped_and_restored` | stopped within ≤ 10 files; process terminated; file I/O for that pid blocked; 60/60 files byte-identical; no `.locked` left |
| `test_offline_burst_copy_and_delete_style_is_stopped_and_restored` | same, for create-sibling + delete-original |
| `test_offline_decisions_are_in_the_spool_and_reach_ledger_after_reconnect` | decision tagged `WARD.OFFLINE_PREVENTION`, `online=false`; nothing forwarded while offline; after reconnect spool is verified and ingested; both chains verify |
| `test_tampered_spool_is_rejected_at_ingest` | an edited device spool is rejected, not merged |
| `test_legitimate_bulk_work_is_not_stopped` | compressor, photo batch export (signature kept), mass text edit: zero incidents |
| `test_slow_trickle_is_not_a_burst` | documents the known limit: 1 file / 20 s does not fire |
| `test_audit_only_mode_logs_but_does_not_block` | audit-only logs, never blocks |
| `test_production_server_freezes_io_immediately_but_waits_for_approver_to_terminate` | I/O frozen at once; terminate and rollback wait for approval; approve → restored |
| `test_clinical_device_needs_two_different_people` | same person twice refused; second person completes |
| `test_unaccepted_pattern_prepares_but_does_not_run` | I/O still frozen; response prepared only |
| `test_file_changed_after_incident_is_left_alone_and_reported` | a file the user edited after the incident is not overwritten |
| `test_quota_exhaustion_is_reported_as_not_restorable` | explicit reason in the report |
| `test_rollback_can_be_undone` | rollback keeps a pre-rollback snapshot |
| `test_simulation_refuses_unauthorized_directory` | simulator cannot touch an unmarked folder |

## 2. Relay actions and authority

`tests/test_actions.py`, `tests/test_authority.py`: role checks; audit record carries actor, reason, scope, approval, reversal,
cannot-undo; isolation leaves only the management path; irreversible actions refuse undo and say why; self-approval refused;
Keeper needs JIT and cannot approve; first-run automation parks until accepted; maintenance window defers ordinary and never
critical; legal hold blocks cleanup until evidence is frozen; customer cannot set a cell below its floor; generated matrix doc is not stale.

## 3. Ward guard rails

`tests/test_ward_misc.py`: known-bad blocked with no connectivity and quarantined; cloud reputation consulted only online;
tampered/deleted agent files restored and logged; uninstall code single-use, expiring, device-bound; unsigned or rolled-back policy refused;
isolation rules render default-deny with only the management path.

## 4. Ledger and tenancy

`tests/test_ledger.py`: edit, deletion, truncation detected; raw content refused; auditor export has no personal strings and verifies with no key; tampered export fails.
`tests/test_tenancy.py`: cross-tenant read, list, object, traversal, forged context, SQL-ish ids, cross-tenant edge, support grants (absent, valid, expired, wrong tenant).

## 5. Day-one setup and coverage

`tests/test_setup_coverage_perf.py`: a driver that knows only `next_step()` / `run_current()` finishes all six steps and the machine is left usable;
failing steps say what failed and what is still protected and do not advance; missing agent on a crown-jewel server is an incident at once;
silent agent flagged only after its promised interval; change window quiets an ordinary gap, never a crown-jewel one; other tenants' assets never appear.

## 6. Performance ceiling

Published in `policy/perf_budget.json`. The test plays a deterministic workday-shaped trace (autosave, cache writes, temp files,
save-as, deletes, backup copies, photo exports) with and without Ward, takes median of 3 runs, and fails if any ceiling is exceeded:
estimated CPU ≤ 2 % of one core over a workday, added latency p99 ≤ 20 ms, memory ≤ 150 MB, journal ≤ 512 MB / workday, install ≤ 200 MB, and no false-positive stop.
Limits: Python reference, cloud VM × 2.0 stand-in multiplier, tracemalloc (Python heap) not RSS, no real-hardware lane. The native agent must pass the same trace.

## 7. Not yet covered

Native hook conformance tests, Windows/macOS/Linux isolation execution, real-hardware perf, fuzzing of the policy and spool parsers, load tests, accessibility and localization tests (console not built), pen-test.

## Phase 2 additions

* `tests/test_linux_sensor.py` (privileged lane, real processes on a private tmpfs): paced burst stopped and restored (both styles), unpaced burst still restored,
  kernel denial of a frozen process, kernel-enforced exec deny offline, exec/file telemetry, memory forensics of a live process.
* `tests/test_hunt.py`: SQL/Python equivalence on hostile data, injection, stages, phrase translator, role limits, simple-search redaction, audit, tenant isolation, retention tiers, export format.
* `tests/test_detections.py`: lifecycle and gates, expiry, backtest noise cap, thresholds, signed packs, offline device detection, learning (suggest, scope, conflicts, preview, revoke, expiry, observe-only for bulk encryption).
* `tests/test_forensics_platforms.py`: profile gating, sealed manifests, ledger contents, legal hold, platform path identity and exclusions, rendered isolation per OS, same core on each profile.
* `tools/mutation_check.py` now runs on throwaway copies (4 workers), requires the baseline to pass in a copy, and holds 50 mutations. Two earlier invalid sweeps (a wrong flag, then a missing `tools/` in the copy) were caught and fixed; the harness now fails loudly if the baseline does not pass where the mutants run.

## Phase 3 additions

* `tests/test_signet_detect.py`: each detector fires on its attack and stays quiet on ordinary traffic (forgotten MFA approval, AES tickets for many services, approved admin changes, VPN egress, nine-hour travel, the home device refreshing), technique tags exist in the bundled list, findings carry no secrets.
* `tests/test_containment.py`: the stolen-session acceptance case against the reference IdP and resource servers (immediate stop where tokens are rechecked, stated residual where they are not), one case from device and identity findings, offline laptop and expired commands, the device re-checking its own rules, forged/replayed/unsafe commands, notification channel rules, ledger agreement on both sides with no secrets, recovery, privileged two-person, hybrid identities, partial failure, tightened component rules.
* `tests/test_signet_posture.py`: access paths, standing and unused privilege, service-account inventory, drift, joiner/mover/leaver, device health into the IdP, connector gaps, tenant isolation of findings, case grouping, scoring and merge.
* `tools/mutation_check.py`: 84 mutations including 34 for Phase 3; four initially survived and exposed real test gaps, now closed.

## Phase 4 additions

* `tests/test_courier.py`: attachment and link analysers (what they flag and leave alone, including look-alike spellings that edit distance alone would miss), impersonation and payment-fraud rules (including bank-account comparison and joiners after start-up), DMARC/SPF/DKIM posture and staged advice, practice exercises and their group-size rule.
* `tests/test_courier_cases.py`: the acceptance case (attachment clean at delivery, opened on a laptop, caught later, one case, every copy pulled, file removed from the laptop, device isolated, same file blocked offline on another device, no automatic password reset), clawback honesty, no message text kept, auditor export without addresses/names/file names, patterns required, sender-only fraud, mailbox rules and forwarding merged with a takeover case and undone, service-desk release rules, user reports, purge under legal hold, telemetry fingerprints and process lineage.
* `tools/mutation_check.py`: 115 mutations, 31 for Phase 4. Two Phase 4 survivors exposed missing look-alike and threshold tests; the evidence run itself exposed two real bugs (a stale staff list, and sender-only fraud mislabelled as a harmful attachment) and the full sweep's baseline exposed a Linux-sensor race (a file renamed between a check and a stat). All three fixed with tests.

## Phase 5 additions

* `tests/test_vaultline_classify.py`: known-valid and known-invalid card, IBAN, Aadhaar and SSN values; ordinary numbers are not regulated data; Office files read, unreadable formats reported; counts and reasons, never values.
* `tests/test_vaultline_device.py` (offline): each kind of drive, the read-only device rule, logs without values or paths, justification (recorded, time-boxed, file-specific, never for secrets), print and upload, blocked process, every consent condition, personal folders, catalog contents, encryption and device health, policy delivery to an offline device and refusal of an unsigned one.
* `tests/test_atlas.py`: posture ordering and context, internet-to-data paths, customer-set values preserved, fixes previewed and reversible, the exposure acceptance case (including production approval and a deliberate website), change detections and flagged-address correlation, audit/exports without card numbers or object names, coverage incident for an agentless crown-jewel workload, policy drift, store scanning gate, outbound mail held/justified/released.
* `tests/test_saas.py`: discovery from the identity provider and a proxy log; rubric with reasons.
* `tools/mutation_check.py`: 154 mutations, 39 for Phase 5. The harness now gives each mutant its own temp directory, and `tests/helpers.py` removes the directories tests create (a full disk, from about 140,000 leftover directories, stopped one sweep).

## Phase 6 additions

* `tests/test_glass_rank.py`: the rule and its factors (each factor moves the number; tiers follow plain rules; a live protection steps only fix-now down), version comparison as numbers, the synthetic feed, items opening and closing in the Ledger, deadlines by tier, who may see the list (refusals recorded), baseline drift (a missing value is not fine; exceptions need role, reason, limit and expire), risk acceptance (owner only, limited, shown not hidden).
* `tests/test_glass_controls.py`: a program switched off on the device itself (named program only, offline, queued protection survives another policy push), production waits for an approver, limits and roles, expiry keeps the protection in force, extension caps, retirement and release, undo, free text kept out of the public record.
* `tests/test_glass_rings.py`: a good rollout goes ring by ring after soaking, a bad pilot halts and rolls back without touching anyone else, rollback waits for a person without the accepted pattern and on production, production goes last, an offline device blocks a ring, the device refuses a command with too little approval, device-side undo.
* `tests/test_glass_surface.py`: nothing probed outside the verified and confirmed scope, domain challenge, only plain connections to a fixed port list, internet-side findings joined to the same list without duplicates, an unknown server with a known flaw, expiry warnings recorded once per level, time-boxed admin exposure.
* `tests/test_glass_board.py`: each outcome shows its working, an unmeasured outcome is left out, the cap holds when every outcome is full marks, exact deductions, a ledger that fails verification, the page answers four questions with the same numbers, who may read it, snapshots and trend; control evidence: never fired vs fired vs exercised vs stale, the exercise (authorization, role, isolation released, a failing exercise proves nothing and repairs test files, exercise events not counted as real).
* `tools/mutation_check.py`: 216 mutations, 62 for Phase 6. The first Phase 6 sweep left eight survivors; they exposed tests that passed whatever the cap, the deductions or the isolation release did, and an exercise that counted an audit-only detection as a stop. The evidence run exposed that enrolled devices had no sensor and so could never go quiet.

## Phase 7 additions

* `tests/test_lumen_inventory.py`: tools found from traffic, grants and devices; look-alike domains do not match; approval needs a role and the enterprise tier needs the customer's own record of the terms; the device rule table (regulated, confidential, internal, secrets) per tier, offline, with no values in the record, and a reason that opens one door only.
* `tests/test_lumen_agents.py`: tagged identities found; registration needs role, owner and actions; a review is refused while the identity can reach more than the tools need; agents are graph entities that act for their owner.
* `tests/test_lumen_gateway.py`: allowed calls run and are recorded by digest; tools refuse calls that did not come through the gateway (no grant, wrong arguments, reuse, expiry, tampering); unregistered agents do nothing; data-type rules, inspection off meaning "unknown", the consent gate; ask/approve/deny/expire/owner rules; unreviewed agents; runaway loops; untrusted content then a sensitive action; automatic suspension with the case recording it; the plain-words explanation and the absence of payloads from the whole ledger; auditor export hides targets.
* `tests/test_hearth_tripwires.py`: placement through the action engine (never over a file, never in system folders, approver on production, undo, offline), a burst stopped on first touch with nothing changed, the same burst without a tripwire changes 7 files, a tripwire reached last does not help, readers and exempt programs, audit-only mode, removal and change behind the hook, rename and delete.
* `tests/test_hearth_decoys.py`: decoy accounts have no rights and refuse real names; a decoy account or key alarms from the first attempt and is not a posture problem; decoy shares (open vs browse, exemptions that end); bait file plus decoy account is one case; catalog visibility and recorded refusals; canary documents and their limits; an alarm with no entity is never lost.
* `tools/mutation_check.py`: 279 mutations, 63 for Phase 7.

## Phase 8 additions

* `tests/test_fabric_isolation.py`: two companies with identical entity ids on one database; forged and cross-claimed identities refused with the record in the target's Ledger; guessed ids, traversal and support grants for another company; separate ledger and policy keys (a pasted ledger line fails, a bundle signed for one company is rejected by another's device); activity in one company absent from another; delegation by scope, role, grantee, region, expiry and revocation; only the company's own admin can open or revoke; parent-ness gives nothing.
* `tests/test_fabric_keeper.py`: charters cannot list what the matrix forbids; crew need assignment, a charter and a grant; queue spans assigned companies without mixing data and hides people; region and deployment refusals; just-in-time elevation per company that expires and does not carry over; charter limits; Keeper only proposes where the matrix says so and cannot approve; out-of-hours mode; revocation stops the crew; the company's activity report.
* `tests/test_fabric_residency_keys.py`: sealed objects, tamper and cross-company detection, revoke/restore/destroy, locked companies refuse their own staff and outsiders, other companies untouched; residency rules for export, staff support and follow-the-sun.
* `tests/test_fabric_deployment.py`: the dependency report, the outbound-call guard and allowlist, remote staff and providers refused on a private deployment, a signed bundle applied on a device with no link (advisories, AI catalog, known-bad hashes block offline), unsigned, altered, wrong-key, old and repeated bundles change nothing.
* `tests/test_harbor.py`: known versus unknown devices, reasons and confidence, thresholds, one finding per device, a case page that names the network, adoption and coverage gaps, expiring exceptions, roles; fan-out and zone-violation detections (and what is not flagged); silent sensors, buffering and counted loss, no payload fields; segmentation advice waits for 14 days, proposes removal and narrowing with nothing broken, and the request is filed only after approval and can be withdrawn.
* `tools/mutation_check.py`: 341 mutations, 62 for Phase 8.

