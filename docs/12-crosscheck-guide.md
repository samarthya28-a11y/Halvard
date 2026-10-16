# Cross-check and manual-testing guide

For: an independent reviewer (Cursor or a person) and for you, testing step by step.
Status: covers Phases 1 to 8. Updated at the end of each phase; the last section says which phases are included.

The author of this code is also the author of its tests and its evidence files. **Do not accept the evidence files on trust.**
Everything below is written so a second reader can re-run it and disagree.

## 0. Setup

* Python 3.11+ (developed on 3.13), standard library only. No install step.
* From the repository root: `python3 -W ignore -m unittest discover -s tests` (about 25 s). The Linux lane needs root and fanotify; elsewhere those tests skip and the summary says so.
* Mutation sweep (removes a behavior on a throwaway copy and requires a named test to fail): `python3 tools/mutation_check.py [name-filter]`.
* Regenerate evidence: `python3 tools/run_acceptance.py`, then `tools/run_acceptance_p2.py` through `tools/run_acceptance_p8.py`.
* On Windows use `py` for `python3` and `$env:PYTHONPATH="src"; py -m halvard.cli <story>` for stories. Two tests skip off Linux.

## 1. Prompt to give Cursor

The single prompt is kept in `docs/23-cursor-prompt.md` (copy it from there). It tells the reviewer to report first, then fix, with a failing test before every fix.

## 2. What each phase claims, and how to check it

### Phase 1 (Ward core, Relay, Ledger, tenancy, setup, performance)
| Claim | Check | Where |
|---|---|---|
| Offline burst is stopped and files restore byte-identical | `python3 -m unittest tests.test_ward_ransomware -v` (run from `tests/` dir or use `discover -p`); read `relay/journal.py` `rollback` | `tests/test_ward_ransomware.py` |
| Destructive actions on production/clinical/privileged assets can never be auto | `tests/test_authority.py`; inspect `relay/matrix_def.py` floors | `docs/03-authority-matrix.md` is generated from it |
| Ledger detects edit, delete, truncation; auditor export has no personal strings | `tests/test_ledger.py`; try your own edits to a `.log` file | `ledger/audit.py` |
| Cross-tenant access fails closed | `tests/test_tenancy.py`; try SQL-ish ids and path traversal | `tenancy.py` |
| Day-one setup proves five protections | `PYTHONPATH=src python3 -m halvard.cli setup` | `setup/guide.py` |
| Performance gate | `tests/test_setup_coverage_perf.py`, `policy/perf_budget.json` | stand-in multiplier is a guess; see doc 07 |

### Phase 2 (Linux/macOS, custom detections, hunt, forensics, FP learning)
| Claim | Check |
|---|---|
| Real kernel sensor stops a real process and restores files | `tests/test_linux_sensor.py` (root). Read `platforms/linux.py`; try breaking `settle()`; look for races between the two fanotify threads |
| HQL SQL and Python paths agree | `tests/test_hunt.py::test_sql_and_python_paths_agree_on_many_queries`; add your own hostile queries |
| IT admin search never returns command lines or users | `tests/test_hunt.py`; read `hunt/service.py` |
| Rules need a different approver, tests, backtest, expiry; devices enforce expiry | `tests/test_detections.py`; `detect/library.py` |
| FP exceptions are narrow, expiring, reversible, observe-only for ransomware | `tests/test_detections.py::LearningTests`; `detect/learning.py` |
| Forensic collection is approval-gated and sealed | `tests/test_forensics_platforms.py`; `relay/forensics.py` |

### Phase 3 (Signet, cases, cross-domain containment)
| Claim | Check |
|---|---|
| A stolen session stops acting after containment, except where an app does not recheck tokens, and that gap is stated | `tests/test_containment.py::StolenSessionAcceptance`; `PYTHONPATH=src python3 -m halvard.cli stolen-session` |
| Device and identity findings become one case with a documented score | `tests/test_signet_posture.py::CaseScoringTests`; `cases.py` |
| Privileged accounts need two approvers | `tests/test_containment.py::PrivilegedAndHybrid` |
| Devices re-check approvals themselves | `test_device_enforces_its_own_approval_rules_even_if_the_control_plane_does_not`, `relay/commands.py` |
| Detectors fire on attacks and stay quiet on normal traffic | `tests/test_signet_detect.py`. Thresholds are untuned constants |

### Phase 4 (Courier, clawback, mail + device + account in one case)
| Claim | Check |
|---|---|
| A malicious mailed attachment and the device that opened it appear as one case | `tests/test_courier_cases.py::MailedAttachmentAcceptance`; `PYTHONPATH=src python3 -m halvard.cli mailed-attachment` |
| Verdict changes after delivery are caught and the delay is measured | `test_nothing_is_wrong_at_delivery_and_the_delay_is_measured_not_assumed` |
| Clawback is recoverable and reports what it cannot undo | `test_clawback_is_honest_about_what_it_cannot_undo`; `relay/courier_actions.py` |
| The same file is blocked on other devices, even offline | `test_the_same_file_is_blocked_on_every_other_device_and_cannot_run_there` |
| Halvard keeps no message text; auditor exports carry no addresses, names or file names | `test_no_message_text_or_subject_is_kept_by_halvard`, `test_auditor_export_of_detections_carries_no_addresses_names_or_file_names`; `ledger/audit.py` `scrub` |
| Service desk can release low-risk mail, not harmful mail alone | `ServiceDeskReleasePath` |
| Mailbox rules and forwarding after a stolen session merge with the takeover case and are undone | `MailboxTamperingMergesWithTakeover` |
| Analysers, impersonation, DMARC, exercises | `tests/test_courier.py` |

### Phase 5 (Atlas cloud posture and workloads, Vaultline classification and controls)
| Claim | Check |
|---|---|
| A regulated bucket made public is closed within one cycle, and anonymous reads really stop | `tests/test_atlas.py::ExposureAcceptance`; `PYTHONPATH=src python3 -m halvard.cli exposed-bucket` |
| Production resources wait for an approver; websites are warned about | `test_a_production_bucket_waits_for_an_approver_and_the_case_says_so`, `test_fixes_preview_what_breaks_and_can_be_undone` |
| Card data cannot leave a laptop by USB or email, offline, and no card number is recorded | `tests/test_vaultline_device.py`, `OutboundMail` in `tests/test_atlas.py`; `PYTHONPATH=src python3 -m halvard.cli data-leak` |
| Nothing is read until consent conditions are met; personal folders never | `InspectionGate` in `tests/test_vaultline_device.py`; `vaultline/inspection.py` |
| Classifiers validate checksums and return counts only | `tests/test_vaultline_classify.py`; `vaultline/classifiers.py` |
| Reasons unlock only one file/door/hour and never secrets | `test_confidential_data_needs_a_reason_which_is_recorded_time_boxed_and_specific`, `test_secrets_cannot_be_unlocked_by_a_reason` |
| Customer-set sensitivity is never overwritten | `test_customer_values_are_never_overwritten_by_a_sync_or_a_scan` |
| A crown-jewel cloud workload without an agent is a coverage incident | `WorkloadsAndCoverage` in `tests/test_atlas.py` |

### Phase 6 (Glass: ranked exposure, temporary protections, patch rings, external surface, baselines, board score)
| Claim | Check |
|---|---|
| One list ranks vulnerabilities and misconfigurations together, and every item shows its working | `tests/test_glass_rank.py`; `glass/exposure.py` (the weights are the thing to challenge) |
| A temporary protection works on the device offline, has an expiry, and an expired one is NOT lifted | `tests/test_glass_controls.py` (`test_expiry_keeps_the_protection_in_force...`, `test_it_works_with_no_network...`) |
| Extensions are capped; only the owner can accept a risk; free text stays out of the public record | `test_extension_is_limited...`, `RiskAcceptanceTests`, `test_free_text_reasons_go_to_the_private_part...` |
| A bad update halts at the pilot ring and rolls back; production waits for an approver; the device re-checks approvals itself | `tests/test_glass_rings.py` |
| Nothing is probed outside the company's own scope; a domain only nominates addresses, a person confirms each | `tests/test_glass_surface.py::ScopeTests` |
| The board score shows its working, leaves unmeasured outcomes out, and is capped by urgent facts | `tests/test_glass_board.py::BoardScoreTests`, `BoardArithmeticTests` |
| Exercised proof is kept apart from real firings, and a failed exercise proves nothing | `ControlEvidenceTests` |
| The whole story | `PYTHONPATH=src python3 -m halvard.cli patch-day` |

### Phase 7 (Lumen AI tools and agents, Hearth tripwires)
| Claim | Check |
|---|---|
| Shadow AI tools are found and regulated data cannot go to them, offline; secrets can never go anywhere | `tests/test_lumen_inventory.py`; `PYTHONPATH=src python3 -m halvard.cli ai-agent` |
| An agent cannot reach a tool except through the gateway | `test_tools_refuse_any_call_that_did_not_come_through_the_gateway` |
| Allow/ask/block by action and data type; "unknown data" is never read as clean | `tests/test_lumen_gateway.py::DataTypeTests`, `AskTests` |
| Hidden instructions in content cannot make an agent send protected data out | `InjectionTests`; the page `ai-agent` prints |
| An incident can be explained afterwards without keeping content | `IncidentTests` (`explain`, absence of card numbers from the whole ledger) |
| An agent's identity cannot reach more than its tools need to be reviewed | `tests/test_lumen_agents.py` |
| A tripwire stops a program on first touch, before any real file changes, offline | `tests/test_hearth_tripwires.py::StopTests`; `PYTHONPATH=src python3 -m halvard.cli tripwires` |
| Tripwires never replace a real file or go in system folders | `PlacementTests` |
| Bait file, decoy account and laptop become one case | `ShareAndLureTests` |
| Canary limits are stated and tested | `CanaryTests` |

### Phase 8 (Harbor, the multi-tenant platform, Keeper across companies, residency and customer keys, deployment profiles)
| Claim | Check |
|---|---|
| Two companies on one database cannot see or change each other, whatever ids they guess or forge | `tests/test_fabric_isolation.py::WallTests`; `PYTHONPATH=src python3 -m halvard.cli platform` |
| Outsiders (providers, parent companies, support staff) get in only through a grant the company opened, and every use is in that company's Ledger | `DelegationTests`; `test_support_access_needs_the_companys_grant...` |
| Keeper is bound by a charter, region, just-in-time access and the matrix, and sees no names unless allowed | `tests/test_fabric_keeper.py` |
| Revoking the customer's key locks the company at once; other companies are untouched | `tests/test_fabric_residency_keys.py::CustomerKeyTests` |
| Data and access stay in the company's regions unless the company allows otherwise | `ResidencyTests` |
| A private deployment accepts no remote staff or crew and makes no unlisted outbound call; a signed bundle updates it | `tests/test_fabric_deployment.py` |
| Unknown devices are found with stated reasons and never blocked by Halvard | `tests/test_harbor.py::DiscoveryTests`; `PYTHONPATH=src python3 -m halvard.cli rogue-device` |
| Segmentation advice waits for enough observation and is a change request only | `AdviceTests` |

## 3. Places most likely to hide bugs (the author's own list)

1. `relay/actions.py`: gate ordering in `request()` (actor check, class resolution, extra requirements, windows, legal hold, pattern gate, approvals); `_apply` sets `req._approvals` for composite steps; `approve()` for two-person counting distinct people.
2. `relay/journal.py`: the "changed after the incident" logic (post-state fingerprints: whole-content hash up to 4 MiB; above that size, ends and mtime; a kernel-hook sensor uses size+mtime because it must not open the files it judges); rate-limited pre-image reuse; `open` records restored only if the file vanished.
3. `platforms/linux.py`: ordering between the permission thread, the notification thread and the response worker; `settle()` is a time-based wait, not a proof; pending events keyed by inode; fails open on its own faults.
4. `ledger/audit.py`: the PII-key list decides what is tokenized in auditor exports; a personal field under an unlisted key would leak. The seal is HMAC with a key the same process holds.
5. `signet/detectors.py`: sliding windows keyed by address/user; thresholds untuned; `token_replay` with no home device is weaker evidence.
6. `signet/idp.py` and `ad.py` are models written by the same author as the detectors. Passing against your own model proves consistency, not correctness against Entra, Okta or a real domain controller.
7. `hunt/nl.py`: regex phrase matching; may mis-translate unusual phrasing. It always shows the query.
9. `courier/analysis.py` and `impersonation.py`: heuristics with hand-set weights; read them as a reviewer would read a spam filter's rules, looking for bypasses (for example a payment request in an attachment, or a look-alike using a character the confusables table lacks).
10. `controlplane.py` `process()` and `auto_respond()`: ordering (telemetry flush, Signet, Courier, Ward), which pattern is chosen, and the rule for resetting passwords. Check it for cases where it would act too eagerly or not at all.
11. The `scrub` defence in `ledger/audit.py` only removes email-shaped strings; other personal identifiers still depend on the PII key list.
12. `vaultline/classifiers.py`: regexes are the attack surface for both misses and false alarms. Try card numbers split by odd separators, numbers in other scripts, and long digit runs; check the cost of the broad `CARD` pattern on large inputs (it is linear in design, but test it).
13. `ward/agent.py` `check_egress`: the order is device rule, then inspection, then rules, then justification; check there is no path where an exception leaves data allowed. `InspectionNotAllowed` deliberately becomes 'inspection off' (content rules do nothing) and is logged.
14. `atlas/aws.py` is a model; `effective_public` simplifies how ACLs, policies and the block settings combine. Do not treat its behavior as AWS's.
15. Test hygiene: the suite once left about 140,000 temp directories and filled the disk. `tests/helpers.py` now removes what it creates and the mutation harness uses a per-mutant temp dir. Confirm after a run that `/tmp` does not grow.
16. `glass/exposure.py`: the weights and tier rules are the whole product opinion of this module. Ask whether a real estate would order the same way, especially local flaws on laptops against internal misconfigurations, and whether `compensated` should step a tier down at all.
17. `glass/service.py` `evaluate()`: first-seen times are kept in memory, so a restart resets every deadline clock (a known gap). Items are keyed by `advisory@entity`; look for keys that could collide or churn.
18. `glass/service.py` rings: `advance()` is a small state machine driven by repeated calls; check the paths where a ring is `awaiting_approval`, then approved, then unhealthy; and the offline-device wait, which relies on a cached report.
19. `glass/surface.py`: scope is the safety property. Try to get a probe to an address that is neither in the cloud account nor confirmed. `candidates()` resolves live DNS each call.
20. `glass/board.py`: the score is arithmetic on stated weights; check every `why` string against its formula, and look for any state in which an unmeasured outcome could still contribute.
21. `glass/evidence.py`: the skipped-sequence ranges that keep exercise entries out of the real count; and the exercise cleanup that rewrites test files. It only touches files under the authorized folder; check that claim.
22. `controlplane.py` `class_of`: a firewall-rule target (`sg|port|cidr`) takes the strictest class of the instances behind it. This changed an earlier phase's behavior (a rule on a production host now waits for an approver).
23. `lumen/gateway.py` `evaluate()`: the rule list is the product opinion. Look for combinations that should be blocked and are only asked (or allowed), and for an action name that maps to a lenient class. `action_class()` decides what counts as leaving the company.
24. `lumen/gateway.py` approvals: one digest, once, expires; check that a different argument, a different session, or a suspended agent cannot reuse a pending id.
25. `ward/agent.py` `tripwire_gate()`: it runs before every file operation and can raise; check that it cannot be bypassed by an operation that does not go through `ProtectedFS` (the native hook must call it), and that its exceptions cannot leave a process frozen forever.
26. `hearth/service.py` `poll()`: entity choice for alarms and the `bait:` campaign key that merges the story; confirm that real activity on a *shared* entity cannot be pulled into a decoy case, and that an alarm is never dropped.
27. `vaultline/dlp.py` tie-break between equal actions: a non-justifiable rule must win ties (a bug here once showed secrets as justifiable).
28. `controlplane.py` `process()`: Lumen and Hearth findings now share the case path with auto-suspension; check the ordering with the other automatic responses.
29. `fabric/platform.py`: the wall depends on `Member` enrolment and on every public method calling `_auth`. Look for any method that takes a tenant id and reaches `rec.cp` without checking who is asking. `cp` objects are plain Python objects: in-process code that obtains one bypasses the wall by design (the real wall is a service boundary).
30. `fabric/platform.py` `delegated()` and `fabric/keeper.py` `_gate()` repeat similar checks in two places. Confirm they cannot drift: a check added to one and not the other is a hole.
31. `fabric/crypto.py`: reference cipher only. Do not review it as cryptography; review the key hierarchy and the lock behaviour (`refresh_key`, `LockedCipher`) and what is NOT encrypted (database rows).
32. `fabric/keeper.py` `_redact()`: string replacement of known names; check pseudonymization against names that are substrings of other words, and against names that appear in fields that are not redacted (entity ids such as `p:alice`).
33. `harbor/service.py`: `unknown()` runs over all devices each call (quadratic in the worst case); confidence weights are hand-set; `_flagged` mixes MAC strings and tuples, check keys cannot collide.
34. `tenancy.py` object cipher hook: `ciphers` is a plain dict keyed by tenant; a missing entry means plain storage. Check that platform tenants can never lack one.
8. The mutation sweeps were wrong twice during development (see docs/08). The harness now refuses to run if the unmutated suite fails in the copy. Verify that yourself.

## 4. Known gaps (aggregate; each phase doc has the full list)

No native Windows or macOS sensor; no installer, updater, console, cloud control plane or network API; HMAC where production needs asymmetric signatures and customer-managed keys;
no real IdP/AD connectors; no scheduler for polling; telemetry covers process and file events only; no public detection-test report; no penetration test; performance is measured on a Python reference with a stand-in multiplier;
every module in the brief's list now has a reference implementation; Harbor's sensor, the key service and the regions are reference models; Lumen's tools and gateway are reference models, Hearth's file server and canary callback are models, Glass runs on a synthetic advisory feed, a reference host that reports what tests set, and a reference internet.

## 5. Step-by-step manual test plan (for you)

Run each step, compare with "expect", and note anything that surprises you.

1. `python3 -W ignore -m unittest discover -s tests` → expect `OK` (counts grow by phase). If not root, Linux tests are skipped.
2. `PYTHONPATH=src python3 -m halvard.cli demo` → expect a plain-language incident page ending `Ledger intact: True`.
3. `PYTHONPATH=src python3 -m halvard.cli setup` → expect six steps, each ✔, ending `6 of 6 setup checks passed`.
4e. `PYTHONPATH=src python3 -m halvard.cli platform` then `... rogue-device` (after Phase 8) → expect two companies with an entity of the same name each seeing only their own, a forged identity refused with the record in the target's ledger, a holding company seeing nothing until a subsidiary grants it, Keeper's queue with names hidden and an action refused without elevation, a bank's data locked and unlocked by its own key, then an unknown device on the server network with reasons, advice withheld until 14 days, and a change request filed that changes nothing itself.
4d. `PYTHONPATH=src python3 -m halvard.cli ai-agent` then `... tripwires` (after Phase 7) → expect shadow AI tools listed first, an agent blocked from sending card data after reading a web page and then suspended with the case saying so, and a ransomware-style burst stopped with zero files changed because of one tripwire, then a bait file, a decoy account and a laptop in one case.
4c. `PYTHONPATH=src python3 -m halvard.cli patch-day` (after Phase 6) → expect a ranked list with the web-server flaw first, a program switched off on a laptop, the production port waiting for an approver, a bad update stopped at the pilot ring, an expired protection that stays in force, and a board page with a capped score and a list of what is not measured.
4b. `PYTHONPATH=src python3 -m halvard.cli exposed-bucket` and `... data-leak` (after Phase 5) → expect a bucket closed again with the production bucket still waiting for an approver, then card data blocked on three drives and held in outbound email, with `Card numbers appear in the record: False`.
4a. `PYTHONPATH=src python3 -m halvard.cli mailed-attachment` (after Phase 4) → expect one case that names Alice, her laptop and the three mailboxes, then what was pulled, what was already opened, and how long the verdict took.
4. `PYTHONPATH=src python3 -m halvard.cli stolen-session` (after Phase 3) → expect a case page, then a table of what stopped at once and what remains usable for how many minutes.
5. Break something on purpose: edit `src/halvard/relay/journal.py` so `_restore` does nothing; rerun step 1 → expect several failures. Revert.
6. Open `docs/03-authority-matrix.md`; pick one cell and ask whether you agree with it. Those are policy decisions for you, not test results.
7. Read the **Not demonstrated** section of each evidence file and decide whether each gap is acceptable for your next milestone.

## 6. Included phases

Phases 1 to 8 (this revision). All eight phases are built; the cross-check by Cursor is next. Later phases will append to sections 2 and 5.
