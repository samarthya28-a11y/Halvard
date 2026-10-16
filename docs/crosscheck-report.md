# Cross-check report (before any source fix)

Date of this run: 2026-10-16. Python 3.12.3 on Linux. Branch `cursor/crosscheck-ab75` (the review asked for a branch named `crosscheck`; this environment requires the `cursor/` prefix and the `-ab75` suffix).

No file under `src/` was changed. The new tests in `tests/test_crosscheck_*.py` are expected to fail. That is the evidence, not a skip.

## How this was run

Author suite plus the new tests, one command:

```
python3 -W ignore -m unittest discover -s tests
```

Result: `Ran 504 tests in 12.160s`, `FAILED (failures=23, skipped=8)`. The performance line printed by the suite was:

```
perf: {"events": 4000, "agent_overhead_us_per_event": 216.6, "cpu_percent_of_one_core_workday_est": 0.451, "added_latency_p99_us_scaled": 973.0, "memory_peak_mb": 3.22, "journal_mb_per_workday_est": 367.8, "install_footprint_mb": 0.001, "blocked_processes": 0, "incidents": 0, "pass": true, "runs_cpu_percent": [0.448, 0.451, 0.564]}
```

The 23 failures are exactly the cross-check tests below. A dedicated run of only those files (`python3 -W ignore -m unittest discover -s tests -p 'test_crosscheck_*.py'`) was `Ran 42 tests in 0.500s`, `FAILED (failures=23)`. So the author's own tests are 462, with 0 failures and 8 skips. The 8 skips are all in `tests/test_linux_sensor.py`, each with reason `needs root + fanotify (privileged lane)`. I did not run them as root.

Stories, each `PYTHONPATH=src python3 -m halvard.cli <name>`, all exited 0: `demo`, `setup`, `stolen-session`, `mailed-attachment`, `exposed-bucket`, `data-leak`, `patch-day`, `ai-agent`, `tripwires`, `rogue-device`, `platform`.

There is no Critical finding. Nothing here is an unauthenticated read of another tenant's plaintext.

## High

### H1. Card numbers split by a dot, a newline, or a non-breaking space are not cards

- File: `src/halvard/vaultline/classifiers.py` line 10 (`CARD`) and lines 37–40 (`cards_in` splits only on space and hyphen).
- What is wrong: a Luhn-valid Visa number written as `4111.1111.1111.1111`, or the same digits broken by a newline or U+00A0, gets no `pci_card` label, so an approved plain USB copy is allowed.
- Proof: `tests/test_crosscheck_p5.py` `test_a_real_card_number_split_by_dots_newlines_or_nbsp_is_still_a_card` (`pci_card` absent; the failure names separator `.`) and `test_dotted_cards_and_unreadable_pdfs_cannot_be_copied_to_an_approved_plain_drive` (`EgressBlocked` not raised). The USB test stops on the dotted payload, so its PDF half did not run.
- Kind: code bug.

### H2. An unread PDF is classified as ordinary internal data and may leave

- File: `src/halvard/vaultline/classifiers.py` line 108 (`extract_text` returns empty text for `%PDF`) and line 121 (that reason becomes `unscannable` and the function returns). `Classification.sensitivity` defaults to `"internal"` (line 84). `decide` in `src/halvard/vaultline/dlp.py` lines 59–71 then allows it, because there are no labels.
- What is wrong: a PDF whose bytes contain a spaced card number is treated as clean internal content. The missing PDF reader is already disclosed; the bug is that the copy and the send proceed with no warning that the file was not read.
- Proof: `test_a_pdf_that_contains_a_card_number_is_not_treated_as_clean` (`sensitivity` is `internal`).
- Kind: code bug. The absent extractor is a design limit already listed under "Not demonstrated"; the fail-open decision is the bug.

### H3. An address with an extra `@` is treated as internal

- File: `src/halvard/vaultline/service.py` line 74 (`rsplit("@", 1)` keeps only the last domain) and `src/halvard/lumen/gateway.py` line 127 (the same split on `send_mail` targets).
- What is wrong: `victim@gmail.example@acme.com` is judged internal, inspection is skipped, and the message is sent. The same shape is allowed through the AI gateway as `write_internal`.
- Proof: `tests/test_crosscheck_p4.py` `test_a_recipient_with_an_extra_at_sign_is_not_treated_as_internal` (status `sent`, expected `held`) and `tests/test_crosscheck_p7.py` `test_regulated_mail_with_an_extra_at_sign_is_not_treated_as_internal` (decision `allow`, expected `block`).
- Kind: code bug.

### H4. Paths and personal names are written into the public half of the ledger

- File: `src/halvard/ledger/audit.py` lines 15–16 (`PII_KEYS` omits `scope`, `reason`, `preview`, `sample_paths`, and `process`). Writers: `src/halvard/ward/agent.py` line 326 (`sample_paths`), `src/halvard/relay/actions.py` lines 206–210 (`scope` and `reason`) and lines 270–272 (stop-process preview includes `user`), `src/halvard/glass/service.py` line 175 (the free-text protection reason is placed on the action request, which relay then logs in public `reason`).
- What is wrong: an auditor export of the public dict contains a payroll path, the string `user alice`, and the name Dana Whitfield. `scrub` only replaces email-shaped strings (line 25).
- Proof: `tests/test_crosscheck_p1.py` `test_paths_and_person_names_do_not_appear_in_the_public_half_of_the_ledger` and `tests/test_crosscheck_p6.py` `test_a_persons_name_in_a_protection_reason_is_absent_from_every_public_audit_field`. The public blob from the Glass test contains `"reason": "ask Dana Whitfield about the vendor (HLV-SAMPLE-0002)"` on `relay.action_executed`.
- Kind: code bug. Also a test gap: the author's Glass test checks `glass.control_extended` / `glass.risk_accepted` and does not inspect `relay.action_executed`.

### H5. A tenant id can climb into another tenant's object directory

- File: `src/halvard/tenancy.py` lines 108–114 (`object_path` joins `t/<tenant_id>` and then `resolve()`), and `src/halvard/fabric/platform.py` line 73 (`create_tenant` accepts the id with no path check).
- What is wrong: tenant id `../t/globex` resolves to the same directory as tenant `globex`. A put of key `quarterly` replaces Globex's object. The victim's later read raises `KeyUnavailable` (integrity check), so this is a cross-tenant overwrite, and the plaintext is not returned.
- Proof: `test_a_tenant_id_that_climbs_out_of_its_prefix_cannot_write_another_tenants_object` (`TenantIsolationError` not raised). A follow-up input in this session, same two ids and the same key, printed `same path True` and `victim read raised KeyUnavailable object failed its integrity check`.
- Kind: code bug.

### H6. `import_bundle` and `external_call` never ask who the caller is

- File: `src/halvard/fabric/platform.py` line 167 (`external_call`) and lines 172–185 (`import_bundle`). The module docstring line 9 says "Nothing here reaches a tenant by guessing an id."
- What is wrong: both methods take a tenant id and use that tenant's control plane with no `_auth` call. Holding the vendor HMAC key, a caller who is not a Globex member applied IOC hash `deadbeef` to Globex's device `LT-1`. `external_call("globex", "https://evil.example", "lookup", fn)` ran `fn` on the cloud profile.
- Proof: `tests/test_crosscheck_p8.py` `test_a_caller_who_is_not_a_member_cannot_import_a_bundle_or_place_a_call_for_another_company` (`AccessRefused` not raised). The test stops there, so its later `external_call` and forged-`customer()` assertions did not run. A separate input this session printed `after ['deadbeef']` and `external_call ok ['ran']`. I am not filing a bypass of `customer()`: that assertion did not execute, and the author's enrolment tests already refuse a forged `Member`.
- Kind: code bug, and a documentation overclaim on the module docstring. In-process code that already holds a `ControlPlane` object bypasses the wall by the author's stated design (guide item 29). These two methods are public and do not require that object from the caller.

### H7. Export still succeeds after the customer key is revoked

- File: `src/halvard/fabric/platform.py` lines 198–203. `export` checks residency and returns `True`. It does not call `refresh_key` or `locked`.
- What is wrong: after `kms.revoke()` and `refresh_key("bank")`, `customer()` raises `AccessRefused` and `export("bank", "eu-central")` returns success.
- Proof: `test_revoking_the_customer_key_refuses_export_as_well_as_sign_in`. The `customer()` assertion in that test passed (the failure is the export assertion).
- Kind: code bug.

### H8. A device command checks how many approvers signed, not whether they hold the role

- File: `src/halvard/relay/commands.py` lines 31–35. The docstring lines 3–6 says the device re-checks approvals against its own matrix.
- What is wrong: `verify` compares rule level and the count of distinct approver ids. Two `service_desk` approvals satisfy a clinical `isolate_host`, whose matrix asks for `it_admin` or `analyst`. The caller must hold the device HMAC key.
- Proof: `tests/test_crosscheck_p3.py` `test_a_clinical_device_rejects_two_service_desk_approvals_for_isolation` (`ok` is `True`, reason `ok`).
- Kind: code bug, and a documentation overclaim in that docstring.

### H9. Every remote command is marked critical, so a maintenance window does not defer it

- File: `src/halvard/ward/agent.py` line 248 (`critical=True` on every `execute_command`) and `src/halvard/relay/actions.py` line 118 (the window applies only when `not req.critical`).
- What is wrong: a routine `install_update` signed for a device inside its maintenance window runs immediately. The interactive path would defer a destructive action.
- Proof: `test_a_remote_update_during_a_maintenance_window_is_deferred_on_the_device` (status `executed`).
- Kind: code bug.

### H10. Keeper's gate does not check the grant's region

- File: `src/halvard/fabric/keeper.py` lines 72–87 (`_gate` calls `delegations.find` and checks the crew's home region against residency). `src/halvard/fabric/platform.py` line 141 (`delegated` refuses when `g.region != region`).
- What is wrong: after the standing `*` grant is revoked and a new grant is opened for `eu-west` only, `delegated(..., "us-east", ...)` refuses, and `desk.elevate` for a crew whose home is `us-east` succeeds. The two copies of the check have drifted.
- Proof: `test_a_keeper_grant_for_one_region_does_not_let_a_crew_in_another_region_act` (`PermissionError` not raised on `elevate`; the `delegated` assertion above it passed).
- Kind: code bug.

### H11. Two people who share a computer become one case, including a decoy

- File: `src/halvard/cases.py` lines 55–65 (`related` walks `uses` / `acts_for` in both directions) and lines 68–79 (`add` merges on that neighbourhood and stores the whole neighbourhood on the case).
- What is wrong: Alice and Bob both use workstation `WS`. Bob's identity finding and a decoy finding on `WS` become case `C-1`, and the case entities include `p:alice`, who had no finding.
- Proof: `tests/test_crosscheck_p7.py` `test_a_decoy_on_a_shared_computer_does_not_absorb_another_persons_finding` (both ids are `C-1`).
- Kind: code bug. This is the question in guide item 26.

### H12. Rollback decides "changed afterwards" from size and mtime only

- File: `src/halvard/relay/journal.py` lines 13–16 (`fingerprint` is `size:mtime_ns`) and lines 160–164 (a mismatch skips restore). The docstring lines 5–6 says files changed after the incident are not overwritten.
- What is wrong: a later edit with the same size and the same mtime is restored over. A pure `os.utime(path, (1, 1))` is treated as a later edit, so the pre-image is left unrestored and the encrypted bytes stay.
- Proof: `test_a_later_edit_with_the_same_size_and_mtime_is_not_overwritten` (path not in `skipped_changed_after`) and `test_a_pure_mtime_touch_does_not_block_restore_of_the_pre_image` (path is in `skipped_changed_after`).
- Kind: code bug, and a documentation overclaim in the journal docstring.

## Medium

### M1. A justification can be stretched far past an hour

- File: `src/halvard/ward/agent.py` lines 222–230. `minutes` is multiplied by 60 with no cap. The docstring says the reason is time-boxed. Outbound mail justification hardcodes 3600 seconds (`vaultline/service.py` line 102) and was not broken.
- What is wrong: `justify(..., minutes=525600)` still allows the same bytes out after 3601 seconds.
- Proof: `test_a_justification_cannot_be_stretched_past_an_hour` (neither `EgressBlocked` nor `NeedsJustification`).
- Kind: code bug.

### M2. A deferred action tells the operator it will be offered again, and nothing is stored

- File: `src/halvard/relay/actions.py` lines 90–94.
- What is wrong: the result message says "this will be offered again then". The pending map is empty afterwards. Absence of a scheduler is already a known gap; the message promises a retry the code does not keep.
- Proof: `test_a_deferred_action_is_kept_so_it_can_be_offered_when_the_window_ends` (stored `{}`; the message contains "offered again").
- Kind: code bug and a user-facing overclaim.

### M3. A payment request that exists only in an attachment produces no impersonation signal

- File: `src/halvard/courier/impersonation.py` line 49 (`analyze` reads `subject` and `body` only).
- What is wrong: a new-bank-account request placed only in an attachment yields an empty signal list.
- Proof: `test_a_payment_request_that_exists_only_in_an_attachment_is_still_a_payment_signal` (signals `[]`).
- Kind: code bug.

### M4. Three characters outside the confusable table are not a lookalike

- File: `src/halvard/courier/analysis.py` line 114 (`CONFUSABLES` has no Greek alpha) and line 134 (`edit_distance <= 2`).
- What is wrong: `pαypαl-αccount.com` (U+03B1 three times) against `paypal-account.com` returns `None`. One mapped Cyrillic letter is still caught (held, below).
- Proof: `test_three_unmapped_homoglyphs_still_count_as_a_lookalike`.
- Kind: code bug (detection gap). One or two substitutions remain inside the distance check.

### M5. IT admin simple search returns a home-directory path, and the path contains the person's name

- File: `src/halvard/hunt/service.py` line 13 (`SIMPLE_FIELDS` includes `path`) and lines 51–62. The module docstring line 5 and the method docstring line 52 say user names are not returned.
- What is wrong: a search for `excel` returns `C:/Users/jsmith/Finance/q3.xlsx`. The author's test searches `powershell` and asserts `jsmith` is absent; that query does not hit this path.
- Proof: `tests/test_crosscheck_p2.py` `test_it_admin_search_does_not_return_a_command_line_or_a_person_name_even_inside_a_path`.
- Kind: code bug, a documentation overclaim, and a test gap in the author's suite.

### M6. Keeper redaction is case-sensitive

- File: `src/halvard/fabric/keeper.py` line 99 (`str.replace` of the HR name as stored).
- What is wrong: HR name `Alice Kim` leaves the queue headline `ALICE KIM exported the payroll file` unchanged.
- Proof: `test_redaction_catches_a_name_when_the_case_text_uses_a_different_case` (regex `(?i)alice` matched `ALICE`).
- Kind: code bug.

### M7. A symlink path does not match the tripwire key, so the write is not stopped

- File: `src/halvard/ward/agent.py` line 106 (`_twkey` is `normpath` plus slash folding, and does not resolve links) and line 142 (`tripwire_gate` looks up that key).
- What is wrong: a write through a symlink whose target is the tripwire file does not raise `Blocked`, and the tripwire bytes change. A direct `Path.write_bytes` that never calls the gate is the design limit already stated (the hook must call the gate). This finding is the path the gate itself compares.
- Proof: `test_a_write_through_a_symlink_is_still_a_touch_of_the_tripwire`.
- Kind: code bug.

## Low (prose and displayed numbers)

These are sentences a customer sees, or a docstring, that the code does not make true. They are listed here so they are not lost inside the High items.

- `src/halvard/setup/guide.py` line 103, printed by the `setup` story: "Only an administrator can stop or remove Halvard, using a short-lived one-time code." The code that ran is a user-space token check (`tamper.stop_or_uninstall`). Kernel self-protection is in "Not demonstrated". Kind: documentation overclaim relative to a native product. The reference behaviour (wrong code refused) did run in the story.
- `src/halvard/setup/guide.py` line 119, printed by `setup`: "You can isolate a computer in one click". There is no console. The story isolates through `engine.request` and then undoes it. Kind: documentation overclaim. "No console" is already a known gap.
- `src/halvard/setup/guide.py` line 50, printed as `6 of 6 protections proven on this computer`. The fraction is computed from the six steps that passed in the reference simulation. "Proven" here means those steps returned ok. Kind: wording that a reader can take as a native-product result.
- `demo` story line: "Confidence 60%." The number is computed in `src/halvard/ward/detect.py` line 87 (`min(0.99, 0.6 + 0.04 * (len(files) - min_files) + ...)`). It is not labelled "heuristic, not a calibrated probability". The case pages in the other stories do print that label. Kind: user-facing presentation. The number is computed, not invented.
- `src/halvard/glass/board.py` line 11 `CAP_URGENT = 59` and line 47 the literal `3` in "of 3 containment controls". The cap is disclosed on the page ("capped at 59"). The `3` matches the three control names in the tuple on line 46. I did not find a drift. The patch-day story ends with the measured footer "Not measured: backup restore tests...". Kind: held, recorded so it is not filed later.
- Docstrings already cited above: `fabric/platform.py` line 9 (H6), `relay/commands.py` lines 3–6 (H8), `relay/journal.py` lines 5–6 (H12), `hunt/service.py` lines 5 and 52 (M5), `ward/agent.py` line 223 (M1).

I did not find a customer-visible number in the eleven stories that was a hard-coded fake measurement. The scores, the `6 of 6`, and the confidence values I checked are computed. The board cap is a constant and the page says so.

## What I tried and could not break (held)

These cross-check tests passed in the 42-test run:

- Requester cannot approve their own production isolation (`test_the_requester_cannot_approve_their_own_production_isolation`).
- Cross-tenant `get_entity` raises `KeyError`. Object keys `../globex/note` and `/etc/passwd` raise `TenantIsolationError`. On this Linux host the key `..\\globex\\note` is a literal name and raises `KeyError` (the test accepts either). Same entity id `srv-fin` stays isolated across two companies.
- IT admin cannot run HQL. Service desk cannot simple-search or collect forensics. A huge `days` value does not widen the 7-day window. `device_status` returns no command line.
- Command replay, expiry, the same approver counted twice, a bad signature, and a command for another device are refused. Two qualified approvers can isolate a clinical device.
- One mapped Cyrillic lookalike is caught. A display name on the company's own domain is not impersonation.
- A secret on an approved encrypted drive stays unjustifiable. A customer label of `public` is not overwritten when a scan suggests regulated.
- An unconfirmed external probe sends nothing. An expired temporary protection still blocks. An analyst cannot accept a risk. A third extension is refused. The board page contains "Not measured" and does not contain "100 / 100".
- An AI grant is bound to the digest and is single-use. A suspended agent is blocked.

I did not write a new support-grant replay test. The author's tests already cover a grant that is required. The mutation of "support grant not required" was killed by those tests (below).

## Tests that notice a broken behaviour (step 4)

`python3 tools/mutation_check.py "<filter>"` on throwaway copies. Each line is the harness output. All ten were killed. None of these ten tests passed whatever the code did.

| Filter | Result |
| --- | --- |
| self-approval allowed | KILLED by `test_requester_cannot_approve_own_request` (+2 more) |
| ledger head anchor ignored | KILLED by `test_tail_truncation_is_detected` |
| support grant not required | KILLED by `test_a_context_for_one_company_cannot_read_another_even_with_a_guessed_id` (+2 more) |
| Commands: replay allowed | KILLED by `test_forged_tampered_or_replayed_commands_are_refused` |
| approval gate skipped | KILLED by `test_files_profile_copies_only_named_paths_and_flags_personal_data` (+28 more) |
| object path traversal allowed | KILLED by `test_a_context_for_one_company_cannot_read_another_even_with_a_guessed_id` (+1 more) |
| hunt: IT admin may run structured hunts | KILLED by `test_analyst_full_it_admin_simple_service_desk_status_only` (+1 more) |
| forensics: memory without acknowledgement | KILLED by `test_memory_needs_acknowledgement_and_named_pids` |
| learning: exceptions never expire | KILLED by `test_exceptions_expire` |
| Commands: second approver not counted | KILLED by `test_device_command_with_too_few_approvers_is_refused` |

The full sweep (`python3 tools/mutation_check.py` with no filter) was not run. I did not verify a survivor count for mutations outside this list.

The object-path mutant being killed does not contradict H5. That mutant relaxes the key check inside one tenant. H5 is the tenant id itself being used as a directory segment before that check.

## Confirmed known gaps, not re-filed

- Glass `first_seen` lives in memory and resets on restart (guide item 17, phase 6 "Not demonstrated").
- No scheduler. The false "offered again" sentence is M2; the missing scheduler stays a gap.
- HMAC where production needs an asymmetric signature. I did not review `fabric/crypto.py` as a cipher. Objects are sealed; I read that database rows are not passed through the object cipher. I did not add a test that dumps a row.
- No native Windows or macOS sensor, no console, no installer. The eight skipped tests are the Linux privileged lane.
- A process that writes a tripwire without calling `tripwire_gate` is outside the hook. M7 is the comparison the gate does make.

## I did not verify

- Windows. Every path check above ran on Linux. The backslash key is a literal name here.
- The eight fanotify tests, including the skipped note that a process can finish before kernel events are processed. I did not run as root, so I did not confirm or refute that race.
- Harbor's quadratic scan, hand-set confidence weights, and `_flagged` key mixing (guide item 33). I did not produce a failing test. Unconfirmed.
- A concurrent nonce check on device commands (verify, then add). I did not run two threads. Unconfirmed.
- The full mutation sweep.
- The forged-member assertion inside the H6 test, because that test fails earlier. I am not claiming `customer()` accepts a forged member.

## Fixes

None. Waiting for "go". Source files are unchanged.


---

# Resolution (after the fixes)

Fixes are on branch `crosscheck-fixes`. All 42 cross-check tests now pass, the author's tests pass, and nothing was skipped or weakened. Test changes, each with its reason:

| Test | Change | Why |
|---|---|---|
| `test_actions` executed-record test | reads `reason` from the private half | the reason is free text and can name a person (H4); an auditor still sees it exists |
| `test_a_finding_that_bridges_two_cases_merges_them` | two people who merely share a computer are no longer one case; a new test covers findings about a shared computer | H11 |
| `test_journal_after_survives_a_file_that_vanishes...` | the stub accepts the new `fingerprint(path, read)` signature | H12 |
| `test_crosscheck_p5` unreadable PDF | accepts a justification prompt as well as a block | H2: the substance is "never a silent allow"; a recorded reason may unlock it |
| `test_crosscheck_p1` tenant id | creation of `../t/globex` is refused (ValueError) instead of failing at write | H5: stops it earlier |
| setup progress text | "6 of 6 setup checks passed ... in the reference build" | prose overclaim |

| Finding | Fix |
|---|---|
| H1 card separators | dots, newlines, thin and no-break spaces split groups; a window of several groups needs short groups, so two long numbers are not one card |
| H2 unread PDF clean | a file Halvard cannot read is treated as confidential and the message says so; a reason can unlock it, it never passes silently |
| H3 extra `@` | one helper, `addr.domain_of`; an address without exactly one `@` has no domain and counts as outside; used by Courier, Vaultline and the AI gateway |
| H4 public audit fields | `reason`, `summary`, `targets`, `sample_paths`, `process` moved to the private half; action scope shows file paths only as tokens |
| H5 tenant id | an id is `[A-Za-z0-9][A-Za-z0-9_-]{0,63}`; anything else is refused at creation |
| H6 `import_bundle`, `external_call` | now take the calling Member and check enrolment (and, for bundles, owner or IT admin); a non-member is refused. `export` still takes a company id: it moves nothing and only reports allowed or refused |
| H7 export after revoke | export refuses while the company is locked |
| H8 command roles | the device counts only approvers whose role the matrix allows for that action |
| H9 maintenance window | only containment (isolate, stop, quarantine, legal hold) is critical; updates and rollbacks are deferred by a window |
| H10 Keeper region | the grant's region is checked in the gate |
| H11 shared computer | the walk never continues through a shared device; a shared device joins only findings directly about it |
| H12 journal fingerprint | content hash (whole file up to 4 MiB); a kernel-hook sensor keeps size+time because opening files it judges deadlocks the hook; the privileged Linux lane caught this during the fix |
| M1 justification | capped at 60 minutes |
| M2 deferral | deferred actions are stored and asked again by `offer_due()` (agent heartbeat, control-plane cycle) |
| M3 attachment payment | attachment text is read for payment wording and bank accounts |
| M4 homoglyphs | more letters in the table, plus a wildcard match for internationalised names that line up with a protected name |
| M5 IT search | the name in a home-folder path is hidden |
| M6 redaction | case-insensitive |
| M7 symlink | tripwire keys resolve links; the gate costs nothing when a device has no tripwires |
| Low: prose | setup messages, the demo confidence line, and four docstrings no longer claim what the reference build does not do |

New mutations: 23 (all killed; three survived the first pass and each got a test). Full sweep result: 364 mutations. 360 were killed outright by a named failing test. Four were not at first: one survived (a public ledger field could carry an email address; a test was added) and three were skipped because earlier fixes had changed the code they targeted (patterns refreshed). All four were re-run on their own and are killed. Final suite: 510 tests, all passing on Linux..
