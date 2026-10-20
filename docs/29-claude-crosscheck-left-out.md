# Prompt for an independent check of 0.10.9

Paste the block below to a reviewer who has not written this change. The reviewer should test, and if a test fails, fix the product and retest until the suite is green. The reviewer should not take this file's word for what the code does.

```
You are checking Halvard branch cursor/assurance-slices-0dae at version 0.10.9.
Do not trust the changelog, the handoff, or the author. Read the code and run the tests.

Rules:
- Python 3.11+ stdlib reference. This is not a shippable endpoint. Do not recommend shipping it.
- Run: python3 -W ignore -m unittest discover -s tests
  On Windows the same command. Say how many passed, failed, and skipped.
- Do not run tools/run_acceptance*.py.
- Do not delete, skip, or weaken an existing test, and do not change an expected value unless you can show the old expectation was wrong. Say why.
- If you find a bug, add a failing test that names the hole, fix the code, and run the whole suite again. Repeat until the suite is green or you can show the remaining item is a limit of the reference, not a defect you can close here.
- Do not add a kernel driver, a PDF reader that treats unread files as ordinary text, or a real KMS. Do not claim those are built.

Check each of these. For each, verdict HOLDS, FAILS, or SPECIFIED ONLY, with the command you ran and what broke.

1. An excluded *.tmp overwrite is named on the rollback and complete is false. Test: test_an_excluded_temp_file_is_named_and_the_report_is_not_complete. Try a *.log as well, and a rename from a normal file onto a *.tmp.
2. A rename onto a file larger than the journal cap names that destination as its own not_restorable row, and the source comes back when it had a pre-image. Test: test_a_rename_onto_a_too_big_file_names_that_destination.
3. Two people pin a log. A new AuditLog on the same path is still pinned. export and compact refuse. release by one person lifts the pin on a third object. Test: test_a_legal_hold_is_still_there_on_a_new_log_and_release_lifts_it. Try deleting only the .hold file.
4. Delete the log, the .head, and the .witness beside the log. A new AuditLog verify() fails because .halvard-witness remains. Test: test_deleting_the_log_the_head_and_the_beside_witness_still_fails_verify. Then also delete .halvard-witness and say what verify() does. That last case is a known limit unless you can close it without a remote service.
5. note_coverage("failed_open") is on the board. heartbeat() removes that live row and writes coverage.cleared. A pending_dropped row stays. Test: test_a_later_heartbeat_clears_a_failed_open_row. Confirm the ledger still has the original coverage.row.
6. Unread PDF/bytes cannot be justified for upload unsanctioned, upload personal, ai_shadow, ai_enterprise, email partner, and print. A readable card to a partner still asks for a reason. Test: test_unread_bytes_cannot_be_justified_on_upload_ai_or_partner_mail.
7. seal() then verified() holds. seal with b"halvard-reference-connector-v1" does not verify. Test: test_resealing_with_the_published_string_does_not_verify. Say whether a second Python process would accept the first process's seal.
8. LinuxHost.proc(os.getpid()) exe_sha256 matches sha256 of /proc/self/exe, and publisher is None. The fanotify exec hook calls pre_execute and denies a known-bad sample when enforcement is on. Tests: test_linux_proc_hashes_the_image_it_can_read, test_the_exec_hook_uses_pre_execute.
9. INSTALL_MANIFEST and UPDATE_MANIFEST service_name are HalvardGuard, built is false, and native/installer/halvard.wxs Service Name is HalvardGuard. The manifest is data. There is no new MSI.

Also re-run the slice tests so the earlier contract still holds: test_slice1_recovery through test_slice7_windows_contract, plus test_left_out.

Report: suite counts, one line per item above, any bug you fixed and the new test name, and anything you left as a limit. Do not say Halvard is ready to ship.
```
