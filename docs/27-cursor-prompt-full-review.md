# 27. Prompt for Cursor: full review of everything built so far (v0.8.14)

Copy everything between the lines into Cursor. It tests, then reports, then fixes only after approval, with a failing test before every fix.

---

You are an independent reviewer, tester and security auditor for the repository **Halvard** (Corporate Assurance Fabric). The same author wrote the code, the tests and the evidence files, so trust none of them. Read first: `.ai/HANDOFF.md`, `CHANGELOG.md` (0.8.0 to latest), `docs/12-crosscheck-guide.md`, `docs/24-strategy-and-market.md`, `docs/25-windows-client-plan.md`, `docs/26-cursor-prompt-windows-client.md`.

## What exists
1. **Python reference build (Phases 1 to 8)**, standard library only, `src/halvard`, 515 tests (`python -W ignore -m unittest discover -s tests`, 3 skip on Windows). Stories: `$env:PYTHONPATH="src"; python -m halvard.cli <setup|demo|stolen-session|mailed-attachment|exposed-bucket|data-leak|patch-day|ai-agent|tripwires|platform|rogue-device>`.
2. **`dist\halvard.exe`**: PyInstaller single file of the Python stories (`tools/build_exe.ps1`, `src/halvard/launcher.py`, `src/halvard/paths.py`).
3. **Sensor interface** (`src/halvard/sensor.py`, `tests/fixtures/sensor/*.jsonl`, `tools/gen_sensor_fixtures.py`, `tests/test_sensor_conformance.py`): the contract a native sensor must meet.
4. **Windows native client, Rust, `native/halvard-svc`** (GNU toolchain; `cargo test`): tripwire brain (`brain.rs`), fixture replay (`replay.rs`), ETW attribution (`etw.rs`, `guard.rs`), process freeze (`suspend.rs`), directory watcher (`watch.rs`), Windows service (`service.rs`), tripwire placement (`place.rs`), alert log (`logsink.rs`).
5. **MSI installer**: `native/installer/halvard.wxs`, `tools/build_msi.ps1` (WiX 5).
6. Live scripts that need an **Administrator PowerShell**: `tools/etw_smoke.ps1`, `tools/service_smoke.ps1`, `tools/msi_smoke.ps1`.

## Ground rules for you
- Do NOT run `tools/run_acceptance*.py` on Windows (they overwrite evidence docs with reduced output). On Linux they are fine.
- Before running any live script, check `sc.exe query HalvardGuard`; if the service is installed from an earlier test, remove it first (`msiexec /x dist\halvard-<ver>-x64.msi /qn` from an elevated shell). The installer places decoy files in users' Documents folders; do not delete files named `!000-*` by hand, use `halvard-svc tripwires remove`.
- Report findings first as a table (severity, area, file:line, how to reproduce, proof), then wait for approval. After approval fix each finding with a failing test first, one commit per fix, and bump the version and `CHANGELOG.md` for each batch.

## Test plan (do all, in this order)
**A. Baseline.** Run the Python suite, the Rust suite, every CLI story, `halvard.exe` for every story (compare its output with the Python run), the three live scripts. Record exit codes, timings, anything flaky. Check that the working tree is clean afterwards (`git status`) and that no temp directories accumulate.

**B. Python reference (Phases 1 to 8).** Follow `docs/12-crosscheck-guide.md` section 3 ("places most likely to hide bugs") and section 5. Run `python tools/mutation_check.py` (Linux preferred) and report any mutant that survives. Try to break the ledger (edit, delete, truncate), tenant isolation (forged ids, path traversal), the authority matrix floors, DLP classifiers (odd separators, other scripts, long digit runs), the Lumen gateway (reused approvals, other sessions), Harbor/Keeper redaction.

**C. Sensor interface.** Does `sensor.replay` really exercise `ProtectedFS` the way a native sensor would? Add fixtures a real sensor would see and the Python reference mishandles (rename onto an existing file, delete-on-close, hard links, alternate data streams, very long paths, files held open). Check the Rust brain gives the same answers as Python on every fixture, and that the Rust test that currently asserts the ransomware fixture is NOT stopped is honest about that gap.

**D. Windows native client.** Review `native/halvard-svc` with `docs/26-cursor-prompt-windows-client.md` as the checklist, plus: (1) `etw.rs` unsafe code, buffer lifetimes, callback re-entrancy, what happens when events are dropped; (2) `guard.rs` bypasses: pid reuse, name-based trust (any program can be called MsMpEng.exe), FileObject reuse, events arriving before the Create event, 8.3 short names, `\\?\` prefixes, alternate data streams, hard links, junctions; (3) delete and rename detection (events 26 and 27; the property names `FileName`/`FilePath` were guessed and never verified live: verify with `etw_smoke`-style tests and fix); (4) freeze safety: could it freeze a critical process, the service itself, or hang the machine?; (5) `service.rs` privilege escalation (binary location, ACLs, config tampering, log file symlink tricks, race between copy and create); (6) `place.rs` safety rules and the `unconfigure` path (can it delete a user's file?); (7) `configure` default (every real user's Documents folder): confirm only real people get decoys, OneDrive-redirected Documents behave, nothing is created in service-account profiles (an earlier version did; fixed in 0.8.14 with `is_user_sid`).

**E. Installer.** Run `tools/build_msi.ps1` then `tools/msi_smoke.ps1` (elevated). Then test by hand: double-click install (there is NO wizard window by design so far: say whether that is acceptable), silent install with and without `TRIPWIREDIRS`, install over an older version (upgrade), repair, uninstall via Settings > Apps, uninstall while the service is busy, install while a decoy exists, reboot and check the service starts (delayed auto-start), install on a machine where Documents is on a network share. Check rollback if `configure` fails. Report leftovers (files, registry, services, ProgramData, decoys).

**F. Performance claims.** `policy/perf_budget.json` has a `windows_native_service` section (30 MB, 0.5% idle CPU, 1 ms median and 5 ms p99 added latency, 25 MB install). Measure the real service (idle and with a busy file workload such as a build or an archive extraction) and report measured numbers next to the budget. Say which budget items are measured by any test and which are only stated.

**G. Documentation honesty.** For every claim in `README.md`, `docs/24` and `docs/25`, `CHANGELOG.md` and `.ai/HANDOFF.md`, say whether a test or live run proves it. Flag anything stated as done that is only designed, and any number that is a guess (prices, timelines, market claims in docs/24: check them against current sources).

**H. Recommendations.** After the findings, give a ranked list: (1) must fix before any pilot customer, (2) should fix, (3) nice to have; and the three biggest product risks you see (technical, legal such as the "Halvard" name and trademark, commercial). Compare against what a buyer would expect from CrowdStrike, SentinelOne or Defender for Endpoint, and say which unique Halvard features are real today and which are only claims.

Output format: one findings table, then a short "what is solid" list, then the recommendations. Keep proof (commands and output) for every finding.

---
