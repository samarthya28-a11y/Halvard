# Changelog

Versioning: MAJOR.MINOR.PATCH. MINOR = a phase or feature; PATCH = fixes, docs, branding. Log every issue against the version it was found in.

## 0.8.12 - 2026-10-17
- Windows client: tripwire placement (`native/halvard-svc/src/place.rs`). `place --dir <folder> [--name f.xlsx]... [--manifest m.json]` creates decoys; `tripwires list|remove [manifest]`. Prints the `service install --tripwire ...` line to use next. No administrator needed.
- Rules enforced and tested: absolute local folder only (never a drive root, network or `\?\` path, Windows, Program Files, ProgramData, Recycle Bin, Recovery, Boot); no `.`/`..`; refuses a folder reached through a junction or symlink (tested with a real junction); NEVER replaces an existing file (atomic create_new, no race); only safe names and document types; decoys are bland (no "halvard", "honeypot", "tripwire", "decoy" inside), deterministic, sort first (`!000-...`); `remove` deletes a file only if its SHA-256 still matches what was placed.
- 28 Rust tests pass (8 new). Two deliberate weakenings (allow overwrite; skip the junction check) were each caught by a named test, then reverted.
- New dependency: `sha2` 0.10 (pure Rust). Release exe 0.47 MB.

## 0.8.11 - 2026-10-17
- Windows service VERIFIED LIVE end to end (owner, Administrator PowerShell, 16:01, `tools/service_smoke.ps1`): RESULT ALL PASS. Install (auto-start delayed, LocalSystem), restart-on-failure actions, binary in Program Files, Running, attacker frozen and logged, service restarted itself after being killed, `stop` clean (the 0.8.10 fix works), uninstall removes the service, no firewall or other system settings changed.
- Not yet verified live: delete/rename of a tripwire (ETW events 26/27), behaviour after reboot (auto-start), behaviour under normal load, coexistence with other security products.

## 0.8.10 - 2026-10-17
- Service live test, first real run (owner, Administrator PowerShell, 15:58): PASS install (auto-start delayed, LocalSystem), restart-on-failure actions present, binary in Program Files, service Running, **service froze the attacker and logged it**, **service restarted itself after its process was killed**, no firewall or system settings changed. FAIL: stop ("IO error in winapi call"), which also left uninstall marked-for-deletion.
- Cause (likely, to confirm on re-run): the stop request arrived while the freshly restarted service was still StartPending, when it accepts no controls (win32 error 1061).
- Fix: `stop` now waits and retries through that window (up to 30 s) and reports the real win32 error code; `uninstall` says when the service could not be stopped first. Smoke script waits for Running before stopping. 20 Rust tests pass.

## 0.8.9 - 2026-10-17
- Fix: `tools/service_smoke.ps1` aborted at its first step on Windows PowerShell 5.1 (native stderr treated as an exception under `-ErrorAction Stop`), so the 0.8.8 live service test never actually ran (owner's run showed `ERROR: error: the service is not installed`). Exe calls now go through `cmd /c ... 2>&1`; checked that uninstall-when-absent no longer aborts.
- Docs: `docs/26-cursor-prompt-windows-client.md`, a review prompt for Cursor covering the native client.
- Service live test still pending.

## 0.8.8 - 2026-10-17
- Windows client: service wrapper (`native/halvard-svc`, `service.rs`, `logsink.rs`). Commands: `service install --tripwire <full path>... [--trust name.exe]`, `service uninstall|start|stop|status`; `service-run` is the entry point the service manager uses.
- Install: auto-start (delayed), LocalSystem, restart after failure (5 s, three times, counter resets after a day, also on non-crash failures), description set. Binary is COPIED to `C:\Program Files\Halvard` (admin-writable only; a SYSTEM service must never run from a user-writable folder). Config `C:\ProgramData\Halvard\service.json`, folder ACL set to admins/SYSTEM write, users read. Alerts go to `guard.log` (5 MB cap, one rotated file).
- Elevation: install, uninstall, start, stop need an Administrator PowerShell; `status` and everything else does not. Unelevated install is refused with a clear message before anything is written (checked).
- 20 Rust tests pass (4 new). Release exe 0.44 MB. Used `windows-service` 0.7 because 0.8 needs `dlltool` on the GNU toolchain.
- Live test script `tools/service_smoke.ps1` (Administrator): install, start, freeze an attacker, kill the service and check it restarts, stop, uninstall. NOT yet run.

## 0.8.7 - 2026-10-17
- Windows client M1b VERIFIED LIVE (owner ran `tools/etw_smoke.ps1` from an Administrator PowerShell, 2026-10-17): ETW attributed the write to the right process (powershell.exe, pid shown), `Open`+`Write` through the FileObject map matched the decoy, the process was frozen (`"frozen":true`, tick file stopped growing), PASS.
- Still unverified live: delete/rename events (ids 26/27 property names), ordinary-load behaviour, long soak, other EDR products running alongside.

## 0.8.6 - 2026-10-17
- Windows client M1b (`native/halvard-svc`): ETW session on Microsoft-Windows-Kernel-File (`etw.rs`) gives each file event its process; `guard.rs` maps FileObject to name and decides; a tripwire change freezes the offender via NtSuspendProcess. New command `halvard-svc guard <tripwire> [--trust name.exe]` (+ `stop`).
- Safety: never freezes itself, pid <= 4, or system processes (csrss, lsass, svchost ... alert only); antivirus (MsMpEng.exe) trusted by default; object map bounded; ETW session stopped on Ctrl+C and stale sessions cleaned on start.
- Event ids and keywords taken from this machine's provider manifest (`wevtutil gp Microsoft-Windows-Kernel-File /ge`).
- 16 Rust tests pass (7 new guard tests, unelevated). **NOT verified live:** ETW needs an elevated PowerShell and the UAC prompt was cancelled. Run `powershell -ExecutionPolicy Bypass -File tools\etw_smoke.ps1` from an Administrator PowerShell; PASS means a fake attacker was frozen. Unverified guesses: property names for events 26/27 (FileName/FilePath) and header ProcessId being the issuing process.
- Release exe 0.33 MB.

## 0.8.5 - 2026-10-17
- Windows client M1 (Stage A prototype), `native/halvard-svc` (Rust, GNU toolchain for now): tripwire brain mirroring `WardAgent.tripwire_gate`, fixture replay (same JSONL as Python), ReadDirectoryChangesW watcher (blocking, no polling), NtSuspendProcess/NtResumeProcess freeze and thaw.
- 9 Rust tests: conformance with the Python fixtures (tripwire first touch denied at event 1; office and compressor never blocked), real process freeze/thaw, protected pids refused, watcher latency under 500 ms.
- Measured (release): 0.31 MB binary, 3.5 MB RAM, 0.000% CPU idle over 10 s, tripwire alert about 1 ms after the write. Budget targets: 30 MB, 0.5% CPU, so far under.
- Not done: attribution of a write to a process (needs ETW, M1b), so the watcher alerts but cannot yet freeze the offender; the bulk-encryption detector (M2); service wrapper, installer, signing. Toolchain is GNU; switch to MSVC (needs Visual Studio Build Tools) before production.
- Run: `cd native/halvard-svc; cargo test; cargo build --release`.

## 0.8.4 - 2026-10-17
- Windows client M0: sensor interface v1 (`halvard/sensor.py`: event format, `replay`, `check_budget`), four deterministic event fixtures in `tests/fixtures/sensor/` (ransomware, tripwire first touch, office session, compressor; regenerate with `tools/gen_sensor_fixtures.py`), 11 new tests (515 total), and native-service targets in `policy/perf_budget.json` (`windows_native_service`).
- A native sensor passes M0 when its recordings of these scenarios replay to the same allow/deny answers.

## 0.8.3 - 2026-10-17
- Docs: `docs/25-windows-client-plan.md`: resident Windows client plan (budgets, Rust service, staged sensor: ETW+tripwires then minifilter, installer, signing, milestones). Design only; nothing built.

## 0.8.2 - 2026-10-17
- New: `halvard.exe` single-file build (`tools/build_exe.ps1`, needs `pip install pyinstaller` on the build machine only). 10.7 MB; peak 25-36 MB RAM while running a story; about 1.2-1.7 s start-to-finish (one-file extraction adds ~1 s per launch). All 11 stories verified from the exe.
- New: `halvard/launcher.py` (lazy imports; `--version`, `list`, `<story>`), `halvard/paths.py` (policy files found inside the exe).
- Fix: stories crashed on a default Windows console (cp1252 could not print the symbols); output is now UTF-8.
- Refactor: `cli.main()`.
- Scope note: this is the reference client, not a resident protection agent. No Windows file/process sensor, service, tray or installer yet.

## 0.8.1 - 2026-10-17
- Brand: gold "blade-shield" logo v2 (`assets/logo/halvard-logo-v2.svg`, `halvard-mark-v2.svg`); README uses it.
- Meaning of the name and backronym added (docs/24-strategy-and-market.md).
- Full manual pass on Windows: 504 tests OK (3 Linux-only skipped); all 11 CLI stories ran clean.
- Process: `.ai/HANDOFF.md` and this changelog are updated after every major change.
- Known: tools/run_acceptance*.py overwrite evidence docs with Windows-only output; run them only on Linux.

## 0.8.0 - Phases 1 to 8 complete (reference build), cross-check fixes merged.
