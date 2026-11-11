# 29. Halvard: product state and handoff (2026-11-11)

For a new session, a new person, or a reviewer. The short, always-current version is `.ai/HANDOFF.md`; read that first. This file is the full picture as of **main at v0.9.3**. Halvard is a **reference model, not a shippable endpoint**; nothing here says otherwise.

## 1. What Halvard is
**Halvard: Corporate Assurance Fabric.** Name: Old Norse *Hallvarðr*, "rock guardian". Working backronym: **H**osts, **A**ccounts, **L**eaks, **V**ulnerabilities, **A**I, **R**esponse, **D**eception. Tagline "Hold the line."
It is two things:
1. A **Python reference implementation** (standard library only, Phases 1 to 8) of the decision, journal, action and evidence logic for an endpoint, identity, mail, cloud, data, exposure, AI-agent and multi-tenant assurance product. It is proven by tests and stories, with every real-world connector replaced by a labelled model.
2. A **Windows prototype client** in Rust (`native/halvard-svc`) with an MSI installer: a small resident service that freezes a program that touches a tripwire file or starts overwriting documents in bulk. It sees writes through ETW, after they happen.

## 2. Repository map (branch `main`, v0.9.3)
| Path | What |
|---|---|
| `src/halvard/ward/` | agent, behavioral detector, verdicts, signed policy, tamper guard, safe simulator, incident page |
| `src/halvard/relay/` | authority matrix, action engine (preview, approval, audit, undo), file journal, host, isolation renderers |
| `src/halvard/ledger/` | hash-chained sealed audit log, spool, auditor export |
| `src/halvard/signet, courier, atlas, vaultline, glass, lumen, hearth, fabric, harbor, hunt, detect/` | identity, mail, cloud, data protection, exposure, AI agents, tripwires, multi-tenant platform, device discovery, telemetry, detections |
| `src/halvard/platforms/linux.py` | the only real kernel sensor (fanotify); needs root; **not run on Windows** |
| `src/halvard/sensor.py`, `tests/fixtures/sensor/` | sensor interface v1 and 9 event fixtures with `golden` decisions that Python and Rust must both reproduce |
| `src/halvard/launcher.py`, `paths.py` | entry point and data-file lookup for `dist\halvard.exe` |
| `native/halvard-svc/` | the Rust Windows client |
| `native/installer/` | WiX 5 MSI definition, wizard artwork (`art/`), placeholder `license.rtf` |
| `tools/` | build scripts, live smoke tests, mutation harness (see section 5) |
| `policy/` | generated authority matrix, performance budgets (`perf_budget.json`, incl. `windows_native_service`) |
| `docs/01` to `docs/28` | narrative, design, evidence per phase, strategy (24), Windows plan (25), reviewer prompts (26, 27), PR #2 review (28) |
| `CLAUDE.md`, `.ai/HANDOFF.md`, `CHANGELOG.md` | session rules, short handoff, full version history |

## 3. Components, how to run them, proof level
**Python reference.** `python -W ignore -m unittest discover -s tests` (about 3 to 5 minutes on Windows). Stories: `$env:PYTHONPATH="src"; $env:PYTHONIOENCODING="utf-8"; python -m halvard.cli <setup|demo|stolen-session|mailed-attachment|exposed-bucket|data-leak|patch-day|ai-agent|tripwires|platform|rogue-device>`. On main (v0.9.3, Windows): **542 tests, all pass, 4 skipped** (about 70 to 80 s). Rust: **38 pass**. Linux-only tests (fanotify, 8 tests), three symlink tests and the perf budget skip on Windows.
**`dist\halvard.exe`** (`tools\build_exe.ps1`, PyInstaller, about 11 MB): the stories as an exe. Reference client, not a resident agent.
**Rust client** (`cd native\halvard-svc`; `cargo test`; `cargo build --release`, about 0.5 MB exe, GNU toolchain, `windows-service` 0.7 because 0.8 needs `dlltool`). Commands: `place --dir`, `tripwires list|remove`, `replay <fixture>`, `watch`, `guard <tripwire>... [--trust x] [--debug]` (ETW, Administrator), `stop`, `configure [--dirs "a;b"]`, `unconfigure`, `service install|uninstall|start|stop|status|tune`, `status-report [--wait]`. Idle cost measured at v0.8.5: about 3.5 MB RAM, 0.000% CPU; budget targets 30 MB, 0.5% CPU, 1 ms median and 5 ms p99 added latency.
**MSI** (`tools\build_msi.ps1` -> `dist\halvard-<ver>-x64.msi`, about 1.5 MB, WiX 5.0.2 + Util + UI extensions): per-machine, wizard with Halvard artwork, service `HalvardGuard` (auto-start delayed, LocalSystem, restart after failure), decoys placed by `configure` (property `TRIPWIREDIRS`, default every real user's Documents, found through the Windows profile list), Start Menu shortcut and a finish-screen checkbox that open `status-report`. Silent: `msiexec /i halvard-<ver>-x64.msi /qn`; remove: `msiexec /x ... /qn`. Unsigned.

## 4. What has really been run, and by whom
- **Verified live by the owner on this PC (Administrator):** ETW write path freezes a fake attacker (v0.8.7); service install, start, freeze, restart after being killed, stop, uninstall, all pass (v0.8.11); a double-click MSI install of 0.8.13 worked (service running, decoys placed), which is how the missing-logo and nothing-opens complaints and the profile-list bug were found.
- **Not verified live:** ETW delete and rename events; the behavioral detector on live ETW; `tools\msi_smoke.ps1`; the 0.9.x wizard and branding on screen; reboot auto-start; load and soak; coexistence with other security products; signing.
- **Never run on Linux:** the fanotify sensor, `/proc` start times and hashing, symlink restore, `os.kill` paths. CI to do this exists on a branch and has never run on GitHub.
- **This PC now:** no service installed, no decoy files, `C:\ProgramData\Halvard` holds an old `guard.log` and an empty `tripwires.json` (harmless). Needs: cargo (`~\.cargo\bin`), wix (`~\.dotnet\tools`), Python 3.12.

## 5. Tools and the quirks that cost time
`tools\build_exe.ps1`, `build_msi.ps1`, `make_installer_art.ps1` (Edge headless + System.Drawing, no downloads), `gen_sensor_fixtures.py` (regenerates fixtures and their golden decisions), live scripts that need an **Administrator** PowerShell: `etw_smoke.ps1` (4 fake attackers), `service_smoke.ps1`, `msi_smoke.ps1` (results saved to `C:\Users\ASUS\halvard-*-smoke.txt`), and `mutation_check.py` (removes a protective behaviour on a copy and requires a test to fail).
- Never run `tools\run_acceptance*.py` on Windows: they overwrite the evidence docs with reduced output.
- The mutation harness is slow on Windows (each mutant reruns a 2 to 5 minute suite): use name filters (`"A|B"`), `HALVARD_MUT_WORKERS=1`; a timeout is reported as TIMEOUT, never as killed. Its work folder must not be under `AppData\Local` (the Windows profile does not journal it). That fix is on branch `claude/review-batch-2-3`, not on main.
- Shell heredocs lose backslashes in Windows paths and Rust/regex text: write such files with the Write or Edit tool. `sleep` is blocked: run long jobs in the background and wait for the notification.
- Stray clones `halvard/`, `halvard-1/` and the review worktrees `..\Halvard-review`, `..\Halvard-pristine` are git-ignored; do not commit them. Remove a worktree with `git worktree remove --force <path>`.

## 6. Branches and the Cursor review thread
| Branch | State |
|---|---|
| `main` | v0.9.3: everything above, plus review batch 1 (rename-over, symlink, hard-link tripwire, placement races, gateway taint per agent, export/report need a member, Linux freeze guard, ledger witness hook) |
| `claude/review-batch-2-3` | v0.9.3, **not merged**: classifier (separators, other-script digits, PDF and nested Office text, 4x faster on number-heavy files), Keeper whole-word redaction, audit privacy, tripwire system-folder rules, Rust trust by full path and pid reuse, Windows mutation harness, CI workflows. Python 559 tests (4 skipped), Rust 43 |
| `cursor/assurance-slices-0dae` | Cursor's PR #2: seven slices (recovery, decoys and unread data, privacy and evidence, keys, program identity, coverage, Windows contract), now v0.10.10 at `53fc217`; builds on our v0.9.2 |
| `claude/pr2-verify` | WIP only: my fixes while verifying v0.10.9; Cursor's 0.10.10 fixes the same holes, so do not merge it. It carries `tests/test_verify_0109.py` (17 tests naming the holes) |
| `crosscheck-fixes`, `cursor/crosscheck-ab75` | older Cursor work |

**Review history.** (1) Cursor's first review (against a stale copy) found real Python bugs; batch 1 fixed the data-loss and authorization ones on main. (2) My review of PR #2 v0.10.7 is `docs/28-review-of-pr2-slices.md` (29 claims; main failures: ledger wipe check hollow if the `.witness` copy survives, legal hold not durable, journal-excluded files not named on the incident page, coverage rows unbounded, residual lines static, DLP over-broad and still missing separators, identity matching never fed hash or publisher by the real Linux host, connector and RSA keys are constants in the source). (3) The v0.10.9 check on Windows: 608 tests, 1 error (an author test patches `os.pread`, which does not exist on Windows) and 6 skips; items 1, 2, 4, 5, 6, 7, 9 hold; item 3 had real holes (deleting only `.hold`, a tampered `.hold`, two sessions holding at once overwriting each other); item 8 is Linux-only and could not run, and I found the exec hook quarantined inside the kernel's permission callback, recorded every harmless exec, and rehashed a binary per process. (4) Against Cursor's 0.10.10 my 17 tests give 11 passing and 6 differing: dedupe with a monitor works, but without a monitor 200 repeats still write 200 spool entries; harmless execs are still recorded (their deliberate choice); a block row naming a publisher still needs that publisher (so a lied publisher string can still dodge it and a Linux host, which has none, can never match such a row); the hash-per-binary cache is keyed differently and could not be exercised here; one of the six is only my extra `occurrences` field.

## 7. Known limits (state them, do not hide them)
- Fixed in 0.9.3: a rollback used to stop with an error at the first file Windows was briefly holding (virus scanner or indexer), leaving the rest unrestored, and the full suite failed at random on it. The restore now retries, and a file that stays locked is reported while the rest are restored (`tests/test_journal_restore_retry.py`).
- Stage A reads writes after they happen (about 1 s late): a burst loses some files before the freeze; no rollback on Windows (that needs the Stage B minifilter driver, which does not exist). A file never seen before gives no "signature destroyed" signal.
- The detector stops 8 distinct files inside 30 s; 7 files or a slow burn is not stopped (tested and documented).
- Local files cannot stop a local administrator: deleting the log, its head and every witness copy still verifies clean. A real answer needs a holder outside the machine.
- Keys: HMAC stand-ins, a 511-bit reference RSA key with its private exponent in the source, a connector key that is random per process (so seals do not cross processes). None is a KMS.
- Unsigned installer and binaries; placeholder license text; GNU toolchain (switch to MSVC before production); no macOS or Linux client; the Linux sensor has never run in CI.
- No pager or email integration behind coverage alerts; the board page is the notice.

## 8. Decisions waiting for the owner
1. How to combine PR #2 (0.10.10) with my branch `claude/review-batch-2-3`: suggested, take PR #2 as the base for slices 1 to 7 and bring over only what it lacks (Rust trust by path and pid reuse, PDF and nested Office text and the faster scan, the Windows mutation harness, CI), reconciling the overlaps by hand.
2. A professional trademark search on "Halvard" before any pilot. A review claimed a registered word mark in another class and other software users of the name; **one search could not confirm it**, so treat it as unconfirmed.
3. Legal entity and a code-signing certificate; the real license text.
4. Pricing model, first segment (suggested: regulated mid-market with private deployment), and the backronym (docs/24).

## 9. Next steps, in order
1. Decide item 1 above and merge accordingly.
2. Push the CI workflows and watch the first real Linux run (including the root fanotify lane); fix what it shows.
3. Elevated live tests: `etw_smoke.ps1`, `msi_smoke.ps1`; confirm the wizard artwork and the finish-screen status page on screen.
4. Stage B: the minifilter driver (journal and rollback on Windows).
5. Signing, license, MSVC toolchain, then a 30-day pilot soak and an independent penetration test.

## 10. Rules for working on this repository
See `CLAUDE.md`. In short: read `.ai/HANDOFF.md` first for any request; update it after every key request; bump the version (Python, Rust and the changelog are kept in step by a test); push every commit and tag immediately; never present Halvard as ready to ship.
