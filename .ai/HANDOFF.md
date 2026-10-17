# Halvard handoff (update after every major change)

Version 0.10.1 (see CHANGELOG.md). Python 3.11+ stdlib only; Rust (GNU toolchain) for `native/`. Slice 1 recovery listing is in the Python reference. The Windows service is still the Stage A ETW prototype, not a minifilter.

## Ground rules from the owner
1. Update this file after every major change. 2. Version every change (`src/halvard/__init__.py` + `CHANGELOG.md`, git tag `vX.Y.Z`). 3. Keep advising on deployment, licensing, commercials, cloud vs on-prem (docs/24). 4. Keep researching competitors and recommend unique features.
5. **Every local commit and tag is pushed to GitHub immediately** (`git push origin main --tags`; a `.git/hooks/post-commit` hook pushes commits automatically, tags need the explicit push; `push.followTags` is on). Standing authorization from the owner. Scan the diff for secrets and large files first. Reason: Cursor reviewed GitHub's stale copy and could not see the Windows work.
Do NOT run `tools/run_acceptance*.py` on Windows (overwrites evidence docs with reduced output). Competitor prices in docs/24 are indicative only. A folder `halvard/` in the repo root is a separate clone (git-ignored): leave it.

## What exists and its proof level
- **Python reference, Phases 1-8**: `python -W ignore -m unittest discover -s tests` -> 521 OK, 3 skipped on Windows. Stories: `$env:PYTHONPATH="src"; python -m halvard.cli <setup|demo|stolen-session|mailed-attachment|exposed-bucket|data-leak|patch-day|ai-agent|tripwires|platform|rogue-device>`. Proven by tests + owner ran suite.
- **`halvard.exe`** (PyInstaller of the Python stories, 10.7 MB): `tools/build_exe.ps1`. Reference client, not a resident agent.
- **Strategy**: docs/24 (name = "rock guardian", backronym Hosts/Accounts/Leaks/Vulnerabilities/AI/Response/Deception, deployment, licensing, pricing, competitors). Owner decisions still open: backronym, pricing model, first segment.
- **Windows plan**: docs/25 (Rust service, Stage A = ETW + tripwires then Stage B minifilter). Cursor review prompts: docs/26 (client), docs/27 (everything).
- **Sensor interface** (`src/halvard/sensor.py`, 9 fixtures in `tests/fixtures/sensor`, regenerate with `tools/gen_sensor_fixtures.py`): fixtures carry `golden` decisions from the Python reference; Python and Rust both must reproduce them. Budget targets in `policy/perf_budget.json` (`windows_native_service`).
- **Rust client `native/halvard-svc`** (`cargo test` -> 38 pass; `cargo build --release` -> 0.52 MB exe; cargo in `~/.cargo/bin`): tripwire brain, detector port (M2), ETW guard, freeze, watcher, service, placement, installer commands.
  - VERIFIED LIVE by owner (Administrator): ETW write path freezes attacker (v0.8.7); Windows service install/start/freeze/restart-after-kill/stop/uninstall ALL PASS (v0.8.11).
  - NOT verified live: ETW delete and rename (property names now discovered at runtime, `guard --debug` dumps them); behavioral detector on live ETW (burst scenario); the MSI end to end; reboot auto-start; load/soak; coexistence with other security products.
- **MSI** (`tools/build_msi.ps1` -> `dist/halvard-0.9.0-x64.msi`, 0.93 MB, WiX 5.0.2 + Util + UI extensions, wizard WixUI_Minimal, license.rtf is a placeholder): per-machine, service auto-start delayed, restart on failure, `TRIPWIREDIRS` property (default = every real user's Documents via the profile list). 0.8.13 was installed by the owner by double-click (no wizard then); it works. Owner PC may still have 0.8.13 installed: uninstall with `msiexec /x` first.

## Elevation (Administrator PowerShell needed)
Install/uninstall/start/stop the service or MSI; ETW (`guard`); live scripts `tools/etw_smoke.ps1` (4 attackers: write, delete, rename, ransomware burst), `tools/service_smoke.ps1`, `tools/msi_smoke.ps1`. No elevation: building, tests, `place`, `tripwires list|remove`, `service status`, `watch`, `replay`.
Pending request to owner: run `etw_smoke.ps1` and `msi_smoke.ps1` elevated, read `C:\Users\ASUS\halvard-etw-smoke.txt` and `halvard-msi-smoke.txt`.

## Known limits (state them, do not hide them)
- Stage A (ETW) sees writes AFTER they happen (about 1 s late): a burst loses a few files before the freeze; no byte-exact rollback (journal needs the Stage B minifilter). A file never seen before gives no "signature destroyed" signal.
- Detector is a port of the Python rules: 8 files in 30 s; 7 files or a slow burn is not stopped (tested, documented).
- Trust is by process NAME (any program can call itself MsMpEng.exe): a Cursor-review item.
- Unsigned binaries/MSI (no code-signing certificate yet); GNU toolchain (switch to MSVC before production); no installer for macOS/Linux client.

## Next steps (recommended order)
1. Owner runs the elevated smoke tests; fix whatever they show. 2. Give Cursor docs/27. 3. Code-signing certificate + legal entity + trademark check on "Halvard". 4. Stage B minifilter (journal/rollback). 5. Replace the placeholder license, then MSVC toolchain, signing, 30-day pilot soak.
