# Halvard handoff (update after every major change)

Version: 0.8.7 (see CHANGELOG.md). Branch: main. Python 3.11+, stdlib only.

## State
- Reference build, Phases 1-8. Tests: `python -W ignore -m unittest discover -s tests` -> 515 OK, 3 skipped on Windows.
- Stories: `$env:PYTHONPATH="src"; python -m halvard.cli <setup|demo|stolen-session|mailed-attachment|exposed-bucket|data-leak|patch-day|ai-agent|tripwires|platform|rogue-device>` all pass.
- Logo v2 (gold, aggressive) added, README points to it. Old logo kept.
- Strategy doc: docs/24-strategy-and-market.md (name meaning, backronym, deployment, licensing, pricing, competitor research).

## Exe
- `powershell -File tools/build_exe.ps1` -> dist/halvard.exe (10.7 MB, ~30 MB RAM). dist/ and build/ are gitignored.
- Next for a real light client: native Windows sensor (ReadDirectoryChangesW + process events), run as a service, MSI/winget installer, code signing, onedir build to avoid the ~1 s startup extraction.

## Windows client
- Plan and sensor design in docs/25-windows-client-plan.md (awaiting owner decisions: Rust vs C++, Stage A first, signing owner). Decisions taken: Rust service, Stage A first. M0 DONE (halvard/sensor.py, tests/fixtures/sensor, tests/test_sensor_conformance.py). M1 partly DONE: native/halvard-svc (Rust, cargo at ~/.cargo/bin; add to PATH). M1b DONE and verified live for the write path (owner ran tools\etw_smoke.ps1 elevated: PASS). Still to verify live: delete/rename (events 26/27 property names). Next: Windows service wrapper (windows-service crate). Then M2 port detector/journal. Switch to MSVC toolchain before production.

## Open / pending
- docs/07 and docs/11 were overwritten by a Windows acceptance run; revert with `git checkout -- docs/07-phase1-evidence.md docs/11-phase3-evidence.md` (user approval pending).
- Decisions needed from user: backronym, pricing model, first go-to-market segment (see doc 24 section 6).

## Ground rules from user
1. Update this file after every major change. 2. Version every change (CHANGELOG, __version__). 3. Keep advising on deployment, licensing, commercials, cloud vs on-prem. 4. Keep researching competitors and recommend unique features.

## Do not
Run tools/run_acceptance*.py on Windows. Treat competitor pricing in doc 24 as indicative.
