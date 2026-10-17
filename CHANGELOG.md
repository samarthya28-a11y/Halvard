# Changelog

Versioning: MAJOR.MINOR.PATCH. MINOR = a phase or feature; PATCH = fixes, docs, branding. Log every issue against the version it was found in.

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
