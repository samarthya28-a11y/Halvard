# Halvard handoff (read first; update after every key request)

**State 2026-11-11: main = v0.9.3, pushed. Python 542 tests pass (4 skipped), Rust 38 pass.** Full picture: `docs/29-product-handoff.md`. Rules: `CLAUDE.md` (read this file first, update it after every key request, push every commit and tag, never call Halvard ready to ship).

## What exists
Python reference (Phases 1 to 8), `dist\halvard.exe`, sensor interface + 9 golden fixtures, Rust Windows client `native/halvard-svc` (ETW guard, freeze, detector, service, placement, status page), WiX MSI with wizard and branding, strategy doc 24, Windows plan 25, reviewer prompts 26/27, PR #2 review 28.
Verified live by the owner (Administrator): ETW write path, service lifecycle. NOT verified live: ETW delete/rename, burst detector on ETW, `msi_smoke.ps1`, wizard visuals, reboot, soak. Linux sensor never run on Windows or in CI.
This PC: no service installed, no decoys left.

## Branches
- `claude/review-batch-2-3` (v0.9.3 numbering clash, unmerged): classifier/PDF/Office, Keeper, audit privacy, Rust trust-by-path and pid reuse, Windows mutation harness, CI workflows (never run on GitHub).
- `cursor/assurance-slices-0dae` (PR #2, v0.10.10, `53fc217`): overlaps my batch; it fixed the holes I found in 0.10.9 except: no-monitor coverage dedupe, harmless execs still recorded, publisher-naming block rows.
- `claude/pr2-verify`: WIP, duplicates Cursor's fixes, do not merge; holds `tests/test_verify_0109.py` (17 tests naming holes; 11 pass on 0.10.10).

## Open decisions for the owner
1. How to combine PR #2 with my batch (suggest PR #2 as base, bring over what it lacks, renumber to 0.9.4+).
2. Professional trademark search on "Halvard" (a review's claim of a registered mark is unconfirmed).
3. Signing certificate, legal entity, real license text; pricing/segment/backronym.

## Next steps
1. Decide merge strategy. 2. Push CI and watch the first Linux run. 3. Elevated live tests (`etw_smoke.ps1`, `msi_smoke.ps1`). 4. Stage B minifilter. 5. Signing, MSVC, soak, pen test.

## Gotchas
Never run `tools/run_acceptance*.py` on Windows. Heredocs lose backslashes: use Write/Edit. `sleep` is blocked: background + notification. Mutation harness is slow on Windows (use filters, `HALVARD_MUT_WORKERS=1`). Stray clones `halvard/`, `halvard-1/` and worktrees `..\Halvard-review`, `..\Halvard-pristine` are git-ignored; remove worktrees with `git worktree remove --force`.
