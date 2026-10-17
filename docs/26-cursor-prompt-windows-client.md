# 26. Prompt for Cursor: independent review of the Windows client (`native/halvard-svc`)

Copy everything between the lines into Cursor. Cursor reports first, then fixes, with a failing test before every fix (same rule as docs/23).

---

You are an independent security reviewer. The author of this code also wrote its tests, so do not trust them. Repository: Halvard. Read `.ai/HANDOFF.md`, `docs/25-windows-client-plan.md` and `CHANGELOG.md` (0.8.4 to 0.8.8) first.

Scope: `native/halvard-svc` (Rust, Windows, GNU toolchain for now). It is a resident protection prototype: an ETW session on Microsoft-Windows-Kernel-File attributes file events to processes, a tripwire brain decides, and a process that changes a decoy file is frozen with NtSuspendProcess. It runs as a LocalSystem Windows service. The Python reference in `src/halvard` is the specification; the fixtures in `tests/fixtures/sensor` are shared.

Report findings first (severity, file:line, how to trigger, proof), then wait. After approval fix each one with a failing test first. Check in particular:
1. `service.rs`: privilege escalation. Binary copied to Program Files, config and log in ProgramData. Can a non-admin change what a SYSTEM service executes, reads or writes (config tampering, log path, symlink or junction tricks on `guard.log`, `icacls` result ignored, race between copy and service creation)?
2. `etw.rs`: unsafe code. Buffer sizes, alignment of EVENT_TRACE_PROPERTIES, lifetime of the logger-name pointer after `OpenTraceW`, the global `STATE` mutex held while calling `suspend` (can an event callback deadlock or stall the kernel logger?), panics inside the callback (release uses `panic = "abort"`).
3. `guard.rs` and `brain.rs`: bypasses. Path normalisation (8.3 short names, `\\?\` prefixes, alternate data streams, hard links, junctions, case, trailing dots), events that arrive before the Create event (unknown FileObject), FileObject reuse after close, pid reuse (a frozen or trusted pid number reused by another program), trust by process NAME (any program can be called MsMpEng.exe).
4. Freeze safety: could a legitimate or critical process be frozen (the NEVER_FREEZE list is by name; also check parent/child, services hosting many tasks, `svchost.exe` being alert-only)? Could the service freeze itself or hang the machine?
5. Missed events: ETW buffer loss under load, `unreadable` counter, what the service reports when events are dropped, and whether that gap is visible to a customer (docs promise an honest coverage report).
6. Resource claims in `policy/perf_budget.json` (`windows_native_service`): are they measured anywhere, or only stated?
7. Everything the docs claim but a test does not prove. List each claim and the test (or absence of one).

Do not run `tools/run_acceptance*.py` on Windows (they overwrite evidence docs). Live ETW and service tests need an Administrator PowerShell: `tools/etw_smoke.ps1` and `tools/service_smoke.ps1`. Python tests: `python -W ignore -m unittest discover -s tests`. Rust tests: `cd native/halvard-svc; cargo test`.

---
