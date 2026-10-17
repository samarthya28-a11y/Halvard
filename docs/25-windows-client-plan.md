# 25. Windows client: plan and sensor design (v0.8.3, 2026-10-17)

Status: design for owner approval. Nothing here is built yet. Costs and timelines are rough estimates, not quotes.

## 1. Goal and hard budgets
A resident protection client that the user never notices. Targets (to be enforced by a test, like `policy/perf_budget.json`):

| Budget | Target |
|---|---|
| Idle CPU | under 0.5% of one core, no polling loops |
| Memory (working set) | under 30 MB service, under 5 MB non-paged driver memory |
| Added file-open latency | under 1 ms median, under 5 ms p99, in protected scope only |
| Disk | journal capped (default 2 GB, per-file cap exists), install under 25 MB |
| Battery / busy machine | back off: lower priority, batch uploads, pause scans on battery |
| Failure mode | fails open on its own faults (as Linux sensor does), and reports the gap as a coverage incident |

The current `halvard.exe` (Python, 10.7 MB, 25-36 MB while running a story, about 1 s start from unpacking) is the **reference client** and the executable specification. It stays for demos and tests. The resident agent should be native.

## 2. Language and shape
- **Service (user mode): Rust.** No runtime, memory safe, 3-8 MB binary, 5-15 MB resident. C++ is the alternative if the team already has it.
- **Driver (kernel): C, a file-system minifilter** (Rust drivers exist but add risk; keep the driver tiny, about 1-2k lines, and put every decision in the service).
- **Policy brain:** the decision logic (detector, authority matrix, verdicts) is specified by the Python reference and its 504 tests. Port it module by module, using the Python tests as conformance vectors (same inputs, same outputs). This is what protects the product claims while the language changes.

## 3. Sensor design: two stages
Linux today is the model: fanotify gives a **permission event before the open** (so Halvard can journal the before-image, or deny) and a **close event after** (so it can classify the write). Windows has the same shape through a minifilter.

### Stage A: user-mode sensor (no driver; ships first)
- Sources: ETW providers `Microsoft-Windows-Kernel-File`, `-Kernel-Process`, `-Kernel-Network`; NTFS change journal (USN) for rename/delete; `ReadDirectoryChangesW` only for tripwire folders.
- Tripwires first: decoy files in user folders. First touch by an untrusted process raises an alarm, and the service suspends the process (`NtSuspendProcess`) within tens of milliseconds. This is the cheapest and quietest protection.
- Recovery: **not byte-exact guaranteed.** ETW is after the fact, so before-images cannot be taken on first touch. Mitigations: protected-folder rolling copies of files, VSS snapshots, backup integration. Evidence and reports must say so ("restored from snapshot", not "byte-identical").
- Pros: no driver signing, no blue-screen risk, fast to ship. Cons: weaker guarantee, ETW can drop events under load, and an attacker with admin can kill it.

### Stage B: minifilter driver (the real equivalent of fanotify)
| Linux (exists) | Windows minifilter |
|---|---|
| `FAN_OPEN_PERM` -> journal before-image, maybe deny | `IRP_MJ_CREATE` pre-operation callback; ask service through the filter port; allow, deny or "allow after copy" |
| `FAN_OPEN_EXEC_PERM` -> verdict on the program | pre-create with execute access, plus `PsSetCreateProcessNotifyRoutineEx` to block process creation |
| `FAN_CLOSE_WRITE` -> classify, journal after-state | `IRP_MJ_CLEANUP`/post-write for modified files |
| rename/delete (FID group) | `IRP_MJ_SET_INFORMATION` (rename, delete dispositions) |
| pending events keyed by inode | keyed by file ID plus volume |
| `FAN_DENY` | return `STATUS_ACCESS_DENIED` from the pre-callback |

Light-weight rules for the driver (this is where the budget is won or lost):
1. **Filter in the kernel, not in the service.** Instance only on fixed local volumes; skip system paths, the service's own I/O, and processes on the trusted list (cached by process ID plus image hash).
2. **Ask the service only when needed:** an untrusted process opening a protected-scope file for write, a new executable, a rename or delete in scope. Everything else is allowed without a round trip. Reads from untrusted processes are counted, not blocked.
3. **Bounded and non-blocking:** fixed-size ring buffer, hard timeout on every port call (default 100 ms; on timeout allow and log), drop-oldest telemetry rather than stall I/O.
4. **No hashing on the hot path.** Hash executables on first run only and cache by (file ID, size, last write).
5. **Self-protection, not self-harm:** if the service dies the driver allows everything and flags the gap.

### Behaviour that must stay identical to the reference
`WardAgent` entry points the sensor must call, unchanged: `tripwire_gate`, journal `before`/`after`, `pre_execute`, `check_egress`, `handle_verdict`, `emit`, `apply_bundle` (signed policy), `execute_command` (signed commands). The sensor only supplies events and enforces the answers; it holds no policy.

## 4. Service, installer, signing
- **Service:** one Windows service (LocalSystem), delayed auto-start, recovery action restart, a small watchdog. IPC to the driver through a filter communication port; to the UI through a named pipe with ACLs. Optional tray status icon is a separate tiny process and can be absent.
- **Tamper protection:** uninstall code and signed policy already exist in the reference. Later: run the service as a Protected Process Light (needs an ELAM driver and Microsoft approval).
- **Installer:** MSI built with WiX, per-machine, silent switches (`/qn`), for Intune, SCCM, GPO and winget. Upgrades through signed update bundles (Phase 8 mechanism), staged by ring (Glass rings already model this). Offline/private deployments get the same MSI plus a signed licence file.
- **Signing (needed before anyone installs it):**
  - Authenticode code-signing certificate for the exe/MSI: EV certificate on an HSM or cloud signing service (hardware/cloud key now mandatory); roughly a few hundred USD per year.
  - Driver: Microsoft Partner Center account, EV certificate, attestation signing first, WHQL certification later for enterprise confidence.
  - Without signing, SmartScreen warns and many companies' policies refuse the install.

## 5. Milestones (each ends with a measurable exit test)
| # | Deliverable | Exit test |
|---|---|---|
| M0 | Define the sensor interface and event fixtures; add a Windows budget test (CPU, RAM, latency) | budget test runs against the Python reference |
| M1 | Stage A prototype: ETW + tripwires, suspend on first touch, runs as a service | a ransomware simulator in an authorized folder is stopped after fewer than N files; idle CPU under budget |
| M2 | Rust service with ported policy brain; conformance vectors from the Python tests | all ported vectors identical |
| M3 | Minifilter (test-signed, in a VM) with pre-create journalling and deny | byte-identical restore test on Windows, as on Linux; latency budget met |
| M4 | MSI, auto-update, uninstall code, coverage reporting | silent install, upgrade and rollback on a clean VM |
| M5 | Signing, attestation, hardening, 30-day soak on a pilot fleet | zero blue screens, performance report |
| M6 | Independent test (detection test, penetration test), SOC 2 evidence | reports filed |

Rough effort: M0-M1 a few weeks; M2-M3 a few months; M4-M6 a few more months plus calendar time for certificates and external tests.

## 6. Risks to state plainly
- A buggy minifilter can crash Windows. Mitigation: tiny driver, test-signed VM lab, ring rollout, a kill switch (service stops, driver goes pass-through).
- Stage A cannot promise byte-exact recovery. Sales claims must match the stage shipped.
- Security-product ecosystems (other EDRs, backup agents) can conflict with filters; budget time for compatibility testing.
- The Windows file-path rules differ (short names, alternate data streams, hard links, reparse points); the reference profile covers case and separators only.

## 7. Decisions needed from the owner
1. Rust for the service (recommended) or C++?
2. Ship Stage A first (recommended: faster, safer) or go straight to the driver?
3. Who funds and holds the signing certificates (company entity needed first)?
4. Keep the Python `halvard.exe` as the demo and test client? (recommended: yes)
