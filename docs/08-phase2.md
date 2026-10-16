# Phase 2: macOS and Linux, custom detections, hunt, forensic collect, false-positive learning

Evidence (generated from real runs): `docs/09-phase2-evidence.md`. Read its **Not demonstrated** section first.

## What Phase 2 adds

| Capability | Where | Features |
|---|---|---|
| Linux sensor: real kernel events, pre-execution deny, pid-attributed rename/delete | `platforms/linux.py` | F001, F004, F006, F019, F040 on Linux |
| Platform profiles: path identity, noisy-path exclusions, persistence locations, rendered isolation (Windows, macOS, Linux) | `platforms/__init__.py`, `relay/isolation.py` | F001 (macOS: profile only) |
| Telemetry store with hot/cold retention and export | `hunt/events.py` | F019 (partial), F033, F128 |
| Query language shared by hunt, detections and the device | `hunt/ql.py` | F027, F034 |
| Natural-language hunt (phrase translator) | `hunt/nl.py` | F027 |
| Role-limited search, audited | `hunt/service.py` | F034, F114 |
| Governed custom-detection library, signed content packs, device-side evaluation | `detect/library.py`, `ward/agent.py` | F022 (subset), F023, F036 |
| Tenant-specific, reversible false-positive learning | `detect/learning.py` | F029 |
| Forensic collection: triage, named files, named-process memory | `relay/forensics.py`, `relay/actions.py` | F026 |

## Linux sensor: how it works and what it cannot do

Two fanotify groups on one mount.

* **Permission group** (`FAN_OPEN_PERM`, `FAN_OPEN_EXEC_PERM`, `FAN_CLOSE_*`). On open it keeps a pre-image in the journal and
  records the file's head; on exec it runs the pre-execution verdict and **denies** known-bad; it denies every open by a process
  Ward has frozen; on close-after-write it classifies the change and feeds the same detector as every other platform. Events from the
  sensor's own process are always allowed, and a fault inside the sensor allows the operation (fail open, counted in `stats["errors"]`).
* **Notification group** (`FAN_RENAME`, `FAN_DELETE`, directory file handles). These carry the acting pid and both names, so `rename to .locked`
  and `delete the original` are journaled exactly. Before rolling back, the response waits up to 3 s for the kernel's already-queued events to arrive.

Limits, stated plainly:

1. Intent is unknown at open time, so any open of an existing file gets a pre-image (rate-limited per process and path, deduplicated, quota-bounded).
   This costs more journal churn than a write-intent hook, and it is not yet in the published performance budget.
2. A burst faster than detection can finish first (`pace 0` in the evidence). Prevention then loses the race and **the journal still restores everything**.
   That is why rollback does not depend on detection speed.
3. Files over the per-file cap are not preserved and are listed as not restorable. Files over 2 GB are unsupported.
4. A mount mark covers one mount. exec events carry the executable and hash, not arguments.
5. A dead sensor fails open; the control is sensor-health/coverage alerting (F121), which is Phase 1's coverage monitor plus a scheduler that does not exist yet.
6. Do not exec files from the watched mount inside the sensor's own process: CPython's `posix_spawn` holds the GIL while the child's exec waits for the
   sensor's reply. This deadlocked the first test run; the tests launch executables through a shell, and the production sensor runs as its own service.
7. Needs root. Tests run it on a private tmpfs mount and skip cleanly where root or fanotify is missing.

macOS and Windows: the profile gives path identity (case folding, NFC), noisy-path exclusions, persistence locations and a rendered isolation ruleset
(`pf` anchor on macOS). The native sensors (Endpoint Security client with its Apple entitlement; minifilter) are not in this repository.
The agent core is OS-neutral: one test drives the same stop-and-restore scenario through each profile's contract.

## Query language (HQL)

`kind=process AND proc~"powershell*" AND cmdline contains "-enc" | count by device | where count > 3`

One grammar, two executors. Store queries compile to parameterized SQL over a whitelist of field names; devices evaluate the same AST in Python.
A test generates 400 events with hostile values (`%`, `_`, `[`, mixed case, nulls) and requires both executors to select identical events for 22 queries.
Comparisons are ASCII case-insensitive on both paths so they cannot disagree.

Roles: **analyst** full HQL, natural language, cold tier, raw fields. **IT administrator** keyword search only: fixed columns, last 7 days, never command lines or user names
(command lines can hold secrets). **Service desk** "is this laptop okay?" only. **Site manager, auditor, owner**: no telemetry. Every search and every denial is in Ledger.

## Custom detections

Draft → in review → active → expired/retired. Gates: ATT&CK ids must exist in the bundled list (a **subset**, `synced_with_upstream: null`), one positive and one negative example
must behave, a 7-day backtest must stay under the noise cap, a **different** analyst approves, and every rule expires (≤ 180 days; renewal = new version + new review).
Active rules ship as an HMAC-signed, monotonic content pack (F036) and run **on the device**, so they fire offline; the device also enforces expiry itself.
Confidence on a custom hit is whatever the author set and is labelled `author-set` everywhere. Halvard does not invent a score for a rule it did not measure.

## False-positive learning

Feedback never changes behavior by itself. Four benign marks on at least two devices produce a **suggested** exception. A different person approves it after a replay preview over history.
Exceptions name the detection and the program **by hash** (not name), may be limited by folder and device, and expire (≤ 90 days). They cannot be approved if they would also hide something an analyst confirmed as malicious,
and known-bad blocks can never be excepted. For bulk-encryption behavior the effect is **observe only**: Ward stops freezing/stopping that program but keeps journaling every write, so a wrong exception stays recoverable.
Revoking restores full protection immediately and lists everything that was suppressed for re-triage.

## Forensic collection

Always needs an approver (the matrix has no auto cell). `triage` is metadata only. `files` copies only the paths the approver saw. `memory` needs a personal-data acknowledgement and named pids, is size-capped, and is labelled.
A sealed manifest (SHA-256 of every item, requester, reason, retention) is verified on demand; changing any collected byte or the manifest is detected. The ledger gets counts and the manifest digest, never contents.
Deleting a collection is the reversal, and it is refused while the case is under legal hold.

## Honest gaps carried forward

No native macOS/Windows sensor; no console, control plane, installer or updater; F019 covers process and file events only; F028 (guided investigation), F021/F030/F031 (campaign story, case grouping, criticality in the score) wait for the case model; the Linux sensor is not in the performance budget.
