# 28. Independent review of PR #2 (branch `cursor/assurance-slices-0dae`, v0.10.7, "Slice 1" to "Slice 7")

Reviewed 2026-10-18 by Claude, against commit `b1cb2dc`, in a separate git worktree. Nothing in that branch was edited. Halvard is a reference model, not a shippable endpoint; this review does not recommend shipping it.

## 1. Suite result
`python -W ignore -m unittest discover -s tests` on **Windows 11, Python 3.12.10**: **595 run, 1 failure, 0 errors, 5 skipped**, 288 s.

Skips: three symlink tests (this account cannot create symbolic links), the **whole fanotify module** (`test_linux_sensor`: "the real fanotify sensor exists only on Linux"; it counts as one skip, so the 8 kernel-sensor tests did **not** run), and the performance-budget test (calibrated on Linux).
Failure: `test_slice2...test_an_unwritable_directory_is_skipped_and_later_decoys_still_run`. It makes a folder "unwritable" with `os.chmod(dir, 0o555)`, which does nothing on Windows and does not bind root on Linux, so the test cannot pass there; it is not skipped on those platforms. I verified the behaviour itself by fault injection instead (it holds, row 6).
**Not run here, so not verified:** every Linux-only claim (real fanotify, real `/proc`, real `os.kill`, symlink restore). WSL has no distribution; Docker exists but I did not download an image unasked.

## 2. Claims

Verdicts: HOLDS, FAILS, SPECIFIED ONLY, or NOT RUN. "Probe" = a case the author's tests do not cover.

| # | Claim | Verdict | What I ran and saw |
|---|---|---|---|
| 1 | Rename A onto existing B keeps and restores B | HOLDS, FAILS at an edge | Test passes. Probe: with the per-file journal cap below B's size, B's bytes are destroyed; the page lists only `a.txt` ("not restorable") and **never names `b.txt`** |
| 2 | Write through a symlink restores the target; link stays a link | NOT RUN | 3 symlink tests skipped on this PC |
| 3 | Hard link to a tripwire stopped before bytes change | HOLDS | Test passes. Probe: a second hard link, and a junction to the folder, both blocked, bytes intact |
| 4 | Open with no `after()`, or a dropped pending record, is not a clean rollback | HOLDS | Both tests pass. Probe: record upgraded to `write` with no `after()`: `complete=False`, file stays encrypted (reason text says "changed after the incident", which is wrong but not clean) |
| 5 | Incident page lists every file as restored / left / not restorable, with reason | FAILS | Listed for journaled files. Probe: 3 `*.tmp` files (journal-excluded) were encrypted, **not on the page, `complete=True`**. Row 1's lost destination is also unlisted |
| 6 | `/var /opt /root /run` refused like `/etc`; unwritable dir skipped and logged; later decoys still run | HOLDS (author's test FAILS here) | String rule fires. Fault injection (open raises PermissionError): skip logged, later decoy placed. **Over-blocks**: prefix match refuses `/var/home/...` (Fedora Atomic homes), `/runner/...`, `/optical`, `/binders`, `/root-share` |
| 7 | Linux suspend refuses 0,1,2, agent, parent, denylist; frozen pid stored with start time, cleared on release; reused pid not frozen | HOLDS (reference) | Passes with `os.kill` mocked. SimHost: reused pid not blocked, no stale consumer of the raw dict. `LinuxHost.proc` reads start time from `/proc` stat field 22 (read, not run) |
| 8 | Card with tab/comma/slash/underscore/colon/middle dot/ideographic space, other-script digits, lowercase IBAN | HOLDS for that list | All pass. **Still missed:** `", "` (comma+space), `;`, `\|`, figure space, soft hyphen, zero-width space |
| 9 | PDF, legacy Office, encrypted zip, non-text OOXML part, unknown bytes are regulated; no justification sends them to an unapproved drive or external address | HOLDS narrowly, FAILS broadly | Fixtures pass. Over-broad: **any** PDF (even readable text, no card), any PNG, docx with an image, EXE, SQLite are regulated. Unread regulated bytes: `email_external`→`partner` **justifiable**, `upload`→`unknown`/`external` **allowed**, `ai_prompt` **allowed**, `print` justifiable |
| 10 | Gateway taint, runaway limit, suspension follow the agent id; approval runs once, only for stored digest | HOLDS | 45 reads over 45 session ids: 15 runaway asks; new session after a web read: ask `agent-untrusted-context`; tampered params, digest unchanged: refused; second approve: unknown. **Not claimed but found:** an `end_user` principal approving the agent's own request **executed** (approver role not checked) |
| 11 | PII keys case-insensitive and nested; subject scrubbed; wiping log + `.head` fails verify, including on a new log | HOLDS, but the wipe check is hollow | PII/subject test passes. Wipe passes **only because a third file `<log>.witness` survives**. Delete log, `.head` **and** `.witness` (no key needed): fresh log `verify()` returns **(True, [])** |
| 12 | Two people pin spool and anchor; compact, uninstall, export refuse | HOLDS in memory only | Refusals work. A new `AuditLog` on the same files (a restart) has `pinned=False`; there is no release API; the files can be deleted directly |
| 13 | Keeper hides a first name; "Ann"/"Annual", "Bo"/"boat" safe | HOLDS, with false positives | Passes. Short tokens redact **ordinary words**: HR "An Nguyen" and "Jo Do" turned "An attachment ... they do not know ... it is an unknown file" into "[person] attachment ... they [person] not know ... [person] unknown file". Hyphenated names are not split; "José" does not match "Jose" |
| 14 | Export and dependency_report take a member; non-member refused, refusal in that company's ledger | HOLDS, with a side effect | Both refused and logged. 200 forged calls naming `bank` added **200 entries to the bank's ledger** (anyone can pollute a real company's evidence) |
| 15 | Isolate, rollback, DLP, gateway each end with a residual line "taken from the result" | FAILS as worded | Isolate: identical fixed text for the first and the second isolate. DLP: fixed "file not read." Rollback: no residual line for a clean rollback and none when files were left because they changed later. Gateway: derived ("minutes left") |
| 16 | customer, export, import_bundle, external_call, dependency_report need an enrolled member; code cannot open another company by id alone | HOLDS narrowly | All five refuse outsiders and wrong roles. Bare-tenant-name methods remain (`create_tenant` refuses an existing name, `delegated`, `locked`, `refresh_key`, `summary`); `Platform.tenants` is reachable in-process |
| 17 | Bundles, commands, ledger entries verify with a reference RSA public key; agent does not hold the private exponent; revoking refuses export, sign-in, commands | HOLDS for tamper checks; SPECIFIED ONLY for the key claim | Edited bundle refused, edited command rejected, replayed command rejected, edited ledger entry fails verify. But the private exponent is a **constant in `fabric/signing.py`**: a signature made from it verifies (true); 511-bit modulus; revocation is **one process-wide flag** (revoking one signer revokes every verifier / tenant) |
| 18 | Missing head anchor fails verify even when the log is empty | HOLDS on the same object | Reopening an empty log recreates the anchor, so verify passes (same cause as row 11) |
| 19 | HMAC is still the ReferenceKMS stand-in and legacy shared-secret path | HOLDS (stated) | Docstring says so; an HMAC-signed command is still accepted when no verifier is set |
| 20 | trusted_writers, tripwire_exempt, identity-shaped blocked_apps match publisher + image hash; same name, other hash not trusted and not recorded as a block | HOLDS in SimHost | Tests pass. But `LinuxHost.proc` always returns `exe_sha256: None` and no publisher, so on the real Linux host an identity row can never match and a name-only row matches every process; the fanotify exec path never calls `pre_execute`, so `blocked_apps` are never applied there. Publisher is an unverified string the host supplies |
| 21 | Leftover name-only paths | CONFIRMED holes | Name-only trusted row matches a process presenting no hash/publisher; a Glass block row with no hash matches by program name (case-insensitive) |
| 22 | Signet/Courier/Atlas automatic actions only when the connector seal verifies; unsigned event stored, `reference_model`, no action | HOLDS | Probe through the control plane: an event edited with its old signature kept, and one with the signature removed: stored, `reference_model`, no isolation, no password reset. **Edited and re-sealed with the key in the source: full response** (constant key `halvard-reference-connector-v1`) |
| 23 | Fail-open, dropped pending, stopped heartbeat each write one ledger event and one coverage row | HOLDS per event; unbounded | Test passes, but it calls sensor methods on a stub object. Probe: 5000 fail-opens = **5000 rows, 5000 ledger entries, 5000 spool entries** (no dedupe); `pending_dropped` fires on every open past 50,000; a failed-open row **never clears** |
| 24 | Board lists live/quiet/failed open/no agent; score lower with a failed-open row | HOLDS | Test passes |
| 25 | Fanotify stand-in allows the open when the hook throws and records it | HOLDS by code and stub test | `_perm_loop` calls `_on_perm_error`; real fanotify not run |
| 26 | No pager, no email integration | HOLDS | No mail, pager, webhook or network client anywhere in `src/halvard`; coverage and board import no notifier. The test's `assertNotIn("pager")` only checks the page text |
| 27 | Replay of the six Windows fixtures; `\\?\C:\...`, 8.3 name, streams, delete-on-close | HOLDS (contract) | Goldens pass. The normalization is in the **replay harness** (`sensor.normalize`) and the 8.3 table comes from the fixture header, not the agent. On this NTFS volume the agent's own gate also blocked `\\?\`, trailing dot, upper case, and a stream written through the normal call (8.3 names are disabled on this volume, so not tested) |
| 28 | Install and update manifests; nothing built | SPECIFIED ONLY | Fields as claimed, `built: False`. They name service **`HalvardSvc`** and file **`halvard.conf`**, but the WiX source already in the tree uses service **`HalvardGuard`** and config **`service.json`**. Nothing enforces "decoys removed only by remove" or "configure failure rolls back": the keys appear only in the manifest file |
| 29 | No new MSI, no driver in the branch | HOLDS | The diff adds none. The base tree already contains WiX source and a build script (from earlier work); the branch does not touch them |

## 3. What the author's tests do not prove
- The kernel sensor, symlink restore, `/proc` start times and every other Linux path: none ran here, and several tests drive stub objects rather than the sensor.
- "Wipe fails verify" is true only when the `.witness` file is left behind.
- The legal hold is a flag on one in-memory object.
- Residual lines are fixed strings in several places; the tests assert the text, not that it follows the result.
- The incident page is complete only for what the journal recorded.
- Identity matching is tested only on SimHost; the real host never supplies a hash or publisher.
- The unwritable-directory test premise is false on Windows and for root.

## 4. Still a reference model
HMAC (ReferenceKMS, legacy shared secret); reference RSA (511-bit, private exponent in the source, one process-wide revocation flag); connector HMAC (constant key in the source); name-only Glass blocks and name-only trusted rows; unverified publisher strings; no NTFS here beyond what Windows provides (streams stored as `path:stream` in the fixtures); no MSI, no driver, no service in the branch; manifests are data only.

## 5. Recommendation
Not shippable, and this review does not suggest otherwise. The slices fix what they name in the cases they test; the gaps above are the cases they do not.
