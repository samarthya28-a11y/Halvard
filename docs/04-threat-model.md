# Threat model: Halvard itself

Halvard is a high-value target: it can isolate machines, run commands, revoke identities and roll back files across a
company. Its compromise is a customer breach. Method: STRIDE per trust boundary, then abuse cases ranked by blast
radius. "Phase" says when the control exists in code; **Built** means present and tested in this repository.

## Assets (what an attacker wants)

1. The ability to act: isolate, run commands, disable accounts (Relay/Signet) on many devices at once.
2. Telemetry and evidence: metadata about every device and person; collected forensics (may hold personal data).
3. Policy: turning prevention off, adding exclusions, accepting an automation pattern.
4. Keys: device identities, tenant policy keys, customer-managed keys, uninstall-code key.
5. The update channel to every agent.
6. The audit record itself (to hide what happened).

## Trust boundaries

Device ⇄ OS file hook ⇄ Ward agent · Agent ⇄ control plane · Console user ⇄ control plane · Halvard staff/Keeper ⇄ tenant ·
Tenant ⇄ tenant · Connectors ⇄ customer SaaS/IdP · Build system ⇄ release channel.

## Abuse cases and controls

| # | Threat | Control | Status |
|---|---|---|---|
| T1 | Malware or admin-level attacker stops, edits or uninstalls the agent | Integrity manifest with self-heal and a tamper record; stop/uninstall only with a console-issued, device-bound, expiring, single-use code; refused attempts are logged | **Built** (user-space reference). Kernel-level self-protection (protected process, driver callbacks) is native work, not built |
| T2 | Forged or downgraded policy turns prevention off | Signed policy bundle; invalid signature keeps the last good policy and logs; version may only increase | **Built** (HMAC; production uses asymmetric signature from the tenant policy key) |
| T3 | Attacker with a stolen console session runs commands everywhere | Authority matrix: remote command is never auto, needs a second approver, expires; requester cannot approve own request; staff/Keeper/provider roles require just-in-time elevation; phishing-resistant MFA at the IdP | Matrix, approvals, JIT **Built**; SSO/MFA integration Phase 3 |
| T4 | Insider at Halvard or a provider reads or acts in a customer tenant | Support access only through a customer-opened, time-boxed grant bound to person and tenant; tenant isolation tests; Keeper bound by the matrix (`never` / `propose_only` cells) | **Built** (grants, matrix); staff identity proofing is operational |
| T5 | Cross-tenant data access (IDOR, injection, path traversal) | `tenant_id` in every key and every query, bound from the authenticated context only; composite foreign keys; object paths resolved under `t/<tenant>/`; denials fail closed, return the same answer as "not found", and are logged | **Built** and tested; Postgres RLS mapping documented, not built |
| T6 | Audit record edited or truncated to hide actions | Hash chain + HMAC seal per entry + sealed head anchor; truncation, edit, deletion, reorder detected; device spool verified before ingest | **Built**. Limit: someone holding the seal key can forge; production keeps it in the customer-managed KMS/HSM (not built) |
| T7 | The audit or telemetry leaks employee content | Raw-content keys and long strings refused at write; personal identifiers committed by digest with per-entry nonce and tokenized in auditor exports; no document content, keystrokes, webcam or microphone collection | **Built** for Ledger. Collector-side limits (never read file bodies beyond a 4 KB signature sample kept in memory) are by design in Ward |
| T8 | Ransomware tuned to evade the detector (slow, low-and-slow, partial encryption, excluded paths) | Signals are structural (signature destroyed, random output) not name-based; sliding window; journal keeps pre-images regardless of detection, so a *late* detection can still roll back everything the process wrote | **Known gap**: below 8 files / 30 s, or only in `journal_exclude` paths, this detector alone does not fire. Mitigations: Hearth encryption tripwires (Phase 7, built; they help only when the program reaches them early), cross-device campaign view (Phase 2+), per-tenant tuning with reversible learning |
| T9 | Attacker fills or poisons the journal to push out good pre-images | Content-addressed dedupe, per-path rate limit, quota with an explicit "not restorable: quota reached" report in the recovery note; incident pids are pinned against compaction | **Built**; quota exhaustion is reported, never silent |
| T10 | Trusted-writer allowlist abused by injecting into a trusted process | Allowlist is policy (signed), per process name today | **Weak**: name-only trust. Needs signer + path + reputation binding in the native agent |
| T11 | Abusing automatic actions to cause outages (false positive isolating the CEO's laptop, or a hospital system) | Automation shows its work, then runs only after a customer admin accepts the pattern; destructive actions on production/clinical/privileged assets need approval no customer setting can remove (floors); maintenance windows delay disruptive actions, never critical cases; every action has a reversal or an explicit "cannot undo" | **Built** |
| T12 | Safe-simulation feature used as an attack tool | Runs only in a directory with a customer-created authorization marker, only on files the harness created, no cryptography, no network, no persistence, no spread | **Built** and tested (refuses an unmarked directory) |
| T13 | Poisoned update or compromised build | Signed builds, pinned dependencies, SBOM, reproducible artifacts, rings with halt, agent verifies before applying | **Not built** (Phase 1 has no installer/updater). Required before any customer release |
| T14 | Secrets in the agent or product | Rotatable device identity only; secrets in a vault | Reference keys are test constants. **Not production-safe by design**; key management is not built |
| T15 | Denial of service against the device (agent consumes CPU, disk, or locks files) | Published CPU/memory/disk ceilings enforced by a test; journal quota; fail-open on internal errors for the *file hook* (never block the OS) with a coverage alert | Budget test **Built** (reference build); fail-open/alert path specified, native hook not built |
| T16 | Console or API abuse (CSRF, injection, SSRF through connectors) | Not applicable until a console/API exists | Phase 3+ |

## Phase 2 additions

| # | Threat | Control | Status |
|---|---|---|---|
| T17 | A custom detection (or a false-positive exception) is used to blind Halvard | Authors cannot approve their own rules; exceptions need a different approver, name the program by hash, are narrow, expire, cannot hide confirmed-malicious findings, never apply to known-bad blocks, and for bulk encryption are observe-only so the journal still protects the files; revoke is immediate and lists what was hidden; all in Ledger | **Built** |
| T18 | Poisoned or replayed detection content | Signed, monotonic content packs; the device re-checks signature, version and per-rule expiry | **Built** (HMAC reference) |
| T19 | Hunt used to read employee content or secrets | Telemetry has no content fields (refused at write); IT admins get fixed columns without command lines or user names; service desk gets a verdict only; every query and denial is audited | **Built** |
| T20 | Injection through the query language | Field names whitelisted; every value is a bound parameter; result-size cap; SQL and device executors proven equivalent on hostile inputs | **Built** |
| T21 | Forensic collection used for covert surveillance | Always approval-gated; scope is named paths/pids; memory needs an explicit personal-data acknowledgement; sealed manifest; retention stated; cannot be deleted under legal hold; contents never in Ledger | **Built** |
| T22 | Sensor bypass or crash on Linux | A dead or faulting sensor fails open (kernel semantics); sensor errors are counted and visible; coverage alert is the control | **Partial**: coverage scheduler not built |
| T23 | The sensor deadlocking the machine (permission events pending) | Own-process events always allowed; closing the group releases the kernel; never exec from the watched mount inside the sensor process; tests run on an isolated tmpfs | **Mitigated**, found the hard way (see docs/08) |
| T24 | Ransomware outruns detection | The journal restores regardless of detection speed (tested with an unpaced burst) | **Built** |

## Phase 3 additions

| # | Threat | Control | Status |
|---|---|---|---|
| T25 | An attacker triggers Halvard's automatic response to lock out a real employee (denial of service by forged evidence) | Automatic response needs case confidence above a customer-set threshold (default 0.85), a customer-accepted pattern, and an `identity_takeover` finding; privileged accounts need two people; every step is reversible or explicitly irreversible and says so; the manager is told | **Partly mitigated**: forged connector events are the residual risk (T26) |
| T26 | Forged or injected identity events | Reference connectors are in-process. Real connectors must authenticate the feed and the polling credential must be least-privilege and read-only for events | **Not built** (no real connectors) |
| T27 | A compromised control plane sends harmful device commands | Devices verify signature, device, expiry, single use, an allow-list of remote actions, and re-check the approval count against their own matrix and asset class | **Built** |
| T28 | Notification used as an exfil/phishing channel, or sent through the attacker's mailbox | Fixed plain-language template with no technical detail; approved channels only; never through a channel owned by an affected identity; ledger stores template and channel kind, not text | **Built** |
| T29 | Revocation believed to be instant when it is not | Preview, result and case page list every application that keeps honouring an already-issued token, with minutes left | **Built** |
| T30 | The hijacked admin is contained too slowly because two approvers are required | Deliberate; customer on-call or Keeper provides approvers; the case page shows what is waiting | **Accepted trade-off**, documented |
| T31 | Signet's own admin credentials at the IdP/AD are a crown jewel | Reference build has none. Real connectors need separate read and act credentials, JIT elevation for act, and Ledger records for every use | **Not built** |
| T32 | Over-containment across hybrid identities | Containment lists exactly which identities and devices it touches in the preview; devices are only those with findings in the case, not every device the person owns | **Built** |

## Phase 4 additions

| # | Threat | Control | Status |
|---|---|---|---|
| T33 | Courier itself reads private mail and keeps it | Bodies/subjects analysed in memory only; stored: ids, hashes, domains, verdicts, reasons without names or file names; audit subjects are opaque; addresses scrubbed from public audit fields; no covert capture | **Built**; mail-system access scope for a real connector is not built |
| T34 | A harmful message is released back to users | Release needs a reason; a malicious verdict raises the requirement to an analyst or administrator and the desk cannot approve its own request | **Built** |
| T35 | Clawback used to destroy evidence or lose a user's mail | Clawback moves to a recoverable quarantine; purge is separate, approval-gated, irreversible and refused under legal hold; every copy touched is listed | **Built** |
| T36 | Attacker abuses automatic clawback by sending harmless-looking mail with a known-bad hash to hide it (denial of service on a mailbox) | Moves are recoverable and logged; confidence threshold; release path exists. A flood is not rate-limited yet | **Partly mitigated** |
| T37 | Verdict arrives after the user opened the file | Measured exposure window; endpoint rules and hash hunt find where it landed; the same hash is blocked on all other devices, offline-capable | **Built**; first-victim protection depends on a dynamic sandbox that does not exist here |
| T38 | A poisoned block list pushed to devices denies legitimate files | Policy bundles are signed and monotonic; hashes come from Courier verdicts through a gated path; an administrator can revoke by pushing a newer bundle; there is no automatic expiry of hashes yet | **Partly built** |
| T39 | Link analysis leaks the analyst's or the company's identity to an attacker site | Reference build has no real fetching. A real fetcher must be isolated and anonymised | **Not built** |
| T40 | Look-alike detection flags real partners or misses new ones | Exact and sub-domain matches are exempt; partner list is a customer setting; confidence is shown with the reason | **Built**, untuned |

## Phase 5 additions

| # | Threat | Control | Status |
|---|---|---|---|
| T41 | Cloud read/act credentials are a crown jewel (a connector that can change firewall rules and bucket policy) | Reference build has none. A real connector needs read-only and separate act credentials, JIT elevation for act, Ledger records for every use | **Not built** |
| T42 | Data-protection scanning becomes covert surveillance | Off by default; needs purpose, effective staff notice, scope and exclusions; refusals are recorded; only labels and counts are kept; no values or snippets ever; personal folders never read | **Built** (tested) |
| T43 | The classifier leaks the data it finds (in logs, catalog, telemetry, errors) | Detectors return counts and reasons only; tests assert card numbers and object names are absent from public audit fields, the catalog, telemetry and exports | **Built** |
| T44 | Rules block legitimate work and people route around them (personal email, photos of screens) | Messages say what to do; justify path is quick and time-boxed; every decision is recorded; analysts can see aggregate blocks to tune. Workarounds outside the hooks are NOT detected | **Partly mitigated**; residual risk accepted |
| T45 | A user uses a justification to exfiltrate | Reason is recorded privately, limited to one file/door/destination class for an hour, never available for secrets or device rules, and visible to reviewers | **Built**; cannot stop a determined insider |
| T46 | Automatic revert breaks a public website | Preview names the tag; production resources need an approver; the revert is one-step reversible | **Built** |
| T47 | Revert is believed to undo the leak | Result states that reads made while it was exposed cannot be undone, and the case keeps the exposure window | **Built** (message); exposure-window reporting from real access logs is **not built** |
| T48 | A sensitivity label is wrong and drives wrong decisions | Halvard's label is only a suggestion beside the person's; both are shown; person's wins | **Built** |
| T49 | An attacker plants decoy card-like data to trigger blocks or reverts | Checksums reduce accidental matches; they do not stop deliberate test numbers (test card numbers validate by design) | **Known gap** |
| T50 | The ordering number is read as a probability or a loss estimate | Shown with its factors and the words "not a probability" beside every item; tiers come from plain rules | **Built**; the weights are unvalidated defaults |
| T51 | A stale or poisoned advisory feed ranks a real flaw low | Exploit status is supplied by the feed and never guessed; the reference feed is labelled synthetic and `synced_with_upstream` is null | **Known gap**: no feed signing, freshness check or import path yet |
| T52 | A temporary protection becomes permanent, or lapses silently | 30-day cap, expiry that keeps the protection in force and re-ranks the item, extension cap, owner-only risk acceptance, board cap | **Built** |
| T53 | Someone with analyst rights switches off a business program as a denial of service | It is an action: roles, matrix, preview, approver on production, undo, ledger | **Built**; a malicious insider with approver rights can still do it, and it will be on the record |
| T54 | A bad update reaches every device | Rings, soak, health gate, automatic halt; production waits for an approver | **Partly built**: the health signal is simulated in this build |
| T55 | A forged or replayed update command | Device verifies signature, target, expiry, one-time nonce and re-checks approvals against its own matrix and asset class | **Built** |
| T56 | The external scan probes a third party | Only the company's cloud addresses, plus addresses a domain-verified name points to AND a person confirmed; refusals are recorded | **Built**; DNS ownership proof shows control of a name, not of every server behind it, hence the confirmation step |
| T57 | The board score hides a fact | Unmeasured outcomes are left out, not full marks; urgent facts cap the number; working and blind spots are on the page; snapshots are in the Ledger | **Built**; deadlines and weights are fixed defaults in this build, so changes to them are not yet audited because they cannot yet be changed |
| T58 | A control exercise damages production files | It acts only on test files in a folder carrying the customer's authorization marker, repairs them afterwards, and needs a staff role | **Built**; the marker is a file, so anyone who can write to a folder can authorize it. A console confirmation is **not built** |
| T59 | Exercise activity is counted as real protection | Device entries it produces are set aside; the report keeps "fired" and "exercised" apart | **Built** |
| T60 | An AI agent is manipulated by instructions hidden in content it reads (prompt injection) | Behavioural rule: after untrusted content, sensitive actions need a person and protected data leaving is blocked; no reliance on spotting injected text | **Built** for the rules; an injection that steers the agent to something the rules allow is **not stopped** |
| T61 | An agent goes around the gateway and calls a tool directly | Tools run only with a single-use grant the gateway signed for that exact call | **Built** in the reference build; with real tools the same property needs the tools or their credentials to sit behind the gateway, which is an integration task |
| T62 | An agent approves its own request, or an attacker approves it through the agent's identity | Only IT, analysts and the owner approve; an agent's own identity is refused; approval is for one digest, once, and expires | **Built** |
| T63 | The agent's identity can reach far more than its tools need, so a manipulated agent has a large blast radius | Effective permissions are computed from the identity; review is refused while it exceeds the tools' needs | **Built** for cloud roles and IdP users |
| T64 | Prompts or payloads are copied into the audit record | The record keeps digests, labels and counts; targets go to private fields; payload content is never stored | **Built**, with a test that card numbers are absent from the whole ledger |
| T65 | A shadow AI tool receives regulated data | Device rule blocks it offline; unknown AI domains are shadow | **Built** for the device hook contract; unmanaged browsers and devices are **not seen** |
| T66 | Vendor claims about training or retention are taken as fact | They are what the customer attests, shown as such; "unknown" stays unknown; enterprise tier needs the attested terms | **Built** |
| T67 | An intruder learns where decoys are and avoids them | The catalog is for IT and analysts only; refusals are recorded; decoys are placed by named admins | **Partly built**: no rotation; an intruder who has IT access sees the list |
| T68 | A tripwire causes an outage (a backup reads or rewrites it) | Reads never stop anything; backups can be exempted by name with a reason; audit-only mode alarms without blocking | **Built**; an unexempted program that rewrites a tripwire will be stopped |
| T69 | A decoy account becomes a real foothold | Decoys get no roles, groups or permissions, never reuse real names, and need an approver | **Built**; a decoy still exists in the directory, so tenant admins should know it is there |
| T70 | Tripwires create a false sense of safety | The doc and tests state that a tripwire reached last does not help and that canary silence is not proof | **Built** (stated and tested) |
| T71 | Company A reads or changes company B's data (shared database, shared code) | Tenant on every row and foreign key; context-bound queries; context handed out only to enrolled members; separate ledgers, seal keys, device-policy keys; objects under `t/<tenant>/`; whole-product scenarios run side by side in the tests | **Built** and tested against forged identities, guessed ids, traversal and pasted ledger lines; **not** penetration-tested |
| T72 | A service provider or parent company reaches a company it was not given | Only a delegation the company's own owner or IT admin opened (one grantee, role, scopes, region, expiry, revocable); parent-ness gives nothing; each use is in the company's Ledger | **Built** |
| T73 | Keeper crew exceed their remit or leak between companies | Charter, region, deployment profile, per-company just-in-time elevation, the authority matrix, redacted names, no raw telemetry; the company reads the activity from its own Ledger | **Built**; a rogue crew member with legitimate access to a company can still see what the charter shows |
| T74 | Halvard staff or a crew member in another country access data that must stay in a region | Residency check on staff, crew and provider access and on export; follow-the-sun is off unless the company allows it | **Built** as policy; no physical regional separation |
| T75 | The platform operator reads a company's data despite a customer-managed key | Objects sealed under a data key wrapped by the company's own master key; revoking it locks the company at the platform boundary | **Partly built**: reference cipher, objects only, database rows not encrypted at rest; an operator with database access defeats it |
| T76 | A forged or replayed offline update bundle | Signature, per-part hash, version newer than installed; whole or nothing; refusals recorded | **Built** with HMAC; asymmetric signing needed for production |
| T77 | A private deployment quietly phones home | Outbound calls in the platform go through a guard that refuses unless the customer listed the destination; refusals recorded | **Built** for the platform's calls; **no network-level control** |
| T78 | An unknown device is believed harmless because it is quiet | Discovery lists it with stated reasons, raises a finding at 0.6+, and a protected adopted device without an agent is a coverage gap | **Built**; a device that never emits ARP/DHCP or traffic is not seen |
| T79 | A segmentation change breaks a rare but legitimate flow | Advice waits 14 days, shows "would break N observed flows", prints the caveat, and is a request a person implements | **Built** |
| T80 | A sensor outage hides an attack | Buffering, counted loss, gap recorded, silent sensor is a coverage gap | **Built** |

## Assumptions and honest limits

- The user-space reference trusts the OS file hook to call it before and after each operation. A hook bypass (raw disk
  writes, a driver) defeats it; the native component must be a signed kernel-boundary filter with its own tamper protection.
- HMAC seals and signatures are symmetric in this build. Asymmetric signing and customer-managed keys (F117) are required for production.
- The detector is behavioral and tenant-tunable; it will have false negatives. They are to be published in the detection report (F129), which does not yet exist.
- A pen-test has not been done. One is required before the first major release, with remediation status published.
