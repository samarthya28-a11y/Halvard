# Phase 6: Glass (ranked exposure, temporary protections, patch rings, external surface, baselines, the board score)

Evidence (generated from real runs): `docs/18-phase6-evidence.md`. Read its **Not demonstrated** section first.

## What Phase 6 adds

| Capability | Where | Features |
|---|---|---|
| One ranked list of open weaknesses, vulnerabilities and misconfigurations together, with the working shown | `glass/exposure.py`, `glass/service.py` | F093 |
| A synthetic advisory feed with a stated exploit status (never guessed) | `glass/feed.py`, `policy/advisories_sample.json` | F093 |
| A temporary protection while a patch cannot land: closes a firewall rule in the cloud, or switches a program off on the device itself (works offline), with an expiry | `relay/glass_actions.py`, `glass/service.py`, `ward/agent.py` | F094 |
| Patch rings with a soak period, a health gate, automatic rollback where the matrix allows, and approvers for production | `glass/service.py`, `relay/actions.py` (device side), `relay/glass_actions.py` | F095 |
| The company's own internet-facing surface, probed only inside an ownership-verified scope | `glass/surface.py` | F096 |
| Expiry warnings for certificates and for time-boxed admin exposure | `glass/surface.py` | F097 |
| Configuration baselines and drift, with owned, reasoned, expiring exceptions | `glass/baseline.py` | F098 |
| One board score tied to the five outcomes, with its working, its caps and its blind spots | `glass/board.py` | F099 |
| Evidence that a control fired: real firings and exercised firings kept apart; a safe, authorized control exercise | `glass/evidence.py` | F100 |

## Ranking (F093): the rule is on the page

`ordering number = exploit x reach x asset value x severity`. Each factor is an **ordinal weight** chosen by Halvard (exploit: used in attacks 4, public exploit 2, none 1; reach: internet 3, inside the network 1.5, needs a foothold 1;
asset value: crown jewel 4, high 2.5, ordinary 1.5, low 1, then x1.5 for regulated or confidential data and x1.25 for production, clinical or privileged hosts; severity: advisory score / 10, or critical 1.0, high 0.8, medium 0.5, low 0.3).
The number **orders** the list. It is not a probability, not a loss estimate, and not comparable between companies; the page says so beside every item.

The **tier** (fix now / this fortnight / schedule) comes from plain rules on the same facts so a person can predict it: a flaw used in attacks that is internet-facing or on a crown jewel is *fix now*; any exploit, any internet reach, or a severe flaw on a crown jewel is *this fortnight*; everything else is *schedule*.
Deadlines are 2, 14 and 60 days (defaults; the customer may change them). The clock starts when Halvard first saw the item. A live temporary protection steps *fix now* down to *this fortnight* and nothing else.
The advisory feed in this build is **synthetic** (`HLV-SAMPLE-*`); no real vulnerability data is claimed.

Misconfigurations (Atlas posture, baseline drift, internet-side findings) and vulnerabilities share one list. A flaw seen both from inside (Ward's inventory) and from the internet is one item with both confirmations, not two.
A machine without an agent has no inventory, so it is **unassessed**, not "clean": its gap shows up as a coverage incident.

## Temporary protections (F094)

A protection is a real change, so it goes through the same action engine: roles, the authority matrix, previews, approvers, the ledger, undo. Kinds in this build: close a firewall rule (previewed with the instances affected) and switch a program off on a device (signed policy, enforced on the device with no connection).
Rules that keep it honest:
- at most 30 days; a reason is required; one protection per item
- **an expired protection stays in force.** Lifting a safeguard because a timer ran out is worse than leaving it. The item returns to the top of the list, the board score is capped, and a person must extend it, patch, or have the owner sign a risk acceptance
- extension: IT admin only, a reason, at most 14 days each, at most twice; after that only a risk acceptance remains
- risk acceptance: owner only, a reason, at most 90 days; it is shown on the list, not hidden from it
- warnings at 3 days and 1 day before expiry, recorded once each
- when the patch lands the protection is marked retired; taking it off is a change and goes through approval like putting it on
- a queued protection is not overwritten by a later policy push (a defect found and fixed this phase)

## Patch rings (F095)

Rings: pilot, early, broad, critical. Crown jewels and production, clinical or privileged hosts default to **critical** and cannot be placed in pilot or early. An update goes to one ring, soaks, is health-checked, then moves on.
The device does the update through a **signed command** and re-checks the approvals against its own copy of the matrix for its own asset class, so a careless control plane cannot push an update to a production host without an approver.
If the pilot breaks something, the rollout halts and later rings are never touched; the pilot rolls back automatically **only** where the matrix cell is auto/notify and the customer accepted the `patch_failure_rollback` pattern. On production, the rollback waits for an approver and the plan says so.
A ring cannot pass while a device in it is offline or has not actually installed. Health is a simulated signal in this build (see below).

## External surface (F096) and expiry (F097)

Halvard probes **only addresses the customer owns**: addresses in the customer's own cloud account, and addresses a person has **confirmed** after a domain proved ownership with a DNS challenge. Proving a domain only *nominates* the addresses it points to; a domain can point at a vendor's shared server, so each address is confirmed by an IT admin, with a note, before anything is sent to it.
Anything else is refused before a packet is sent, and the refusal is recorded (the address goes in a private audit field). The probe is a plain connection with a banner and certificate read. No exploit, no password guessing. Findings: remote administration or a database open to the internet, a server that answers for your domain but is not in your inventory, and a service version matched against the feed.
An admin exposure can be approved for up to 30 days; it goes quiet, warns three days before the end, and becomes a critical finding if it is still open after. Certificates warn at 30 days, then urgent at 7, then expired; each level is recorded once.

## Baselines (F098)

Default baseline for a device: disk encryption, host firewall, automatic updates, screen lock at 15 minutes or less. A value a device does not report is **unknown, never fine**. Exceptions are by a named admin, with a reason, at most 90 days, and come back on their own.
Drift is reported; remediation is not automated in this phase (the fix text is on the item).

## The board score (F099)

Five outcomes, each 0 to 100 from a stated formula, shown with its working:
1. **Shrink** (not measured until something has been assessed: a device inventory, a cloud posture run or an external scan): 100 minus deductions for items past their deadline (20 fix-now, 5 this-fortnight, 1 schedule) and 20 per expired protection.
2. **Stop**: protected machines that checked in on time x agents set to block rather than watch.
3. **Limit**: half devices able to take a containment command now, half containment controls seen working.
4. **Restore**: half devices keeping a file journal, half a restore seen working in 90 days. Backups are **not measured**.
5. **Prove**: half the Ledger verifying, half the share of controls seen working.

Overall = the mean of the **measured** outcomes (an outcome with nothing measured is left out, never given full marks; with fewer than 3 of 5 measured **no overall number is given** and the page says why), **capped at 59** while a fix-now item is past its deadline, a protection is past expiry, a crown-jewel machine has no working agent, or the Ledger does not verify.
The page answers the four board questions (covered, open, stopped, evidence) with the same numbers, ends with what is **not measured**, and each snapshot is recorded in the Ledger with the previous value so a trend is evidence, not memory.
Weights and thresholds are Halvard defaults, not derived from data and not a comparison with other companies. The score is arithmetic, not a forecast.

## Evidence that a control fired (F100)

Every control is listed with its outcome and one of: **fired** (the Ledger or a device record holds real entries within 90 days), **exercised** (a safe simulation proved it within 90 days), **stale**, or **never fired**. "Never fired" is not a failure; it means the control has not been seen working.
The exercise runs a ransomware-style burst of plain file overwrites and renames on test files inside a folder the customer marked as authorized, checks that Ward stopped it and the files came back, then releases any isolation Ward applied. The device entries it produces are set aside and **do not count as real firings**; the Ledger records the exercise itself, marked as a simulation.

## Authorization at a glance

| Operation | Who |
|---|---|
| See the ranked list | owner, IT admin, analyst |
| See the board | owner, IT admin, analyst, auditor (auditor sees aggregates; no raw employee content) |
| Apply a temporary protection | analyst or IT admin request; IT admin approves (production always; standard per matrix) |
| Extend a protection | IT admin |
| Accept a risk | owner |
| Baseline exception | IT admin |
| Patch rings, rollout | IT admin; approvals per the matrix |
| Declare / verify a domain, confirm or remove an address, approve a temporary exposure | IT admin |
| Scan the external surface | IT admin, analyst |
| Run a control exercise | IT admin, analyst |

Every refusal is recorded (`glass.denied`).

## Not built

Real vulnerability data (a feed import and its refresh); software inventory beyond name and version; an agent-side inventory collector for real operating systems (the reference host reports what a test sets); real health checks after an update (the reference
host reports defects a test sets); update download, signing and staging; maintenance windows applied to rollouts (the action engine has them; Glass does not yet schedule); automated baseline remediation; internet scanning of a real network (the "internet" is a reference model); cloud load balancers and DNS as discovered assets;
backup immutability and restore tests (F092) as inputs to the Restore score; framework mappings and the insurer packet (F101, F102); a trend view over time; persistence of Glass state (controls, plans, exceptions, risks) beyond the process; and every item in earlier "Not built" lists.
