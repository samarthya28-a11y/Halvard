# Phase 5: Atlas (cloud posture and workloads for one cloud) and Vaultline (classification, USB and email controls)

Evidence (generated from real runs): `docs/16-phase5-evidence.md`. Read its **Not demonstrated** section first.

## What Phase 5 adds

| Capability | Where | Features |
|---|---|---|
| Reference AWS account that enforces what decides exposure (public-access block, ACL, policy, firewall rules, keys, roles) and logs changes | `atlas/aws.py` | contract for a real connector |
| Posture checks with context-raised severity, evidence and a fix Relay can run; internet-to-data paths | `atlas/posture.py` | F079 |
| Change detections: bucket opened, admin port opened, foreign key, admin rights | `atlas/service.py` | F079, F085 |
| Automatic revert of an exposure, recoverable, gated by asset class | `controlplane.auto_revert_exposure`, `relay/atlas_actions.py` | F079, F085 |
| Cloud workloads under the same agent, policy bundle and coverage monitor as laptops; policy drift | `atlas/service.py`, `coverage.py` | F002, F080, F121 |
| SaaS discovery and a short risk rubric | `atlas/saas.py` | F081, F082 |
| Content classifiers that validate (not just match) and never keep values | `vaultline/classifiers.py` | F083 |
| An opt-in, scoped, purposed, noticed gate in front of all content inspection | `vaultline/inspection.py` | section 6 of the brief |
| Data-handling rules for USB, print, upload, outside email, public sharing, enforced on the device offline | `vaultline/dlp.py`, `ward/agent.py` | F014, F084 |
| Outbound mail held before it leaves; sender's reason or a second person's release | `vaultline/service.py`, `courier/mail.py` | F084 |
| Disk and removable-media encryption status feeding device health | `ward/agent.py`, `signet/service.py` | F015 (status and health; not enforcement of encryption itself) |
| Sensitive-and-exposed join; weakly protected sensitive stores | `vaultline/service.py` | F085 |

## The data-protection gate

Looking inside files and messages is the most invasive thing this product does, so nothing reads content until all of these are true:
**inspection is on; a purpose is stated; a staff notice has been issued and has taken effect; the location is inside the stated scope; it is not an excluded personal location.**
The reasons are shown in plain words when something is missing, and each refusal is recorded. Device decisions that do not need content (an unapproved drive is read-only) work with inspection off.

What is stored: labels and counts per file, a hash of the path, a sensitivity. What is never stored: matched values, snippets, document text. File and object names are written only to private audit fields (tokenized in auditor exports).
A scan sets Halvard's **suggestion** beside the entity; it never replaces a value a person set, and a person's value wins wherever both exist.

## Classification: validated, not guessed

Card numbers need a Luhn pass, a real prefix and length; IBANs pass mod-97; Aadhaar numbers pass the Verhoeff check; US SSNs exclude never-issued ranges; secrets need randomness. That is why a sheet of order numbers is not "regulated data".
Counts and a plain reason accompany every label; confidence is rule-assigned. Office files (docx/xlsx/pptx), text, CSV, JSON and XML are read. **PDF, legacy Office and other binaries are reported as unreadable, not guessed.** Customer-defined patterns are supported.

## Controls: what happens at each door

Rules live in the signed policy bundle, so they apply with no connection. Actions run allow, warn, justify, block; the strictest matching rule wins.
Defaults: regulated data to an unapproved or unencrypted drive is blocked; to an approved encrypted drive it is allowed and recorded; confidential data to a plain drive needs a reason; regulated data to a stranger by email is held; to a partner needs a reason; uploads to unapproved or personal services are blocked or need a reason;
secrets cannot leave any way and **no reason unlocks them**. A reason is 10 to 200 characters, kept in a private audit field, and unlocks only that file, that door and that kind of destination, for an hour. A held message that cannot be justified needs another person (`release_outbound_message`).

## Posture and exposure: what the checks are

They are Halvard's own checks, informed by common benchmark themes. **No claim is made of conformance to CIS or any other benchmark.** Severity is raised by context (internet reachable, regulated data, administrator role) and the reason is written beside it. Ordering is severity, then exposure; no invented risk number.

## Automatic response to an exposure

When a bucket is opened to the internet, Atlas sees it on the next cycle, Vaultline's earlier scan says whether it holds regulated data, and (with the `cloud_exposure_revert` pattern accepted) the public-access block is put back: recoverable, with a preview and the undo path.
On **production** resources the matrix asks one approver first, and the case says the data is still exposed until someone approves. That delay is a deliberate cost of not auto-changing production; the customer can tighten but not loosen it. A deliberately public website bucket is warned about in the preview.

## Not built

A real AWS, Azure or Google connector, its credentials and rate limits (T41); Azure and Google Cloud; Kubernetes and container image scanning (F003, F089); infrastructure-as-code checks (F090); secrets in repositories (F088); backup immutability (F092);
a browser sensor (uploads are decided by the device hook contract, not intercepted in a browser); print spooler and Bluetooth/peripheral hooks beyond USB mass storage; encryption **enforcement** (only status and health); PDF text extraction;
insider-risk scoring (F086) and legal-hold-aware cloud actions; a polling scheduler; and every item in earlier "Not built" lists.
