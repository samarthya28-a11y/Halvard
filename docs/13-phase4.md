# Phase 4: Courier on one mail platform, clawback, and one story for mail, device and account

Evidence (generated from real runs): `docs/14-phase4-evidence.md`. Read its **Not demonstrated** section first.

## What Phase 4 adds

| Capability | Where | Features |
|---|---|---|
| Reference mail platform (mailboxes, rules, forwarding, delegates, quarantine, events) that Courier integrates with after delivery | `courier/mail.py` | contract for a Graph/Gmail-style API |
| Attachment analysis (static) and link analysis against an offline model of the web | `courier/analysis.py` | F063 (partial: no dynamic sandbox) |
| Impersonation and payment-fraud detection, including bank-account comparison against the supplier on file | `courier/impersonation.py` | F064 |
| Clawback to a recoverable quarantine, exposure report, separate gated purge | `relay/courier_actions.py` | F065 |
| Mailbox rules, forwarding and outside delegates, correlated with an already-flagged sign-in | `courier/service.py` | F066 |
| SPF, DKIM, DMARC posture and spoofing attempts against the company's domain | `courier/auth.py` | F069 |
| Practice exercises built from real incidents, safe and private | `courier/exercises.py` | F068 |
| Service-desk quarantine-release path with reason, audit and analyst escalation for harmful mail | `ReleaseMessage` | F070 |
| Mail, device and account findings in one case, one campaign in one case | `cases.py`, `controlplane.py` | F021, F030 |
| File fingerprint and process lineage in telemetry, so a mail verdict can find the devices a file landed on | `ward/agent.py`, `hunt/` | F019 (partial), F024 |
| Block list pushed to devices (offline-capable) when an attachment is judged harmful | `controlplane.push_ioc`, `relay/fleet.py` | F006, F024 |

## How Courier works, and what it cannot do

Courier works **after delivery** through the mail platform's API. Mail routing is unchanged, so mail still flows if Halvard is down, and there is
always a gap between delivery and verdict. The gap is measured (`exposure_s` on delayed verdicts) and reported, not assumed away.
It does **not** block mail inline; a customer who wants pre-delivery blocking keeps their existing gateway.

Two separate paths pull the cord:
1. **Clawback** (needs the `mail_clawback` pattern, runs under the matrix): every copy of a message judged harmful (at confidence ≥ 0.9, including forwards) moves to a recoverable quarantine.
   The result lists who had already opened the attachment, clicked, replied or forwarded; moving a message does not undo that. Hard deletion is a different, approval-gated action (`purge_message`), refused under legal hold.
2. **Case containment** (the `malicious_mail_containment` or `identity_takeover_containment` pattern): when the harmful message and Ward's evidence about a device (or Signet's about an account) belong to the same case with enough confidence,
   one containment pulls the mail, quarantines the saved file on the device, marks the device unhealthy, isolates it, removes mailbox rules and forwarding the case found, and tells the manager.
   Passwords are reset **only** when there is evidence of account takeover or a credential trap; for malware the case instead asks a human whether to reset them after the device is clean.

## Verdicts: honest scope

* **Attachments**: static analysis only (type by content, macros and downloader strings inside the container, encrypted archives, double extensions, runnable file types, HTML smuggling, known-bad hashes and the standard test string). **Nothing is executed.**
  The verdict says `evidence: static` or `reputation`. A real dynamic sandbox plugs into the same seam; until then F063's "detonation" is not met, and a document that is clean to static analysis passes (the acceptance case relies on this and is caught later by intelligence and by the endpoint).
* **Links**: judged by address tricks (look-alikes, raw IPs, look-alike characters, mismatched text) and by following redirects in an **offline model of the web** and reading the final page. No real network access, no real fetching.
* **Impersonation**: header and wording facts plus comparison of bank accounts by hash. No language model. Confidence values are rule-assigned and each finding says why. No detection or false-positive rate is claimed.

## Privacy

Message bodies and subjects stay in the customer's mail system. Courier reads them in memory to analyse and stores only: ids, hashes, the sender address and domain, link hosts, the verdict and its reasons.
Reasons name an attachment by hash prefix, not file name, and do not name employees. The audit record uses opaque ids for mailboxes and accounts, keeps addresses in tokenized private fields, and a write-time scrub removes any address that reaches a public field.
The service-desk view shows sender, time, reasons and the first 40 characters of the subject so a person can recognise the message; Halvard does not write that text anywhere.
Practice exercises use no live link, attachment or real sender, and department results appear only when at least five people have answered; individuals see their own result.

## Not built

A dynamic sandbox and a real isolated link fetcher; inline (pre-delivery) filtering; a real Microsoft 365 or Google Workspace connector and its credentials; mail-flow rules in a real tenant; file-sharing and third-party app monitoring in collaboration suites (F067);
Teams/Slack; per-recipient behavior baselines; a polling scheduler; and everything in earlier "Not built" lists.
