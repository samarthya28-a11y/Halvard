# Phase 8: Harbor (network and site), the multi-tenant platform, Keeper across companies, private deployment and residency

Evidence (generated from real runs): `docs/22-phase8-evidence.md`. Read its **Not demonstrated** section first.

## What Phase 8 adds

| Capability | Where | Features |
|---|---|---|
| Network sensor contract: metadata only, store-and-forward, counted loss | `harbor/sensor.py` | F071 |
| Discovery of unknown devices on a site, with reasons; adopt, expect (with expiry), or leave open | `harbor/service.py` | F072 |
| East-west detections: administration fan-out, flows across a zone the policy does not allow | `harbor/service.py` | F071 |
| Segmentation advice as a change request filed in the customer's own tool; never applied | `harbor/service.py`, `relay/harbor_actions.py` | F076 |
| Many companies on one deployment with hard walls; service-provider and parent-company access only by the company's own grant | `fabric/platform.py`, `fabric/delegation.py`, `tenancy.py` | F116 |
| Keeper as one desk for many companies, each bound by a written charter, region, just-in-time access and the authority matrix | `fabric/keeper.py` | F120 |
| Regional residency; customer-managed keys that can lock a company's data at once | `fabric/residency.py`, `fabric/crypto.py` | F117 |
| Deployment profiles (cloud, customer cloud, private, disconnected), an outbound-call guard, a dependency report, and a signed offline update bundle | `fabric/deployment.py`, `fabric/platform.py` | F118 |

## Harbor

**What the sensor sends.** Flow metadata (source and destination address, destination port, protocol, bytes, the zones) and address-resolution or DHCP sightings (hardware address, address, host name, vendor class, VLAN). No payloads, no URLs. A test asserts the exact set of fields.
**When the link is down.** The site sensor buffers (bounded) and forwards when the link returns. If the buffer overflowed, the loss is **counted and recorded as a gap** and never hidden. A site whose sensor has gone quiet is a coverage gap, not a quiet network.

**Unknown devices.** A hardware address is *known* if a Ward agent reported it as its own, if IT adopted it, if a graph record carries it, or if IT said to expect it (a printer, a camera) with a reason and an expiry (one year at most). Everything else is *unknown*, with a confidence that is the sum of stated reasons: no record (0.4), seen in the last 24 hours (+0.1),
on a sensitive network (servers, OT, finance, clinical: +0.2), talked to a crown-jewel system (+0.2); capped at 0.9. Below 0.6 it is listed but raises no finding (a phone on guest wifi is not an incident). A general-purpose computer with no agent is called out as one that should have one.
Halvard **never blocks a device by itself**. IT adopts it (it becomes a graph entity; if it should be protected and has no agent it appears as a coverage gap), expects it (expires), or files a change request.

**East-west.** One machine contacting administration ports (SSH, SMB, RDP, WinRM) on 15 or more different hosts within five minutes is flagged once (0.6; backup and patch servers do this legitimately and can be exempted). A flow between zones that the site's policy does not allow is flagged once per zone pair and port (0.5).

**Segmentation advice.** After at least 14 days of observation, rules that allowed flows nobody used are proposed for removal, and wildcard rules for narrowing to the ports actually seen, each with "would break N observed flows". The caveat is printed: rare but legitimate flows (quarter-end, disaster recovery) may not appear in a short window.
Before 14 days the answer is "not enough observation", and nothing is proposed. The change request is filed in the customer's own network tool after an approver agrees; **Halvard changes no firewall or switch**. Withdrawal is one undo.

## The platform: hard walls (F116)

From the bottom up:
1. **One shared tenant database in which every row and every foreign key carries the tenant id.** The schema refuses an edge between companies. Two companies in the tests both have `srv-fin`, `LT-1` and a person each; neither can see or change the other's.
2. **Every query binds the tenant from a context** that the platform hands out only to that company's own enrolled people. A forged member (an invented identity, or another company's real admin claimed against this one) is refused, and the refusal is recorded in the *target* company's Ledger.
3. **Object storage resolves under `t/<tenant>/`** and refuses anything that escapes (`../`, absolute paths).
4. **Separate Ledger, seal key and device-policy key per company**, derived from a platform secret no company sees. A record from one Ledger pasted into another fails verification; a policy bundle signed for one company is rejected by another's devices.
5. **Outsiders get in only by a delegation the company opened**: one grantee, one role, a set of scopes (summary, cases, act), a region, an expiry (30 days; Keeper charters up to a year), revocable at once. Every use is recorded in that company's Ledger with the grantee's identity.
   A **parent company sees nothing of a subsidiary** unless the subsidiary grants it a summary. A summary is headline numbers only: score, band, per-outcome numbers, how many items are open. No titles, names or paths.
6. **Support staff** reach a company only through a time-boxed support grant that the company opens, only from an allowed region, and only if the deployment accepts remote staff.

## Keeper across companies (F120)

One desk, many companies. For each company the crew is bound by, in this order: assignment; the company's standing grant and **charter** (its written list of actions, which cannot include anything the matrix forbids to Keeper); the crew member's region against the company's residency; the deployment profile; a **just-in-time elevation for that company** (two hours at most, a reason, recorded);
the charter's mode (always, or out of the company's business hours only); and then the **authority matrix**: Keeper may act alone only where the cell is auto or notify, may only *propose* where the matrix says so (a customer approver runs it; a crew member cannot approve), and never where the matrix says never.
Elevation in one company does nothing in another. Crew see case summaries with **people's names replaced by stable pseudonyms** unless the charter says otherwise; raw telemetry and hunting are not part of the desk. The company reads what Keeper did from its own Ledger (viewed, elevated, acted, refused). Revoking the grant stops the crew at once.

## Residency and customer-managed keys (F117)

A company has a home region and a set of regions its data may be stored in or exported to. **Staff, crew and provider access from another region is refused** unless the company explicitly allows that region (follow-the-sun support is off by default). An export to another region is refused and recorded.
Where the company chooses its own key: each company's objects are sealed under a data key that exists only wrapped by the company's master key in the company's own key service. **Revoking the master key locks the company at once** (objects unreadable, the company's own staff and every outsider refused at the platform boundary, the state change recorded); restoring it unlocks; destroying it is final.
Other companies are untouched. **Reference limitation, stated plainly:** the cipher is encrypt-then-MAC with an HMAC-SHA256 keystream because the standard library has no AES. It shows the key hierarchy, revocation and tamper detection; it is not production cryptography. The reference database rows are not encrypted at rest (production uses database encryption under the same key hierarchy); the lock is enforced at the platform boundary and on objects.

## Deployment profiles (F118)

| Profile | Remote Halvard staff | Keeper | Outbound calls | Updates |
|---|---|---|---|---|
| cloud / customer cloud | with a company grant | with a charter | allowed | online |
| private | refused | refused | only to destinations the customer listed | signed bundle or an internal mirror |
| disconnected | refused | refused | none | signed bundle carried in |

`dependency_report()` lists every outside service a module would use and what it does instead. Device prevention never needed the platform. The **signed offline bundle** (advisories, AI tool catalog, known-bad hashes) is verified before anything is applied: signature, every part's hash, and a version newer than the one installed; it applies whole or not at all, and every refusal is recorded.
Bundles are signed with HMAC here; production uses an asymmetric vendor signature.

## Authorization at a glance

| Operation | Who |
|---|---|
| Register a site, adopt or expect a device | IT admin |
| See unknown devices; ask for advice | IT admin, analyst (advice: IT admin, analyst) |
| File a segmentation change request | IT admin or analyst request; IT admin approves |
| Open, revoke or widen access to a company | that company's owner or IT admin (a forged identity is refused) |
| Set Keeper's charter | that company's owner or IT admin |
| Read Keeper's activity report | that company's owner, IT admin, auditor |
| Open a support grant | that company's owner or IT admin; refused by profile or region |

## Not built

Packet capture or a real sensor (the contract and the reference are what exist); OT/industrial gateways and protocol parsing; automatic enforcement of segmentation (Halvard only files requests); device fingerprinting beyond DHCP vendor class and zone; wireless controllers; asymmetric signing of bundles and policy (HMAC here);
real AES, a hardware-backed key service, and database-at-rest encryption under the customer key; a real identity provider for the company's own staff (members are enrolled records); a console; per-region physical storage (regions are policy and labels here, not separate infrastructure);
backup and replication across regions (the policy function exists and is tested; nothing replicates); a network-level egress firewall for private deployments (the guard is in the platform's calls); Keeper rotas, shift handover and customer-visible SLAs; and every item in earlier "Not built" lists.
