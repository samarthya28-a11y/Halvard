# Module map: a 40-person company vs. a bank

One codebase. Modules switch on per tenant; deployment shape and operator are tenant settings. "Phase" is when the module exists in this repository.
The public pricing unit is **protected people and workloads** (F123); the module list below is the public module map.

| Module | What it answers | 40-person company (one IT generalist, Keeper on) | 5,000-person bank (security team) | Phase |
|---|---|---|---|---|
| **Ward** | Protect and stop on devices/workloads | On, all devices; enforce from day one; defaults | On, staged by ring; app control audit→enforce on servers; custom detections; kernel/driver rules strict | 1 / 2 |
| **Relay** | Contain, clean, restore | On; auto for standard laptops; approval for the two servers | On; automation limited to accepted patterns; clinical-style two-person on trading and core-banking hosts; break-glass | 1 |
| **Ledger** | Prove it | On; monthly board page; insurer packet | On; framework evidence for PCI DSS/SOC 2/ISO 27001/NIS2; auditor role; customer-managed keys; export to GRC | 1 (audit) |
| **Signet** | Identity and access paths | On with the one IdP; revoke/disable; standing-privilege tips | On; AD + cloud IdP; JIT, service-account inventory, access-path to crown jewels, joiner/mover/leaver checks | 3 (built against reference models; real connectors not yet) |
| **Courier** | Email and collaboration | On for the one mail platform; clawback | On; impersonation/payment-fraud tuning; DMARC monitoring; service-desk quarantine release | 4 (reference platform; static analysis only; real connector not yet) |
| **Atlas** | Cloud and SaaS | On if they have a cloud account (posture only) | On; AWS+Azure+GCP posture and workload; unsanctioned SaaS | 5 (AWS-shaped reference model only) |
| **Vaultline** | Data and leakage | Off (labels need a data owner) | On; classification, USB/email/upload/print controls, insider-risk with notice | 5 (insider-risk not built) |
| **Glass** | Exposure and patch reality | On, ranked list + board score | On; patch rings, compensating controls, external attack surface, baselines | 6 (reference models and a synthetic advisory feed; real feed, collector and network scan not built) |
| **Lumen** | AI tools and agents | On, inventory only | On; per-agent allow/ask/block, data-type policy | 7 (reference tools and gateway; no real agent SDK or browser sensor) |
| **Hearth** | Customer-owned tripwires | On: a handful of canary files (encryption tripwires) | On; decoy accounts, shares, repo canaries | 7 (reference file server and canary callback) |
| **Harbor** | Network and site | Off, or firewall ingest only | On; sensor, rogue-device discovery, VPN anomalies, site zones (branches) | 8 (sensor is a contract and reference model; VPN anomalies and OT not built) |
| **Keeper** | 24/7 crew inside the customer's authority | On; matrix cells `within_auto` only; everything else proposes to the generalist | Off (own SOC), or on for out-of-hours only | 8 (charter, region, just-in-time access, matrix; no rota or console) |

| Setting | 40-person company | Bank |
|---|---|---|
| Deployment | Halvard Cloud, nearest region | Private cluster or customer cloud account; residency fixed; customer-managed keys |
| Operator | Keeper | Customer SOC |
| Roles in use | owner, it_admin, service_desk (often the same person: still separate role grants, no shared superuser) | all templates + auditor + site_manager for branches |
| Authority matrix | Shipped defaults | Tightened cells (e.g. isolate on production = two_person) within floors |
| Retention (hot/cold) | Defaults | Per regulation; legal hold used |
| Day one | Guided setup reaches F004, F006, F016, F037, F040 | Pilot ring first, then rings by site |

Not in this table because they are not separate products: hospital group (clinical asset class on, site zones, two-person on clinical systems), university (many unmanaged devices → Harbor discovery, lighter rings), manufacturer (OT gateway, plant-manager role, site zones), holding company / provider (multi-tenant parent with delegated grants and hard walls).
