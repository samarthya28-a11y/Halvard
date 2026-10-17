# 24. Name, strategy and market (v0.8.1, 2026-10-17)

Status: recommendations for the owner to decide. Competitor prices come from vendor-adjacent blogs that disagree; get real quotes.

## 1. What "Halvard" means
Old Norse *Hallvarðr*: *hallr* (rock) + *varðr* (guardian): "the rock guardian". It fits a product whose promise is to hold the line and then prove it.

## 2. Proposed backronym (matches the modules)
| Letter | Word | Halvard module |
|---|---|---|
| H | Hosts and endpoints | Ward |
| A | Accounts and identity | Signet |
| L | Leaks (data loss) | Vaultline, Atlas |
| V | Vulnerabilities and exposure | Glass |
| A | AI agents and tools | Lumen |
| R | Response and recovery | Relay, Ledger |
| D | Deception and detection | Hearth, Hunt, Harbor |

**Halvard: Hosts, Accounts, Leaks, Vulnerabilities, AI, Response, Deception.** Tagline: "Hold the line." Existing descriptor "Corporate Assurance Fabric" stays.

## 3. Deployment strategy
- **Cloud (SaaS), default**: multi-tenant (Harbor already isolates tenants), regional data residency, fastest to ship, recurring revenue.
- **Private / on-premise**: single-tenant, no outbound calls, signed update bundles (already modelled in Phase 8). Target banks, health, government, defence.
- **Hybrid**: on-device Ward works offline; control plane in cloud or on-prem. This is the real differentiator: prevention without internet.
- Order of work: (1) real endpoint agent for Windows (current build is reference only; this is the biggest gap), (2) Linux, (3) macOS, (4) hosted control plane, (5) installable on-prem bundle (container or appliance image).

## 4. Licensing strategy
- Software licence for the product: proprietary, per-endpoint subscription. Keep the core closed; consider an open-source detection-rule pack and agent-protocol spec for credibility.
- Per-module SKUs plus bundles, annual terms, true-up each quarter.
- On-prem: annual subscription (not perpetual), offline licence file bound to tenant, signed, expiry-enforced.
- Before selling: choose a legal entity, trademark check on "Halvard" (the name is also a common personal name and used by other firms), third-party licence audit (stdlib only today, so clean), and independent security review.

## 5. Recommended commercials (starting hypotheses, validate with 10 prospects)
| Tier | Who | Model | Indicative price |
|---|---|---|---|
| Core (Ward + Relay + Ledger) | SMB, 25-500 seats | per endpoint / month | $4-6 |
| Complete (+ Signet, Courier, Glass) | mid-market | per endpoint / month | $9-13 |
| Assurance (+ Vaultline, Lumen, Hearth, Harbor) | regulated, enterprise | per endpoint + platform fee | $15-22 + annual platform fee |
| Private deployment | regulated | annual minimum | 30-50% uplift, minimum annual contract |
| Add-ons | | AI agents protected, cloud accounts, retention, 24x7 service | priced per unit |

Market anchors: CrowdStrike about $8-18, SentinelOne about $6-12, Defender bundled free with Microsoft 365 E5. Price below the premium players on "Core", and win on bundled breadth plus evidence. Channel: sell through MSPs/MSSPs (multi-tenant is ready) with 20-30% margin.

## 6. Competitor research and where Halvard can stay ahead
Findings: CrowdStrike leads on threat intel and hunting; SentinelOne on autonomous response and offline AI with rollback; Defender wins on bundling. 2026 trends: governing AI agents at runtime, exposure management, non-human identity, resilience/recovery, autonomous SOC.

| Opportunity | Why it matters | Halvard status |
|---|---|---|
| Agent runtime gateway (Lumen) | Hot 2026 category, few complete products | Built (reference). Strongest differentiator; extend to MCP protocol security |
| Offline prevention plus byte-exact rollback | Matches SentinelOne's best feature | Built (reference); needs native Windows agent |
| Evidence-first ("prove each control works", Ledger, auditor export with no personal data) | Compliance buyers; competitors report, few prove | Built; market this hard |
| Tripwires with one case across file, account, laptop | Low-noise detection | Built |
| Honest limits stated in every report | Trust | Built |
| Non-human identity (service accounts, API keys, agent identities) | Machine identities outnumber people ~100:1 per vendor claims | Partial: add inventory and rotation actions |
| Autonomous SOC copilot with human approval gates | Industry direction | Gap: Relay's approval model is the safe base |
| Managed 24x7 service (MDR) | Needed to win SMB | Gap |
| Third-party certifications (SOC 2, ISO 27001, independent test e.g. MITRE) | Procurement gate | Gap |

**Recommended next steps (your decision):** (a) native Windows agent, (b) non-human identity module, (c) SOC 2 readiness plus an independent penetration test, (d) pick the first segment: regulated mid-market with private deployment is the best fit for the current design, MSP channel second.

Sources: [redresscompliance comparison](https://redresscompliance.com/crowdstrike-vs-sentinelone-vs-defender-comparison.html), [CSO Online Black Hat 2026](https://www.csoonline.com/article/4204921/the-top-cybersecurity-product-announcements-from-black-hat-2026.html), [Help Net Security March 2026](https://www.helpnetsecurity.com/2026/04/03/new-infosec-products-of-the-month-march-2026/).
