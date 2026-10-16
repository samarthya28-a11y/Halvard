# Phase 7: Lumen (AI tools and AI agents) and Hearth (tripwires the customer places)

Evidence (generated from real runs): `docs/20-phase7-evidence.md`. Read its **Not demonstrated** section first.

## What Phase 7 adds

| Capability | Where | Features |
|---|---|---|
| Inventory of AI tools, approved and not, from proxy logs, sign-in grants and installed software | `lumen/inventory.py`, `policy/ai_tools_sample.json` | F103 |
| A rule for which data may go to which AI tool, enforced on the device with no connection | `vaultline/dlp.py` (channel `ai_prompt`), `ward/agent.py` | F104 |
| Inventory of AI agents: owner, identity, declared tools, and what the identity could actually reach | `lumen/agents.py` | F105 |
| A gateway that allows, asks or blocks each agent tool call by action and data type; real enforcement through single-use grants | `lumen/gateway.py` | F106 |
| An audit of every call sufficient to explain an incident afterwards, without keeping content | `lumen/gateway.py` (`explain`) | F107 |
| Suspend an agent (automatic where the matrix allows) and resume it | `relay/lumen_actions.py` | F106 |
| Decoy files, decoy accounts and keys, decoy shares, credentials bait | `hearth/service.py`, `hearth/fileserver.py`, `ward/agent.py` | F109 |
| Canary tokens for documents and repositories the customer chooses | `hearth/canary.py` | F110 |
| Encryption tripwires that stop a program on first touch, before real files are changed | `ward/agent.py` (`tripwire_gate`) | F111 |

## Lumen: AI tools (F103, F104)

A tool is **sanctioned** only when an IT admin or the owner says so, with a tier. The **enterprise** tier can only be given to a tool whose record shows an enterprise agreement and "does not train on inputs"; those facts are what the customer attests after reading the vendor's terms.
Halvard does not verify vendor claims, and "unknown" stays "unknown" in the rating. Everything found and not approved is **shadow**, listed first, with reasons (not approved, vendor terms unknown, volume, number of people).

Data rules ride in the signed policy bundle so they work offline. Defaults: regulated data to a shadow or standard tool is **blocked**; to the enterprise tool it needs a reason (one hour, that file, that door); confidential data to a shadow tool is blocked and to a standard tool needs a reason;
internal data to a shadow tool is allowed with a warning; **secrets are blocked everywhere and no reason unlocks them**. An AI domain the device has never been told about is treated as shadow. Content is read only if the customer's inspection gate allows it (purpose, notice, scope).
The sample catalog uses fictional names (`*.example-ai.test`); no real vendor is characterized.

## Lumen: AI agents (F105, F106, F107)

**Inventory.** Three ways onto the list: a person registers an agent (owner required, tools and actions declared), the gateway sees an unknown agent call a tool (listed, unreviewed, no tools, every call refused), or an identity the customer tagged as an agent's is found in the identity provider or cloud.
**Effective permissions** are computed from the identity's real access, not from what the agent says it needs. A **review** (IT admin only) is refused while the identity can reach more than its tools need or is an administrator; the refusal names what.

**Gateway.** Every call names agent, session, tool, action and target. Rules, strictest wins, and every rule that applied is listed to the person who is asked:
- not registered, suspended, undeclared tool or action, target outside the declared resources: **block**
- credentials or keys in the payload: **block** (an agent may not move them)
- regulated data going outside the company: **block**; confidential: **ask**
- the data type is unknown (inspection off) and something is leaving: **ask**. "Unknown" is never read as "clean"
- delete, run code, change access, spend: **ask** for a reviewed agent, **block** for an unreviewed one
- the session read **untrusted content** (a web page, an email) and is now asked for something sensitive: **ask**; with protected data leaving: **block**. This is the defence against instructions hidden in content, and it is a rule on behaviour, not a detector of injected text
- unreviewed agents' writes and sends: **ask**; a burst of calls (a loop): **ask**
- mail to a colleague is not leaving the company

**Enforcement is real.** In the reference build tools run only with a grant the gateway signed for that exact call (agent, tool, action, a digest of the arguments, 60 seconds, once). Calling a tool directly, reusing a grant, or changing the arguments is refused. An **ask** waits for IT, an analyst or the agent's owner;
the approval is for that call's digest, once, and expires after 15 minutes into a refusal. An agent cannot approve anything, including its own request.

**Record.** Per call: agent, session, step, tool, action, action class, decision, every rule that applied, data labels and counts, whether the data type was known, whether untrusted content had been read and from where, argument digest, approver role. Targets (paths, addresses) are in private audit fields and tokenized in auditor exports.
Payload content is never kept. `explain()` rebuilds the timeline in plain words, what was blocked, what left the company, which data classes, and says that digests identify exactly what was approved.

**Response.** A confident finding (tried to send regulated data out, tried to move credentials) suspends the agent under the accepted `ai_agent_suspend` pattern (standard class; reversible; production or privileged agents wait for an approver). The case records what was done.

## Hearth (F109, F110, F111)

Nothing here attacks anything. Everything is placed by a named IT admin in the customer's own environment, recorded, and reversible.

- **Encryption tripwires.** Generated filler files in folders the customer chooses. Ward checks every file operation **before** it happens; changing, renaming or deleting a tripwire by a program that is not exempt freezes the program on the spot (the same freeze, stop and journal rollback as the bulk-encryption detector) and refuses the operation, so no real file is changed first. Works offline.
  Reading an encryption tripwire is what indexers and backups do: it is logged as informational and stops nothing. Backup and search programs can be exempted by name, with a recorded reason.
  **Limit, stated and tested:** a tripwire the program reaches last does not help; Ward's own detector still stops that burst after 7 files. Place them where programs reach them first (names that sort early, top of each folder).
- **Decoy files and bait.** Opening a decoy file raises a finding (0.9) without freezing anything. A credentials-bait file contains a decoy account's name and password (or a decoy cloud key); using the account or key raises an alarm (0.95 / 0.97) from the first attempt, and the bait and the attempt are one case because they share a bait id.
- **Decoy accounts and keys.** They have no roles, groups or permissions (refused otherwise), never reuse a real name, and are excluded from cloud posture findings so they are not "fixed". Placement needs an approver.
- **Decoy shares.** Opening a file is 0.9, browsing is 0.5. Scanners and backups are exempted per account, with a reason, for at most 90 days.
- **Canary tokens.** A unique address in a document (a Word file whose package carries the address as an external image) or a repository file. **Limit shown with every token:** it fires only if the file is opened by software that loads remote content with network access; silence is not proof that nothing was read.
- **Tripwires that disappear or change** behind the file hook are noticed once per state.
- **The list of decoys is for IT and analysts only.** An intruder who knows where they are avoids them.
- Confidence is rule-assigned, not calibrated. An alarm with no known entity lands on a Hearth anchor and is never dropped.

## Authorization at a glance

| Operation | Who |
|---|---|
| Approve or withdraw an AI tool | IT admin, owner (enterprise tier needs the attested terms) |
| Register an agent | IT admin, analyst (owner required) |
| Review an agent | IT admin (refused while its identity can reach more than its tools need) |
| Approve or deny an agent's request | IT admin, analyst, the agent's owner; never an agent |
| Suspend an agent | analyst or IT admin request; automatic on confident findings; production needs an approver |
| Place tripwires, create decoys | IT admin request; IT admin approves (production, and all decoy identities) |
| Exempt a program or account, mint a canary | IT admin |
| See where decoys are | IT admin, analyst |

Refusals are recorded (`hearth.denied`).

## Not built

A real browser sensor or proxy that sees AI prompts (the device hook contract stands in); a real agent framework integration (an SDK or MCP gateway, the reference build's tools are models); semantic detection of injected text (the gateway reasons about behaviour only); model/prompt logging beyond digests;
agent identities beyond a cloud role and an IdP user; agent-to-agent calls; cost and rate budgets beyond the burst rule; the real canary callback service and DNS tokens; decoy rotation; Active Directory honey objects such as fake SPN accounts; decoy shares on real file servers;
isolated browsing (F108); campaign intelligence (F112); persistence of Lumen and Hearth state beyond the process; and every item in earlier "Not built" lists.
