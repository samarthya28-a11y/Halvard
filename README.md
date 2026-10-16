<p align="center"><img src="assets/logo/halvard-logo.svg" alt="Halvard: Corporate Assurance Fabric" width="560"></p>

# Halvard: Corporate Assurance Fabric (reference build, Phases 1 to 8)

Read in this order: `docs/01-narrative.md` → `02-assurance-graph.md` → `03-authority-matrix.md` → `04-threat-model.md` →
`05-phase1-test-plan.md` → `06-module-map.md` → `07-phase1-evidence.md` → `08-phase2.md` → `09-phase2-evidence.md` → `10-phase3.md` → `11-phase3-evidence.md` → `13-phase4.md` → `14-phase4-evidence.md` → `15-phase5.md` → `16-phase5-evidence.md` → `17-phase6.md` → `18-phase6-evidence.md` → `19-phase7.md` → `20-phase7-evidence.md` → `21-phase8.md` → `22-phase8-evidence.md`.

**For an independent reviewer or for step-by-step testing, start with `docs/12-crosscheck-guide.md`.**

## Run it

```
python3 -W ignore -m unittest discover -s tests      # all tests (~25 s, includes the performance gate)
python3 tools/mutation_check.py                      # remove each behavior, require a named test to fail
python3 tools/run_acceptance.py                      # regenerate docs/07-phase1-evidence.md from real runs
python3 tools/run_acceptance_p2.py                   # regenerate docs/09-phase2-evidence.md (Linux lane needs root + fanotify)
python3 tools/run_acceptance_p3.py                   # regenerate docs/11-phase3-evidence.md
PYTHONPATH=src python3 -m halvard.cli stolen-session # Phase 3 story: stolen session, containment, what still works
python3 tools/run_acceptance_p4.py                   # regenerate docs/14-phase4-evidence.md
python3 tools/run_acceptance_p5.py                   # regenerate docs/16-phase5-evidence.md
PYTHONPATH=src python3 -m halvard.cli exposed-bucket # Phase 5 story: public bucket with card data, closed again
PYTHONPATH=src python3 -m halvard.cli data-leak      # Phase 5 story: card data blocked on USB and email, offline
PYTHONPATH=src python3 -m halvard.cli patch-day      # Phase 6 story: ranked exposure, temporary protections, patch rings, board page
python3 tools/run_acceptance_p6.py                   # regenerate docs/18-phase6-evidence.md
PYTHONPATH=src python3 -m halvard.cli ai-agent       # Phase 7 story: AI inventory, an agent manipulated by a web page, suspended, explained
PYTHONPATH=src python3 -m halvard.cli tripwires      # Phase 7 story: ransomware stopped on first touch; bait, decoy account and laptop in one case
python3 tools/run_acceptance_p7.py                   # regenerate docs/20-phase7-evidence.md
PYTHONPATH=src python3 -m halvard.cli platform       # Phase 8 story: four companies, the wall, Keeper, residency, customer keys, private deployment
PYTHONPATH=src python3 -m halvard.cli rogue-device   # Phase 8 story: unknown device, east-west, segmentation advice, sensor outage
python3 tools/run_acceptance_p8.py                   # regenerate docs/22-phase8-evidence.md
PYTHONPATH=src python3 -m halvard.cli mailed-attachment # Phase 4 story: mail, laptop and account as one case
PYTHONPATH=src python3 -m halvard.cli demo           # offline ransomware simulation + plain-language incident page
PYTHONPATH=src python3 -m halvard.cli setup          # the day-one guide
PYTHONPATH=src python3 tools/gen_matrix.py           # regenerate policy/authority_matrix.json + docs/03 from matrix_def.py
```

Python 3.11+ standard library only.

## Layout

| Path | What |
|---|---|
| `src/halvard/ward/` | agent, file-hook contract (`ProtectedFS`), behavioral detector, verdicts, signed policy, tamper guard, safe simulator, incident page |
| `src/halvard/relay/` | authority engine, action engine (preview, approval, audit, undo), file journal, host adapter, isolation rule renderers, recovery note |
| `src/halvard/ledger/` | hash-chained sealed audit log, device spool ingest, auditor export |
| `src/halvard/tenancy.py`, `graph/schema.sql` | tenant-scoped store and the assurance graph |
| `src/halvard/platforms/` | per-OS profiles; `linux.py` is a real fanotify sensor (privileged lane) |
| `src/halvard/hunt/`, `detect/` | telemetry store, HQL, hunt service; detection library, content packs, false-positive learning |
| `src/halvard/signet/`, `cases.py`, `controlplane.py` | reference IdP and AD, identity detections, posture, notifier; cases; control-plane wiring |
| `src/halvard/relay/signet_actions.py`, `commands.py`, `fleet.py` | Signet actions, cross-domain containment, signed device commands |
| `src/halvard/courier/`, `relay/courier_actions.py` | reference mail platform, analysis, impersonation, DMARC, exercises, clawback and release actions |
| `src/halvard/atlas/`, `vaultline/`, `relay/atlas_actions.py` | reference AWS account, posture, SaaS discovery; classifiers, consent gate, data-handling rules |
| `src/halvard/coverage.py`, `setup/guide.py`, `perf.py` | coverage incidents, day-one guide, performance gate |
| `policy/` | generated authority matrix, published performance budget |

## Honest status

Phases 1 to 5 are a **reference implementation of the decision, journal, action and evidence logic**, proven on Linux through a file-hook
contract. It is not a shippable endpoint product: there is no kernel/Endpoint Security component, installer, updater, console,
cloud control plane, asymmetric signing or key management yet. See "Not demonstrated" in `docs/07-phase1-evidence.md`.
Safe simulations only run inside a directory the customer marks as authorized.

## Running it on your own machine

Needs Python 3.11 or newer and nothing else (standard library only).

```
git clone https://github.com/samarthya28-a11y/halvard && cd halvard
python3 -W ignore -m unittest discover -s tests          # the full suite
PYTHONPATH=src python3 -m halvard.cli platform            # any story from the list above
```

The same commands work in a cloud session on this repository. Keep both in step with `git pull` / `git push`.
On a machine that is not Linux, or when not root, the Linux file-sensor tests and the performance-budget test are skipped, so fewer tests run; that is expected.

### Windows (PowerShell)

```
git clone https://github.com/samarthya28-a11y/Halvard
cd Halvard
py -W ignore -m unittest discover -s tests
$env:PYTHONPATH="src"; py -m halvard.cli platform
```

Tests and demos create their working files under `.test-tmp` (tests) or `~\halvard-work` (demos), not under `AppData\Local\Temp`, because Halvard's Windows profile deliberately does not journal AppData caches and temp files.
If your antivirus removes a file during a run, tell me which: the tests use a harmless marker instead of the EICAR file for exactly that reason.
