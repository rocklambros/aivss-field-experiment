# AIVSS Field Experiment

Version 1.1. Owner: Rock Lambros. License: Apache 2.0 (see LICENSE and NOTICE).

This repository tests the OWASP Agentic AI Vulnerability Scoring System (AIVSS 1.0) on 48 documented attack paths in three deliberately vulnerable AI agent applications. It holds the briefings, every raw assessor response, the analysis code, and an executed notebook that reproduces every number and figure without calling a model.

AIVSS starts from a CVSS v4.0 score and adds five questions about the agent: how attacker language reaches it, whether poisoned context persists, whether compromise crosses into other agents, whether the agent games its own evaluator, and how loosely its tools are bound. The answers place the agent in a class, and a lookup table turns the CVSS score and the class into the AIVSS score. The experiment asks whether that score changes how urgent agent findings look, whether independent assessors reproduce it, and whether it carries information that CVSS does not.

## Start Here

Open `AIVSS-field-experiment-RockLambros-v1.1.ipynb`. It is saved with its outputs, so it reads without running. Its sections follow the ten registered hypotheses (H1 to H10), then the FinBot case study and the figures. Each section opens with a plain description of the test and states the verdict rule.

Headline results from the notebook:

- 27 of 48 findings (56.2%, 95% interval 42.2% to 70.0%) sit below High on CVSS-BT and land in High or Critical on AIVSS. No finding scores lower on AIVSS.
- Assessor agreement (Fleiss' kappa) on the AIVSS band is 0.47 against 0.41 on the CVSS-BT band. Most band disagreements trace to the CVSS answers, not the agentic ones.
- Agreement on agentic propagation is 0.21, and reward hacking drew too many unknown answers for agreement to be measured.
- None of 970 single answer changes between choices the rubric distinguishes moved the AIVSS score.

## Target Applications

| Application | Source | Commit | Findings |
|---|---|---|---|
| Damn Vulnerable AI Agent (DVAA) | [opena2a-org/damn-vulnerable-ai-agent](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | 519b68d | 25 |
| agent-sec-lab | [wstran118/agent-sec-lab](https://github.com/wstran118/agent-sec-lab) | 3537e7a | 19 |
| OWASP FinBot CTF demo | [OWASP-ASI/finbot-ctf-demo](https://github.com/OWASP-ASI/finbot-ctf-demo) | 3bdeca0 | 4 |

The DVAA and agent-sec-lab attack paths come from those projects' own documentation, tests, and code, which the findings cite by file and line. The FinBot attack scenarios in `finbot_exploits.md` were written by Rock Lambros for this experiment and are not part of the FinBot project. Scoring used the OWASP AIVSS reference calculator, aivss-calc 1.2.0, vendored unchanged in `work/aivss-calc/`.

## Credits

Thanks to the maintainers of these projects, whose work made the experiment possible:

- DVAA, by OpenA2A and its contributors.
- agent-sec-lab, by Sang Tran.
- The OWASP FinBot CTF demo, by the OWASP Agentic Security Initiative and its contributors.
- The OWASP AIVSS project and its reference calculator, which carries CVSS v4.0 lookup data from the FIRST and Red Hat reference implementation.

Each keeps its own license. NOTICE lists them.

## Reproduce the Analysis

The analysis recomputes from the saved assessor responses with no model calls.

```bash
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install -e work/aivss-calc
./run_all.sh
```

`run_all.sh` checks the environment against `requirements.lock`, rebuilds the provenance record, rubric, briefings, results, and notebook, executes the notebook, and finishes with a self check that reconciles the spend ledger against the raw responses. Seeds are fixed (bootstrap seed 42, 2,000 resamples).

Rerunning the assessors themselves (`scripts/execute_raters_v12.py`) calls models through OpenRouter, costs money, and reads the API key from the `pass` password store. The final run cost $81.31.

## Repository Layout

| Path | Contents |
|---|---|
| `AIVSS_EXPERIMENT.md` | The protocol |
| `LOG.md`, `STATE.md` | The execution ledger and rulings, in order |
| `findings.json`, `findings.md`, `labs/` | The 48 findings and the profile of each agent |
| `packets_v11/` | The briefings each assessor saw, by arm (base, retest, ablation, fixed) |
| `rubric/` | The rubric text copied from the calculator |
| `premortem/` | The adversarial review of the design and the frozen hypothesis criteria (`hypothesis_criteria.json`) |
| `runs/v11-20261107T200429Z/` | The final run: manifest, endpoint locks, spend ledger, and every raw response |
| `runs/v1.0/`, `runs/v11-20261107T180544Z/`, `runs/v11-dryrun-*` | The first scoring pass, a stopped pass, and dry runs, kept for the spend record and the build inputs |
| `live/` | Recorded outcomes of local exploit runs and test suites |
| `results_v11/` | Adjudicated scores, agreement tables, and `notebook_numbers.json` |
| `figures_v11/` | Figures exported by the notebook |
| `scripts/` | Briefing builder, assessor runner, analysis package (`scripts/aivss_v11/`), notebook builder, self check |
| `work/` | The vendored calculator and logs from local test runs |

## Safety

Every target application ran on localhost only. The DVAA agent fleet was never started, and DVAA telemetry was turned off. `finbot_exploits.md` and `scripts/run_finbot_*.py` contain prompt injection payloads aimed at a deliberately vulnerable demo. Run them only against a local FinBot copy you control.

## Limits

The assessors are seven AI models from seven developers, not people. The findings come from three small, synthetic applications that each run under a single principal. The hypotheses were registered by name before scoring, and their falsification thresholds were fixed after an earlier pass and before the final run. Chance corrected agreement drops when one answer dominates, and the intervals are wide because the 48 findings form only 43 independent path groups. Read every result with these limits in mind.
