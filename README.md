# AIVSS Field Experiment

Version 1.1. Owner: Rock Lambros. License: Apache 2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)).

This repository tests a proposed severity score for AI agents, OWASP AIVSS 1.0, on 48 real attack paths taken from three deliberately vulnerable agent applications. Seven AI models from seven developers scored every attack path from the same written briefing, and the analysis asks three questions: does AIVSS change how urgent agent findings look, do independent assessors reproduce it, and does it carry information that the standard score misses?

The README walks through how AIVSS turns a finding into a number, then how this experiment tested that number, then what came out. Every result here is reproduced by the executed notebook, [`AIVSS-field-experiment-RockLambros-v1.1.ipynb`](AIVSS-field-experiment-RockLambros-v1.1.ipynb), from saved responses and with no model calls.

**The short answer.** AIVSS raised 27 of the 48 findings into the High or Critical bands and never lowered one. The assessors agreed on its band only moderately, about as well as on the standard band. One of its five agent questions went mostly unanswered, and three of its answer distinctions never changed the score.

## Part 1: How AIVSS Scores an Agent

### The starting point: CVSS

Security teams rate software vulnerabilities with CVSS, the Common Vulnerability Scoring System, maintained by FIRST. An assessor answers eleven base questions about a vulnerability (how the attacker reaches the system, whether a user has to click something, what the attacker can read, change, or break) and the answers, written as a string called a vector, produce a score from 0 to 10.

A second input, exploit maturity, records whether anyone has seen the attack work. This experiment uses three values: attacked (seen working against a real system), proof of concept (a test or complete payload exists), and unreported. The score with exploit maturity applied, and no deployment specific adjustments, is called CVSS-BT. Its bands are what most teams act on:

| Band | CVSS-BT range | Usual treatment |
|---|---|---|
| None | 0.0 | Ignore |
| Low | 0.1 to 3.9 | Backlog |
| Medium | 4.0 to 6.9 | Planned fix |
| High | 7.0 to 8.9 | Urgent |
| Critical | 9.0 to 10.0 | Urgent |

### What AIVSS adds

CVSS was designed for software that does what its code says. An AI agent is software that uses a language model to pursue a goal and choose its own actions, such as reading web pages, calling tools, or approving payments. An attacker who can put words in front of that model can sometimes steer what it does. AIVSS keeps the CVSS vector unchanged and adds five questions about the agent.

| Agent question | Official name | Possible answers | What the answer means |
|---|---|---|---|
| Can attacker words steer the agent? | Language control (LC) | Direct, Indirect, Mediated, None | Directly, through content the agent reads, only through a check outside the model, or not at all |
| Does poisoned context outlive the session? | Context persistence (CP) | Cross-session, Session, None | Survives in durable memory, lives only in the session, or does not persist |
| Can compromise spread to others? | Agentic propagation (AP) | Lateral, Contained, None | Into another agent, tenant, or principal, within one principal's components, or not at all |
| Does the agent game its own evaluator? | Reward hacking (RH) | Demonstrated, Possible, None | A verified episode exists, the evaluator is reachable, or a test confirms isolation |
| How loosely are its tools bound? | Extension surface (ES) | Wide, Managed, None | Dynamic or unconstrained tools, an allow list with gaps, or a fixed least privilege set |

Every question also accepts X, meaning the evidence cannot decide. The official vector writes each answer as one letter, such as `LC:I` for Indirect.

### From answers to a score

The flow below is what the reference calculator does. Read it left to right.

```mermaid
flowchart LR
    V["CVSS v4.0 vector<br/>eleven base answers"] --> BT["CVSS-BT<br/>0 to 10"]
    E["Exploit maturity<br/>attacked, proof of concept,<br/>or unreported"] --> BT
    BT --> BAND["CVSS-BT band<br/>None to Critical"]
    Q["Five agent answers"] --> LAD["Class ladder"]
    LAD --> CLS["Agent class<br/>A0, A1, A2, or AX"]
    BAND --> LUT["Lookup table"]
    CLS --> LUT
    LUT --> MAX["Take the higher of<br/>the table cell and CVSS-BT"]
    BT --> MAX
    MAX --> AIVSS["AIVSS score"]
    GATE["Applicability gate<br/>does a model pursue goals<br/>and choose actions?"] -. "both answers must be yes" .-> AIVSS
    ES["Extension surface"] -. "reported, never scored" .-> AIVSS
```

Three things in that picture matter for everything that follows.

**The class ladder decides almost everything.** The five answers collapse into one of four classes. The calculator checks the rules in order and the first match wins:

```mermaid
flowchart TD
    START["Five agent answers"] --> Q1{"Propagation<br/>Lateral?"}
    Q1 -- yes --> A2["A2<br/>most severe"]
    Q1 -- no --> Q2{"Language control Direct or Indirect,<br/>and context persists across sessions<br/>or reward hacking Demonstrated?"}
    Q2 -- yes --> A2
    Q2 -- no --> Q3{"Any one of: language control Direct or Indirect,<br/>any context persistence, propagation Contained,<br/>reward hacking Demonstrated?"}
    Q3 -- yes --> A1["A1<br/>elevated"]
    Q3 -- no --> Q4{"An answer that could<br/>change the class is X?"}
    Q4 -- yes --> AX["AX<br/>unknown"]
    Q4 -- no --> A0["A0<br/>no agent condition"]
```

Notice what the ladder ignores. Direct and Indirect language control lead to the same place. Reward hacking only matters at Demonstrated. Extension surface never appears. Part 3 shows that assessors spend real effort on those distinctions, and the score discards them.

**The lookup table sets the number.** For A1 and A2, the score comes from a fixed table indexed by the CVSS-BT band. A0 and AX keep the CVSS-BT score.

| CVSS-BT band | A0 or AX | A1 | A2 |
|---|---|---|---|
| None | 0.0 | 0.0 | 0.0 |
| Low | CVSS-BT | 5.5 | 7.1 |
| Medium | CVSS-BT | 7.5 | 8.9 |
| High | CVSS-BT | 8.7 | 9.5 |
| Critical | CVSS-BT | 9.7 | 10.0 |

A Medium finding in class A1 becomes 7.5, which is High. A Low finding in class A2 becomes 7.1, also High. A single class decision can move a finding across the line most teams use for urgent work.

**AIVSS never falls below CVSS-BT.** The calculator takes the higher of the table cell and CVSS-BT, so inflation only runs one way. The notebook's H7 enumeration scores every possible input and finds no case below CVSS-BT.

### One finding, start to finish

Finding ASL-S1 comes from agent-sec-lab. An office assistant agent fetches a web page during a normal task. Anyone who can edit that page can plant instructions that make the agent read the workspace `.env` file and email the credentials to the attacker, while the user sees a normal answer.

| Step | Value | Why |
|---|---|---|
| CVSS vector | `AV:L/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:N/SC:H/SI:N/SA:N` | Majority or median of seven assessors, metric by metric |
| Exploit maturity | Proof of concept | The project ships an automated test and a real model script for the path |
| CVSS-BT | 6.8, Medium | The vector scored with proof of concept applied |
| Agent answers | LC Indirect, CP Cross-session, AP Contained, ES Wide, RH X | Majority of the assessors |
| Agent class | A2 | Indirect language control plus cross-session persistence fires the second rung |
| Lookup | Medium and A2 give 8.9 | Higher than 6.8, so the cell wins |
| AIVSS | 8.9, High | One class decision moved a Medium finding into the urgent band |

ASL-S1 is also marked provisional because reward hacking is X. Its range is still a single value, 8.9 to 8.9, because the finding already reached A2 by another rule. Provisional does not always mean uncertain, which is why `results_v11/adjudicated.json` records the lowest and highest possible score for every provisional finding.

## Part 2: How the Experiment Tests the Score

A score is only useful if different people reach the same number from the same evidence, and if the number tells you something the old one did not. Testing that needs many assessors, identical inputs, recorded outputs, and rules for judging the result that are fixed before the result is known. The pipeline below provides those four things.

```mermaid
flowchart TD
    subgraph SRC["1. Sources, pinned to commits"]
        DV["DVAA<br/>25 findings"]
        ASL["agent-sec-lab<br/>19 findings"]
        FB["OWASP FinBot CTF demo<br/>4 findings"]
        CALC["aivss-calc 1.2.0<br/>reference calculator"]
        LIVE["live/<br/>recorded local exploit runs"]
    end
    subgraph BRIEF["2. Briefings"]
        FIND["findings.json<br/>48 attack paths with cited lines"]
        RUB["rubric/rubric_v1.1.txt<br/>metric definitions from the calculator"]
        PK["packets_v11/<br/>100 briefings in four arms"]
    end
    subgraph SCORE["3. Scoring"]
        RUN["execute_raters_v12.py<br/>7 assessors x 100 briefings = 700 calls"]
        RAW["runs/v11-20261107T200429Z/raw/<br/>every response, never overwritten"]
        LED["spend.jsonl<br/>cost of every call"]
    end
    subgraph ANALYZE["4. Analysis"]
        PARSE["Strict parse<br/>malformed answers become defects"]
        ADJ["Adjudication<br/>one vector per finding"]
        EM["Exploit maturity rule"]
        SCOREC["Calculator scores<br/>each assessor and the adjudicated vector"]
        STAT["Agreement statistics<br/>kappa with bootstrap intervals"]
        HYP["Hypotheses H1 to H10"]
        CRIT["premortem/hypothesis_criteria.json<br/>verdict rules, frozen"]
    end
    subgraph OUT["5. Outputs"]
        RES["results_v11/"]
        NB["Executed notebook and figures_v11/"]
        CHECK["Self check<br/>ledger against raw responses"]
    end
    DV --> FIND
    ASL --> FIND
    FB --> FIND
    CALC --> RUB
    FIND --> PK
    RUB --> PK
    PK --> RUN
    RUN --> RAW
    RUN --> LED
    RAW --> PARSE
    PARSE --> ADJ
    PARSE --> SCOREC
    ADJ --> SCOREC
    LIVE --> EM
    EM --> SCOREC
    CALC --> SCOREC
    SCOREC --> STAT
    SCOREC --> HYP
    CRIT --> HYP
    STAT --> RES
    HYP --> RES
    RES --> NB
    RAW --> CHECK
    LED --> CHECK
```

### Findings

A finding is one documented attack path: an entry point the attacker controls, the steps, the sink where damage happens, and the impact. The experiment kept every vulnerability, challenge, or attack that a target application documents with an exploit path, and cites the exact source and documentation lines for each one in `findings.json`. Findings that share an attack path form a path group. The 48 findings fall into 43 path groups, and the statistics treat each group as one unit so duplicates cannot inflate confidence.

### Briefings

Each assessor saw one written briefing per finding, built by `scripts/build_packets_v11.py`. A briefing holds the finding, the agent's profile and full tool list, verbatim excerpts of every cited line, and a rubric copied from the calculator.

What a briefing withholds matters as much as what it holds. Briefings never contain the lookup table, the target application's own severity labels, the exploit evidence, or anyone else's answers. A build check fails if any of those appear. That keeps assessors scoring the evidence instead of anchoring on a label.

Quoted source code is untrusted text, and some of it is attack text. Every excerpt sits between markers that carry a random value fixed per build, so an excerpt cannot fake the end of its own block. Each briefing also carries a harmless planted instruction, a canary, asking the assessor to add a `canary_followed` field to its answer. An assessor that obeys text inside quoted evidence will add the field, which measures how far untrusted text steers the scoring. One assessor did so in 15 of 48 base briefings.

The 100 briefings fall into four arms, each answering a different question:

| Arm | Briefings | What changes | What it measures |
|---|---|---|---|
| Base | 48 | Nothing | The main scores |
| Retest | 12 | Nothing, sent again | Each assessor's run to run variation |
| Ablation | 17 | Payload lines withheld | Whether the attack text itself moves the score |
| Fixed | 23 | The application's documented fix applied | Whether a real fix moves AIVSS |

### Assessors and the scoring run

The assessors are seven reasoning models from seven developers, run at the same reasoning effort. Several developers keep one model's habits from setting the result, and an odd number keeps majorities clean. They are models, so their agreement measures how consistently models read this rubric. That is a useful test of the rubric, and it is not a measure of human agreement.

Every call goes through one runner that records what actually happened:

```mermaid
sequenceDiagram
    participant R as Runner
    participant O as OpenRouter
    participant P as Locked provider endpoint
    participant D as Disk
    R->>O: Briefing, model, locked provider list, effort high
    O->>P: Route only to a listed endpoint
    P-->>O: Answer and reasoning
    O-->>R: Response, served provider, cost
    R->>R: Reject if the served provider is not on the lock list
    R->>D: Write the raw response, never overwrite an earlier one
    R->>D: Append the cost to the spend ledger
    R->>R: Halt if one call costs over $1 or the run passes $200
```

The final run made 700 calls and completed 698. The two gaps are safety refusals from one provider, kept as data. The run cost $81.31.

### Adjudication

Seven answers per question have to become one scorecard per finding. The rule, in `scripts/aivss_v11/adjudicate.py`, runs separately for every metric:

```mermaid
flowchart TD
    A["Seven answers to one metric"] --> B{"More than half<br/>answered X?"}
    B -- yes --> X["Unknown"]
    B -- no --> C{"More than half of the known<br/>answers agree?"}
    C -- yes --> M["That answer"]
    C -- no --> D["Median of the known answers,<br/>the less severe middle when the count is even"]
```

Reward hacking is decided from the facts the assessors reported, such as whether the evaluator was reachable, and the calculator derives the answer from those facts. Because each metric is decided on its own, an adjudicated vector can match no single assessor. That happened often, and the notebook counts it.

### Agreement

Raw agreement overstates consistency when one answer dominates, because assessors who always pick the common answer agree by luck. Fleiss' kappa corrects for that: 0 means chance level and 1 means perfect agreement. Kappa is computed across all seven assessors for each metric and for each band. Its uncertainty comes from a cluster bootstrap, which redraws the 43 path groups 2,000 times with seed 42 and reports the middle 95% of the results.

### Hypotheses

The protocol named ten hypotheses before any scoring. The rules for each verdict, including what would falsify it, were frozen in `premortem/hypothesis_criteria.json` before the final run. The analysis code computes every verdict from that file, so no verdict is typed by hand.

## Part 3: What Came Out

| ID | Claim in plain words | Verdict | Deciding number |
|---|---|---|---|
| H1 | AIVSS puts more findings in the urgent bands | Supported | 27 of 48 cross into High or Critical |
| H2 | AIVSS gives more findings the same score | Supported | 278 pairs share a score against 124 |
| H3 | Spreading to other agents drives the top class | Not supported | 1 of 11 A2 findings got there that way |
| H4 | The agent questions cause most band disagreement | Not supported | CVSS answers explain 188 of 312 disagreements |
| H5 | Unknown answers leave scores provisional | Supported | 33 of 48 provisional |
| H6 | How exploit evidence is recorded changes the band | Supported | 20 of 48 change band |
| H7 | Some answer choices never change the score | Supported | 0 of 970 answer changes moved AIVSS |
| H8 | The applicability gate rejects some agents | Supported | 6 of 15 agents rejected as documented |
| H9 | Controls move AIVSS less often than CVSS | Mixed | 45 against 47 of 48 |
| H10 | AIVSS changes the five most urgent findings | Supported | 1 finding leaves the top five |

How to read the main results:

Inflation is large and runs one way. The count of High or Critical findings goes from 6 under CVSS-BT to 33 under AIVSS, and the mean gap is 2.35 points. For findings with no reported exploit, the common case outside a test lab, the urgent bands hold 3 findings under CVSS-BT and 30 under AIVSS. This does not prove the lift is wrong. It does mean AIVSS bands cannot replace CVSS bands in an existing service level without moving most agent findings into faster queues.

Agreement is moderate on both scores. Band kappa is 0.47 for AIVSS and 0.41 for CVSS-BT, and the intervals overlap. Language control and context persistence reach 0.60, extension surface 0.53, and propagation only 0.21. Reward hacking drew so many X answers that its kappa cannot be computed.

Disagreement starts in CVSS. When two assessors land in different AIVSS bands, swapping in the other assessor's CVSS answers closes the gap in 188 of 312 pairs, against 65 for swapping the agent class. Better CVSS guidance for agent paths would do more for reproducibility than refining the agent questions.

Some distinctions are free to disagree on. Direct against Indirect, Mediated against None, reward hacking Possible against None, and every extension surface value never change the score. Narrowing an agent's tools, simulated on 27 findings, moved AIVSS on none of them.

### The FinBot case study

FinBot is a demo invoice approval agent. Its attack scenarios in [`finbot_exploits.md`](finbot_exploits.md) were written for this experiment and replayed against a local copy, twice, against two different systems:

```mermaid
flowchart LR
    INV["Same $7,500 invoices<br/>plain and with persuasion text"] --> NOKEY["FinBot with no model key<br/>fixed fallback rules"]
    INV --> MODEL["FinBot with a model<br/>through a US endpoint"]
    NOKEY --> R1["Persuasion invoice approved and paid"]
    MODEL --> R2["Persuasion invoice sent to review"]
    CFG["Approval limit raised through<br/>the open configuration endpoint"] --> BOTH["Plain invoice approved in both systems"]
```

The fallback approval says nothing about whether a model falls for the payload, because the fallback is a rule set and the model sent the same invoice to review. The configuration attack is the one observed in both systems. One scored FinBot path has no payload in the file, and none was invented, so it stays unreported.

## Limits

The assessors are models, and seven developers still share training data and habits. The findings come from three small applications built to be vulnerable, each running under a single principal, so propagation across agents was hardly possible. The same author wrote the briefings and the FinBot scenarios. The verdict thresholds were fixed after an earlier scoring pass on the same findings, so the verdicts are confirmatory only in part. Kappa drops when one answer dominates, and 43 path groups make every interval wide. Read the results as evidence about how the score behaves on documented attack paths, not as a measurement of real world risk.

## Run It Yourself

Read the notebook first. It is saved with outputs and takes the hypotheses in order, then the FinBot case study and the figures. To recompute everything from the saved responses:

```bash
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install -e work/aivss-calc
./run_all.sh
```

`run_all.sh` checks the environment against `requirements.lock`, rebuilds the briefings, results, and notebook, and ends with the self check that reconciles the spend ledger against the raw responses. Rerunning the assessors (`scripts/execute_raters_v12.py`) calls models through OpenRouter and costs money. It reads the API key from the `pass` password store.

| Path | What it holds |
|---|---|
| `AIVSS_EXPERIMENT.md`, `LOG.md` | The protocol, and every ruling in the order it was made |
| `findings.json`, `labs/` | The findings and each agent's profile |
| `packets_v11/` | The 100 briefings by arm |
| `runs/v11-20261107T200429Z/` | The final run: endpoint locks, spend ledger, raw responses |
| `runs/` (other folders) | An earlier pass, a stopped pass, and dry runs, kept for the spend record and build inputs |
| `scripts/aivss_v11/` | Parsing, adjudication, statistics, hypotheses, figures |
| `premortem/` | The design review and the frozen verdict rules |
| `live/` | Recorded outcomes of local exploit runs and test suites |

## Safety

Every target application ran on localhost only. The DVAA agent fleet was never started and its telemetry was off. `finbot_exploits.md` and `scripts/run_finbot_*.py` contain prompt injection payloads aimed at a deliberately vulnerable demo. Run them only against a local FinBot copy you control.

## Credits

| Project | Source | Commit | Findings |
|---|---|---|---|
| Damn Vulnerable AI Agent (DVAA), by OpenA2A and contributors | [opena2a-org/damn-vulnerable-ai-agent](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | 519b68d | 25 |
| agent-sec-lab, by Sang Tran | [wstran118/agent-sec-lab](https://github.com/wstran118/agent-sec-lab) | 3537e7a | 19 |
| OWASP FinBot CTF demo, by the OWASP Agentic Security Initiative and contributors | [OWASP-ASI/finbot-ctf-demo](https://github.com/OWASP-ASI/finbot-ctf-demo) | 3bdeca0 | 4 |
| OWASP AIVSS reference calculator, aivss-calc 1.2.0 | [OWASP AIVSS project](https://github.com/OWASP/www-project-artificial-intelligence-vulnerability-scoring-system) | 007b72b | Vendored unchanged in `work/aivss-calc/` |

The DVAA and agent-sec-lab attack paths come from those projects' own documentation, tests, and code. The FinBot attack scenarios were written by Rock Lambros for this experiment and are not part of the FinBot project. The calculator carries CVSS v4.0 lookup data from the FIRST and Red Hat reference implementation. Each project keeps its own license, listed in [NOTICE](NOTICE).
