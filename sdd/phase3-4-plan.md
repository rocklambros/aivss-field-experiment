# Phase 3 and Phase 4 plan

Spec: `aivss_experiment/AIVSS_EXPERIMENT.md` Phase 3 and Phase 4.
Owner: Rock Lambros.

## Global constraints

- Labs are read-only. Do not edit files in the four repos. Do not run git commands that change state.
- Write outputs only under `aivss_experiment/`.
- Bind only to 127.0.0.1. Never contact a host other than a process you started.
- Do not write FinBot exploit code. FinBot stays E:U.
- Do not run the DVAA ResearchBot demo against an external site.
- Set `OPENA2A_TELEMETRY=off` for DVAA. Set `TMPDIR` under `aivss_experiment/work/`.
- FinBot `DATABASE_URL` is a SQLite file under `aivss_experiment/work/`. Bind a port other than 5000.
- Do not print `OPENROUTER_API_KEY` or any secret.
- Do not invent numbers. Cite command output.
- Stop every process you start and confirm the port is closed.
- No git commits. This folder is not the experiment's git repo.

## Rulings already made

- CHECKPOINT 2 is treated as approved because the owner said proceed to Phase 3. Live validation runs.
- Key env var is `OPENROUTER_API_KEY`, injected from pass only if a live model call is required. Scripted tests must not call a model.
- Reuse the remaining Phase 2 budget. Do not exceed $500 total including the $5.3613 already spent.
- Prefer each lab's own automated or local mode over Docker. Docker only if the README says the check cannot run without it, and only on a private network bound to localhost.

## Tasks

### Task 1: agent-sec-lab scripted exploit tests

Run `uv run --group dev pytest` from `/Users/klambros/github_projects/vulnerable_agents/agent-sec-lab` with the working directory set on the command, not by moving the session. No API key. No Docker. Record pass/fail counts and which scenario tests ran. Write `aivss_experiment/live/agent-sec-lab.json` and a short log under `aivss_experiment/live/agent-sec-lab.log`. Do not edit the lab.

### Task 2: DVAA local tests, telemetry off

Run `npm test` in damn-vulnerable-ai-agent with `OPENA2A_TELEMETRY=off` and `TMPDIR` under `aivss_experiment/work/dvaa-tmp`. Do not start a public listener. Do not fetch an external site. Record counts. Write `aivss_experiment/live/dvaa.json`. If a documented local demo can run with telemetry off and no external host, run that too and record it. Otherwise say not run and why.

### Task 3: FinBot localhost smoke, no exploit

Start FinBot bound to 127.0.0.1 on a port other than 5000, with `DATABASE_URL` pointing at a SQLite file under `aivss_experiment/work/`. Confirm it answers on that port. Do not write or run an exploit. Record E:U. Stop the process and confirm the port is closed. Write `aivss_experiment/live/finbot.json`.

### Task 4: Phase 3 closeout

Confirm no experiment-started listener remains. Write `aivss_experiment/live/summary.json` with per-finding live result: success, failure, or not run, and the exploit-maturity consequence (E:A only if a documented exploit succeeded locally).

### Task 5: Phase 4 hypotheses

Using `scores/agreement.json`, the calculator reports, findings.json, and live/summary.json, compute H1 through H10. Write `aivss_experiment/phase4/hypotheses.json` and `aivss_experiment/phase4/HYPOTHESES.md`. Numbers must come from code you run. State N beside every statistic. Do not treat rater-C RH:X as a crash. Do not repair DV-L3-04 `VC:LV`.
