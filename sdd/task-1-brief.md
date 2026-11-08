# Task 1: agent-sec-lab scripted exploit tests

Run the lab's own pytest suite. It uses a scripted model. It needs no API key and no Docker.

## Exact command

Working directory for the command only: `/Users/klambros/github_projects/vulnerable_agents/agent-sec-lab`

```
uv run --group dev pytest
```

If `uv` is missing, stop and report BLOCKED. Do not pip-install into the lab. Do not edit any file under agent-sec-lab.

## Outputs

- `/Users/klambros/github_projects/vulnerable_agents/aivss_experiment/live/agent-sec-lab.log` — full pytest output
- `/Users/klambros/github_projects/vulnerable_agents/aivss_experiment/live/agent-sec-lab.json` with keys:
  - `lab`: `agent-sec-lab`
  - `mode`: `scripted-pytest`
  - `command`: the exact command
  - `exit_code`: integer
  - `passed`: integer or null
  - `failed`: integer or null
  - `skipped`: integer or null
  - `duration_s`: number or null
  - `model_calls`: 0
  - `ports_opened`: []
  - `notes`: short string

## Constraints

- Do not print secrets.
- Do not start Docker.
- Do not contact any host except 127.0.0.1 if a test does that on its own.
- Do not git commit.
- Write the report to `/Users/klambros/github_projects/vulnerable_agents/aivss_experiment/sdd/task-1-report.md`.
- Return only status, a one-line test summary, and concerns.
