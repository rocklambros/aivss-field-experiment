# Task 2: DVAA local tests, telemetry off

Run the lab's own test command. Do not start a public listener. Do not fetch any host that is not 127.0.0.1.

## Exact environment

- Lab directory for the command only: `/Users/klambros/github_projects/vulnerable_agents/damn-vulnerable-ai-agent`
- `OPENA2A_TELEMETRY=off`
- `TMPDIR=/Users/klambros/github_projects/vulnerable_agents/aivss_experiment/work/dvaa-tmp`
- Create that TMPDIR before the test.

## Exact command

```
npm test
```

If npm or node is missing, report BLOCKED. Do not edit the lab. Do not run a demo that fetches an external site. Do not run ResearchBot against the network.

If `npm test` does not start a server, do not start one yourself.

## Outputs

- `/Users/klambros/github_projects/vulnerable_agents/aivss_experiment/live/dvaa.log`
- `/Users/klambros/github_projects/vulnerable_agents/aivss_experiment/live/dvaa.json` with keys:
  - `lab`: `damn-vulnerable-ai-agent`
  - `mode`: `npm-test`
  - `command`: `OPENA2A_TELEMETRY=off npm test`
  - `exit_code`
  - `passed`, `failed`, `skipped` (integers or null)
  - `duration_s` or null
  - `model_calls`: 0 unless the log shows a model call, in which case count it
  - `external_hosts_contacted`: list, must be empty
  - `ports_left_open`: list of listeners you started, must be empty when you finish
  - `notes`

## Constraints

- Do not print secrets.
- Do not git commit.
- Do not edit lab files.
- Write the report to `/Users/klambros/github_projects/vulnerable_agents/aivss_experiment/sdd/task-2-report.md`.
- Return only status, a one-line test summary, and concerns.
