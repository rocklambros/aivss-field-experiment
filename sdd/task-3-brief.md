# Task 3: FinBot localhost smoke, no exploit

FinBot's `src/main.py` calls `app.run(host='0.0.0.0', ...)`. Do not run that entry point. Do not use gunicorn.conf.py. Both bind beyond localhost.

## How to start

From a shell whose working directory is `/Users/klambros/github_projects/vulnerable_agents/finbot-ctf-demo`, run a one-off Python command that imports the Flask app and calls `app.run(host='127.0.0.1', port=5055, debug=False)`. Do not write that command into the lab. Do not edit any lab file.

Environment:

- `DATABASE_URL=sqlite:////Users/klambros/github_projects/vulnerable_agents/aivss_experiment/work/finbot.db`
- `PORT` is irrelevant if you pass port=5055 yourself. Do not use port 5000.
- No OpenAI key. No model calls.

Create the work directory first. If the app needs packages that are not installed, install them into a venv under `aivss_experiment/work/finbot-venv`, not into the lab.

## What to do

1. Start the server in the background.
2. Request `http://127.0.0.1:5055/` or `/entry` and record the status code.
3. Do not submit an attack. Do not write an exploit. Do not call a model.
4. Stop the process.
5. Confirm nothing is listening on 5055.

## Output

`/Users/klambros/github_projects/vulnerable_agents/aivss_experiment/live/finbot.json` with keys:

- `lab`: `finbot-ctf-demo`
- `mode`: `localhost-smoke`
- `bind`: `127.0.0.1:5055`
- `http_status`: integer or null
- `exploit_run`: false
- `exploit_maturity`: `E:U`
- `model_calls`: 0
- `stopped`: true
- `port_closed`: true
- `notes`

Also write `/Users/klambros/github_projects/vulnerable_agents/aivss_experiment/sdd/task-3-report.md`.

Return only status, a one-line summary, and concerns.
