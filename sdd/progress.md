# SDD ledger — plan: aivss_experiment/sdd/phase3-4-plan.md

Ruling: no git worktree and no commits. The experiment root is not a git repo, and ground rule 1 forbids state-changing git in the four labs. Cost if wrong: no commit SHAs in this ledger. Recovery is the files under aivss_experiment/.

Ruling: CHECKPOINT 2 approved by the owner's "proceed to phase 3". Live validation runs. Key name is OPENROUTER_API_KEY, never printed. Budget is the remainder of $500 after $5.3613. Local/scripted mode before Docker. Cost if wrong: a live run the owner meant to decline. Undo by marking live results not-run and ignoring them in Phase 4.

Task 1: complete (no commits, review verified against live/agent-sec-lab.log summary line). 179 passed, 0 failed, exit 0, 116.90s, model_calls 0.
Task 1: minor (deferred): uv created a gitignored .venv and pytest cache inside agent-sec-lab. Ruling: leave them. They are not source edits. Cost if wrong: a dirty lab tree. Delete .venv later if the owner wants a clean status.
Task 1: observation: README said 177 passed. This run passed 179. Report the observed count, do not force the README number.

Task 2: complete after fix round 1. Post-install npm test exit 0: 330 passed, 0 failed, 39 skipped, 11.41s. The 39 skips need a fleet that was not started. No listeners left open.
Task 2: minor (deferred): npm ci wrote node_modules and a gitignored cache file in the DVAA tree. Leave them. Not source edits.

Task 2: fix round 1/5. First run exited 1 because node_modules was missing (177 passed, 33 failed, 42 skipped). Ruling: npm install from the lab lockfile is an allowed package install under ground rule 5, same class as the agent-sec-lab uv venv. Re-run npm test after install. Do not start the fleet. Do not treat the first exit 1 as a product failure.

Ruling: model parameter omitted on subagent dispatch. The harness forbids setting a model unless the owner names one. Cost if wrong: a more expensive subagent than the skill prefers.

Preflight scan:
- Task 1 produces live/agent-sec-lab.json. Task 4 consumes it. No file conflict.
- Task 2 produces live/dvaa.json. Task 4 consumes it. No file conflict.
- Task 3 produces live/finbot.json. Task 4 consumes it. No file conflict.
- Task 5 consumes live/summary.json and scores/agreement.json. It does not edit lab repos.
- Task 1 text agrees with itself: pytest, no key, write one json and one log.
- Task 2 text agrees with itself: npm test, telemetry off, no external fetch.
- Task 3 text agrees with itself: smoke only, no exploit.
- Task 5 text agrees with itself: compute from saved files, do not invent.
