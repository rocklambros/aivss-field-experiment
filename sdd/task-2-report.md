# Task 2 report: DVAA local tests, telemetry off

Status: DONE_WITH_CONCERNS

## Command

Working directory: `/Users/klambros/github_projects/vulnerable_agents/damn-vulnerable-ai-agent`

Command: `OPENA2A_TELEMETRY=off npm test`

`TMPDIR` was created first at `/Users/klambros/github_projects/vulnerable_agents/aivss_experiment/work/dvaa-tmp`.

`node` was present at `/opt/homebrew/bin/node` (v26.12.0). `npm` was present at `/opt/homebrew/bin/npm` (11.20.0). The lab `engines` field asks for Node `>=24.0.0`. This Node satisfies that.

npm exit code: 1. Taken from the process status of `npm test`.

The script npm ran, quoted from log lines 1-3:

```
> damn-vulnerable-ai-agent@0.9.3 test
> node --test "test/*.test.js" "src/**/*.test.js"
```

## Evidence

Log: `aivss_experiment/live/dvaa.log`

Result: `aivss_experiment/live/dvaa.json`

Summary, quoted from log lines 815-822:

```
ℹ tests 252
ℹ suites 0
ℹ pass 177
ℹ fail 33
ℹ cancelled 0
ℹ skipped 42
ℹ todo 0
ℹ duration_ms 5885.110709
```

177 + 33 + 42 = 252. That matches the tests line.

| Field | Value | Source |
| --- | --- | --- |
| passed | 177 | summary `pass` |
| failed | 33 | summary `fail` |
| skipped | 42 | summary `skipped` |
| cancelled | 0 | summary line |
| todo | 0 | summary line |
| duration_s | 5.885110709 | `duration_ms 5885.110709` divided by 1000 |
| exit_code | 1 | process status of `npm test` |
| model_calls | 0 | no provider request in the log or on the process tree |
| external_hosts_contacted | [] | socket samples were only `127.0.0.1` LISTEN |
| ports_left_open | [] | listener table unchanged after the process exited |

Wall clock around the process was 6.353 seconds. That includes npm startup. `duration_s` is the runner figure, not the wall clock.

## Why the 33 failures are not product failures

`node_modules/` was absent before the command and absent after it. The README says to run `npm ci` before `npm test`. `npm ci` was not run. It would write into the lab and contact `registry.npmjs.org`. Both are outside this task.

Every failure in the `failing tests` section (log lines 824-1236) is a missing install artifact.

| Count | Cause | Where it shows |
| --- | --- | --- |
| 11 | `Cannot find package 'openai'` imported from `src/playground/engine.js` | five `src/playground/*.test.js` files, plus `test/attack-log-integration.test.js`, `test/dashboard-request-hardening.test.js`, `test/playground-integration.test.js`, `test/playground-routes.test.js`, `test/telemetry-server-path.test.js`, `test/tutor-routes.test.js` |
| 3 | `Cannot find package '@opena2a/aim-core'` imported from `src/aim-enforcer.js` | two tests in `test/aim-cloud-pairing.test.js`, and the file `test/aim-trust-behavioral.test.js` |
| 9 | `Cannot find package '@opena2a/telemetry'` | `test/cli-parsing.test.js`, `test/readme-telemetry-section.test.js`, one test in `test/selftest-filters.test.js`, the file `test/selftest-help.test.js`, three tests in `test/telemetry-server-optout.test.js`, two tests in `test/telemetry-offline.test.js` |
| 8 | `ENOENT` scandir of `node_modules` | eight tests in `test/hackmyagent-telemetry-callers.test.js` |
| 1 | HackMyAgent binary path is null | `test/cli-hma-resolution.test.js` |
| 1 | CLI spawn never printed the expected refusal | `test/research-agent-llm-mode.test.js` |

11 + 3 + 9 + 8 + 1 + 1 = 33.

The telemetry-offline pair does not print the child's stderr. Those spawns set `stdio` to `ignore` and then assert a post count. Both got 0 posts. The child is `src/index.js`, which imports `@opena2a/telemetry` before `tele.init()`. That package is not installed, so the child cannot post. The same import error is in the captured stderr of the selftest and server-optout spawns.

`test/research-agent-llm-mode.test.js` is one node:test failure. Its own harness printed `Results: 15 passed, 4 failed`. The four failures are `dvaa chat --llm` spawns that should refuse before any provider ping. The harness did not echo the child stderr. It printed that the expected refusal text was missing. Those spawns run `node src/index.js`, which cannot load `@opena2a/telemetry`. No provider request appears in the log.

`test/cli-hma-resolution.test.js` is one node:test failure. Its harness printed `Results: 2 passed, 4 failed`. The failures are a null binary path. `hackmyagent` is not on `PATH`. One case called `spawnSync` with that null path and got a local type error. It did not start a network client.

`test/selftest-help.test.js` is one node:test failure. Its harness printed `Results: 1 passed, 5 failed`. The captured stderr is `Cannot find package '@opena2a/telemetry'`.

Do not add those inner `Results:` lines to 177 or 33. node:test already counted each of those files once. Other inner lines that exited 0 are the same shape: `test/repo-demo.test.js` printed `Results: 19 passed, 0 failed` and node:test marked the file passed once. `test/research-agent.test.js` printed `Results: 15 passed, 0 failed` and was one pass. Use the summary, not the inner lines.

## Skips

42 skip marks, all with a reason after `#`. None is a model call.

| Count | Reason |
| --- | --- |
| 16 | DVAA fleet not running on :9000 |
| 11 | DVAA fleet not running on :9000 (start it with `npm run start:all`). This 11 already includes the five MCP containment skips. |
| 4 | DVAA fleet not reachable on 7000-base ports |
| 2 | no fleet on :9000 |
| 2 | DVAA fleet not running on :9000, with a `npm run test:fleet` hint |
| 1 | no fleet on :7002 |
| 1 | no fleet on :7006 |
| 1 | no fleet on :7015 |
| 1 | 7017/7018 not held by a running fleet. The skip text says the demo would start its own. |
| 3 | hackmyagent is not installed |

16 + 11 + 4 + 2 + 2 + 1 + 1 + 1 + 1 + 3 = 42. Of those, 39 are a missing fleet and 3 are a missing HackMyAgent install. The fleet was not started. The brief says not to start a server when `npm test` does not start one.

## What this run did not do

- Did not run `npm ci` or `npm install`.
- Did not edit lab files. A search for lab files newer than a stamp taken before the command returned nothing. `node_modules/` is still absent.
- Did not start a fleet, a dashboard, or a public listener.
- Did not run a demo. `dvaa demo flight` and `dvaa demo repo` start a fleet. The flight cleanup test skipped for that reason. ResearchBot's documented demo fetches an external URL and refuses loopback by default. No documented demo runs with telemetry off, no listener, and no external host, beyond the unit tests already inside `npm test`.
- Did not call a model. The log line `[LLM] Error: boom` is a stub throw inside `renderResearchNarration`, not a provider call. API key variables were unset in the parent shell. The GitHub token name was set in the parent shell and was removed from the child environment. Its value was not printed.
- Did not leave a listener. During the run, node held `127.0.0.1` ports 53371, 53372, 53378, and 53380 in LISTEN. Those sockets died with the process. The TCP listen table before and after had the same 27 lines. `ControlCenter` on `*:7000` was already there and was not started by this task.

## Network and telemetry

`OPENA2A_TELEMETRY=off` was set for the npm process. The child also had `NO_UPDATE_NOTIFIER=1`, `npm_config_update_notifier=false`, `npm_config_fund=false`, `npm_config_audit=false`, and `npm_config_offline=true`. Those extras are not part of the recorded command string. They were set so npm would not contact the registry. The script still ran. Log lines 1-3 show `node --test`.

A sampler polled `lsof` on the npm process tree about every 0.2 seconds. The only sockets were the four loopback listeners above. No established connection. No non-loopback address. The sampler did not kill the run.

`~/.config/opena2a/telemetry.json` was not present after the run. The missing `@opena2a/telemetry` package never reached `tele.init()`.

`TMPDIR` received a Node compile cache and three empty directories: `dvaa-aim-behavioral-yvg0nZ`, `dvaa-dashboard-test-D3Kj1k`, and `dvaa-tutor-routes-test-W2ViPc`. Those are outside the lab.

## Concerns

1. The 177 passes are the tests that do not import the missing packages. They are not a clean result for an installed tree. Do not treat exit code 1, or the 33 failures, as evidence that a vulnerability check failed.
2. 39 tests that need a local fleet were skipped. This task did not start that fleet. Live challenge paths were not exercised.
3. Three scenario checks skipped because `hackmyagent` is not installed. The resolution test failed for the same absence.
4. The child environment had notifier, fund, audit, and offline flags beyond the two required variables, and the GitHub token was unset in the child. The recorded command string is still `OPENA2A_TELEMETRY=off npm test`. The script that ran is the lab script.
5. Inner `Results:` lines are not extra tests. Adding them to 177 or 33 would double-count.

## Fix: install, then re-run

Status: DONE_WITH_CONCERNS

The first run failed because `node_modules/` was absent. A later ruling allowed the install. `package-lock.json` exists, so the command was `npm ci` in `/Users/klambros/github_projects/vulnerable_agents/damn-vulnerable-ai-agent`. It was not `npm install`.

`npm ci` exit code: 0. Log text: `added 139 packages in 4s`.

The install log is above the `=== npm test ===` separator in `aivss_experiment/live/dvaa.log`. The test output starts at that separator (line 8).

npm 11 printed that `onnxruntime-node@1.30.0` has a postinstall not covered by `allowScripts`, so that script did not run. The lockfile resolves every package from `registry.npmjs.org`. The darwin/arm64 ONNX binary is already in that tarball. `ONNXRUNTIME_NODE_INSTALL=skip` was also set so the script would exit before NuGet if npm had run it. It did not run. Socket samples during `npm ci` were TCP to `104.16.9.34:443` only. That address was in the set returned by resolving `registry.npmjs.org`. No other host.

No source file changed. A search for lab files newer than a pre-install stamp, excluding `node_modules/`, found one path after the test: `.hackmyagent-cache/check-metadata-v0.33.2.json`. That directory is listed in the lab `.gitignore` as a scanner cache. It is not source.

### Re-run command

Working directory: the lab.

Command: `OPENA2A_TELEMETRY=off npm test`

`TMPDIR` was the same path as the first run.

npm test exit code: 0.

Summary, quoted from the combined log lines 762-769:

```
ℹ tests 369
ℹ suites 0
ℹ pass 330
ℹ fail 0
ℹ cancelled 0
ℹ skipped 39
ℹ todo 0
ℹ duration_ms 11410.541542
```

330 + 39 = 369.

| Field | Value | Source |
| --- | --- | --- |
| passed | 330 | summary `pass` |
| failed | 0 | summary `fail` |
| skipped | 39 | summary `skipped` |
| duration_s | 11.410541542 | `duration_ms 11410.541542` divided by 1000 |
| exit_code | 0 | process status of the re-run |
| model_calls | 0 | no provider request in the log or on the process tree |
| external_hosts_contacted | [] | test sockets were `127.0.0.1` only |
| ports_left_open | [] | listener table unchanged after the process exited |

Wall clock around the test process was 11.967 seconds. `duration_s` is the runner figure.

The 33 missing-package failures from the first run are gone. The three skips whose reason was `hackmyagent is not installed` are also gone. The remaining 39 skips are the same fleet-not-running reasons as the first run:

| Count | Reason |
| --- | --- |
| 16 | DVAA fleet not running on :9000 |
| 11 | DVAA fleet not running on :9000 (start it with `npm run start:all`) |
| 4 | DVAA fleet not reachable on 7000-base ports |
| 2 | no fleet on :9000 |
| 2 | DVAA fleet not running on :9000, with a `npm run test:fleet` hint |
| 1 | no fleet on :7002 |
| 1 | no fleet on :7006 |
| 1 | no fleet on :7015 |
| 1 | 7017/7018 not held. The skip text says the demo would start its own. |

16 + 11 + 4 + 2 + 2 + 1 + 1 + 1 + 1 = 39. No fleet was started.

Inner `Results:` lines still appear (6, 7, 3, 75, 19, 19, 15, and 6 passed, all with 0 failed). Those files also show as single node:test results. Do not add the inner lines to 330.

`[LLM] Error: boom` is still the stub throw inside `renderResearchNarration`. It is not a provider call.

### What the re-run did not do

- Did not edit source.
- Did not git commit.
- Did not start a fleet, a dashboard, or a public listener.
- Did not run ResearchBot against the network. Did not run `dvaa demo flight` or `dvaa demo repo`.
- Did not call a model.
- Did not write `~/.config/opena2a/telemetry.json`. The test process set `XDG_CONFIG_HOME` under `aivss_experiment/work/dvaa-tmp/xdg`, so a telemetry config file landed there instead of the user home. Its contents were not printed.
- Did not leave a listener. During the test, node used `127.0.0.1` ports 56922, 57082, 57125, and 57164. Those died with the process. The TCP listen table before and after matched.

### Concerns after the fix

1. 39 tests that need a local fleet were skipped. Live challenge paths were not exercised. Starting the fleet was out of scope for this fix.
2. The test child had notifier, fund, and audit flags off, the GitHub token unset, and `XDG_CONFIG_HOME` pointed at the experiment tmp. The recorded command string is still `OPENA2A_TELEMETRY=off npm test`.
3. `npm ci` wrote `node_modules/` into the lab. That is the install, not a source edit. It also left the gitignored `.hackmyagent-cache/` file.
4. Use the re-run counts (330 passed, 0 failed, 39 skipped), not the first-run counts.
