# Task 1 report: agent-sec-lab scripted exploit tests

Status: DONE_WITH_CONCERNS

## Command

Working directory: `/Users/klambros/github_projects/vulnerable_agents/agent-sec-lab`

Command: `uv run --group dev pytest`

`uv` was present at `/opt/homebrew/bin/uv` (0.13.1). API key variables were unset in the shell before the command. The command itself was not changed. Pytest config already excludes the `live` marker (`addopts = "-m 'not live'"` in `pyproject.toml`).

Pytest exit code: 0. Taken from `$?` immediately after the command.

## Evidence

Log: `aivss_experiment/live/agent-sec-lab.log`

Result: `aivss_experiment/live/agent-sec-lab.json`

The log is the full command output. Lines 1-5 are uv. Lines 6-26 are pytest. Summary line, quoted from the log:

```
=========== 179 passed, 1 deselected, 2 xfailed in 116.90s (0:01:56) ===========
```

Session header, quoted from the log:

```
collected 182 items / 1 deselected / 181 selected
```

| Field | Value | Source |
| --- | --- | --- |
| passed | 179 | summary line |
| failed | 0 | summary line does not name failed or error |
| skipped | 0 | summary line does not name skipped |
| deselected | 1 | summary line and collected line |
| xfailed | 2 | summary line, lowercase `x` in the progress, not `X` |
| duration_s | 116.90 | summary line |
| exit_code | 0 | shell `$?` after the command |
| model_calls | 0 | live test deselected, keys unset, no API traffic in the log |
| ports_opened | [] | no recorded listener left by this task |

## Scenario files that ran

Progress characters are from the log. `x` is an expected xfail. No `F`, `E`, or `X` appears.

| File | Progress | Passed | Xfailed |
| --- | --- | --- | --- |
| tests/test_baseline.py | `.....` | 5 | 0 |
| tests/test_demo_build.py | `..` | 2 | 0 |
| tests/test_s1_indirect_injection.py | `........` | 8 | 0 |
| tests/test_s2_over_permissioned.py | `.....................` | 21 | 0 |
| tests/test_s3_exfiltration.py | `.................x.......` | 24 | 1 |
| tests/test_s4_mcp_rug_pull.py | `..............x` | 14 | 1 |
| tests/test_s5_output_handling.py | 39 dots, then 11 dots on the next line | 50 | 0 |
| tests/test_s6_secrets_leakage.py | `...................` | 19 | 0 |
| tests/test_s7_human_in_the_loop.py | `................` | 16 | 0 |
| tests/test_s8_memory_poisoning.py | `....................` | 20 | 0 |

File totals: 179 passed + 2 xfailed = 181 selected. That matches the collected line.

The mandated command does not pass `-v`, so the log does not name individual tests. The two `x` marks match the only `@pytest.mark.xfail(strict=True)` tests in `tests/`:

- `tests/test_s3_exfiltration.py`: `test_dlp_known_bypass_rot13`. Reason in source: DLP is pattern-based and rot13-encoded data evades it.
- `tests/test_s4_mcp_rug_pull.py`: `test_scan_known_bypass_paraphrase`. Reason in source: a paraphrased instruction evades the heuristic scan. Pinning is the control.

`strict=True` means an unexpected pass would have failed the run. The marks are `x`, so both failed as expected.

The one deselected test is `tests/test_baseline.py::test_live_model_benign_task`, marked `live`. It was not run. That is the only `live` marker under `tests/`.

## What this run did not do

- Did not start Docker.
- Did not call a model.
- Did not edit lab source. A search for files modified in the last 15 minutes, excluding `.venv`, `.pytest_cache`, and `__pycache__`, returned nothing.
- Did not leave a recorded listener. Fixture servers bind `127.0.0.1` on port 0 and shut down in teardown. The pytest process exited. Those port numbers were not captured, so `ports_opened` stays `[]`.

## Concerns

1. `uv run` created `agent-sec-lab/.venv` (20:09) and downloaded `anthropic` (2.0 MiB) before pytest. Log lines 1-5. That is a gitignored tree change and a package-index fetch, caused by the mandated command because no venv existed. Source files were not edited. `.venv/` is in `.gitignore`.
2. Pytest wrote gitignored `.pytest_cache` (20:11) and `__pycache__` directories under the lab. Same class of local artifact. Not a source edit.
3. The lab README and `docs/results.md` say 177 passed and 2 expected xfails. This run collected 182, selected 181, passed 179, xfailed 2, and deselected 1. Use this log, not the README, for Phase 3 counts.
4. `skipped` is 0. The live test was deselected, not skipped. Do not treat deselected as a skip or as a model call.
