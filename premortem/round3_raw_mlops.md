# Round 3 (plan) MLOps, condensed
1. v1.0 vs v1.1 not comparable; reconciliation undefined. Fix: D2 decomposition: (a) rescore v1.0 raw with v1.1 code, (b) bridge arm: v1.0 prompts rebuilt byte for byte sent on v1.1 day, (c) duplicate 10 v1.1 packets per rater for noise floor, (d) full run. Critical, Very likely.
2. Runner repairs output (parse_json_object fence and regex) before strict parse; raw response not saved. Fix: save full response body and prompt; scorer json.loads only. High.
3. max_tokens 2500 will truncate B (v1.0 max 2418, reasoning counts). Fix: 8000 for A and B, record C cap not enforced, dry run 3 longest packets, finish_reason != stop is defect. High, Likely.
4. Silent reasoning fallback. Fix: delete; record supported_parameters. Medium.
5. Frozen routing cannot detect model change; v1.0 baseline unrecorded. Fix: full endpoint record lock, diff at start and end, halt on diff, 72 h hold limit. High.
6. Fixed packets collide on finding_id. Fix: arm field, id <fid>~fixed, separate dirs, registry. High.
7. No recovery or canonical run rule; 4-failure stop; timeout not wall clock; C serial ~4 h. Fix: manifest, resume same run_id only, 2 attempts, 900 s deadline, C concurrency 3-4, caffeinate, RUN_ID required, runs/CANONICAL. High.
8. Spend misses billed-not-returned; cap loose. Fix: key usage snapshot reconcile, per-run cap $60, per-call halt $0.50. Medium.
9. Determinism: bootstrap cluster key order input dependent; repo HEAD not asserted; self-check unspecified. Fix: sort keys, assert HEAD equals provenance, enumerated self-check. Medium.
