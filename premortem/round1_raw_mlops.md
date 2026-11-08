# Round 1 MLOps/SRE, raw (condensed)
1. B and C FB-01 outputs from an earlier unlogged pilot run with different code (22:19Z, skip lines in log, script modified 22:21:41Z); FB-01 AP:C ES:M come from them. High. Fix: rescore under new run id, disclose pilot.
2. Spend ledger $5.3613 omits B/C FB-01 ($0.105190) and failed pilot A call; result files sum $5.466454; record_spend only after success. Medium. Fix: record at post_chat, run_id, restate spend.
3. MAX_TOKENS 2500 and reasoning off not honored: all 48 C calls >2500 completion tokens (max 25,020), reasoning tokens present; B reasoned 44/48. No finish_reason, no payload record. High (repro). Fix: record request and finish_reason; call outputs a single sample.
4. Partial rerun mixes runs: skip-if-exists, routing re-resolved each run (gemini may now be up -> C changes model), scores/ never cleared. High. Fix: run-scoped dirs, frozen routing lock, fail closed on mixed model/run/packet hash, run_all clears outputs.
5. run_all.sh does not rebuild Phase 0, CSVs, REPORT; no self-check; build_styled_report hardcodes captions. Medium. Fix: CSV writer, number check, provenance/pytest/verify in run_all.
6. Environment/calculator not content-pinned; no lockfile; nested calculator-source copy. Medium. Fix: requirements.lock, sha256 of calculator in provenance, assert.
7. Mock writers in git history at exact output paths; no check rejects non-API outputs. Medium. Fix: validate gen- id, served_provider, cost>0, run_id.
8. No record owner confirmed rater set and projected spend before first call (LOG gate section unresolved). Low-Med. Fix: log the confirmation status honestly.
9. Counter-evidence: saved outputs regenerate exactly today (0 diffs).
