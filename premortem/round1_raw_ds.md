# Round 1 Data Scientist, raw (condensed)
1. Packets: lead prose, no code (0/48 excerpts); evidence share citing lab profile only ES 79%, AP 72%, CP 71%, LC 33%, RH 37%; lead static inference text ("As implemented by default", "Static reading") in 20 DVAA + 2 ASL packets. Critical, Very likely.
2. Real cluster is lab: 42 clusters for 47 nearly iid; per-lab ES kappa ASL 0.15, DVAA 0.62, FinBot -0.37; AP pooled 0.11, ASL -0.30. Rater A ES:W on all 19 ASL, AP:N on all 48. High. Fix: per-lab kappa, two-stage bootstrap.
3. Gate: majority fail as modeled 21/25 DVAA; as-implemented answer constant within lab. Subset 25/27 vs 14/27, uplift 1.51. High.
4. RH rewritten (33/143 notes; 29 N-to-X with isolation set true); 8 of 15 adjudicated RH:N unsupported by any rater facts; RH construct not exercised by labs. High. Fix: RH = classify_rh(facts); declare RH not estimable.
5. H3/H4/H7 cells empty: AP:L 1/141, LC:M 0, RH:D 1. AP disagreements 48 of 57 involve rater A (constant N); B-C Cohen 0.62 vs Fleiss 0.11. cohen() reports 0.0 when one rater marginal degenerate instead of declining. High. Fix: Insufficient data; decline on degenerate per-rater marginal; H4 with A excluded.
6. CVSS baseline hinges on AV convention: no CVSS text in rubric; A AV:N 47/48, C AV:L 38/48; AV kappa -0.10; AV:N->AV:L drops CVSS High/Critical 22 -> 6 of 48. High, Likely. Fix: CVSS text, AV rule, sensitivity row.
7. H1 true by construction (floor); 33 above, 15 equal, 0 below. Medium. Fix: reframe as magnitude.
8. Scope 48 vs ~58; FinBot N=4 uplift no interval; 5 findings CVSS 0.0 in pooled stats. Medium. Fix: ruling, intervals, sensitivity excluding 0.0.
9. E labels: 7 DVAA "documented payload" get E:P; 6 ASL E:A rest on "Direct tool call, no model in the loop" tests. Medium. Fix: map poc.kind to evidence.
10. Bad rater outputs silently repaired (B DV-L1-01 double prefix, DV-L1-03 no prefix); 63 of B's evidence refs are prose; AX as own category in effect_class kappa; bootstrap drops undefined resamples silently (AC 1740/2000) and reports CI at p0 0.97; single pass only. Medium.
11. FB-01 B/C from older runner. Low (dup of MLOps 1).
12. Downgrade: truncation cut only duplicate rubric_text and profile tail (exploit_artifacts, injection_text_observed); lab_severity "critical" reached DV-D1..D3 with no visible anchoring. Low.
