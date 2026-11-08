# Adversarial premortem: AIVSS 1.0 field experiment v1.0 and the v1.1 fix plan

Artifact: aivss_experiment on branch feature/aivss-report-v1.1, base commit 68c86f3. Date 2026-11-07.

## Rounds

1. Problem framing and data. Six perspectives. 54 raw findings merged to P01 to P33.
2. Methodology, statistics, figures, conclusions. Data Scientist, ML Engineer, Governance. Red Teamer, Security Architect, and MLOps skipped: round 1 attacked their layers and round 2's code gave them nothing new to anchor on. 38 raw findings merged to P34 to P59.
3. Security, implementation, and residual statistics of the fix plan. Red Teamer, MLOps, Data Scientist. Security Architect and Governance skipped: the plan adds no trust boundary or decision surface beyond what rounds 1 and 2 covered. 34 raw findings merged to P60 to P74.

Layers 4 (implementation and MLOps) and 5 (governance and second-order effects) were attacked inside rounds 1 to 3: MLOps in rounds 1 and 3, Governance in rounds 1 and 2. All five layers are covered.

## Convergence

Round 3 produced no finding against the original analysis that rounds 1 and 2 had missed. Every round 3 survivor targets the fix plan, and each is closed by plan revision 2 or criteria v1.1.1 before any code runs. That is the stop signal.

## Register

The full register with impact, posterior confidence, fix status, and rerun need is PREMORTEM_PROGRESS.md. Raw condensed reports are premortem/round*_raw_*.md.

## Cross-attack adjustments

- Governance R1-8 claimed DVAA's top-level applicability reached assessors. The runner strips top-level keys, so the DVAA leak is the steps text. The nested leak in agent-sec-lab and FinBot (Red Teamer R1-2) stands. Merged into P02 with that correction.
- The known truncation issue (P33) was downgraded to Low after the Data Scientist and ML Engineer measured that the cut removed only the duplicate rubric and the profile tail.
- The Security Architect's proposal to derive exploit maturity from the static check (R1-6) was overruled in round 3 (Red Teamer R3-4, Data Scientist R3-9), because it reintroduces lead inference into a score input.
- The MLOps counter-evidence (R1-9: saved outputs regenerate exactly) narrowed the reproducibility findings to generation, not recomputation.

## Dropped ledger

- Red Teamer R1-8, payloads steered v1.0 scores: Unlikely. No compliance marker in 144 outputs. Kept as a test (ablation arm), not a finding.
- Lab severity anchoring on DV-D1 to D3 (Data Scientist R1-12): Unlikely. Adjudicated 8.7, 5.5, 6.8 show no pull to Critical.

Tail risk: a destructive automation wired to an AIVSS band (Governance R2-5). Critical and irreversible. Addressed as a product guardrail in the report, not in the analysis.

## Residual risk

Model assessors remain models. The 48 findings come from three deliberately vulnerable target applications. The criteria were set after v1.0 was known. These go to Threats to Validity in the report.
