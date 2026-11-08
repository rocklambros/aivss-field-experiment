#!/usr/bin/env python3
"""Write AIVSS-field-experiment-RockLambros-v1.1.ipynb (unexecuted).

Version: 1.1.0
Owner: Rock Lambros

The notebook recomputes every number, table, and figure of the experiment from
the saved assessor outputs, with no model calls, and writes
results_v11/notebook_numbers.json, the single number source for any summary of
the results. Execute with nbconvert (run_all.sh does).
"""

from __future__ import annotations

from pathlib import Path

import nbformat as nbf

ROOT = Path(__file__).resolve().parents[1]
NB = ROOT / "AIVSS-field-experiment-RockLambros-v1.1.ipynb"

cells: list = []


def md(text: str) -> None:
    cells.append(nbf.v4.new_markdown_cell(text.strip()))


def code(text: str) -> None:
    cells.append(nbf.v4.new_code_cell(text.strip()))


md("""
# AIVSS Field Experiment: Notebook

**Version 1.1. Owner: Rock Lambros.**

This notebook reproduces every number, table, and figure of the AIVSS field experiment from the saved experiment outputs. It makes no model calls. It runs top to bottom on a fresh kernel with fixed seeds. Its sections run in this order: data loading and the calculator results, one section per hypothesis, the FinBot case study, and the figures.

Terms used throughout. A **finding** is one documented attack path in a target application. The **target applications** are agent-sec-lab, DVAA (Damn Vulnerable AI Agent), and FinBot (the OWASP FinBot CTF demo). The **assessors** are Assessors A through G, seven reasoning models from seven model families, all run with the same reasoning effort setting. **CVSS-BT** is the CVSS v4.0 score with exploit maturity applied and no environmental metrics. **CVSS-BTE** appears only in the mitigation pass, where environmental metrics are set.
""")

code("""
import json, math, random, sys
from collections import Counter
from pathlib import Path

ROOT = Path.cwd()
if not (ROOT / "scripts" / "aivss_v11").exists():
    ROOT = Path("/Users/klambros/github_projects/vulnerable_agents/aivss_experiment")
sys.path.insert(0, str(ROOT / "scripts"))
random.seed(42)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from IPython.display import Image, display

from aivss_v11 import data as D, hypotheses as H, stats as S

FIG = ROOT / "figures_v11"
FIG.mkdir(exist_ok=True)
N = {}  # every headline number, written to results_v11/notebook_numbers.json at the end

def rec(key, value):
    N[key] = value
    return value

def pct(a, b):
    return round(100 * a / b, 1) if b else None
""")

md("""
## 1. Data Loading and the Calculator Results

### 1.1 Scorecards and Adjudicated Vectors

The run named in `runs/CANONICAL` holds every assessor response from the final scoring run, saved as raw HTTP bodies. This section parses each response strictly, applies the one exploit maturity rule, scores every scorecard through the AIVSS reference calculator (aivss-calc 1.2.0), and adjudicates one vector per finding. The experiment files call the headline score field `cvss_bte`. The calculator labels those scores CVSS-BT because no environmental metric is set, so this notebook calls it CVSS-BT.
""")

code("""
findings = D.load_findings()
emr = D.exploit_maturity_rule(findings)
run = ROOT / "runs" / (ROOT / "runs" / "CANONICAL").read_text().strip()
manifest = json.loads((run / "manifest.json").read_text())
arms = {a: D.score_rows([D.parse(r) for r in D.load_v11(run, a)], findings, emr)
        for a in ("base", "retest", "ablation", "fixed")}
primary = H.analyze(arms["base"], findings, emr, {"fixed": arms["fixed"]}, label="v1.1")
saved = json.loads((ROOT / "results_v11" / "results.json").read_text())
assert saved["primary"]["hypotheses"]["H1"]["crossings"] == primary["hypotheses"]["H1"]["crossings"], "results_v11 is stale; rerun analyze_v11.py"
A = {f: a for f, a in primary["_adjudicated"].items() if a["scores"] and "error" not in a["scores"]}
labs = {"agent-sec-lab": "agent-sec-lab", "damn-vulnerable-ai-agent": "DVAA", "finbot-ctf-demo": "FinBot"}

rec("n_findings", len(findings))
rec("n_by_app", {labs[k]: v for k, v in Counter(f["lab"] for f in findings.values()).items()})
rec("run_id", manifest["run_id"])
rec("cells_total", len(manifest["cells"]))
rec("cells_complete", sum(1 for c in manifest["cells"] if c["status"] == "complete"))
base = arms["base"]
rec("base_scorecards", len(base))
rec("base_scorecards_accepted", sum(1 for r in base if r["scores"]))
rec("base_defects", {s: dict(Counter(d.split(":")[0] for r in base if r["slot"] == s for d in r["defects"])) for s in D.SLOTS})
rec("exploit_maturity_counts", dict(Counter(v["e"] for v in emr.values())))
rec("adjudication", {k: v for k, v in primary["adjudication"].items() if k != "unscored"})
prov = saved["provenance"]
rec("spend", {"scoring_run": prov["spend_run_usd"], "dry_runs": prov["spend_dry_runs_usd"], "all_scoring_to_date": prov["spend_total_usd"]})
rec("assessors", {s: p["model"] for s, p in manifest["pins"].items()})
rec("reasoning_tokens_median", prov["reasoning_tokens_median"])
rec("retried_cells", prov["retried_cells"])
print(json.dumps({k: N[k] for k in ("n_findings", "n_by_app", "cells_total", "cells_complete", "base_scorecards_accepted", "exploit_maturity_counts", "spend")}, indent=1))
""")

code("""
rows = []
for f in sorted(A):
    a = A[f]; s = a["scores"]
    rows.append((f, labs[a["lab"]], s["cvss_bt"], s["cvss_band"], s["effect_class"], s["aivss"], s["aivss_band"], s["provisional"]))
rec("per_finding", rows)
print(f"{'Finding':10} {'App':14} {'CVSS-BT':>7} {'Band':9} {'Class':5} {'AIVSS':>5} {'Band':9} Prov")
for r in rows:
    print(f"{r[0]:10} {r[1]:14} {r[2]:7.1f} {r[3]:9} {r[4]:5} {r[5]:5.1f} {r[6]:9} {r[7]}")
""")

md("""
### 1.2 Agreement Among the Assessors

Agreement is reported before the hypotheses because several hypotheses lean on it. The headline statistic is Fleiss' kappa, a chance corrected agreement measure for many assessors where 0 means chance level and 1 means perfect. Each kappa carries its observed agreement, the number of findings it covers, and a 95 percent cluster bootstrap interval (seed 42, 2000 resamples, clusters are the documented path groups). A finding drops out of a metric's kappa when any assessor answered unknown (X), and that count is shown. The retest arm, a second pass of 12 briefings by the same seven assessors, gives the noise floor.
""")

code("""
ag = primary["agreement"]
order = ["LC", "CP", "AP", "RH", "ES", "effect_class", "aivss_band", "cvss_band"] + list(D.CVSS_BASE)
table = {}
for m in order:
    b = ag[m]
    table[m] = {"n": b["n"], "p0": None if b["p0"] is None else round(b["p0"], 2),
                "kappa": None if b.get("kappa") is None else round(b["kappa"], 2),
                "ci_low": None if b["ci"]["low"] is None else round(b["ci"]["low"], 2),
                "ci_high": None if b["ci"]["high"] is None else round(b["ci"]["high"], 2),
                "ci_defined": b["ci"]["defined"], "excluded_unknown": b["excluded_unknown"], "declined": b.get("declined"),
                "three_agree": b["three_agree"], "three_present": b["three_present"],
                "alpha": None if b["alpha"].get("alpha") is None else round(b["alpha"]["alpha"], 2),
                "per_app": {labs[k]: (None if v["kappa"] is None else round(v["kappa"], 2), v["n"]) for k, v in b["per_target_application"].items()},
                "pairwise": {p: (None if v.get("kappa") is None else round(v["kappa"], 2)) for p, v in b["pairwise"].items()},
                "weighted": {p: (None if (v.get("linear_weighted") or {}).get("kappa") is None else round(v["linear_weighted"]["kappa"], 2)) for p, v in b["pairwise"].items()}}
rec("agreement", table)
for m in order:
    t = table[m]
    print(f"{m:13} N={t['n']:2} p0={t['p0']} kappa={t['kappa']} CI=[{t['ci_low']}, {t['ci_high']}] ({t['ci_defined']}) X-excluded={t['excluded_unknown']} alpha={t['alpha']} {t['declined'] or ''}")
ret = H.compare_rows(arms["base"], arms["retest"])
rec("retest", {s: {k: v for k, v in r.items() if k != "changed_findings"} for s, r in ret.items()})
print("retest", json.dumps(N["retest"]))
""")

md("""
### 1.3 Control Arms

Two checks test whether differences come from ordinary run to run variation or from the injection text inside the briefings. The retest arm sent 12 briefings a second time. The ablation arm sent each briefing that quotes payload lines addressed to the assistant with those lines withheld. The canary is a harmless instruction inside the untrusted text, and following it shows an assessor obeyed text it was told to treat as data.
""")

code("""
ctl = saved["controls"]
rec("ablation_vs_base", ctl["ablation_vs_base"])
rec("canary", ctl["canary"])
rec("defects_by_payload", ctl["defects_by_payload"])
for k in ("retest_vs_base", "ablation_vs_base"):
    print(k, json.dumps({s: {kk: vv for kk, vv in v.items() if kk != "changed_findings"} for s, v in ctl[k].items()}))
print("canary", ctl["canary"])
""")

hyp_text = {
    "H1": ("Inflation", "AIVSS places more findings in High or Critical than CVSS-BT alone. The test counts findings that sit below High under CVSS-BT and reach High or Critical under AIVSS, a band crossing. The calculator never scores AIVSS below CVSS-BT, so the direction is fixed by design and the result is about size."),
    "H2": ("Information Loss", "AIVSS separates fewer pairs of findings than CVSS-BT. The test counts tied pairs under each score and the pairs that only one score separates."),
    "H3": ("Propagation Across Trust Boundaries as the Main Switch", "Findings reach the top agent class, A2, mainly because compromised intent crosses a trust boundary into another agent or principal. The test counts how each A2 finding got there."),
    "H4": ("Where the Assessors Disagree", "The assessors' disagreements on the agentic metrics concentrate on two named boundaries, and disagreements on the AIVSS band come from the agentic answers rather than from the CVSS answers. The test swaps one assessor's CVSS vector or agent class into another's scorecard and records which swap closes the band gap."),
    "H5": ("Unknown Answers", "Unknown answers are common enough to leave results provisional, with a material gap between the lowest and highest AIVSS the calculator reports for them."),
    "H6": ("Exploit Maturity Policy", "The choice of exploit maturity policy changes the AIVSS band for a material share of findings."),
    "H7": ("Distinctions That Do Not Change the Score", "Some distinctions the rubric asks assessors to make never change the AIVSS score. The test enumerates the calculator's whole input space and also swaps single answers between assessors."),
    "H8": ("The Applicability Gate", "A strict reading of the calculator's applicability gate rejects some agents, and the assessors disagree about which."),
    "H9": ("Controls", "Plausible mitigations move AIVSS less often than they move the CVSS score. The mitigation pass has three arms: environmental edits only, agentic edits only, and both, plus the target applications' own fixed configurations."),
    "H10": ("Ordering", "AIVSS reorders findings relative to CVSS-BT enough that a defender's top five changes."),
}
for hid, (title, text) in hyp_text.items():
    md(f"## {2 + list(hyp_text).index(hid)}. {hid}: {title}\n\n{text} The verdict comes from the rule frozen in `premortem/hypothesis_criteria.json` before the rerun.")
    code(f"""
h = primary["hypotheses"]["{hid}"]
rec("{hid}", {{k: v for k, v in h.items() if not k.startswith("_")}})
print("verdict:", h["verdict"])
print(json.dumps({{k: v for k, v in h.items() if k not in ("verdict",)}}, indent=1, default=str)[:3500])
""")

md("""
## 12. Case Study: FinBot Invoice Approval

FinBot was replayed twice on this machine only. The first replay ran with no model key, so FinBot used its own fallback rules. The second ran with a model reached through a US endpoint. These are two different systems. The fallback approval is not evidence that a model falls for the payload. Rock wrote the FinBot payloads by hand, and they live in `finbot_exploits.md`, which this notebook does not open.
""")

code("""
fb_fallback = json.loads((ROOT / "live" / "finbot_scenarios.json").read_text())
fb_model = json.loads((ROOT / "live" / "finbot_model.json").read_text())
fallback = {r["id"]: (r.get("decision") or r.get("bland_decision_after_config")) for r in fb_fallback["runs"]}
model = {r["id"]: r.get("decision") for r in fb_model["runs"]}
rec("finbot_fallback", fallback)
rec("finbot_model", model)
rec("finbot_model_calls", len(fb_model.get("calls") or []))
rec("finbot_model_cost", round(sum(float(c.get("cost") or 0) for c in fb_model.get("calls") or []), 4))
rec("finbot_model_served", sorted({c.get("served") for c in fb_model.get("calls") or []}))
rec("finbot_fb02_payload", bool(fb_fallback.get("fb02_scored_path", {}).get("artifact_payload")))
rec("finbot_scores", {f: A[f]["scores"] for f in ("FB-01", "FB-02", "FB-03", "FB-04") if f in A})
rec("finbot_e", {f: emr[f]["e"] for f in ("FB-01", "FB-02", "FB-03", "FB-04")})
print("fallback", fallback); print("model", model); print(N["finbot_model_calls"], N["finbot_model_cost"], N["finbot_model_served"])
""")

md("""
## 13. Figures

Every figure is drawn here, saved to `figures_v11/`, and followed by the table it was drawn from, so no value depends on reading a color. The forms follow the data's job: a tile row for the headline numbers, ribbons and dumbbells for inflation, a forest plot for agreement, a unit chart for what drives disagreement, a heatmap for unknown answers, a slope chart for exploit maturity, a bump chart for ordering, and an outcome grid for FinBot. The colors come from one fixed palette. Severity bands run lavender to dark purple. Each of the seven assessors has its own color and carries its letter on every mark.
""")

code("""
from aivss_v11 import figures as V
V.setup()
figs, tables = {}, {}
def show(key, result):
    path, table = result
    figs[key] = str(Path(path).relative_to(ROOT)); tables[key] = table
    display(Image(path))
    print(json.dumps(table, indent=1, default=str)[:2500])

h = primary["hypotheses"]
rows_s = [{"id": f, **A[f]["scores"]} for f in sorted(A)]
ag_tbl = N["agreement"]
swaps = h["H7"]["observed_swaps"]
swap_n = sum(v["swaps"] for v in swaps.values()); swap_changed = sum(v["aivss_changed"] for v in swaps.values())
rec("h7_swaps_total", swap_n); rec("h7_swaps_changed", swap_changed)
show("tiles", V.kpi_tiles([
    (f"{h['H1']['crossings']} of {h['H1']['n']}", "findings rise into High or Critical", "they sit below High under CVSS-BT"),
    (f"{ag_tbl['aivss_band']['kappa']:.2f}", "agreement on the AIVSS band beyond chance", f"CVSS-BT band {ag_tbl['cvss_band']['kappa']:.2f}; Fleiss' kappa, N={ag_tbl['aivss_band']['n']}"),
    (f"{h['H3']['a2_through_lc_and_cp']} of {h['H3']['a2']}", "top class findings that got there through persistent language control", f"{h['H3']['a2_only_through_ap_lateral']} through propagation across a trust boundary alone"),
    (f"{swap_changed} of {swap_n}", "single answer swaps that changed AIVSS", "distinctions the score never uses"),
], FIG / "fig0_tiles.png"))
""")

code("""
show("flow", V.band_flow(rows_s, FIG / "fig1_band_flow.png"))
""")

code("""
show("dumbbell", V.dumbbells(rows_s, FIG / "fig2_dumbbells.png"))
""")

code("""
names = {"LC": "Language control", "CP": "Context persistence", "AP": "Propagation", "RH": "Reward hacking",
         "ES": "Extension surface", "effect_class": "Agent class", "aivss_band": "AIVSS band", "cvss_band": "CVSS-BT band",
         "AV": "Attack vector", "UI": "User interaction", "VC": "Confidentiality impact", "VI": "Integrity impact"}
stats_rows = [{"name": names[m], "kappa": ag_tbl[m]["kappa"], "low": ag_tbl[m]["ci_low"], "high": ag_tbl[m]["ci_high"],
               "n": ag_tbl[m]["n"], "declined": ag_tbl[m]["declined"] or ("no finding without an unknown answer" if ag_tbl[m]["n"] == 0 else None)}
              for m in names]
show("forest", V.forest(stats_rows, None, FIG / "fig3_agreement.png", "How often the seven assessors agree beyond chance"))
""")

code("""
att = h["H4"]["attribution"]
show("attribution", V.unit_chart(att, "cvss_only",
     {"cvss_only": "CVSS swap closes it", "class_only": "Agent class swap closes it", "either": "Either swap closes it", "neither": "Neither closes it"},
     FIG / "fig4_attribution.png", f"What closes each disagreement on the AIVSS band (one square per assessor pair, N={h['H4']['band_disagreements']})"))
""")

code("""
xc = h["H5"]["x_counts_used"]
show("unknowns", V.heatmap({s: xc[s] for s in D.SLOTS}, list(D.AIVSS),
     ["Language\\ncontrol", "Context\\npersistence", "Propagation", "Reward\\nhacking", "Extension\\nsurface"], len(findings), FIG / "fig5_unknowns.png"))
""")

code("""
show("policy", V.slope(h["H1"]["uniform_policy"], len(A), FIG / "fig6_policy.png"))
""")

code("""
show("ranking", V.bump({f: A[f]["scores"]["aivss"] for f in A}, {f: A[f]["scores"]["cvss_bt"] for f in A}, 5, FIG / "fig7_ranking.png"))
""")

code("""
fb_rows = [("FB-01 persuasive invoice text", N["finbot_fallback"].get("FB-01"), N["finbot_model"].get("FB-01")),
           ("FB-03 goals rewritten, then a plain invoice", N["finbot_fallback"].get("FB-03"), N["finbot_model"].get("FB-03")),
           ("FB-04 approval limits raised, then a plain invoice", N["finbot_fallback"].get("FB-04"), N["finbot_model"].get("FB-04")),
           ("Control: plain invoice", N["finbot_fallback"].get("control"), N["finbot_model"].get("control"))]
show("finbot", V.outcome_grid(fb_rows, FIG / "fig8_finbot.png"))
""")

code("""
ctl = saved["controls"]
stab = {"Same briefing sent twice (retest)": {s: (v["same_aivss_band"], v["scores_compared"]) for s, v in ctl["retest_vs_base"].items()},
        "Payload lines withheld (ablation)": {s: (v["same_aivss_band"], v["scores_compared"]) for s, v in ctl["ablation_vs_base"].items()}}
show("stability", V.stability(stab, FIG / "fig9_stability.png"))
rec("figures", figs)
rec("figure_tables", tables)
""")

md("""
## 14. Headline Numbers

This cell gathers every derived number that summaries of the experiment quote, such as shares, ranges, and rounded statistics, into `results_v11/notebook_numbers.json`, so every summary reads its numbers from this notebook and none computes its own.
""")

code('''
h = primary["hypotheses"]; ag = N["agreement"]; ctl = saved["controls"]
def r2(x): return None if x is None else round(x, 2)
def rng(vals): return [min(vals), max(vals)]
R = {}
R["crossings"] = h["H1"]["crossings"]; R["crossing_pct"] = round(100 * h["H1"]["share"], 1)
R["crossing_ci_pct"] = [round(100 * h["H1"]["share_ci"]["low"], 1), round(100 * h["H1"]["share_ci"]["high"], 1)]
R["cvss_hc"] = h["H1"]["cvss_high_or_critical"]; R["aivss_hc"] = h["H1"]["aivss_high_or_critical"]
R["cvss_hc_pct"] = pct(R["cvss_hc"], h["H1"]["n"]); R["aivss_hc_pct"] = pct(R["aivss_hc"], h["H1"]["n"])
R["gap"] = r2(h["H1"]["mean_gap"]); R["gap_ci"] = [r2(h["H1"]["mean_gap_ci"]["low"]), r2(h["H1"]["mean_gap_ci"]["high"])]
R["above"], R["equal"], R["below"] = h["H1"]["above"], h["H1"]["equal"], h["H1"]["below"]
R["policy"] = {k: {"cvss": v["cvss_hc"], "aivss": v["aivss_hc"], "crossings": v["crossings"], "gap": r2(v["mean_gap"])} for k, v in h["H1"]["uniform_policy"].items()}
R["gated"] = h["H1"]["gate_passing_as_modeled"]; R["gated_pct"] = round(100 * R["gated"]["share"], 1)
R["by_app"] = {labs[k]: {"n": v["n"], "aivss": v["aivss_high_or_critical"], "cvss": v["cvss_high_or_critical"], "crossings": v["crossings"], "gap": r2(v["mean_gap"])} for k, v in h["H1"]["by_target_application"].items()}
R["av_sens"] = {k: {"cvss": v["cvss_hc"], "aivss": v["aivss_hc"], "crossings": v["crossings"]} for k, v in h["H1"]["av_ui_sensitivity"].items()}
R["listener_findings"] = next(iter(h["H1"]["av_ui_sensitivity"].values()))["listener_findings"]
R["kappa"] = {m: {"k": ag[m]["kappa"], "lo": ag[m]["ci_low"], "hi": ag[m]["ci_high"], "n": ag[m]["n"], "p0": ag[m]["p0"], "x": ag[m]["excluded_unknown"], "alpha": ag[m]["alpha"], "per_app": ag[m]["per_app"]} for m in ag}
R["h2"] = {k: h["H2"][k] for k in ("pairs", "distinct_cvss_bt", "distinct_aivss", "tied_pairs_cvss_bt", "tied_pairs_aivss", "separated_only_by_cvss_bt", "separated_only_by_aivss")}
R["h2_dup_identical"] = sum(1 for d in h["H2"]["duplicate_groups"] if d["identical_aivss"]); R["h2_dup_groups"] = len(h["H2"]["duplicate_groups"])
R["h3"] = {k: h["H3"][k] for k in ("a2", "a2_only_through_ap_lateral", "a2_through_lc_and_cp", "a2_through_lc_and_rh", "ap_lateral_any")}
R["h3_loo_lateral_survives"] = sorted(k.replace("without_", "") for k, v in h["H3"]["leave_one_out"].items() if v["a2_only_through_ap_lateral"] > 0)
R["h3_single_a2"] = rng([v["a2"] for v in h["H3"]["single_assessor"].values()])
R["h4"] = {"band_disagreements": h["H4"]["band_disagreements"], **h["H4"]["attribution"]}
R["h4_no_av_ui"] = h["H4"]["attribution_without_av_ui"]
R["h4_top_pairs"] = list(h["H4"]["pair_disagreements"].items())[:4]
R["h4_never"] = h["H4"]["values_never_chosen"]
R["h5"] = {"provisional": h["H5"]["provisional"], "pct": round(100 * h["H5"]["share"], 1), "spread": r2(h["H5"]["mean_spread_provisional"])}
rh_x = [h["H5"]["x_counts_used"][s]["RH"] for s in h["H5"]["x_counts_used"]]
R["rh_unknown_range"] = rng(rh_x); R["rh_unknown_by_assessor"] = {s: h["H5"]["x_counts_used"][s]["RH"] for s in h["H5"]["x_counts_used"]}
R["h6"] = {"aivss": h["H6"]["aivss_band_changes"], "aivss_pct": round(100 * h["H6"]["aivss_share"], 1), "cvss": h["H6"]["cvss_band_changes"], **{k: h["H6"]["empty_evidence_demo"][k] for k in ("finding_id", "cvss_bt_returned", "attacked_cvss_bt")}}
R["h7"] = {"swaps": N["h7_swaps_total"], "changed": N["h7_swaps_changed"], "enum_inputs": sum(v["inputs"] for v in h["H7"]["enumeration"].values())}
R["h8"] = {"agents": h["H8"]["agents"], "fail_as_modeled": len(h["H8"]["fail_as_modeled_by_majority"]), "split": len(h["H8"]["agents_with_split_answers"]), "dvaa_fail_impl": h["H8"]["dvaa_as_implemented"].get("fail", 0)}
a9 = h["H9"]["arms"]
R["h9"] = {k: {kk: a9[k][kk] for kk in ("edited", "cvss_moved", "aivss_moved", "cvss_moved_aivss_not", "aivss_moved_cvss_not", "cvss_band_changed", "aivss_band_changed")} for k in a9}
R["h9_fired"] = a9["agentic"]["edit_fired"]; R["h9_moved_alone"] = a9["agentic"]["edit_moved_aivss_alone"]
lf = h["H9"].get("lab_fix_arm") or {}
R["labfix"] = {"not_exploitable": rng([v["not_exploitable_as_configured"] for v in lf.values()]), "aivss_band_changed": rng([v["aivss_band_changed"] for v in lf.values()]),
               "cvss_band_changed": rng([v["cvss_band_changed"] for v in lf.values()]), "rows": None}
R["h10"] = {k: h["H10"][k] for k in ("moved", "strict_inversions", "tied_pairs", "top5_aivss_fifth_value", "top5_cvss_fifth_value")}
R["h10"]["tau"] = r2(h["H10"]["kendall_tau_b"]); R["h10"]["tau_ci"] = [r2(h["H10"]["kendall_tau_b_ci"]["low"]), r2(h["H10"]["kendall_tau_b_ci"]["high"])]
R["h10"]["jaccard"] = r2(h["H10"]["jaccard_tie_inclusive"]); R["h10"]["aivss_top_size"] = len(h["H10"]["top5_aivss_strict"]) + len(h["H10"]["top5_aivss_tie_block"])
R["canary"] = {s: v for s, v in ctl["canary"]["base"].items()}
R["canary_rows"] = ctl["canary_rows_per_assessor"]
R["retest_same_band"] = {s: [v["same_aivss_band"], v["scores_compared"]] for s, v in ctl["retest_vs_base"].items()}
R["retest_same_letters"] = {s: [v["same_all_letters"], v["letters_compared"]] for s, v in ctl["retest_vs_base"].items()}
R["ablation_same_band"] = {s: [v["same_aivss_band"], v["scores_compared"]] for s, v in ctl["ablation_vs_base"].items()}
R["ablation_packets"] = len(arms["ablation"]) // len(D.SLOTS)
R["reasoning_median_range"] = rng(list(N["reasoning_tokens_median"].values()))
R["verdicts"] = {k: h[k]["verdict"] for k in h}
R["refused_cells"] = N["cells_total"] - N["cells_complete"]
R["zero_impact"] = h["H1"]["zero_impact_findings"]
asl_live = json.loads((ROOT / "live" / "agent-sec-lab.json").read_text())
dvaa_live = json.loads((ROOT / "live" / "dvaa.json").read_text())
calc_prov = json.loads((ROOT / "phase0" / "provenance_v11.json").read_text())
from aivss_calc.lookup import TABLE_6
ctrl_inv = next(r_ for r_ in fb_fallback["runs"] if r_["id"] == "control")
R["context"] = {
    "asl_tests_passed": asl_live["passed"], "dvaa_tests_passed": dvaa_live["passed"], "dvaa_tests_skipped": dvaa_live["skipped"],
    "calculator_tests": calc_prov["pytest_summary"].split(" in ")[0], "invoice_amount": ctrl_inv["result"]["fetched"]["body"]["invoice"]["amount"],
    "max_tokens_final": prov["max_tokens_final"], "resumes": prov["resumes"], "cap_total_usd": prov["cap_total_usd"],
    "spend_first_pass": prov["spend_first_pass_usd"], "spend_stopped_pass": prov["spend_stopped_pass_usd"],
    "lookup": TABLE_6, "path_groups": h["H10"]["kendall_tau_b_ci"]["clusters"], "retest_briefings": len(arms["retest"]) // len(D.SLOTS),
    "labfix_findings": len(arms["fixed"]) // len(D.SLOTS), "seed": 42, "resamples": h["H10"]["kendall_tau_b_ci"]["resamples"],
}
R["labfix"]["rows"] = R["context"]["labfix_findings"]
R["lab_severity"] = saved["primary"]["lab_severity_comparison"]
rec("report", R)
print(json.dumps(R, indent=1, default=str)[:6000])
''')

code("""
(ROOT / "results_v11" / "notebook_numbers.json").write_text(json.dumps(N, indent=1, default=str))
print("numbers written:", len(N))
""")

nb = nbf.v4.new_notebook()
nb["cells"] = cells
nb["metadata"] = {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
                  "language_info": {"name": "python"}, "aivss": {"version": "1.1", "owner": "Rock Lambros"}}
nbf.write(nb, NB)
print(f"wrote {NB} ({len(cells)} cells)")
