#!/usr/bin/env python3
"""Recompute every v1.1 score, statistic, and verdict from saved assessor outputs.

Version: 1.1.0
Owner: Rock Lambros

No model calls. Reads runs/<run_id>/ (the run named in runs/CANONICAL) and
runs/v1.0/, writes results_v11/. Deterministic: sorted inputs, seed 42.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aivss_v11 import data as D  # noqa: E402
from aivss_v11 import hypotheses as H  # noqa: E402

ROOT = D.ROOT
OUT = ROOT / "results_v11"
V10_SPEND_USD = 5.466454  # first scoring run, sum of usage.cost in its result files (premortem P11)


def superseded_spend() -> float:
    """Spend of runs stopped and superseded during v1.1 (counted against the cap, never cited)."""
    total = 0.0
    for m in sorted((ROOT / "runs").glob("v11-2*/manifest.json")):
        man = json.loads(m.read_text())
        if man.get("stopped_by_owner"):
            total += float(man.get("spend_run_usd") or 0)
    return total


def median(xs: list) -> float | None:
    xs = sorted(xs)
    return xs[len(xs) // 2] if xs else None


def canonical_run() -> Path:
    rid = (ROOT / "runs" / "CANONICAL").read_text().strip()
    run = ROOT / "runs" / rid
    manifest = json.loads((run / "manifest.json").read_text())
    if manifest.get("halted"):
        raise SystemExit(f"run {rid} halted. Not canonical.")
    return run


def scored_arm(run: Path, arm: str, findings, emr) -> list[dict]:
    return D.score_rows([D.parse(r) for r in D.load_v11(run, arm)], findings, emr)


def defect_table(base: list[dict], packets_manifest: dict) -> dict:
    bearing = {p["finding_id"] for p in packets_manifest["packets"] if p["arm"] == "base" and p["payload_lines_in_excerpts"] > 0}
    out = {}
    for s in D.SLOTS:
        rows = [r for r in base if r["slot"] == s]
        a = sum(1 for r in rows if r["finding_id"] in bearing and r["defects"])
        b = sum(1 for r in rows if r["finding_id"] in bearing and not r["defects"])
        c = sum(1 for r in rows if r["finding_id"] not in bearing and r["defects"])
        d = sum(1 for r in rows if r["finding_id"] not in bearing and not r["defects"])
        out[s] = {"payload_bearing_defect": a, "payload_bearing_clean": b, "payload_free_defect": c, "payload_free_clean": d,
                  "fisher_p": H.fisher_exact(a, b, c, d)}
    return out


def strip_private(d: dict) -> dict:
    return {k: v for k, v in d.items() if not k.startswith("_")}


def main() -> int:
    OUT.mkdir(exist_ok=True)
    findings = D.load_findings()
    emr = D.write_exploit_maturity(findings, OUT / "exploit_maturity.json")
    run = canonical_run()
    manifest = json.loads((run / "manifest.json").read_text())
    packets_manifest = json.loads((ROOT / "packets_v11" / "manifest.json").read_text())
    arms = {a: scored_arm(run, a, findings, emr) for a in manifest["arms"]}

    primary = H.analyze(arms["base"], findings, emr, {"fixed": arms["fixed"]}, label="v1.1")

    controls = {
        "retest_vs_base": H.compare_rows(arms["base"], arms["retest"]),
        "ablation_vs_base": H.compare_rows(arms["base"], arms["ablation"]),
        "canary": {arm: {s: sum(1 for r in rows if r["slot"] == s and r.get("canary_followed")) for s in D.SLOTS}
                   for arm, rows in arms.items()},
        "canary_rows_per_assessor": {arm: len(rows) // len(D.SLOTS) for arm, rows in arms.items()},
        "defects_by_payload": defect_table(arms["base"], packets_manifest),
        "defects_by_arm": {arm: {s: dict(Counter(d.split(":")[0] for r in rows if r["slot"] == s for d in r["defects"])) for s in D.SLOTS} for arm, rows in arms.items()},
    }
    cells = manifest["cells"]
    spend = sum(float(json.loads(x)["usd"] or 0) for x in (run / "spend.jsonl").read_text().splitlines() if x.strip())
    dry = sum(float(json.loads(x)["usd"] or 0) for p in sorted((ROOT / "runs").glob("v11-dryrun-*/spend.jsonl")) for x in p.read_text().splitlines() if x.strip())
    provenance = {
        "run_id": manifest["run_id"], "started": manifest["started"], "finished": manifest.get("finished"),
        "status_counts": manifest.get("status_counts"), "endpoint_record_unchanged": manifest.get("endpoint_record_unchanged"),
        "pins": manifest["pins"], "max_tokens": manifest["max_tokens"], "spend_run_usd": round(spend, 6),
        "spend_dry_runs_usd": round(dry, 6), "spend_earlier_scoring_usd": round(V10_SPEND_USD + superseded_spend(), 6),
        "spend_first_pass_usd": V10_SPEND_USD, "spend_stopped_pass_usd": round(superseded_spend(), 6),
        "max_tokens_final": max(([r.get("max_tokens", {}).get("default") for r in manifest.get("resumes", [])] or [manifest["max_tokens"]["default"]])),
        "cap_total_usd": 500.0, "resumes": len(manifest.get("resumes", [])),
        "key_usage_before": manifest.get("key_usage_before"), "key_usage_after": manifest.get("key_usage_after"),
        "attempts": sum(len(c.get("attempts") or []) for c in cells), "retried_cells": sum(1 for c in cells if len(c.get("attempts") or []) > 1),
        "reasoning_tokens_median": {s: median([a.get("reasoning_tokens") or 0 for c in cells if c["slot"] == s for a in c.get("attempts") or []]) for s in D.SLOTS},
        "criteria_sha256": manifest["criteria_sha256"], "packet_manifest_sha256": manifest["packet_manifest_sha256"],
        "script_sha256": manifest["script_sha256"],
    }
    provenance["spend_total_usd"] = round(provenance["spend_earlier_scoring_usd"] + spend + dry, 6)
    results = {"version": "1.1.0", "owner": "Rock Lambros", "provenance": provenance,
               "exploit_maturity": {f: v["e"] for f, v in emr.items()},
               "primary": strip_private(primary), "controls": controls}
    (OUT / "results.json").write_text(json.dumps(results, indent=2, default=str))
    (OUT / "adjudicated.json").write_text(json.dumps(primary["_adjudicated"], indent=2, default=str))
    (OUT / "adjudication_disagreements.json").write_text(json.dumps(primary["_disagreements"], indent=2))
    with (OUT / "findings.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["finding_id", "target_application", "title", "exploit_maturity", "cvss_vector", "cvss_bt", "cvss_band",
                    "aivss_vector", "agent_class", "aivss", "aivss_band", "provisional", "aivss_min", "aivss_max",
                    "gate_as_implemented_majority", "gate_as_modeled_majority"])
        for fid, a in sorted(primary["_adjudicated"].items()):
            s = a["scores"] or {}
            w.writerow([fid, a["lab"], a["title"], emr[fid]["e"], a["cvss_vector"], s.get("cvss_bt"), s.get("cvss_band"),
                        "AIVSS:1.0/" + "/".join(f"{k}:{a['letters'][k]}" for k in D.AIVSS), s.get("effect_class"), s.get("aivss"),
                        s.get("aivss_band"), s.get("provisional"), s.get("aivss_min"), s.get("aivss_max"),
                        a["gate_majority"]["applicability_as_implemented"], a["gate_majority"]["applicability_as_modeled"]])
    with (OUT / "agreement.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["metric", "n", "p0", "fleiss_kappa", "declined", "ci_low", "ci_high", "ci_defined_resamples", "prevalence",
                    "excluded_unknown", "alpha", "kappa_A_B", "kappa_A_C", "kappa_B_C"])
        for m, blk in primary["agreement"].items():
            w.writerow([m, blk["n"], blk.get("p0"), blk.get("kappa"), blk.get("declined"), blk["ci"].get("low"), blk["ci"].get("high"),
                        blk["ci"].get("defined"), json.dumps(blk.get("prevalence")), blk.get("excluded_unknown"),
                        blk["alpha"].get("alpha"), *[blk["pairwise"][p].get("kappa") for p in ("A-B", "A-C", "B-C")]])
    print("verdicts", {k: v["verdict"] for k, v in primary["hypotheses"].items()})
    print("spend run", provenance["spend_run_usd"], "total", provenance["spend_total_usd"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
