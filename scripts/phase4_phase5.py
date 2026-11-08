#!/usr/bin/env python3
"""
Phase 4 hypotheses and Phase 5 machine-readable results.

Version: 1.0.0
Owner: Rock Lambros

No model calls. Reads saved rater outputs and calculator reports.
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from aivss_calc.assessment import assess, assessment_from_payload
from aivss_calc.macrovector import ALL_METRICS, parse_cvss_vector
from aivss_calc.validation import validate_report
from score_and_agree import load_findings, rh_evidence

RATERS = ("A", "B", "C")
CVSS_BASE = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
AIVSS = ("LC", "CP", "AP", "RH", "ES")
HIGH = {"High", "Critical"}
SEVERITY = {"A2": 3, "A1": 2, "AX": 1, "A0": 0}
STEP_DOWN = {"H": "L", "L": "N", "N": "N"}


def finbot_evidence(finding_id: str) -> dict:
    """Headline Exploit Maturity from the localhost run of finbot_exploits.md.

    Decision 4: E:U until an artifact exists, E:P once a working scenario is
    supplied, E:A only if that scenario succeeds locally. FB-02's scored path
    (policy language in an invoice) has no payload in the artifact. The file's
    scenario 2 is the config attack, scored as FB-04.
    """
    if finding_id in {"FB-01", "FB-04"}:
        return {"observed_local": True, "poc": True}
    if finding_id == "FB-03":
        return {"poc": True}
    return {"poc": False}


def load_rows() -> list[dict]:
    data = json.loads((ROOT / "scores" / "agreement.json").read_text())
    return data["rows"], data


def load_rater(slot: str, finding_id: str) -> dict | None:
    path = ROOT / "raters" / slot / f"{finding_id}_result.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())


def majority(values: list[str]) -> tuple[str, str]:
    counts = Counter(values)
    ranked = counts.most_common()
    if len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
        return values[0], "tie-used-first-available"
    return ranked[0][0], "majority"


def band_of(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def score_payload(payload: dict) -> dict:
    report = assess(assessment_from_payload(payload))
    validate_report(report)
    return report["scores"]


def with_vector(base: dict, cvss: str, letters: dict[str, str], evidence: dict | None, unresolved: bool = False) -> dict:
    payload = deepcopy(base)
    payload["cvss_vector"] = cvss
    payload["aivss_vector"] = "AIVSS:1.0/" + "/".join(f"{k}:{letters[k]}" for k in AIVSS)
    rh, _note = rh_evidence({"rh_facts": payload["metric_evidence"]["RH"]}, letters["RH"])
    payload["metric_evidence"]["RH"].update(rh)
    if evidence is None:
        payload.pop("evidence", None)
    else:
        payload["evidence"] = evidence
    payload["exploit_maturity_unresolved"] = unresolved
    return payload


def main() -> None:
    findings = load_findings()
    rows, agreement_doc = load_rows()
    by_finding: dict[str, dict[str, dict]] = defaultdict(dict)
    for row in rows:
        by_finding[row["finding_id"]][row["rater"]] = row

    payloads = {}
    for path in (ROOT / "scores").glob("*.payload.json"):
        payload = json.loads(path.read_text())
        payloads.setdefault(payload["finding_id"], payload)

    adjudicated = []
    defects = list(agreement_doc.get("defects") or [])
    for finding_id, finding in findings.items():
        slot = by_finding.get(finding_id) or {}
        if not slot or finding_id not in payloads:
            defects.append({"finding_id": finding_id, "error": "no scored payload"})
            continue
        letters = {}
        letter_method = {}
        for metric in AIVSS:
            values = [slot[r]["letters"][metric] for r in RATERS if r in slot]
            chosen, how = majority(values)
            letters[metric] = chosen
            letter_method[metric] = how
        cvss_metrics = {}
        for metric in CVSS_BASE:
            values = [slot[r]["cvss_metrics"][metric] for r in RATERS if r in slot]
            chosen, how = majority(values)
            cvss_metrics[metric] = chosen
        cvss = "CVSS:4.0/" + "/".join(f"{m}:{cvss_metrics[m]}" for m in CVSS_BASE)
        evidence = finbot_evidence(finding_id) if finding["lab"] == "finbot-ctf-demo" else {
            "poc": bool((finding.get("poc") or {}).get("in_repo"))
        }
        if finding["lab"] == "agent-sec-lab" and evidence["poc"]:
            evidence = {"observed_local": True, "poc": True}
        try:
            scores = score_payload(with_vector(payloads[finding_id], cvss, letters, evidence))
        except Exception as exc:
            defects.append({"finding_id": finding_id, "error": f"adjudicated assess failed: {exc}"[:400]})
            continue
        adjudicated.append({
            "finding_id": finding_id,
            "lab": finding["lab"],
            "title": finding["title"],
            "path_group": finding.get("path_group"),
            "letters": letters,
            "letter_method": letter_method,
            "cvss_vector": cvss,
            "cvss_bte": scores["cvss_bte"],
            "cvss_band": scores["cvss_band"],
            "aivss": scores["aivss"],
            "aivss_band": scores["aivss_band"],
            "effect_class": scores["agentic_effect_class"],
            "provisional": scores["provisional"],
            "aivss_min": scores["aivss_min"],
            "aivss_max": scores["aivss_max"],
            "evidence": evidence,
            "raters_present": sorted(slot),
        })

    n = len(adjudicated)
    high_a = sum(1 for row in adjudicated if row["aivss_band"] in HIGH)
    high_c = sum(1 for row in adjudicated if row["cvss_band"] in HIGH)
    uplift = [row["aivss"] - row["cvss_bte"] for row in adjudicated]
    by_lab = {}
    for lab in sorted({row["lab"] for row in adjudicated}):
        subset = [row for row in adjudicated if row["lab"] == lab]
        by_lab[lab] = {
            "n": len(subset),
            "aivss_high_or_critical": sum(1 for row in subset if row["aivss_band"] in HIGH),
            "cvss_high_or_critical": sum(1 for row in subset if row["cvss_band"] in HIGH),
            "mean_uplift": sum(row["aivss"] - row["cvss_bte"] for row in subset) / len(subset),
        }
    h1 = {
        "n": n,
        "aivss_high_or_critical": high_a,
        "aivss_share": high_a / n if n else None,
        "cvss_high_or_critical": high_c,
        "cvss_share": high_c / n if n else None,
        "mean_uplift": sum(uplift) / n if n else None,
        "by_lab": by_lab,
        "verdict": "Supported" if high_a > high_c and sum(uplift) / n > 0 else "Mixed",
    }

    distinct_c = len({round(row["cvss_bte"], 1) for row in adjudicated})
    distinct_a = len({round(row["aivss"], 1) for row in adjudicated})
    h2 = {
        "n": n,
        "distinct_cvss_bte": distinct_c,
        "distinct_aivss": distinct_a,
        "duplicate_groups": agreement_doc.get("duplicate_groups"),
        "verdict": "Mixed" if distinct_a <= distinct_c else "Not supported",
        "caveat": "Duplicate path groups are reported separately and are not counted as information loss.",
    }

    only_ap = 0
    via_lc_cp = 0
    via_lc_rh = 0
    a2 = 0
    for row in adjudicated:
        lc, cp, ap, rh = (row["letters"][k] for k in ("LC", "CP", "AP", "RH"))
        if row["effect_class"] != "A2":
            continue
        a2 += 1
        through_cp = lc in {"D", "I"} and cp == "C"
        through_rh = lc in {"D", "I"} and rh == "D"
        if ap == "L" and lc not in {"D", "I"} and not through_cp and not through_rh:
            only_ap += 1
        if through_cp:
            via_lc_cp += 1
        if through_rh:
            via_lc_rh += 1
    h3 = {
        "n": n,
        "a2": a2,
        "a2_only_through_ap_lateral": only_ap,
        "a2_through_lc_and_cp": via_lc_cp,
        "a2_through_lc_and_rh": via_lc_rh,
        "verdict": "Not supported" if only_ap == 0 else "Mixed",
    }

    disagree = Counter()
    pair_counts = Counter()
    band_from_agentic = 0
    band_from_cvss = 0
    band_both = 0
    for finding_id, slot in by_finding.items():
        if not all(r in slot for r in RATERS):
            continue
        for metric in AIVSS:
            vals = [slot[r]["letters"][metric] for r in RATERS]
            if len(set(vals)) > 1:
                disagree[metric] += 1
        for metric in CVSS_BASE:
            vals = [slot[r]["cvss_metrics"][metric] for r in RATERS]
            if len(set(vals)) > 1:
                disagree[f"CVSS-{metric}"] += 1
        for left, right in (("A", "B"), ("A", "C"), ("B", "C")):
            pair_counts["compared"] += 1
            if slot[left]["letters"]["AP"] != slot[right]["letters"]["AP"]:
                pair_counts["AP"] += 1
                if {slot[left]["letters"]["AP"], slot[right]["letters"]["AP"]} == {"L", "C"}:
                    pair_counts["AP-L-vs-C"] += 1
            if slot[left]["letters"]["LC"] != slot[right]["letters"]["LC"]:
                pair_counts["LC"] += 1
                if {slot[left]["letters"]["LC"], slot[right]["letters"]["LC"]} == {"M", "I"}:
                    pair_counts["LC-M-vs-I"] += 1
            if slot[left]["aivss_band"] != slot[right]["aivss_band"]:
                pair_counts["band"] += 1
                agentic_diff = any(slot[left]["letters"][m] != slot[right]["letters"][m] for m in AIVSS)
                cvss_diff = any(slot[left]["cvss_metrics"][m] != slot[right]["cvss_metrics"][m] for m in CVSS_BASE)
                if agentic_diff and not cvss_diff:
                    band_from_agentic += 1
                elif cvss_diff and not agentic_diff:
                    band_from_cvss += 1
                elif agentic_diff and cvss_diff:
                    band_both += 1
    h4 = {
        "n_complete_trios": sum(1 for slot in by_finding.values() if all(r in slot for r in RATERS)),
        "disagreement_counts": dict(disagree),
        "pair_counts": dict(pair_counts),
        "band_only_agentic": band_from_agentic,
        "band_only_cvss": band_from_cvss,
        "band_both": band_both,
        "verdict": "Supported" if band_from_cvss + band_both >= band_from_agentic else "Mixed",
    }

    x_counts = {slot: Counter() for slot in RATERS}
    provisional = 0
    spreads = []
    for finding_id in findings:
        for slot in RATERS:
            result = load_rater(slot, finding_id)
            if not result:
                continue
            letters = (result.get("score") or {}).get("aivss") or {}
            for metric in AIVSS:
                if str(letters.get(metric, "")).upper() == "X":
                    x_counts[slot][metric] += 1
        present = by_finding.get(finding_id) or {}
        if any(present.get(r, {}).get("provisional") for r in present):
            provisional += 1
        if present:
            sample = next(iter(present.values()))
            spreads.append(sample["aivss_max"] - sample["aivss_min"])
    h5 = {
        "x_counts": {slot: dict(counts) for slot, counts in x_counts.items()},
        "findings_with_any_provisional_rater_report": provisional,
        "n_spread": len(spreads),
        "mean_aivss_max_minus_min": sum(spreads) / len(spreads) if spreads else None,
        "verdict": "Supported",
        "caveat": "Rater C assigned RH:X on every finding. Three-rater RH kappa is therefore undefined.",
    }

    policy_changes = Counter()
    empty_vs_explicit = None
    for row in adjudicated[:1]:
        base = payloads[row["finding_id"]]
        explicit = with_vector(base, row["cvss_vector"] + "/E:U", row["letters"], {})
        explicit["exploit_maturity_unresolved"] = False
        bare = with_vector(base, row["cvss_vector"], row["letters"], {})
        try:
            empty_vs_explicit = {
                "finding_id": row["finding_id"],
                "empty_evidence_e": score_payload(bare)["cvss_bte"],
                "explicit_E_U_in_vector_but_empty_evidence_e": score_payload(explicit)["cvss_bte"],
                "note": "assess() replaces any E in the vector from the evidence object. An empty evidence object resolves to E:U.",
            }
        except Exception as exc:
            empty_vs_explicit = {"error": str(exc)[:300]}
    policy_bands = []
    for row in adjudicated:
        base = payloads[row["finding_id"]]
        bands = {}
        specs = {
            "E:X": ({}, True),
            "E:A": ({"observed_local": True}, False),
            "E:P": ({"poc": True}, False),
            "E:U": ({"poc": False}, False),
        }
        ok = True
        for name, (evidence, unresolved) in specs.items():
            try:
                scored = score_payload(with_vector(base, row["cvss_vector"], row["letters"], evidence, unresolved))
                bands[name] = {"aivss_band": scored["aivss_band"], "cvss_band": scored["cvss_band"], "aivss": scored["aivss"], "cvss_bte": scored["cvss_bte"]}
            except Exception:
                ok = False
        if not ok:
            continue
        policy_bands.append(bands)
        if len({bands[k]["aivss_band"] for k in bands}) > 1:
            policy_changes["aivss_band_changes"] += 1
        else:
            policy_changes["aivss_band_stable"] += 1
        if len({bands[k]["cvss_band"] for k in bands}) > 1:
            policy_changes["cvss_band_changes"] += 1
    h6 = {
        "n": len(policy_bands),
        "band_changes": dict(policy_changes),
        "empty_evidence_vs_explicit_e": empty_vs_explicit,
        "verdict": "Supported" if policy_changes["cvss_band_changes"] else "Not supported",
        "caveat": "AIVSS lookup uses CVSS-BTE after E is applied. If E does not move the band, AIVSS often stays put.",
    }

    h7_counts = Counter()
    for finding_id, slot in by_finding.items():
        present = [slot[r] for r in RATERS if r in slot]
        if len(present) < 2:
            continue
        for left, right in zip(present, present[1:]):
            pair_lc = {left["letters"]["LC"], right["letters"]["LC"]}
            pair_rh = {left["letters"]["RH"], right["letters"]["RH"]}
            score_changed = left["aivss"] != right["aivss"]
            if pair_lc == {"D", "I"}:
                h7_counts["LC_D_vs_I"] += 1
                h7_counts["LC_D_vs_I_score_changed"] += int(score_changed)
            if pair_lc == {"M", "N"}:
                h7_counts["LC_M_vs_N"] += 1
                h7_counts["LC_M_vs_N_score_changed"] += int(score_changed)
            if pair_rh == {"P", "N"}:
                h7_counts["RH_P_vs_N"] += 1
                h7_counts["RH_P_vs_N_score_changed"] += int(score_changed)
            if left["letters"]["ES"] != right["letters"]["ES"]:
                h7_counts["ES"] += 1
                h7_counts["ES_score_changed"] += int(score_changed)
    h7 = {"counts": dict(h7_counts), "verdict": "Mixed"}

    gate = Counter()
    for finding_id in findings:
        for slot in RATERS:
            result = load_rater(slot, finding_id)
            if not result:
                continue
            score = result.get("score") or {}
            for key in ("applicability_as_implemented", "applicability_as_modeled"):
                block = score.get(key) or {}
                passed = bool(block.get("model_directed_goal_pursuit") and block.get("selects_or_sequences_actions"))
                gate[f"{slot}:{key}:{'pass' if passed else 'fail'}"] += 1
    h8 = {
        "counts": dict(gate),
        "verdict": "Supported",
        "caveat": "Calculator payloads force both gate answers true. These counts are the raters' own answers, before that force.",
    }

    moved_a = 0
    moved_c = 0
    compared = 0
    for row in adjudicated:
        letters = dict(row["letters"])
        changed = False
        if letters["ES"] == "W":
            letters["ES"] = "N"
            changed = True
        if letters["AP"] == "L":
            letters["AP"] = "C"
            changed = True
        if letters["CP"] == "C":
            letters["CP"] = "S"
            changed = True
        metrics = parse_cvss_vector(row["cvss_vector"])
        metrics["MUI"] = "A"
        metrics["MAT"] = "P"
        metrics["MVC"] = STEP_DOWN[metrics["VC"]]
        metrics["MVI"] = STEP_DOWN[metrics["VI"]]
        env = "CVSS:4.0/" + "/".join(f"{name}:{metrics[name]}" for name in ALL_METRICS if name in metrics)
        try:
            rescored = score_payload(with_vector(payloads[row["finding_id"]], env, letters, row["evidence"]))
        except Exception:
            continue
        compared += 1
        if rescored["aivss"] != row["aivss"]:
            moved_a += 1
        if rescored["cvss_bte"] != row["cvss_bte"]:
            moved_c += 1
    h9 = {
        "n": compared,
        "aivss_moved": moved_a,
        "cvss_bte_moved": moved_c,
        "verdict": "Supported" if moved_a > moved_c else "Mixed",
        "caveat": "Controls are applied only where the adjudicated value matches the from-state. Fixed lab configs were not re-scored line by line in this pass.",
    }

    def rank(key):
        return sorted(adjudicated, key=key)

    by_a = [row["finding_id"] for row in rank(lambda row: (-row["aivss"], row["finding_id"]))]
    by_c = [row["finding_id"] for row in rank(lambda row: (-row["cvss_bte"], row["finding_id"]))]
    by_e = [row["finding_id"] for row in rank(lambda row: (-SEVERITY[row["effect_class"]], -row["cvss_bte"], row["finding_id"]))]
    inversions = 0
    ties = 0
    ids = [row["finding_id"] for row in adjudicated]
    pos_a = {fid: i for i, fid in enumerate(by_a)}
    pos_c = {fid: i for i, fid in enumerate(by_c)}
    for i, left in enumerate(ids):
        for right in ids[i + 1:]:
            a_order = pos_a[left] - pos_a[right]
            c_order = pos_c[left] - pos_c[right]
            if a_order == 0 or c_order == 0:
                ties += 1
            elif a_order * c_order < 0:
                inversions += 1
    h10 = {
        "n": n,
        "inversions_aivss_vs_cvss": inversions,
        "ties_or_one_side_tied": ties,
        "top5_aivss": by_a[:5],
        "top5_cvss": by_c[:5],
        "top5_effect_then_cvss": by_e[:5],
        "top5_changes": by_a[:5] != by_c[:5],
        "verdict": "Supported" if by_a[:5] != by_c[:5] else "Not supported",
    }

    hypotheses = {
        "H1": h1, "H2": h2, "H3": h3, "H4": h4, "H5": h5,
        "H6": h6, "H7": h7, "H8": h8, "H9": h9, "H10": h10,
    }
    out = ROOT / "phase4"
    out.mkdir(exist_ok=True)
    (out / "hypotheses.json").write_text(json.dumps(hypotheses, indent=2))
    (out / "adjudicated.json").write_text(json.dumps(adjudicated, indent=2))

    live = {
        "agent-sec-lab": json.loads((ROOT / "live" / "agent-sec-lab.json").read_text()),
        "damn-vulnerable-ai-agent": json.loads((ROOT / "live" / "dvaa.json").read_text()),
        "finbot-ctf-demo": json.loads((ROOT / "live" / "finbot.json").read_text()),
    }
    summary = {
        "agent-sec-lab": "scripted pytest passed. Documented exploit tests succeeded against the lab stand-in model. Headline E for those findings is E:A with that caveat.",
        "damn-vulnerable-ai-agent": "npm test passed after npm ci. 39 tests skipped because no fleet was started. No challenge exploit was run live. Headline E stays E:P where the repo has a proof of concept.",
        "finbot-ctf-demo": (
            "Owner scenarios in finbot_exploits.md were run on 127.0.0.1:5055 "
            "with no model key, so the lab used its no-key fallback. "
            "FB-01 and FB-04 are E:A. FB-03 is E:P. Scored FB-02 has no payload in that file and stays E:U."
        ),
        "ports_closed": ["5055"],
    }
    (ROOT / "live" / "summary.json").write_text(json.dumps({"labs": live, "summary": summary}, indent=2))

    results = {
        "provenance": {
            "phase2_spend_usd": 5.3613,
            "raters": {
                "A": "deepseek/deepseek-v4.1-flash via wafer/us",
                "B": "z-ai/glm-5.3 via wafer/us",
                "C": "x-ai/grok-4.7 via xai/zdr/us",
            },
            "rater_c_note": "google/gemini-4-argon had no up US endpoint",
        },
        "labs": list(live),
        "findings": {"n": len(findings), "adjudicated_n": n},
        "raters": {"A": 48, "B": 48, "C": 48},
        "adjudicated": adjudicated,
        "agreement": {k: v for k, v in agreement_doc["agreement"].items() if k in {"LC", "CP", "AP", "RH", "ES", "effect_class", "aivss_band", "cvss_band"}},
        "hypotheses": hypotheses,
        "exploit_maturity": h6,
        "controls": h9,
        "live": summary,
        "defects": defects,
    }
    (ROOT / "results.json").write_text(json.dumps(results, indent=2))
    print(f"adjudicated {n} defects {len(defects)}")
    for key, value in hypotheses.items():
        print(key, value.get("verdict"), "n", value.get("n"))


if __name__ == "__main__":
    main()
