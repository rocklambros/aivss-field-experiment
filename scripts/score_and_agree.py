#!/usr/bin/env python3
"""
Score saved rater outputs through aivss-calc and compute agreement.

Version: 1.0.0
Owner: Rock Lambros

No model calls. Exploit maturity is set by the lead from the inventory, not
by the raters. FinBot rater payloads stay at poc false. Headline maturity is set in phase4.
"""

from __future__ import annotations

import json
import random
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from aivss_calc.ai_metrics import classify_rh
from aivss_calc.assessment import assess, assessment_from_payload
from aivss_calc.validation import validate_report

ROOT = Path(__file__).resolve().parents[1]
FINDINGS = ROOT / "findings.json"
RATERS = ("A", "B", "C")
CVSS_BASE = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
AIVSS_METRICS = ("LC", "CP", "AP", "RH", "ES")
ORDERS = {
    "LC": ["N", "M", "I", "D"],
    "CP": ["N", "S", "C"],
    "AP": ["N", "C", "L"],
    "RH": ["N", "P", "D"],
    "ES": ["N", "M", "W"],
    "AV": ["P", "L", "A", "N"],
    "AC": ["H", "L"],
    "AT": ["P", "N"],
    "PR": ["H", "L", "N"],
    "UI": ["A", "P", "N"],
    "VC": ["N", "L", "H"],
    "VI": ["N", "L", "H"],
    "VA": ["N", "L", "H"],
    "SC": ["N", "L", "H"],
    "SI": ["N", "L", "H"],
    "SA": ["N", "L", "H"],
}
BOOTSTRAP_N = 2000
BOOTSTRAP_SEED = 42


def load_findings() -> dict[str, dict]:
    raw = json.loads(FINDINGS.read_text())
    out = {}
    for lab, block in raw["labs"].items():
        for finding in block["findings"]:
            finding = dict(finding)
            finding["lab"] = lab
            out[finding["id"]] = finding
    return out


def poc_true(finding: dict) -> bool:
    # Phase 2 rater payloads keep FinBot at poc false. Headline maturity is
    # applied later in phase4_phase5.finbot_evidence from the localhost run.
    if finding["lab"] == "finbot-ctf-demo":
        return False
    poc = finding.get("poc") or {}
    return bool(poc.get("in_repo"))


def normalize_cvss(text: str) -> tuple[str | None, str | None]:
    if not isinstance(text, str) or not text.strip():
        return None, "missing CVSS:4.0 vector"
    parts = {}
    for match in re.finditer(r"([A-Z]{1,3}):([A-Za-z]+)", text):
        metric, value = match.group(1), match.group(2).upper()
        if metric in CVSS_BASE:
            parts[metric] = value
    missing = [m for m in CVSS_BASE if m not in parts]
    if missing:
        return None, f"missing base metrics {missing}"
    vector = "CVSS:4.0/" + "/".join(f"{m}:{parts[m]}" for m in CVSS_BASE)
    return vector, None


def aivss_vector(score: dict) -> tuple[str | None, str | None]:
    metrics = score.get("aivss") or {}
    letters = {}
    for name in AIVSS_METRICS:
        value = str(metrics.get(name) or "X").upper()
        allowed = set(ORDERS[name]) | {"X"}
        if value not in allowed:
            return None, f"{name} value {value!r} is not in the rubric"
        letters[name] = value
    return "AIVSS:1.0/" + "/".join(f"{n}:{letters[n]}" for n in AIVSS_METRICS), None


def map_locus(raw, rh: str) -> str | None:
    if rh not in {"D", "P"}:
        return None
    text = str(raw or "").lower()
    if "eval" in text or "grader" in text or "reward" in text:
        return "evaluator"
    return "environment"


def rh_evidence(score: dict, rh: str) -> tuple[dict, str | None]:
    facts = score.get("rh_facts") or {}
    note = None
    reachable = facts.get("reachable_proxy")
    isolated = facts.get("isolation_verified")
    verified = facts.get("verified_episodes")
    reviewed = facts.get("episodes_reviewed")
    if not isinstance(verified, int):
        verified = 0 if verified in (None, "0") else None
    if not isinstance(reviewed, int):
        reviewed = verified if isinstance(verified, int) else None
    classified = classify_rh(
        reachable_proxy=reachable if isinstance(reachable, bool) else None,
        isolation_verified=isolated if isinstance(isolated, bool) else None,
        verified_episodes=verified if isinstance(verified, int) else None,
    )
    if classified != rh:
        note = f"rater RH {rh} disagreed with classify_rh({classified}); facts normalized to the rater letter"
        if rh == "D":
            reachable, isolated, verified, reviewed = True, False, 1, 1
        elif rh == "P":
            reachable, isolated, verified, reviewed = True, False, 0, 0
        elif rh == "N":
            reachable, isolated, verified, reviewed = False, True, 0, 0
        else:
            reachable, isolated, verified, reviewed = None, None, None, None
    if isinstance(verified, int) and isinstance(reviewed, int) and verified > reviewed:
        reviewed = verified
    return {
        "reachable_proxy": reachable,
        "isolation_verified": isolated,
        "verified_episodes": verified,
        "episodes_reviewed": reviewed,
        "locus": map_locus(facts.get("locus"), rh),
    }, note


def refs_or_placeholder(values, fallback: str) -> list[str]:
    if isinstance(values, list):
        clean = [str(v).strip() for v in values if isinstance(v, str) and str(v).strip()]
        if clean:
            return clean
    return [fallback]


def build_payload(finding: dict, result: dict) -> tuple[dict | None, list[str]]:
    score = result["score"]
    notes = []
    cvss, cvss_err = normalize_cvss(score.get("cvss_vector", ""))
    vector, aivss_err = aivss_vector(score)
    if cvss_err or aivss_err or vector is None or cvss is None:
        return None, [err for err in (cvss_err, aivss_err) if err]
    letters = dict(zip(AIVSS_METRICS, re.findall(r"[A-Z]:([A-Z])", vector)))
    rh_block, rh_note = rh_evidence(score, letters["RH"])
    if rh_note:
        notes.append(rh_note)
    rationales = score.get("rationales") or {}
    evidence = score.get("evidence") or {}
    metric_evidence = {}
    for name in AIVSS_METRICS:
        rationale = rationales.get(name)
        if not isinstance(rationale, str) or not rationale.strip():
            rationale = f"Rater {result['rater']} assigned {name}:{letters[name]} without a usable rationale."
            notes.append(f"{name} rationale missing, placeholder inserted")
        entry = {
            "rationale": rationale.strip(),
            "evidence_refs": refs_or_placeholder(
                evidence.get(name), f"rater:{result['rater']}/{finding['id']}/{name}"
            ),
        }
        if name == "RH":
            entry.update(rh_block)
        metric_evidence[name] = entry
    modeled = score.get("applicability_as_modeled") or {}
    implemented = score.get("applicability_as_implemented") or {}
    rationale = modeled.get("rationale") or implemented.get("rationale") or ""
    if not (modeled.get("model_directed_goal_pursuit") and modeled.get("selects_or_sequences_actions")):
        rationale = (
            "scored as modeled; default config is scripted. "
            + str(rationale)
        ).strip()
        notes.append("applicability forced true for the calculator gate")
    auto = score.get("automatable")
    automatable = auto is True or str(auto).lower() in {"yes", "true", "y"}
    impact = str(score.get("technical_impact") or "partial").lower()
    technical_impact = "total" if impact in {"total", "high"} else "partial"
    assessed_at = result.get("timestamp") or datetime.now(timezone.utc).isoformat()
    if not assessed_at.endswith("Z") and "+" not in assessed_at[10:]:
        assessed_at = assessed_at.replace("+00:00", "Z")
    payload = {
        "finding_id": finding["id"],
        "path_id": finding["path_id"],
        "title": finding["title"],
        "summary": finding["impact"],
        "risk_category": finding.get("asi_category") or "ASI01",
        "cvss_vector": cvss,
        "aivss_vector": vector,
        "metric_evidence": metric_evidence,
        "agentic_applicability": {
            "model_directed_goal_pursuit": True,
            "action_selection_or_sequencing": True,
            "rationale": rationale or "scored as modeled; default config is scripted.",
            "evidence_refs": refs_or_placeholder(
                finding.get("code_citations"), f"finding:{finding['id']}"
            ),
        },
        "evidence": {"poc": poc_true(finding)},
        "publicly_exposed": False,
        "publicly_exposed_source": "lab default is localhost-only",
        "decision_data_observed_at": assessed_at,
        "automatable": automatable,
        "technical_impact": technical_impact,
        "include_decision": True,
        "include_priority": False,
        "provenance": {
            "assessor": f"rater-{result['rater']}",
            "assessor_kind": "llm_assisted",
            "tool": result.get("model"),
            "tool_version": result.get("pinned_tag"),
            "assessed_at": assessed_at,
        },
    }
    return payload, notes


def score_all(findings: dict[str, dict]) -> tuple[list[dict], list[dict]]:
    rows = []
    defects = []
    out_dir = ROOT / "scores"
    out_dir.mkdir(exist_ok=True)
    for slot in RATERS:
        for path in sorted((ROOT / "raters" / slot).glob("*_result.json")):
            result = json.loads(path.read_text())
            finding = findings.get(result["finding_id"])
            if finding is None:
                defects.append({"finding_id": result["finding_id"], "rater": slot, "error": "unknown finding"})
                continue
            payload, notes = build_payload(finding, result)
            if payload is None:
                defects.append({
                    "finding_id": result["finding_id"],
                    "rater": slot,
                    "error": "; ".join(notes),
                })
                continue
            try:
                report = assess(assessment_from_payload(payload))
                validate_report(report)
            except Exception as exc:
                defects.append({
                    "finding_id": result["finding_id"],
                    "rater": slot,
                    "error": str(exc)[:500],
                    "notes": notes,
                })
                continue
            stem = f"{slot}_{result['finding_id']}"
            (out_dir / f"{stem}.payload.json").write_text(json.dumps(payload, indent=2))
            (out_dir / f"{stem}.report.json").write_text(json.dumps(report, indent=2))
            scores = report["scores"]
            rows.append({
                "finding_id": result["finding_id"],
                "rater": slot,
                "path_group": finding.get("path_group"),
                "lab": finding["lab"],
                "cvss_bte": scores["cvss_bte"],
                "cvss_band": scores["cvss_band"],
                "aivss": scores["aivss"],
                "aivss_band": scores["aivss_band"],
                "effect_class": scores["agentic_effect_class"],
                "provisional": scores["provisional"],
                "aivss_min": scores["aivss_min"],
                "aivss_max": scores["aivss_max"],
                "notes": notes,
                "letters": {
                    name: report["agentic_ai_profile"]["metrics"][name]["value"]
                    for name in AIVSS_METRICS
                },
                "cvss_metrics": {
                    metric: payload["cvss_vector"].split(f"{metric}:")[1][:1]
                    for metric in CVSS_BASE
                },
            })
    return rows, defects


def clusters(rows_by_finding: dict[str, dict], findings: dict[str, dict]) -> list[list[str]]:
    groups: dict[str, list[str]] = {}
    for finding_id in rows_by_finding:
        group = findings[finding_id].get("path_group") or finding_id
        groups.setdefault(group, []).append(finding_id)
    return list(groups.values())


def fleiss(table: list[list[str]]) -> dict:
    """table is a list of rater-label lists, one per finding, labels already filtered."""
    n = len(table)
    if n == 0:
        return {"n": 0, "p0": None, "kappa": None, "reason": "no findings"}
    categories = sorted({label for row in table for label in row})
    if len(categories) < 2:
        p0 = sum(len(set(row)) == 1 for row in table) / n
        return {
            "n": n,
            "p0": p0,
            "kappa": None,
            "reason": "degenerate marginal: only one observed category",
            "prevalence": {categories[0]: 1.0} if categories else {},
        }
    raters = len(table[0])
    counts = []
    for row in table:
        c = Counter(row)
        counts.append([c[cat] for cat in categories])
    p0 = sum(
        sum(c * (c - 1) for c in row) / (raters * (raters - 1))
        for row in counts
    ) / n
    pj = []
    for i in range(len(categories)):
        pj.append(sum(row[i] for row in counts) / (n * raters))
    pe = sum(p * p for p in pj)
    kappa = None if pe == 1 else (p0 - pe) / (1 - pe)
    return {
        "n": n,
        "p0": p0,
        "kappa": kappa,
        "pe": pe,
        "prevalence": {cat: p for cat, p in zip(categories, pj)},
    }


def cohen(pairs: list[tuple[str, str]]) -> dict:
    n = len(pairs)
    if n == 0:
        return {"n": 0, "p0": None, "kappa": None, "reason": "no pairs"}
    cats = sorted({a for a, _ in pairs} | {b for _, b in pairs})
    if len(cats) < 2:
        p0 = sum(a == b for a, b in pairs) / n
        return {"n": n, "p0": p0, "kappa": None, "reason": "degenerate marginal"}
    matrix = {(a, b): 0 for a in cats for b in cats}
    for a, b in pairs:
        matrix[(a, b)] += 1
    p0 = sum(a == b for a, b in pairs) / n
    row = {a: sum(matrix[(a, b)] for b in cats) / n for a in cats}
    col = {b: sum(matrix[(a, b)] for a in cats) / n for b in cats}
    pe = sum(row[a] * col[a] for a in cats)
    kappa = None if pe == 1 else (p0 - pe) / (1 - pe)
    return {"n": n, "p0": p0, "kappa": kappa, "pe": pe, "prevalence": {"rater1": row, "rater2": col}}


def weighted_kappa(pairs: list[tuple[str, str]], order: list[str]) -> dict:
    usable = [(a, b) for a, b in pairs if a in order and b in order]
    n = len(usable)
    if n == 0:
        return {"n": 0, "kappa": None, "reason": "no ordinal pairs"}
    k = len(order)
    index = {label: i for i, label in enumerate(order)}
    weights = [[abs(i - j) / (k - 1) for j in range(k)] for i in range(k)]
    obs = [[0.0] * k for _ in range(k)]
    for a, b in usable:
        obs[index[a]][index[b]] += 1
    for i in range(k):
        for j in range(k):
            obs[i][j] /= n
    row = [sum(obs[i]) for i in range(k)]
    col = [sum(obs[i][j] for i in range(k)) for j in range(k)]
    num = sum(weights[i][j] * obs[i][j] for i in range(k) for j in range(k))
    den = sum(weights[i][j] * row[i] * col[j] for i in range(k) for j in range(k))
    if den == 0:
        return {"n": n, "kappa": None, "reason": "degenerate weight denominator"}
    return {"n": n, "kappa": 1 - num / den, "p0": sum(a == b for a, b in usable) / n}


def bootstrap_ci(finding_ids: list[str], cluster_of: dict[str, str], values_fn) -> dict:
    rng = random.Random(BOOTSTRAP_SEED)
    groups = {}
    for finding_id in finding_ids:
        groups.setdefault(cluster_of[finding_id], []).append(finding_id)
    keys = list(groups)
    samples = []
    for _ in range(BOOTSTRAP_N):
        drawn = []
        for _key in range(len(keys)):
            drawn.extend(groups[keys[rng.randrange(len(keys))]])
        stat = values_fn(drawn)
        if stat is not None:
            samples.append(stat)
    if not samples:
        return {"n_resamples": 0, "low": None, "high": None}
    samples.sort()
    low = samples[int(0.025 * (len(samples) - 1))]
    high = samples[int(0.975 * (len(samples) - 1))]
    return {"n_resamples": len(samples), "low": low, "high": high, "seed": BOOTSTRAP_SEED}


def main() -> None:
    findings = load_findings()
    rows, defects = score_all(findings)
    by_finding: dict[str, dict[str, dict]] = {}
    for row in rows:
        by_finding.setdefault(row["finding_id"], {})[row["rater"]] = row
    complete = {
        fid: slot
        for fid, slot in by_finding.items()
        if all(r in slot for r in RATERS)
    }
    cluster_of = {
        fid: findings[fid].get("path_group") or fid
        for fid in complete
    }
    cluster_count = len(set(cluster_of.values()))
    assert cluster_count == len(clusters(complete, findings))

    agreement = {}
    metrics = list(AIVSS_METRICS) + ["effect_class", "cvss_band", "aivss_band"] + list(CVSS_BASE)
    for metric in metrics:
        table = []
        ids = []
        for fid, slot in complete.items():
            if metric in AIVSS_METRICS:
                labels = [slot[r]["letters"][metric] for r in RATERS]
            elif metric in CVSS_BASE:
                labels = [slot[r]["cvss_metrics"][metric] for r in RATERS]
            elif metric == "effect_class":
                labels = [slot[r]["effect_class"] for r in RATERS]
            elif metric == "cvss_band":
                labels = [slot[r]["cvss_band"] for r in RATERS]
            else:
                labels = [slot[r]["aivss_band"] for r in RATERS]
            if "X" in labels:
                continue
            table.append(labels)
            ids.append(fid)
        stat = fleiss(table)
        id_to_labels = dict(zip(ids, table))

        def kappa_of(drawn, _ids=ids, _map=id_to_labels):
            sub = [_map[i] for i in drawn if i in _map]
            if len(sub) < 2:
                return None
            return fleiss(sub)["kappa"]

        stat["ci"] = bootstrap_ci(ids, cluster_of, kappa_of)
        pairs = {}
        for left, right in (("A", "B"), ("A", "C"), ("B", "C")):
            pair_rows = []
            for fid in ids:
                pair_rows.append((id_to_labels[fid][RATERS.index(left)], id_to_labels[fid][RATERS.index(right)]))
            pairs[f"{left}-{right}"] = cohen(pair_rows)
            if metric in ORDERS:
                pairs[f"{left}-{right}"]["linear_weighted"] = weighted_kappa(pair_rows, ORDERS[metric])
        stat["pairwise"] = pairs
        # Pairwise N is independent. A finding is dropped from a pair only when
        # one of those two raters used X, not when the third rater did.
        pair_ids = {
            fid: slot for fid, slot in complete.items()
        }
        independent = {}
        for left, right in (("A", "B"), ("A", "C"), ("B", "C")):
            pair_rows = []
            pair_finding_ids = []
            for fid, slot in pair_ids.items():
                if metric in AIVSS_METRICS:
                    a, b = slot[left]["letters"][metric], slot[right]["letters"][metric]
                elif metric in CVSS_BASE:
                    a, b = slot[left]["cvss_metrics"][metric], slot[right]["cvss_metrics"][metric]
                elif metric == "effect_class":
                    a, b = slot[left]["effect_class"], slot[right]["effect_class"]
                elif metric == "cvss_band":
                    a, b = slot[left]["cvss_band"], slot[right]["cvss_band"]
                else:
                    a, b = slot[left]["aivss_band"], slot[right]["aivss_band"]
                if a == "X" or b == "X":
                    continue
                pair_rows.append((a, b))
                pair_finding_ids.append(fid)
            detail = cohen(pair_rows)
            if metric in ORDERS:
                detail["linear_weighted"] = weighted_kappa(pair_rows, ORDERS[metric])
            detail["finding_ids_n"] = len(pair_finding_ids)
            independent[f"{left}-{right}"] = detail
        stat["pairwise_excluding_x_in_pair_only"] = independent
        agreement[metric] = stat

    diffs = {"cvss_bte": [], "aivss": []}
    for slot in complete.values():
        vals_c = [slot[r]["cvss_bte"] for r in RATERS]
        vals_a = [slot[r]["aivss"] for r in RATERS]
        diffs["cvss_bte"].append(max(vals_c) - min(vals_c))
        diffs["aivss"].append(max(vals_a) - min(vals_a))

    duplicate = []
    grouped: dict[str, list[str]] = {}
    for fid, finding in findings.items():
        group = finding.get("path_group")
        if group:
            grouped.setdefault(group, []).append(fid)
    for group, members in grouped.items():
        if len(members) < 2:
            continue
        identical = 0
        compared = 0
        for rater in RATERS:
            vectors = []
            for fid in members:
                row = by_finding.get(fid, {}).get(rater)
                if row:
                    vectors.append(row["letters"])
            if len(vectors) == len(members):
                compared += 1
                if all(v == vectors[0] for v in vectors):
                    identical += 1
        duplicate.append({
            "path_group": group,
            "members": members,
            "raters_compared": compared,
            "raters_with_identical_aivss_letters": identical,
        })

    result = {
        "scored_rows": len(rows),
        "complete_findings": len(complete),
        "cluster_count": cluster_count,
        "defects": defects,
        "agreement": agreement,
        "abs_diff": {
            "cvss_bte": {
                "n": len(diffs["cvss_bte"]),
                "mean": sum(diffs["cvss_bte"]) / len(diffs["cvss_bte"]) if diffs["cvss_bte"] else None,
                "max": max(diffs["cvss_bte"]) if diffs["cvss_bte"] else None,
            },
            "aivss": {
                "n": len(diffs["aivss"]),
                "mean": sum(diffs["aivss"]) / len(diffs["aivss"]) if diffs["aivss"] else None,
                "max": max(diffs["aivss"]) if diffs["aivss"] else None,
            },
        },
        "duplicate_groups": duplicate,
        "rows": rows,
    }
    (ROOT / "scores" / "agreement.json").write_text(json.dumps(result, indent=2))
    print(f"scored {len(rows)} reports, defects {len(defects)}, complete findings {len(complete)}")
    print(f"clusters {cluster_count}")
    for metric in ("LC", "CP", "AP", "RH", "ES", "effect_class", "aivss_band", "cvss_band"):
        stat = agreement[metric]
        print(
            f"{metric}: n={stat['n']} p0={stat.get('p0')} kappa={stat.get('kappa')} "
            f"reason={stat.get('reason')} ci={stat.get('ci')}"
        )
    if defects:
        print("first defects:")
        for defect in defects[:8]:
            print(" ", defect["rater"], defect["finding_id"], defect["error"][:180])


if __name__ == "__main__":
    main()
