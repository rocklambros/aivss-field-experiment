"""H1 to H10, the control arms, and the agreement tables for v1.1.

Version: 1.1.0
Owner: Rock Lambros

Every verdict is computed from premortem/hypothesis_criteria.json (v1.1.1).
Closes K1 to K5, P15, P17, P18, P22, P31, P34 to P36, P39, P40, P43, P45,
P47, P48, P59, P71, P74.
"""

from __future__ import annotations

import json
import math
import random
from collections import Counter, defaultdict
from copy import deepcopy
from itertools import combinations
from pathlib import Path

from aivss_calc.ai_metrics import AIProfile
from aivss_calc.lookup import aivss_lookup
from aivss_calc.macrovector import ALL_METRICS, parse_cvss_vector

from . import data as D
from . import stats as S
from .adjudicate import adjudicate_finding, disagreement_record

ROOT = D.ROOT
HIGH = {"High", "Critical"}
CLASS_RANK = {"A2": 3, "A1": 2, "AX": 1, "A0": 0}
STEP_DOWN = {"H": "L", "L": "N", "N": "N"}
CRITERIA = json.loads((ROOT / "premortem" / "hypothesis_criteria.json").read_text())


# ---------------------------------------------------------------- helpers

def fisher_exact(a: int, b: int, c: int, d: int) -> float:
    """Two-sided Fisher exact p for [[a, b], [c, d]]."""
    n1, n2, m1, n = a + b, c + d, a + c, a + b + c + d

    def p(x):
        return math.comb(n1, x) * math.comb(n2, m1 - x) / math.comb(n, m1)

    obs = p(a)
    lo, hi = max(0, m1 - n2), min(n1, m1)
    return min(1.0, sum(p(x) for x in range(lo, hi + 1) if p(x) <= obs * (1 + 1e-9)))


def synth_parsed(rows: dict[str, dict], adj: dict) -> dict:
    autos = Counter(r.get("automatable") for r in rows.values() if r.get("automatable") is not None)
    tis = Counter(r.get("technical_impact") for r in rows.values() if r.get("technical_impact"))
    return {"letters": adj["letters"], "rh_facts": adj["rh_facts"], "rationales": {},
            "applicability_as_implemented": {"pass": adj["gate_majority"]["applicability_as_implemented"]},
            "applicability_as_modeled": {"pass": adj["gate_majority"]["applicability_as_modeled"]},
            "automatable": autos.most_common(1)[0][0] if autos else False,
            "technical_impact": tis.most_common(1)[0][0] if tis else "partial"}


def score_adjudicated(f: dict, rows: dict, adj: dict, evidence: dict, *, cvss: str | None = None,
                      letters: dict | None = None, unresolved: bool = False) -> dict | None:
    if not (cvss or adj["cvss_vector"]):
        return None
    p = synth_parsed(rows, adj)
    try:
        return D.score(D.build_payload(f, f["lab"], p, evidence, cvss_vector=cvss or adj["cvss_vector"],
                                       letters=letters or adj["letters"], rh_facts=adj["rh_facts"], unresolved=unresolved))
    except ValueError as exc:
        return {"error": str(exc)[:200]}


def verdict(name: str, cond: dict[str, bool]) -> str:
    for label in ("insufficient", "supported", "not_supported", "mixed"):
        if cond.get(label):
            return {"insufficient": "Insufficient data", "supported": "Supported", "not_supported": "Not supported", "mixed": "Mixed"}[label]
    return "Mixed"


def env_vector(cvss: str, edits: set[str]) -> tuple[str, list[str]]:
    m = parse_cvss_vector(cvss)
    fired = []
    if "MUI" in edits and m["UI"] != "A":
        m["MUI"] = "A"; fired.append("MUI")
    if "MAT" in edits and m["AT"] != "P":
        m["MAT"] = "P"; fired.append("MAT")
    if "MVC" in edits and m["VC"] != "N":
        m["MVC"] = STEP_DOWN[m["VC"]]; fired.append("MVC")
    if "MVI" in edits and m["VI"] != "N":
        m["MVI"] = STEP_DOWN[m["VI"]]; fired.append("MVI")
    return "CVSS:4.0/" + "/".join(f"{k}:{m[k]}" for k in ALL_METRICS if k in m), fired


def agentic_edit(letters: dict, edits: set[str]) -> tuple[dict, list[str]]:
    out, fired = dict(letters), []
    if "ES" in edits and out["ES"] == "W":
        out["ES"] = "N"; fired.append("ES")
    if "AP" in edits and out["AP"] == "L":
        out["AP"] = "C"; fired.append("AP")
    if "CP" in edits and out["CP"] == "C":
        out["CP"] = "S"; fired.append("CP")
    return out, fired


# ---------------------------------------------------------------- main analysis

def analyze(base_rows: list[dict], findings: dict[str, dict], emr: dict, extra: dict[str, list[dict]],
            label: str = "v1.1") -> dict:
    SL = tuple(sorted({r["slot"] for r in base_rows}))
    by = defaultdict(dict)
    for r in base_rows:
        by[r["finding_id"]][r["slot"]] = r
    cluster_of = {fid: findings[fid].get("path_group") or fid for fid in findings}
    lab_of = {fid: f["lab"] for fid, f in findings.items()}
    res: dict = {"label": label, "n_findings": len(findings), "assessors": list(SL)}

    # ---- defects and canary
    res["defects"] = {s: Counter(d.split(":")[0] for r in base_rows if r["slot"] == s for d in r["defects"]) for s in SL}
    res["canary"] = {s: {"followed": sum(1 for r in base_rows if r["slot"] == s and r.get("canary_followed")),
                         "noticed": sum(1 for r in base_rows if r["slot"] == s and r.get("canary_noticed")),
                         "n": sum(1 for r in base_rows if r["slot"] == s)} for s in SL}

    # ---- agreement
    def vals(metric):
        out = {}
        for fid in sorted(findings):
            row = {}
            for s in SL:
                r = by[fid].get(s)
                v = None
                if r is None:
                    v = None
                elif metric in D.AIVSS:
                    v = r["letters"][metric] if r.get("valid_letters") else None
                elif metric in D.CVSS_BASE:
                    v = r["cvss"][metric] if r.get("valid_cvss") else None
                else:
                    v = (r.get("scores") or {}).get(metric)
                row[s] = v
            out[fid] = row
        return out

    agreement = {}
    for metric in list(D.AIVSS) + ["effect_class", "aivss_band", "cvss_band"] + list(D.CVSS_BASE):
        v = vals(metric)
        blk = S.agreement_block(v, metric, cluster_of, slots=SL)
        per_lab = {}
        for lab in sorted(set(lab_of.values())):
            sub = [[v[f][s] for s in SL] for f in sorted(v) if lab_of[f] == lab and all(v[f][s] not in (None, "X", "AX") for s in SL)]
            fl = S.fleiss(sub)
            per_lab[lab] = {"n": fl["n"], "kappa": fl.get("kappa"), "p0": fl.get("p0"), "declined": fl.get("declined")}
        blk["per_target_application"] = per_lab
        blk["three_agree"] = sum(1 for f in v if all(v[f][s] is not None for s in SL) and len({v[f][s] for s in SL}) == 1)
        blk["three_present"] = sum(1 for f in v if all(v[f][s] is not None for s in SL))
        agreement[metric] = blk
    res["agreement"] = agreement
    res["x_counts"] = {s: {m: sum(1 for r in base_rows if r["slot"] == s and r.get("valid_letters") is not None and (r.get("letters") or {}).get(m) == "X") for m in D.AIVSS} for s in SL}
    res["x_counts_claimed"] = {s: {m: sum(1 for r in base_rows if r["slot"] == s and (r.get("letters_claimed") or {}).get(m) == "X") for m in D.AIVSS} for s in SL}
    diffs = {"cvss_bt": [], "aivss": []}
    for fid in findings:
        sc = [by[fid][s]["scores"] for s in SL if by[fid].get(s) and by[fid][s].get("scores")]
        if len(sc) == len(SL):
            diffs["cvss_bt"].append(round(max(x["cvss_bt"] for x in sc) - min(x["cvss_bt"] for x in sc), 1))
            diffs["aivss"].append(round(max(x["aivss"] for x in sc) - min(x["aivss"] for x in sc), 1))
    res["score_range_across_assessors"] = {k: {"n": len(v), "distribution": dict(sorted(Counter(v).items())),
                                               "mean": sum(v) / len(v) if v else None} for k, v in diffs.items()}

    # ---- adjudication
    adjudicated, disagreements = {}, []
    variants = {"less_severe": {}, "unknown_wins": {}, "more_severe": {}}
    for fid, f in sorted(findings.items()):
        rows = {s: r for s, r in by[fid].items() if r.get("valid_letters")}
        if len(rows) < 2:
            continue
        disagreements += disagreement_record(fid, rows)
        for rule in variants:
            adj = adjudicate_finding(rows, rule)
            sc = score_adjudicated(f, rows, adj, emr[fid]["evidence"])
            variants[rule][fid] = {**adj, "scores": sc, "lab": f["lab"], "title": f["title"], "path_group": f.get("path_group")}
        adjudicated[fid] = variants["less_severe"][fid]
    scored = {fid: a for fid, a in adjudicated.items() if a["scores"] and "error" not in a["scores"]}
    res["adjudication"] = {
        "n": len(adjudicated), "scored": len(scored),
        "unscored": {fid: a["scores"] for fid, a in adjudicated.items() if fid not in scored},
        "cvss_vector_matches_no_assessor": sum(1 for a in adjudicated.values() if a["cvss_vector"] and not a["cvss_matches_assessors"]),
        "letters_match_no_assessor": sum(1 for a in adjudicated.values() if not a["letters_match_assessors"]),
        "letter_methods": dict(Counter(h for a in adjudicated.values() for h in a["letter_method"].values())),
        "disagreements": len(disagreements),
    }
    res["_adjudicated"] = adjudicated
    res["_disagreements"] = disagreements
    res["_variants"] = variants
    A = scored
    n = len(A)
    ids = sorted(A)

    # ---- H1
    floor_violations = sum(1 for k in range(0, 101) for cls in ("A0", "A1", "A2", "AX") if aivss_lookup(k / 10, cls)["aivss"] < k / 10)
    crossing = lambda a: a["scores"]["cvss_band"] not in HIGH and a["scores"]["aivss_band"] in HIGH  # noqa: E731
    cross_ids = [f for f in ids if crossing(A[f])]
    share = len(cross_ids) / n if n else None
    ci = S.cluster_bootstrap(ids, cluster_of, lambda d: sum(1 for f in d if crossing(A[f])) / len(d) if d else None)
    gaps = [A[f]["scores"]["aivss"] - A[f]["scores"]["cvss_bt"] for f in ids]
    gap_ci = S.cluster_bootstrap(ids, cluster_of, lambda d: sum(A[f]["scores"]["aivss"] - A[f]["scores"]["cvss_bt"] for f in d) / len(d))
    by_lab = {}
    for lab in sorted(set(lab_of.values())):
        sub = [f for f in ids if lab_of[f] == lab]
        ha = sum(1 for f in sub if A[f]["scores"]["aivss_band"] in HIGH)
        hc = sum(1 for f in sub if A[f]["scores"]["cvss_band"] in HIGH)
        by_lab[lab] = {"n": len(sub), "aivss_high_or_critical": ha, "aivss_ci": S.exact_binomial_ci(ha, len(sub)),
                       "cvss_high_or_critical": hc, "cvss_ci": S.exact_binomial_ci(hc, len(sub)),
                       "crossings": sum(1 for f in sub if crossing(A[f])),
                       "mean_gap": sum(A[f]["scores"]["aivss"] - A[f]["scores"]["cvss_bt"] for f in sub) / len(sub) if sub else None}
    policy = {}
    for name, ev in (("Attacked", {"observed_local": True, "poc": True}), ("Proof of concept", {"poc": True}), ("Unreported", {"poc": False})):
        rescored = {f: score_adjudicated(findings[f], by[f], A[f], ev) for f in ids}
        per_lab = {}
        for lab in sorted(set(lab_of.values())):
            sub = [f for f in ids if lab_of[f] == lab]
            per_lab[lab] = {"n": len(sub), "aivss_hc": sum(1 for f in sub if rescored[f]["aivss_band"] in HIGH),
                            "cvss_hc": sum(1 for f in sub if rescored[f]["cvss_band"] in HIGH),
                            "crossings": sum(1 for f in sub if rescored[f]["cvss_band"] not in HIGH and rescored[f]["aivss_band"] in HIGH)}
        policy[name] = {"aivss_hc": sum(1 for f in ids if rescored[f]["aivss_band"] in HIGH),
                        "cvss_hc": sum(1 for f in ids if rescored[f]["cvss_band"] in HIGH),
                        "crossings": sum(1 for f in ids if rescored[f]["cvss_band"] not in HIGH and rescored[f]["aivss_band"] in HIGH),
                        "mean_gap": sum(rescored[f]["aivss"] - rescored[f]["cvss_bt"] for f in ids) / n, "by_target_application": per_lab}
    gated = [f for f in ids if A[f]["gate_majority"]["applicability_as_modeled"] is True]
    nonzero = [f for f in ids if A[f]["scores"]["cvss_bt"] > 0]
    listener = [f for f in ids if lab_of[f] in ("damn-vulnerable-ai-agent", "finbot-ctf-demo")]
    av_sens = {}
    for name, (av, ui) in (("AV Local, UI None", ("L", "N")), ("AV Network, UI Passive", ("N", "P")), ("AV Network, UI Active", ("N", "A"))):
        hc_a = hc_c = cr = 0
        for f in ids:
            vec = A[f]["cvss_vector"]
            if f in listener:
                vec = vec.replace(f"AV:{parse_cvss_vector(vec)['AV']}", f"AV:{av}", 1).replace(f"UI:{parse_cvss_vector(vec)['UI']}", f"UI:{ui}", 1)
            s = score_adjudicated(findings[f], by[f], A[f], emr[f]["evidence"], cvss=vec)
            hc_a += s["aivss_band"] in HIGH; hc_c += s["cvss_band"] in HIGH; cr += s["cvss_band"] not in HIGH and s["aivss_band"] in HIGH
        av_sens[name] = {"aivss_hc": hc_a, "cvss_hc": hc_c, "crossings": cr, "listener_findings": len(listener)}

    def sub_share(sub):
        return {"n": len(sub), "crossings": sum(1 for f in sub if crossing(A[f])),
                "share": (sum(1 for f in sub if crossing(A[f])) / len(sub)) if sub else None,
                "aivss_hc": sum(1 for f in sub if A[f]["scores"]["aivss_band"] in HIGH),
                "cvss_hc": sum(1 for f in sub if A[f]["scores"]["cvss_band"] in HIGH)}

    g = sub_share(gated)
    side = lambda s: s is not None and s >= 0.10  # noqa: E731
    h1 = {"n": n, "crossings": len(cross_ids), "crossing_ids": cross_ids, "share": share, "share_ci": ci,
          "aivss_high_or_critical": sum(1 for f in ids if A[f]["scores"]["aivss_band"] in HIGH),
          "cvss_high_or_critical": sum(1 for f in ids if A[f]["scores"]["cvss_band"] in HIGH),
          "mean_gap": sum(gaps) / n, "mean_gap_ci": gap_ci, "above": sum(1 for x in gaps if x > 0), "equal": sum(1 for x in gaps if x == 0),
          "below": sum(1 for x in gaps if x < 0), "floor_violations_in_enumeration": floor_violations,
          "by_target_application": by_lab, "uniform_policy": policy, "gate_passing_as_modeled": g,
          "excluding_cvss_zero": sub_share(nonzero), "zero_impact_findings": [f for f in ids if A[f]["scores"]["cvss_bt"] == 0],
          "av_ui_sensitivity": av_sens}
    h1["verdict"] = verdict("H1", {"insufficient": n < 10, "not_supported": len(cross_ids) == 0,
                                   "mixed": (share is not None and 0 < share < 0.10) or (side(share) != side(g["share"])),
                                   "supported": side(share) and side(g["share"])})

    # ---- H2
    pairs = list(combinations(ids, 2))
    rc = {f: round(A[f]["scores"]["cvss_bt"], 1) for f in ids}
    ra = {f: round(A[f]["scores"]["aivss"], 1) for f in ids}
    tied_c = sum(1 for a, b in pairs if rc[a] == rc[b])
    tied_a = sum(1 for a, b in pairs if ra[a] == ra[b])
    only_c = sum(1 for a, b in pairs if rc[a] != rc[b] and ra[a] == ra[b])
    only_a = sum(1 for a, b in pairs if ra[a] != ra[b] and rc[a] == rc[b])
    groups = defaultdict(list)
    for fid, f in findings.items():
        if f.get("path_group"):
            groups[f["path_group"]].append(fid)
    dup = [{"path_group": g_, "members": m, "identical_aivss": len({ra.get(x) for x in m}) == 1,
            "identical_letters": len({json.dumps(A[x]["letters"], sort_keys=True) for x in m if x in A}) == 1}
           for g_, m in sorted(groups.items()) if len(m) > 1]
    h2 = {"n": n, "pairs": len(pairs), "distinct_cvss_bt": len(set(rc.values())), "distinct_aivss": len(set(ra.values())),
          "tied_pairs_cvss_bt": tied_c, "tied_pairs_aivss": tied_a, "separated_only_by_cvss_bt": only_c,
          "separated_only_by_aivss": only_a, "duplicate_groups": dup}
    h2["verdict"] = verdict("H2", {"insufficient": n < 10, "not_supported": tied_a <= tied_c,
                                   "supported": tied_a > tied_c and only_c > only_a, "mixed": tied_a > tied_c and only_a >= only_c})

    # ---- H3
    def h3_counts(letters_by):
        a2 = [f for f, L in letters_by.items() if L["class"] == "A2"]
        only_ap = sum(1 for f in a2 if letters_by[f]["AP"] == "L" and letters_by[f]["LC"] not in ("D", "I"))
        lc_cp = sum(1 for f in a2 if letters_by[f]["LC"] in ("D", "I") and letters_by[f]["CP"] == "C")
        lc_rh = sum(1 for f in a2 if letters_by[f]["LC"] in ("D", "I") and letters_by[f]["RH"] == "D")
        ap_l = sum(1 for L in letters_by.values() if L["AP"] == "L")
        return {"a2": len(a2), "a2_only_through_ap_lateral": only_ap, "a2_through_lc_and_cp": lc_cp, "a2_through_lc_and_rh": lc_rh, "ap_lateral_any": ap_l}

    adj_letters = {f: {**A[f]["letters"], "class": A[f]["scores"]["effect_class"]} for f in ids}
    h3 = {"n": n, **h3_counts(adj_letters)}
    single = {}
    for s in SL:
        L = {f: {**by[f][s]["letters"], "class": by[f][s]["scores"]["effect_class"]} for f in ids if by[f].get(s) and by[f][s].get("scores")}
        single[s] = h3_counts(L)
    loo = {}
    for drop in SL:
        L = {}
        for f in ids:
            rows = {s: r for s, r in by[f].items() if s != drop and r.get("valid_letters")}
            if len(rows) == len(SL) - 1:
                adj = adjudicate_finding(rows)
                sc = score_adjudicated(findings[f], rows, adj, emr[f]["evidence"])
                if sc and "error" not in sc:
                    L[f] = {**adj["letters"], "class": sc["effect_class"]}
        loo[f"without_{drop}"] = h3_counts(L)
    var_counts = {}
    for rule, vs in variants.items():
        L = {f: {**a["letters"], "class": a["scores"]["effect_class"]} for f, a in vs.items() if a["scores"] and "error" not in a["scores"]}
        var_counts[rule] = h3_counts(L)
    h3.update({"single_assessor": single, "leave_one_out": loo, "tie_rule_variants": var_counts})
    h3["verdict"] = verdict("H3", {"insufficient": h3["ap_lateral_any"] == 0 or h3["a2"] == 0,
                                   "supported": h3["a2_only_through_ap_lateral"] > h3["a2"] / 2,
                                   "not_supported": h3["a2_only_through_ap_lateral"] <= h3["a2"] / 2})

    # ---- H4
    pair_kinds = Counter()
    x_involved = Counter()
    chosen = Counter()
    for f in findings:
        for s in SL:
            r = by[f].get(s)
            if r and r.get("valid_letters"):
                for m in D.AIVSS:
                    chosen[(m, r["letters"][m])] += 1
        for a, b in combinations(SL, 2):
            ra_, rb_ = by[f].get(a), by[f].get(b)
            if not (ra_ and rb_ and ra_.get("valid_letters") and rb_.get("valid_letters")):
                continue
            for m in D.AIVSS:
                va, vb = ra_["letters"][m], rb_["letters"][m]
                if va == vb:
                    continue
                if "X" in (va, vb):
                    x_involved[m] += 1
                else:
                    pair_kinds[f"{m} {'-'.join(sorted((va, vb)))}"] += 1
    ranked = pair_kinds.most_common()
    second = ranked[1][1] if len(ranked) > 1 else (ranked[0][1] if ranked else 0)
    top_two = {k for k, c in ranked if c >= second}
    named = {"AP C-L": chosen[("AP", "L")] > 0 and chosen[("AP", "C")] > 0, "LC I-M": chosen[("LC", "M")] > 0 and chosen[("LC", "I")] > 0}
    named_in_top = {k: (k in top_two) for k, testable in named.items() if testable}
    cells = Counter()
    cells_no_avui = Counter()
    band_disagreements = 0
    for f in ids:
        for a, b in combinations(SL, 2):
            ra_, rb_ = by[f].get(a), by[f].get(b)
            if not (ra_ and rb_ and ra_.get("scores") and rb_.get("scores")):
                continue
            if ra_["scores"]["aivss_band"] == rb_["scores"]["aivss_band"]:
                continue
            band_disagreements += 1
            for variant, store in (("all", cells), ("no_av_ui", cells_no_avui)):
                def swapped(src, dst, part):
                    p = deepcopy(src)
                    if part == "cvss":
                        if variant == "no_av_ui":
                            m_src, m_dst = dict(src["cvss"]), dict(dst["cvss"])
                            for k in D.CVSS_BASE:
                                if k not in ("AV", "UI"):
                                    m_src[k] = m_dst[k]
                            p["cvss_vector"] = "CVSS:4.0/" + "/".join(f"{k}:{m_src[k]}" for k in D.CVSS_BASE)
                        else:
                            p["cvss_vector"] = dst["cvss_vector"]
                    else:
                        p["letters"], p["rh_facts"] = dst["letters"], dst["rh_facts"]
                    try:
                        return D.score(D.build_payload(findings[f], findings[f]["lab"], p, emr[f]["evidence"]))["aivss_band"]
                    except ValueError:
                        return None
                closes = {}
                for part in ("cvss", "class"):
                    c1 = swapped(ra_, rb_, part) == rb_["scores"]["aivss_band"]
                    c2 = swapped(rb_, ra_, part) == ra_["scores"]["aivss_band"]
                    closes[part] = c1 or c2
                key = ("either" if closes["cvss"] and closes["class"] else "cvss_only" if closes["cvss"]
                       else "class_only" if closes["class"] else "neither")
                store[key] += 1
    testable_any = bool(named_in_top)
    sup = testable_any and all(named_in_top.values()) and cells["class_only"] > cells["cvss_only"]
    nsup = testable_any and not any(named_in_top.values()) and cells["cvss_only"] > cells["class_only"]
    if not testable_any:
        sup = False
        nsup = cells["cvss_only"] > cells["class_only"]
    h4 = {"pair_disagreements": dict(ranked), "x_involved": dict(x_involved), "named_pairs_testable": named,
          "named_pairs_in_top_two": named_in_top, "band_disagreements": band_disagreements,
          "attribution": dict(cells), "attribution_without_av_ui": dict(cells_no_avui),
          "values_never_chosen": sorted(f"{m}:{v}" for m in D.AIVSS for v in D.LETTERS[m] if v != "X" and chosen[(m, v)] == 0)}
    h4["verdict"] = verdict("H4", {"insufficient": not testable_any and band_disagreements < 10,
                                   "supported": sup, "not_supported": nsup})
    h4["verdict_note"] = "Named value pairs untestable on this data: " + ", ".join(k for k, t in named.items() if not t) if not all(named.values()) else ""

    # ---- H5
    prov = [f for f in ids if A[f]["scores"]["provisional"]]
    spreads = [A[f]["scores"]["aivss_max"] - A[f]["scores"]["aivss_min"] for f in prov]
    every = [r["scores"]["aivss_max"] - r["scores"]["aivss_min"] for r in base_rows if r.get("scores")]
    per_assessor = {s: {"provisional": sum(1 for r in base_rows if r["slot"] == s and r.get("scores") and r["scores"]["provisional"]),
                        "scored": sum(1 for r in base_rows if r["slot"] == s and r.get("scores"))} for s in SL}
    var_prov = {rule: sum(1 for a in vs.values() if a["scores"] and "error" not in a["scores"] and a["scores"]["provisional"]) for rule, vs in variants.items()}
    h5 = {"n": n, "provisional": len(prov), "share": len(prov) / n if n else None, "mean_spread_provisional": sum(spreads) / len(spreads) if spreads else 0.0,
          "spread_distribution_all_assessor_reports": dict(sorted(Counter(round(x, 1) for x in every).items())),
          "per_assessor": per_assessor, "tie_rule_variants_provisional": var_prov,
          "x_counts_used": res["x_counts"], "x_counts_claimed": res["x_counts_claimed"]}
    h5["verdict"] = verdict("H5", {"not_supported": len(prov) == 0,
                                   "supported": h5["share"] is not None and h5["share"] >= 0.10 and h5["mean_spread_provisional"] >= 1.0})

    # ---- H6
    pol = {"Not defined": ({}, True), "Attacked": ({"observed_local": True, "poc": True}, False),
           "Proof of concept": ({"poc": True}, False), "Unreported": ({"poc": False}, False)}
    bands = {f: {k: score_adjudicated(findings[f], by[f], A[f], ev, unresolved=u) for k, (ev, u) in pol.items()} for f in ids}
    distinct = ("Attacked", "Proof of concept", "Unreported")
    a_change = [f for f in ids if len({bands[f][k]["aivss_band"] for k in distinct}) > 1]
    c_change = [f for f in ids if len({bands[f][k]["cvss_band"] for k in distinct}) > 1]
    nd_equals_a = all(bands[f]["Not defined"]["cvss_bt"] == bands[f]["Attacked"]["cvss_bt"] for f in ids)
    demo_id = "FB-04" if "FB-04" in A else ids[0]
    demo_vec = A[demo_id]["cvss_vector"] + "/E:A"
    p_demo = synth_parsed(by[demo_id], A[demo_id])
    empty = D.score(D.build_payload(findings[demo_id], findings[demo_id]["lab"], p_demo, {}, cvss_vector=demo_vec,
                                    letters=A[demo_id]["letters"], rh_facts=A[demo_id]["rh_facts"]))
    transitions = Counter((bands[f]["Attacked"]["aivss_band"], bands[f]["Proof of concept"]["aivss_band"], bands[f]["Unreported"]["aivss_band"]) for f in ids)
    h6 = {"n": n, "aivss_band_changes": len(a_change), "aivss_share": len(a_change) / n, "cvss_band_changes": len(c_change),
          "not_defined_scores_as_attacked": nd_equals_a,
          "aivss_band_transitions_A_P_U": {" > ".join(k): v for k, v in transitions.most_common()},
          "empty_evidence_demo": {"finding_id": demo_id, "vector_written": demo_vec, "evidence_object": {},
                                  "cvss_bt_returned": empty["cvss_bt"], "attacked_cvss_bt": bands[demo_id]["Attacked"]["cvss_bt"],
                                  "unreported_cvss_bt": bands[demo_id]["Unreported"]["cvss_bt"]}}
    h6["verdict"] = verdict("H6", {"not_supported": len(a_change) == 0, "supported": h6["aivss_share"] >= 0.10})

    # ---- H7
    kinds = {"LC D vs I": ("LC", "D", "I"), "LC M vs N": ("LC", "M", "N"), "RH P vs N": ("RH", "P", "N"),
             "ES N vs M": ("ES", "N", "M"), "ES M vs W": ("ES", "M", "W"), "ES N vs W": ("ES", "N", "W")}
    enum = {}
    for k, (m, v1, v2) in kinds.items():
        moved = total = 0
        others = {"LC": "NMID", "CP": "NSC", "AP": "NCL", "RH": "NPD", "ES": "NMW"}
        letters_space = [dict(zip(D.AIVSS, combo)) for combo in
                         ((lc, cp, ap, rh, es) for lc in others["LC"] for cp in others["CP"] for ap in others["AP"] for rh in others["RH"] for es in others["ES"])]
        for L in letters_space:
            if L[m] != v1:
                continue
            L2 = dict(L); L2[m] = v2
            c1 = AIProfile(*(L[x] for x in D.AIVSS)).effect_class()
            c2 = AIProfile(*(L2[x] for x in D.AIVSS)).effect_class()
            for sc10 in range(0, 101):
                total += 1
                moved += aivss_lookup(sc10 / 10, c1)["aivss"] != aivss_lookup(sc10 / 10, c2)["aivss"]
        enum[k] = {"inputs": total, "aivss_changes": moved, "share": moved / total}
    observed = {}
    for k, (m, v1, v2) in kinds.items():
        tried = changed = 0
        for f in ids:
            for a, b in combinations(SL, 2):
                for src, dst in ((a, b), (b, a)):
                    rs, rd = by[f].get(src), by[f].get(dst)
                    if not (rs and rd and rs.get("scores") and rd.get("valid_letters")):
                        continue
                    if {rs["letters"][m], rd["letters"][m]} != {v1, v2}:
                        continue
                    p = deepcopy(rs)
                    p["letters"] = dict(rs["letters"]); p["letters"][m] = rd["letters"][m]
                    if m == "RH":
                        p["rh_facts"] = rd["rh_facts"]
                    try:
                        new = D.score(D.build_payload(findings[f], findings[f]["lab"], p, emr[f]["evidence"]))
                    except ValueError:
                        continue
                    tried += 1
                    changed += new["aivss"] != rs["scores"]["aivss"]
        observed[k] = {"swaps": tried, "aivss_changed": changed}
    h7 = {"enumeration": enum, "observed_swaps": observed}
    all_zero = all(v["aivss_changes"] == 0 for v in enum.values()) and all(v["aivss_changed"] == 0 for v in observed.values())
    h7["verdict"] = verdict("H7", {"supported": all_zero, "not_supported": all(v["share"] >= 0.5 for v in enum.values())})

    # ---- H8
    agent_of = {fid: f["agent"] for fid, f in findings.items()}
    per_agent = {}
    for agent in sorted(set(agent_of.values())):
        fids = [f for f in findings if agent_of[f] == agent]
        rec = {"findings": len(fids), "target_application": findings[fids[0]]["lab"]}
        for key in ("applicability_as_implemented", "applicability_as_modeled"):
            answers, consistency = {}, {}
            for s in SL:
                votes = [by[f][s][key]["pass"] for f in fids if by[f].get(s) and by[f][s].get(key, {}).get("pass") is not None]
                c = Counter(votes).most_common()
                answers[s] = None if not c else ("split" if len(c) > 1 and c[0][1] == c[1][1] else ("pass" if c[0][0] else "fail"))
                consistency[s] = (c[0][1] / len(votes)) if votes else None
            maj = Counter(v for v in answers.values() if v in ("pass", "fail")).most_common()
            rec[key] = {"per_assessor": answers, "within_assessor_consistency": consistency,
                        "majority": maj[0][0] if maj and (len(maj) == 1 or maj[0][1] > maj[1][1]) else "split",
                        "unanimous": len(set(answers.values())) == 1}
        per_agent[agent] = rec
    conf = {s: dict(Counter((by[f][s].get(k) or {}).get("confidence") for f in findings for k in ("applicability_as_implemented", "applicability_as_modeled") if by[f].get(s) and by[f][s].get(k))) for s in SL}
    fail_mod = [a for a, r in per_agent.items() if r["applicability_as_modeled"]["majority"] == "fail"]
    split_any = [a for a, r in per_agent.items() if not (r["applicability_as_implemented"]["unanimous"] and r["applicability_as_modeled"]["unanimous"])]
    dvaa_impl = Counter(r["applicability_as_implemented"]["majority"] for r in per_agent.values() if r["target_application"] == "damn-vulnerable-ai-agent")
    h8 = {"agents": len(per_agent), "per_agent": per_agent, "fail_as_modeled_by_majority": fail_mod, "agents_with_split_answers": split_any,
          "dvaa_as_implemented": dict(dvaa_impl), "confidence": conf}
    all_pass_unan = all(r["applicability_as_modeled"]["majority"] == "pass" for r in per_agent.values()) and not split_any
    h8["verdict"] = verdict("H8", {"supported": len(fail_mod) >= 1 and len(split_any) >= 2, "not_supported": all_pass_unan})

    # ---- H9
    arms = {"environmental": ({"MUI", "MAT", "MVC", "MVI"}, set()), "agentic": (set(), {"ES", "AP", "CP"}),
            "both": ({"MUI", "MAT", "MVC", "MVI"}, {"ES", "AP", "CP"})}
    h9 = {"n": n, "arms": {}}
    for arm, (env, ag) in arms.items():
        fired = Counter(); moved_fire = Counter(); edited = c_moved = a_moved = a_band = c_band = c_not_a = a_not_c = 0
        for f in ids:
            vec, f_env = env_vector(A[f]["cvss_vector"], env)
            L, f_ag = agentic_edit(A[f]["letters"], ag)
            if not (f_env or f_ag):
                continue
            edited += 1
            s = score_adjudicated(findings[f], by[f], A[f], emr[f]["evidence"], cvss=vec, letters=L)
            cm = s["cvss_bt"] != A[f]["scores"]["cvss_bt"]; am = s["aivss"] != A[f]["scores"]["aivss"]
            c_moved += cm; a_moved += am; c_not_a += cm and not am; a_not_c += am and not cm
            c_band += s["cvss_band"] != A[f]["scores"]["cvss_band"]; a_band += s["aivss_band"] != A[f]["scores"]["aivss_band"]
            for e in f_env + f_ag:
                fired[e] += 1
                single_env = env_vector(A[f]["cvss_vector"], {e})[0] if e in env else A[f]["cvss_vector"]
                single_L = agentic_edit(A[f]["letters"], {e})[0] if e in ag else A[f]["letters"]
                s1 = score_adjudicated(findings[f], by[f], A[f], emr[f]["evidence"], cvss=single_env, letters=single_L)
                moved_fire[e] += s1["aivss"] != A[f]["scores"]["aivss"]
        h9["arms"][arm] = {"edited": edited, "cvss_moved": c_moved, "aivss_moved": a_moved, "cvss_moved_aivss_not": c_not_a,
                           "aivss_moved_cvss_not": a_not_c, "cvss_band_changed": c_band, "aivss_band_changed": a_band,
                           "edit_fired": dict(fired), "edit_moved_aivss_alone": dict(moved_fire)}
    e = h9["arms"]["environmental"]
    h9["verdict"] = verdict("H9", {"insufficient": e["edited"] < 10,
                                   "not_supported": e["aivss_moved"] >= e["cvss_moved"],
                                   "supported": (e["cvss_moved"] - e["aivss_moved"]) >= 0.10 * e["edited"]})
    fixed_rows = extra.get("fixed") or []
    if fixed_rows:
        lf = {}
        for s in SL:
            pairs_ = [(by[r["finding_id"]].get(s), r) for r in fixed_rows if r["slot"] == s and r.get("scores") and by[r["finding_id"]].get(s, {}).get("scores")]
            lf[s] = {"pairs": len(pairs_),
                     "aivss_band_changed": sum(1 for b, x in pairs_ if b["scores"]["aivss_band"] != x["scores"]["aivss_band"]),
                     "cvss_band_changed": sum(1 for b, x in pairs_ if b["scores"]["cvss_band"] != x["scores"]["cvss_band"]),
                     "aivss_lower": sum(1 for b, x in pairs_ if x["scores"]["aivss"] < b["scores"]["aivss"]),
                     "cvss_lower": sum(1 for b, x in pairs_ if x["scores"]["cvss_bt"] < b["scores"]["cvss_bt"]),
                     "not_exploitable_as_configured": sum(1 for r in fixed_rows if r["slot"] == s and r.get("not_exploitable_as_configured") is True),
                     "fixed_rows": sum(1 for r in fixed_rows if r["slot"] == s)}
        h9["lab_fix_arm"] = lf

    # ---- H10
    rng = random.Random(S.SEED)
    sc_a = {f: A[f]["scores"]["aivss"] for f in ids}
    sc_c = {f: A[f]["scores"]["cvss_bt"] for f in ids}
    sc_e = {f: (CLASS_RANK[A[f]["scores"]["effect_class"]], A[f]["scores"]["cvss_bt"]) for f in ids}

    def top_block(scores):
        ordered = sorted(scores.values(), reverse=True)
        fifth = ordered[4]
        strictly_in = {f for f, v in scores.items() if v > fifth}
        tie_block = {f for f, v in scores.items() if v == fifth}
        return fifth, strictly_in, tie_block

    fa, in_a, tie_a = top_block(sc_a)
    fc, in_c, tie_c = top_block(sc_c)
    moved = sorted((in_a - in_c - tie_c) | (in_c - in_a - tie_a))
    inc_a, inc_c = in_a | tie_a, in_c | tie_c

    def rand_top(scores):
        keys = sorted(scores, key=lambda f: (-scores[f], rng.random()))
        return set(keys[:5])

    draws = 10_000
    changed = sum(1 for _ in range(draws) if rand_top(sc_a) != rand_top(sc_c))
    inv = ties = 0
    for a, b in combinations(ids, 2):
        da, dc = sc_a[a] - sc_a[b], sc_c[a] - sc_c[b]
        if da == 0 or dc == 0:
            ties += 1
        elif da * dc < 0:
            inv += 1
    tau = S.kendall_tau_b([sc_a[f] for f in ids], [sc_c[f] for f in ids])
    tau_ci = S.cluster_bootstrap(ids, cluster_of, lambda d: S.kendall_tau_b([sc_a[f] for f in d], [sc_c[f] for f in d]))
    fe, in_e, tie_e = top_block(sc_e)
    h10 = {"n": n, "top5_aivss_strict": sorted(in_a), "top5_aivss_tie_block": sorted(tie_a), "top5_aivss_fifth_value": fa,
           "top5_cvss_strict": sorted(in_c), "top5_cvss_tie_block": sorted(tie_c), "top5_cvss_fifth_value": fc,
           "moved": moved, "jaccard_tie_inclusive": len(inc_a & inc_c) / len(inc_a | inc_c),
           "random_tiebreak_top5_differs_share": changed / draws, "strict_inversions": inv, "tied_pairs": ties,
           "kendall_tau_b": tau, "kendall_tau_b_ci": tau_ci,
           "top5_class_then_cvss_strict": sorted(in_e), "top5_class_then_cvss_tie_block": sorted(tie_e),
           "class_then_cvss_vs_cvss_jaccard": len((in_e | tie_e) & inc_c) / len((in_e | tie_e) | inc_c)}
    h10["verdict"] = verdict("H10", {"insufficient": n < 10, "supported": bool(moved), "not_supported": not moved})

    res["hypotheses"] = {"H1": h1, "H2": h2, "H3": h3, "H4": h4, "H5": h5, "H6": h6, "H7": h7, "H8": h8, "H9": h9, "H10": h10}
    sev = {fid: f.get("lab_severity") for fid, f in findings.items() if f.get("lab_severity")}
    res["lab_severity_comparison"] = {fid: {"lab_severity": v, "aivss_band": A[fid]["scores"]["aivss_band"] if fid in A else None,
                                            "cvss_band": A[fid]["scores"]["cvss_band"] if fid in A else None} for fid, v in sorted(sev.items())}
    return res


# ---------------------------------------------------------------- control arms

def compare_rows(a_rows: list[dict], b_rows: list[dict]) -> dict:
    """Per assessor: how often two runs of the same finding agree (letters, bands)."""
    out = {}
    for s in sorted({r["slot"] for r in a_rows} | {r["slot"] for r in b_rows}):
        A_ = {r["finding_id"]: r for r in a_rows if r["slot"] == s}
        B_ = {r["finding_id"]: r for r in b_rows if r["slot"] == s}
        common = sorted(set(A_) & set(B_))
        rec = {"findings": len(common)}
        both_letters = [f for f in common if A_[f].get("valid_letters") and B_[f].get("valid_letters")]
        for m in D.AIVSS:
            rec[f"same_{m}"] = sum(1 for f in both_letters if A_[f]["letters"][m] == B_[f]["letters"][m])
        rec["letters_compared"] = len(both_letters)
        rec["same_all_letters"] = sum(1 for f in both_letters if A_[f]["letters"] == B_[f]["letters"])
        both_sc = [f for f in common if A_[f].get("scores") and B_[f].get("scores")]
        rec["scores_compared"] = len(both_sc)
        rec["same_aivss_band"] = sum(1 for f in both_sc if A_[f]["scores"]["aivss_band"] == B_[f]["scores"]["aivss_band"])
        rec["same_cvss_band"] = sum(1 for f in both_sc if A_[f]["scores"]["cvss_band"] == B_[f]["scores"]["cvss_band"])
        rec["same_class"] = sum(1 for f in both_sc if A_[f]["scores"]["effect_class"] == B_[f]["scores"]["effect_class"])
        rec["changed_findings"] = [f for f in both_sc if A_[f]["scores"]["aivss_band"] != B_[f]["scores"]["aivss_band"]]
        out[s] = rec
    return out
