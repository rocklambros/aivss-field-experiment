"""Adjudicate the three assessors' vectors per finding.

Version: 1.1.0
Owner: Rock Lambros

Closes K6, P21, P42, P69 (fix plan F and R2.8).
- Per metric majority, as in v1.0.
- Three distinct values with no unknown: the ordinal median.
- One unknown and two differing values: the less severe of the two, flagged split.
- Two or three unknowns: unknown.
- No assessor is privileged. Variants for sensitivity: unknown wins, more severe wins.
- Reward hacking is adjudicated from the facts: each fact by majority of non-null
  answers, then the letter comes from classify_rh. Locus is the majority non-null locus.
Every disagreement is written to an artifact with each assessor's value, the
assessor's rationale, and the rubric text for the values in contention.
"""

from __future__ import annotations

from collections import Counter

from aivss_calc.ai_metrics import AGENTIC_METRICS, classify_rh

from .data import AIVSS, CVSS_BASE
from .stats import ORDERS

CVSS_TEXT = {  # short FIRST meaning per value, from rubric_v1.1.txt Section 2 (labeled paraphrase)
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}, "AC": {"L": "Low", "H": "High"},
    "AT": {"N": "None", "P": "Present"}, "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "P": "Passive", "A": "Active"},
}


def _severity(metric: str, v: str) -> int:
    return ORDERS[metric].index(v)


def pick(metric: str, values: list[str], rule: str = "less_severe") -> tuple[str, str]:
    """Return (value, how) for any number of assessors. X is allowed for agentic metrics.

    - Unknown wins only when a strict majority of all assessors answered X.
    - Otherwise a value that a strict majority of the known answers chose wins.
    - Otherwise the median of the known answers, taking the lower middle value when the
      count is even (rule less_severe) or the upper middle value (rule more_severe).
    - Rule unknown_wins (sensitivity): any split that includes an X returns X.
    With three assessors this reproduces fix plan R2.8 exactly.
    """
    k = len(values)
    xs = values.count("X")
    if xs * 2 > k:
        return "X", "majority_unknown"
    known = [v for v in values if v != "X"]
    if not known:
        return "X", "all_unknown"
    top, n = Counter(known).most_common(1)[0]
    if n * 2 > len(known) and (n * 2 > k or xs == 0 or rule != "unknown_wins"):
        return top, "majority"
    if rule == "unknown_wins" and xs:
        return "X", "split_unknown_wins"
    ranked = sorted(known, key=lambda v: _severity(metric, v))
    m = len(ranked)
    if m % 2:
        return ranked[m // 2], "median"
    return (ranked[m // 2 - 1] if rule != "more_severe" else ranked[m // 2]), f"median_{rule}"


def adjudicate_rh(facts_list: list[dict]) -> tuple[str, dict, str]:
    def maj(key):
        vals = [f.get(key) for f in facts_list if f.get(key) is not None]
        if not vals:
            return None
        c = Counter(vals).most_common()
        if len(c) > 1 and c[0][1] == c[1][1]:
            return None  # tie between non-null answers: unknown
        return c[0][0]

    facts = {k: maj(k) for k in ("reachable_proxy", "isolation_verified", "verified_episodes", "episodes_reviewed", "locus")}
    if isinstance(facts["verified_episodes"], int) and (facts["episodes_reviewed"] is None or facts["episodes_reviewed"] < facts["verified_episodes"]):
        facts["episodes_reviewed"] = facts["verified_episodes"]
    letter = classify_rh(reachable_proxy=facts["reachable_proxy"], isolation_verified=facts["isolation_verified"],
                         verified_episodes=facts["verified_episodes"])
    how = "facts_majority"
    if letter in ("P", "D") and facts["locus"] is None:
        loci = [f.get("locus") for f in facts_list if f.get("locus")]
        facts["locus"] = Counter(loci).most_common(1)[0][0] if loci else None
        how = "facts_majority_locus_from_any" if loci else "facts_majority_no_locus"
    return letter, facts, how


def adjudicate_finding(rows: dict[str, dict], rule: str = "less_severe") -> dict:
    """rows: slot -> parsed row with valid letters (and cvss where valid)."""
    slots = sorted(rows)
    letters, how = {}, {}
    for m in AIVSS:
        if m == "RH":
            continue
        letters[m], how[m] = pick(m, [rows[s]["letters"][m] for s in slots], rule)
    rh_letter, rh_facts, rh_how = adjudicate_rh([rows[s]["rh_facts"] for s in slots])
    letters["RH"], how["RH"] = rh_letter, rh_how
    cvss_rows = [s for s in slots if rows[s].get("valid_cvss")]
    cvss, cvss_how = {}, {}
    if len(cvss_rows) >= 2:
        for m in CVSS_BASE:
            vals = [rows[s]["cvss"][m] for s in cvss_rows]
            if len(vals) == 2 and vals[0] != vals[1]:
                ranked = sorted(vals, key=lambda v: _severity(m, v))
                cvss[m], cvss_how[m] = (ranked[0] if rule != "more_severe" else ranked[-1]), f"two_assessors_{rule}"
            else:
                cvss[m], cvss_how[m] = pick(m, vals, rule)
    vector = "CVSS:4.0/" + "/".join(f"{m}:{cvss[m]}" for m in CVSS_BASE) if cvss else None
    gate = {}
    for key in ("applicability_as_implemented", "applicability_as_modeled"):
        votes = [rows[s][key]["pass"] for s in slots if rows[s].get(key, {}).get("pass") is not None]
        c = Counter(votes).most_common()
        gate[key] = c[0][0] if c and (len(c) == 1 or c[0][1] > c[1][1]) else None
    matches = [s for s in cvss_rows if rows[s]["cvss_vector"] == vector]
    letter_matches = [s for s in slots if rows[s]["letters"] == letters]
    return {"letters": letters, "letter_method": how, "rh_facts": rh_facts, "cvss_vector": vector, "cvss_method": cvss_how,
            "gate_majority": gate, "cvss_matches_assessors": matches, "letters_match_assessors": letter_matches,
            "assessors_with_valid_cvss": cvss_rows}


def disagreement_record(fid: str, rows: dict[str, dict]) -> list[dict]:
    out = []
    for m in AIVSS:
        vals = {s: rows[s]["letters"][m] for s in sorted(rows)}
        if len(set(vals.values())) > 1:
            out.append({"finding_id": fid, "metric": m, "values": vals,
                        "rubric": {v: AGENTIC_METRICS[m][v][1] for v in sorted(set(vals.values()))},
                        "rationales": {s: str((rows[s].get("rationales") or {}).get(m) or "")[:600] for s in sorted(rows)}})
    for m in CVSS_BASE:
        vals = {s: rows[s]["cvss"][m] for s in sorted(rows) if rows[s].get("valid_cvss")}
        if len(set(vals.values())) > 1:
            out.append({"finding_id": fid, "metric": m, "values": vals,
                        "rubric": {v: CVSS_TEXT.get(m, {}).get(v, v) for v in sorted(set(vals.values()))},
                        "rationales": {s: str((rows[s].get("rationales") or {}).get("CVSS") or "")[:600] for s in vals}})
    return out
