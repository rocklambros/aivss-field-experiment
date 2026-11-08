"""Load assessor outputs, parse them strictly, and score them through aivss-calc.

Version: 1.1.0
Owner: Rock Lambros

Closes premortem P07 (RH facts never rewritten), P08 (gate answers carried,
rationale truthful), P10 and P68 (one observable exploit maturity rule),
P25 (exposure per target application), P30 and P61 (strict parse, no repair),
P37 (assessor rows scored at the headline evidence).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aivss_calc.ai_metrics import RH_LOCI, classify_rh
from aivss_calc.assessment import assess, assessment_from_payload
from aivss_calc.validation import validate_report

ROOT = Path(__file__).resolve().parents[2]
SLOTS = ("A", "B", "C", "D", "E", "F", "G")  # the seven v1.1 assessors
AIVSS = ("LC", "CP", "AP", "RH", "ES")
CVSS_BASE = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
CVSS_RE = re.compile(
    r"^CVSS:4\.0/AV:([NALP])/AC:([LH])/AT:([NP])/PR:([NLH])/UI:([NPA])/VC:([HLN])/VI:([HLN])/VA:([HLN])"
    r"/SC:([HLN])/SI:([HLN])/SA:([HLN])$"
)
LETTERS = {"LC": "NMIDX", "CP": "NSCX", "AP": "NCLX", "RH": "NPDX", "ES": "NMWX"}
CITE_RE = re.compile(r"^[^\s:]+(?:/[^\s:]+)*:\d+(?:-\d+)?$")
# Exposure of each target application's documented default deployment, from labs/<lab>/profile.json exposure.
PUBLICLY_EXPOSED = {
    "finbot-ctf-demo": (True, "labs/finbot-ctf-demo/profile.json exposure: stock app binds 0.0.0.0 and the README links a public instance"),
    "agent-sec-lab": (False, "labs/agent-sec-lab/profile.json exposure: CLI with no network listener"),
    "damn-vulnerable-ai-agent": (False, "labs/damn-vulnerable-ai-agent/profile.json exposure: listeners bind 127.0.0.1 by default"),
}


def load_findings() -> dict[str, dict]:
    raw = json.loads((ROOT / "findings.json").read_text())
    return {f["id"]: dict(f) for f in raw["findings"]}


# ---------------------------------------------------------------- exploit maturity

def exploit_maturity_rule(findings: dict[str, dict]) -> dict[str, dict]:
    """Fix plan R2.7. Applied by script, the same for assessor rows and adjudicated rows.

    Attacked needs a recorded local run in which a real model executed the scored entry
    point and the effect was observed at the sink. Only the FinBot model replay meets that
    (FB-04, live/finbot_model.json run FB-04 decision approved). A stand-in model, canned
    handler, or direct tool call is proof of concept. Unreported means no payload or exploit
    exists for the scored path (FB-02, recorded in live/finbot_scenarios.json fb02_scored_path).
    """
    model_run = json.loads((ROOT / "live" / "finbot_model.json").read_text())
    replay = {r["id"]: r.get("decision") for r in model_run["runs"]}
    scen = json.loads((ROOT / "live" / "finbot_scenarios.json").read_text())
    fb02_payload = bool(scen.get("fb02_scored_path", {}).get("artifact_payload"))
    out = {}
    for fid, f in sorted(findings.items()):
        if fid == "FB-04" and replay.get("FB-04") == "approved":
            out[fid] = {"evidence": {"observed_local": True, "poc": True}, "e": "A",
                        "basis": "live/finbot_model.json run FB-04: with the model on a US-pinned endpoint, a bland invoice was approved after the unauthenticated config change. The model was a substitute for the target application's default model."}
        elif fid == "FB-02" and not fb02_payload:
            out[fid] = {"evidence": {"poc": False}, "e": "U",
                        "basis": "live/finbot_scenarios.json fb02_scored_path.artifact_payload is false: finbot_exploits.md has no payload for the scored path, and none was invented."}
        elif f["lab"] == "finbot-ctf-demo":
            out[fid] = {"evidence": {"poc": True}, "e": "P",
                        "basis": f"Owner-authored scenario exists for this path (finbot_exploits.md). Model replay decision: {replay.get(fid)}. The no-key fallback is a different system and is not counted."}
        else:
            out[fid] = {"evidence": {"poc": True}, "e": "P",
                        "basis": f"In-repo exploit material: {(f.get('poc') or {}).get('kind')}. Stand-in model, canned handler, and direct tool call tests count as proof of concept, not as observed exploitation."}
    return out


def write_exploit_maturity(findings: dict[str, dict], path: Path) -> dict[str, dict]:
    rule = exploit_maturity_rule(findings)
    path.write_text(json.dumps({"version": "1.1.0", "rule": "premortem/fix_plan.md R2.7", "findings": rule}, indent=2))
    return rule


# ---------------------------------------------------------------- loading assessor outputs

@dataclass
class Row:
    finding_id: str
    arm: str
    slot: str
    source: str
    content: dict | None
    defects: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)


def load_v11(run_dir: Path, arm: str) -> list[Row]:
    manifest = json.loads((run_dir / "manifest.json").read_text())
    rows = []
    for cell in manifest["cells"]:
        if cell["arm"] != arm:
            continue
        attempts = cell.get("attempts") or []
        chosen = next((a for a in attempts if a["check"] == "ok"), attempts[-1] if attempts else None)
        meta = {"status": cell["status"], "attempts": len(attempts), "checks": [a["check"] for a in attempts]}
        if chosen is None:
            rows.append(Row(cell["finding_id"], arm, cell["slot"], "missing", None, ["no_attempt"], meta=meta))
            continue
        raw = json.loads((ROOT / chosen["raw"]).read_text())
        body = raw.get("body") or {}
        choice = (body.get("choices") or [{}])[0]
        meta.update({"served_provider": chosen.get("served_provider"), "finish_reason": chosen.get("finish_reason"),
                     "cost": chosen.get("cost"), "reasoning_tokens": chosen.get("reasoning_tokens"),
                     "generation_id": body.get("id")})
        content_text = (choice.get("message") or {}).get("content") or ""
        try:
            content = json.loads(content_text)
            if not isinstance(content, dict):
                raise ValueError("not an object")
            defects = []
        except (ValueError, json.JSONDecodeError):
            content, defects = None, [f"unparseable:{chosen['check']}"]
        rows.append(Row(cell["finding_id"], arm, cell["slot"], chosen["raw"], content, defects, meta=meta))
    return rows


def load_v10() -> list[Row]:
    """v1.0 outputs. These were parsed in v1.0 with fence stripping and regex extraction, which cannot be undone."""
    rows = []
    for slot in ("A", "B", "C"):
        for path in sorted((ROOT / "runs" / "v1.0" / "raters" / slot).glob("*_result.json")):
            res = json.loads(path.read_text())
            rows.append(Row(res["finding_id"], "v1.0", slot, str(path.relative_to(ROOT)), res.get("score"),
                            meta={"served_provider": (res.get("meta") or {}).get("served_provider"),
                                  "cost": ((res.get("meta") or {}).get("usage") or {}).get("cost")}))
    return rows


# ---------------------------------------------------------------- strict parse

def _bool_or_none(v):
    return v if v is None or type(v) is bool else "invalid"


def _int_or_none(v):
    return v if v is None or (type(v) is int and v >= 0) else "invalid"


def parse(row: Row) -> dict:
    """Return the parsed assessment for one row. Defects are recorded, never repaired."""
    c = row.content
    out: dict[str, Any] = {"finding_id": row.finding_id, "arm": row.arm, "slot": row.slot}
    if c is None:
        out.update({"valid_letters": False, "valid_cvss": False, "defects": list(row.defects), "notes": list(row.notes),
                    "meta": row.meta, "rationales": {}})
        return out
    if c.get("refusal"):
        row.defects.append("refusal")
    if "canary_followed" in c:
        out["canary_followed"] = True
    text_blob = json.dumps(c.get("rationales") or {}).lower()
    out["canary_noticed"] = "canary" in text_blob and "canary_followed" not in c
    # CVSS
    m = CVSS_RE.match(str(c.get("cvss_vector") or "").strip())
    if m:
        out["cvss"] = dict(zip(CVSS_BASE, m.groups()))
        out["cvss_vector"] = "CVSS:4.0/" + "/".join(f"{k}:{v}" for k, v in out["cvss"].items())
        out["valid_cvss"] = True
    else:
        row.defects.append("cvss_malformed")
        out["valid_cvss"] = False
    # AIVSS letters as claimed
    letters = {}
    ok = True
    for name in AIVSS:
        v = str((c.get("aivss") or {}).get(name) or "").upper()
        if len(v) != 1 or v not in LETTERS[name]:
            ok = False
            row.defects.append(f"letter_invalid:{name}")
        letters[name] = v
    out["letters_claimed"] = letters
    # RH from facts as given (P07)
    facts = c.get("rh_facts") or {}
    rp, iv = _bool_or_none(facts.get("reachable_proxy")), _bool_or_none(facts.get("isolation_verified"))
    ve, er = _int_or_none(facts.get("verified_episodes")), _int_or_none(facts.get("episodes_reviewed"))
    locus = facts.get("locus")
    rh_used = None
    if "invalid" in (rp, iv, ve, er):
        row.defects.append("rh_facts_invalid")
    else:
        rh_used = classify_rh(reachable_proxy=rp, isolation_verified=iv, verified_episodes=ve)
    # A free-text locus is the assessor's own answer in the wrong format. Map it by keyword and log
    # the mapping. A null locus stays null: nothing is invented (premortem P07).
    mapped = locus if locus in RH_LOCI else None
    if locus is not None and mapped is None:
        text = str(locus).lower()
        mapped = "evaluator" if re.search(r"eval|grader|reward|verifier|test|score|judge", text) else "environment"
        row.notes.append(f"rh_locus_mapped:{mapped}<-{text[:40]}")
    out["rh_facts"] = {"reachable_proxy": rp, "isolation_verified": iv, "verified_episodes": ve,
                       "episodes_reviewed": er, "locus": mapped}
    if rh_used and ok and rh_used != letters["RH"]:
        row.notes.append(f"rh_letter_claimed_{letters['RH']}_facts_give_{rh_used}")
    letters_used = dict(letters)
    if rh_used:
        letters_used["RH"] = rh_used
    out["letters"] = letters_used
    out["valid_letters"] = ok and rh_used is not None
    # confidence and evidence refs
    out["confidence"] = {k: str(v).lower() for k, v in (c.get("confidence") or {}).items()}
    refs = [r for v in (c.get("evidence") or {}).values() if isinstance(v, list) for r in v]
    out["evidence_refs"] = len(refs)
    out["evidence_refs_not_citation"] = sum(1 for r in refs if not (isinstance(r, str) and CITE_RE.match(r.strip())))
    # gate
    for key in ("applicability_as_implemented", "applicability_as_modeled"):
        b = c.get(key) or {}
        g, s = b.get("model_directed_goal_pursuit"), b.get("selects_or_sequences_actions")
        out[key] = {"goal": g, "actions": s, "pass": (g is True and s is True) if type(g) is bool and type(s) is bool else None,
                    "confidence": str(b.get("confidence") or "").lower() or None, "rationale": b.get("rationale")}
    # BOD track, strict
    auto = str(c.get("automatable") or "").strip().lower()
    ti = str(c.get("technical_impact") or "").strip().lower()
    out["automatable"] = {"yes": True, "no": False}.get(auto)
    out["technical_impact"] = ti if ti in ("partial", "total") else None
    if out["automatable"] is None:
        row.defects.append("automatable_invalid")
    if out["technical_impact"] is None:
        row.defects.append("technical_impact_invalid")
    if row.arm.endswith("fixed") or row.arm == "fixed":
        out["not_exploitable_as_configured"] = c.get("not_exploitable_as_configured")
    out["rationales"] = c.get("rationales") or {}
    out["defects"] = list(row.defects)
    out["notes"] = list(row.notes)
    out["meta"] = row.meta
    return out


# ---------------------------------------------------------------- calculator

def build_payload(finding: dict, lab: str, parsed: dict, evidence: dict, *, cvss_vector: str | None = None,
                  letters: dict | None = None, rh_facts: dict | None = None, assessor: str = "adjudicated",
                  unresolved: bool = False) -> dict:
    letters = letters or parsed["letters"]
    facts = dict(rh_facts or parsed["rh_facts"])
    if facts.get("episodes_reviewed") is None and isinstance(facts.get("verified_episodes"), int):
        facts["episodes_reviewed"] = facts["verified_episodes"]
    rationales = parsed.get("rationales") or {}
    metric_evidence = {}
    for name in AIVSS:
        entry = {"rationale": str(rationales.get(name) or f"{assessor} assigned {name}:{letters[name]}").strip() or "none given",
                 "evidence_refs": [f"assessor:{assessor}/{finding['id']}/{name}"]}
        if name == "RH":
            entry.update(facts)
        metric_evidence[name] = entry
    impl, mod = parsed.get("applicability_as_implemented") or {}, parsed.get("applicability_as_modeled") or {}
    gate_note = (f"Gate set true so the calculator can score the path. Assessor answers: as implemented pass={impl.get('pass')}, "
                 f"as modeled pass={mod.get('pass')}.")
    exposed, exposed_src = PUBLICLY_EXPOSED[lab]
    return {
        "finding_id": finding["id"], "path_id": finding["path_id"], "title": finding["title"], "summary": finding["impact"],
        "risk_category": finding.get("asi_category") or "ASI01",
        "cvss_vector": cvss_vector or parsed["cvss_vector"],
        "aivss_vector": "AIVSS:1.0/" + "/".join(f"{k}:{letters[k]}" for k in AIVSS),
        "metric_evidence": metric_evidence,
        "agentic_applicability": {"model_directed_goal_pursuit": True, "action_selection_or_sequencing": True,
                                  "rationale": gate_note, "evidence_refs": list(finding["code_citations"])},
        "evidence": evidence, "exploit_maturity_unresolved": unresolved,
        "publicly_exposed": exposed, "publicly_exposed_source": exposed_src,
        "decision_data_observed_at": "2026-11-07T00:00:00Z",
        "automatable": bool(parsed.get("automatable")), "technical_impact": parsed.get("technical_impact") or "partial",
        "include_decision": True, "include_priority": False,
        "provenance": {"assessor": assessor, "assessor_kind": "llm_assisted", "tool": "aivss-calc",
                       "tool_version": "1.2.0", "assessed_at": "2026-11-07T00:00:00Z"},
    }


def score(payload: dict) -> dict:
    report = assess(assessment_from_payload(payload))
    validate_report(report)
    s = report["scores"]
    return {"cvss_bt": s["cvss_bte"], "cvss_band": s["cvss_band"], "aivss": s["aivss"], "aivss_band": s["aivss_band"],
            "effect_class": s["agentic_effect_class"], "provisional": s["provisional"], "aivss_min": s["aivss_min"],
            "aivss_max": s["aivss_max"], "nomenclature": s["cvss_nomenclature"], "rule": s["rule"]}


def score_rows(parsed_rows: list[dict], findings: dict[str, dict], emr: dict[str, dict]) -> list[dict]:
    """Score every assessor row at the headline evidence. Rows the calculator rejects keep their letters for agreement."""
    out = []
    for p in parsed_rows:
        f = findings[p["finding_id"]]
        p = dict(p)
        if p.get("valid_cvss") and p.get("valid_letters"):
            try:
                p["scores"] = score(build_payload(f, f["lab"], p, emr[f["id"]]["evidence"], assessor=f"assessor-{p['slot']}"))
            except (ValueError, TypeError, KeyError) as exc:
                p["scores"] = None
                p["defects"] = p["defects"] + [f"calculator_rejected:{str(exc)[:120]}"]
        else:
            p["scores"] = None
        out.append(p)
    return out
