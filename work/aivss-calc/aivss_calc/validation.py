"""Syntactic and semantic validation for AIVSS v1 artifacts."""

from __future__ import annotations

import json
from pathlib import Path
import sysconfig
from typing import Any

import jsonschema

from .ai_metrics import (
    AGENTIC_EFFECT_CLASS_LABELS,
    AGENTIC_METRIC_ORDER,
    AGENTIC_METRICS,
    parse_aivss_vector,
    validate_metric_evidence,
)
from .assessment import UNKNOWN_EXPOSURE_SOURCE, Provenance
from .lookup import AIVSS_BASIS, aivss_lookup, cvss_nomenclature
from .cvss_score import score_cvss_bte
from .decision import (
    EVIDENCE_LADDER,
    TIMELINE_LABELS,
    ExploitationEvidence,
    advance_timeline,
    bod_timeline,
    decide,
)
from .macrovector import macrovector, parse_cvss_vector
from .exploit_maturity import apply_exploit_maturity
from .priority import compute_priority
from .taxonomy import ASI_TOP_10

_SOURCE_SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
_INSTALLED_SCHEMA_DIR = Path(sysconfig.get_path("data")) / "share" / "aivss" / "schemas"
SCHEMA_DIR = (
    _SOURCE_SCHEMA_DIR
    if (_SOURCE_SCHEMA_DIR / "aivss-report-v1.0.json").is_file()
    else _INSTALLED_SCHEMA_DIR
)
INPUT_SCHEMA = SCHEMA_DIR / "aivss-assessment-input-v1.0.json"
REPORT_SCHEMA = SCHEMA_DIR / "aivss-report-v1.0.json"


def _schema(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_assessment_input(payload: dict[str, Any]) -> None:
    """Validate input shape plus vector and evidence semantics."""
    jsonschema.validate(payload, _schema(INPUT_SCHEMA))
    for name in ("finding_id", "path_id"):
        if payload[name] != payload[name].strip():
            raise ValueError(f"{name} must not contain surrounding whitespace")
    for name in ("title", "summary"):
        if name in payload and not payload[name].strip():
            raise ValueError(f"{name} must not be whitespace-only")
    applicability = payload["agentic_applicability"]
    if not applicability["rationale"].strip() or any(
        not ref.strip() for ref in applicability["evidence_refs"]
    ):
        raise ValueError("agentic_applicability evidence must not be whitespace-only")
    parse_cvss_vector(payload["cvss_vector"])
    score_cvss_bte(payload["cvss_vector"])
    has_profile = "aivss_vector" in payload
    if has_profile != ("metric_evidence" in payload):
        raise ValueError(
            "aivss_vector and metric_evidence must both be present or both omitted"
        )
    profile = parse_aivss_vector(payload["aivss_vector"]) if has_profile else None
    if profile is not None:
        validate_metric_evidence(profile, payload["metric_evidence"])
    Provenance(**payload["provenance"])
    evidence = ExploitationEvidence(**payload.get("evidence", {}))
    if payload.get("include_decision", True):
        publicly_exposed = payload.get("publicly_exposed")
        publicly_exposed_source = payload.get("publicly_exposed_source")
        if publicly_exposed is None:
            publicly_exposed = False
            publicly_exposed_source = publicly_exposed_source or UNKNOWN_EXPOSURE_SOURCE
        decide(
            evidence=evidence,
            publicly_exposed=publicly_exposed,
            publicly_exposed_source=publicly_exposed_source,
            decision_data_observed_at=payload["decision_data_observed_at"],
            agentic_effect_class=(
                profile.effect_class() if profile is not None else "AX"
            ),
            automatable=payload.get("automatable"),
            technical_impact=payload.get("technical_impact"),
            cve_id=payload.get("cve_id"),
            fceb_bod_2604_scope=payload.get("fceb_bod_2604_scope", False),
            vulnrichment_automatable=payload.get("vulnrichment_automatable"),
            vulnrichment_technical_impact=payload.get("vulnrichment_technical_impact"),
        )


def validate_report(report: dict[str, Any]) -> None:
    """Validate JSON shape and cross-field scoring invariants."""
    jsonschema.validate(report, _schema(REPORT_SCHEMA))
    Provenance(**report["provenance"])
    for name in ("title", "summary"):
        if name in report and not report[name].strip():
            raise ValueError(f"{name} must not be whitespace-only")
    applicability = report["agentic_applicability"]
    if not applicability["rationale"].strip() or any(
        not ref.strip() for ref in applicability["evidence_refs"]
    ):
        raise ValueError("agentic_applicability evidence must not be whitespace-only")

    asi = report["risk_category"]
    if asi.get("scheme") == "MAESTRO-extended":
        if asi.get("id") != "MAESTRO-EXTENDED":
            raise ValueError("MAESTRO-extended risk_category id mismatch")
        if asi.get("name") != "MAESTRO-extended finding":
            raise ValueError("MAESTRO-extended risk_category name mismatch")
    elif asi.get("scheme") == "ASI":
        if ASI_TOP_10[asi["id"]] != asi["name"]:
            raise ValueError("risk_category name does not match its ASI identifier")
    else:
        raise ValueError("risk_category.scheme must be ASI or MAESTRO-extended")

    cvss = report["cvss"]
    expected_cvss = score_cvss_bte(cvss["vector"])
    if cvss["cvss_bte"] != expected_cvss or cvss["cvss_score"] != expected_cvss:
        raise ValueError("cvss_score does not match the CVSS vector")
    expected_macrovector = macrovector(parse_cvss_vector(cvss["vector"]))
    if cvss["macrovector"] != expected_macrovector:
        raise ValueError("macrovector does not match the CVSS vector")
    maturity = cvss.get("exploit_maturity")
    if not isinstance(maturity, dict):
        raise ValueError("cvss.exploit_maturity is required")
    if apply_exploit_maturity(maturity["input_vector"], maturity["e"]) != cvss["vector"]:
        raise ValueError("cvss.vector does not match resolved Exploit Maturity")

    extension = report.get("agentic_ai_profile")
    if extension is None:
        raise ValueError("Level 1 reports require agentic_ai_profile")
    profile = parse_aivss_vector(extension["vector"])
    for name in AGENTIC_METRIC_ORDER:
        value = getattr(profile, name.lower())
        if extension["metrics"][name]["value"] != value:
            raise ValueError(f"{name} does not match the AIVSS vector")
        if extension["metrics"][name]["label"] != AGENTIC_METRICS[name][value][0]:
            raise ValueError(f"{name} label does not match its value")
    validate_metric_evidence(
        profile,
        {
            name: extension["metrics"][name]["evidence"]
            for name in AGENTIC_METRIC_ORDER
        },
    )
    if extension["complete"] != profile.complete:
        raise ValueError("profile complete flag does not match metric values")
    if extension["provisional"] != profile.provisional:
        raise ValueError("provisional flag does not match the classifying metrics")
    class_min, class_max = profile.effect_class_range()
    if (
        extension["agentic_effect_class_min"] != class_min
        or extension["agentic_effect_class_max"] != class_max
    ):
        raise ValueError("effect class range does not match the AIVSS vector")
    if extension["agentic_uplift_u"] != profile.agentic_uplift_u():
        raise ValueError("agentic_uplift_u does not match Lookup Table U")
    if extension["agentic_effect_class"] != profile.effect_class():
        raise ValueError("agentic_effect_class does not match the AIVSS vector")
    if (
        extension["agentic_effect_class_label"]
        != AGENTIC_EFFECT_CLASS_LABELS[profile.effect_class()]
    ):
        raise ValueError("agentic_effect_class_label does not match the class")
    if extension["agentic_effect_class_status"] != "unvalidated":
        raise ValueError(
            "agentic_effect_class_status must disclose validation status"
        )

    scores = report["scores"]
    lookup = aivss_lookup(expected_cvss, profile.effect_class())
    expected_scores = {
        "cvss_score": expected_cvss,
        "cvss_bte": expected_cvss,
        "cvss_nomenclature": cvss_nomenclature(parse_cvss_vector(cvss["vector"])),
        "cvss_band": lookup["cvss_band"],
        "agentic_effect_class": profile.effect_class(),
        "provisional": profile.provisional,
        "agentic_uplift_u": profile.agentic_uplift_u(),
        "aivss": lookup["aivss"],
        "aivss_min": aivss_lookup(expected_cvss, class_min)["aivss"],
        "aivss_max": aivss_lookup(expected_cvss, class_max)["aivss"],
        "aivss_band": lookup["aivss_band"],
        "table_cell": lookup["table_cell"],
        "rule": lookup["rule"],
        "status": "normative",
        "basis": AIVSS_BASIS,
    }
    if scores != expected_scores:
        raise ValueError("scores do not match Lookup Table AIVSS for this vector pair")
    if scores["aivss"] < scores["cvss_bte"]:
        raise ValueError("AIVSS must never be lower than CVSS-BTE")

    if decision := report.get("decision"):
        recommended = decision["aivss_recommended_timeline"]
        branch_fields = {
            "cisa_bod_26_04": {
                "bod_2604_timeline",
                "bod_2604_label",
                "forensic_triage_required",
            },
            "informative_bod_26_04_cve_guidance": {
                "bod_2604_guidance_timeline",
                "bod_2604_guidance_label",
                "forensic_triage_indicated",
            },
            "informative_bod_26_04_analogy": {
                "bod_2604_analogy_timeline",
                "bod_2604_analogy_label",
                "forensic_triage_indicated",
            },
        }
        allowed_branch_fields = branch_fields[decision["decision_basis"]]
        all_branch_fields = set().union(*branch_fields.values())
        if any(key in decision for key in all_branch_fields - allowed_branch_fields):
            raise ValueError(
                "decision contains fields from the wrong BOD result branch"
            )
        if decision["compliance_applicable"]:
            base_key = "bod_2604_timeline"
            label_key = "bod_2604_label"
        elif decision["decision_basis"] == "informative_bod_26_04_cve_guidance":
            base_key = "bod_2604_guidance_timeline"
            label_key = "bod_2604_guidance_label"
        else:
            base_key = "bod_2604_analogy_timeline"
            label_key = "bod_2604_analogy_label"
        points = decision["decision_points"]
        exploitation = decision["exploitation"]
        rung = exploitation["rung"]
        state_by_rung = {
            "cisa_kev": ("known_exploited", True),
            "vulnrichment_active": ("active_reported", True),
            "observed_local": ("active_observed_local", False),
            "poc": ("poc", False),
            "none": ("no_evidence_supplied", False),
        }
        expected_state, expected_authoritative = state_by_rung[rung]
        if exploitation["state"] != expected_state:
            raise ValueError("exploitation state does not match its evidence rung")
        if exploitation["authoritative"] != expected_authoritative:
            raise ValueError("exploitation authority does not match its evidence rung")
        if exploitation["rationale"] != dict(EVIDENCE_LADDER)[rung]:
            raise ValueError("exploitation rationale does not match its evidence rung")
        ExploitationEvidence(
            epss=exploitation["epss"], epss_date=exploitation["epss_date"]
        )
        if points["in_kev"] != (rung == "cisa_kev"):
            raise ValueError("KEV decision point does not match exploitation evidence")
        sources = {
            points["automatable_source"],
            points["technical_impact_source"],
        }
        if decision["cve_id"] is None and sources != {"supplied"}:
            raise ValueError("non-CVE analogies must use explicitly supplied inputs")
        if points["in_kev"] and any("default" in source for source in sources):
            raise ValueError(
                "KEV decision points must not use missing-metadata defaults"
            )
        faq_applied = decision.get("missing_metadata_faq_applied") is True
        expected_class = profile.effect_class() if profile is not None else "AX"
        if points["agentic_effect_class"] != expected_class:
            raise ValueError("decision class does not match the AIVSS profile")
        if faq_applied and (points["automatable"], points["technical_impact"]) != (
            False,
            "total",
        ):
            raise ValueError(
                "missing-metadata rule must apply Automatable no and Technical Impact total"
            )
        expected_base = bod_timeline(
            in_kev=points["in_kev"],
            publicly_exposed=points["publicly_exposed"],
            automatable=points["automatable"],
            technical_impact=points["technical_impact"],
        )
        if decision[base_key] != expected_base:
            raise ValueError("BOD timeline does not match its decision points")
        expected_base = decision[base_key]
        if decision[label_key] != TIMELINE_LABELS[expected_base]:
            raise ValueError("BOD timeline label does not match its key")
        triggered = points["agentic_effect_class"] == "A2"
        expected_recommended = advance_timeline(expected_base, 1 if triggered else 0)
        expected_status = (
            "provisional"
            if points["agentic_effect_class"] == "AX"
            else "experimental-uncalibrated"
        )
        if decision["overlay_status"] != expected_status:
            raise ValueError("overlay has the wrong status")
        if decision["overlay_triggered"] != triggered:
            raise ValueError("overlay_triggered does not match A2 SSVC extension")
        if recommended != expected_recommended:
            raise ValueError("AIVSS timeline does not match the overlay rule")
        if decision["aivss_recommended_label"] != TIMELINE_LABELS[recommended]:
            raise ValueError("AIVSS timeline label does not match its key")
        if decision["escalated"] != (expected_recommended != expected_base):
            raise ValueError("escalated does not match the timeline change")
        triage = decision[base_key] == "3DF"
        triage_key = (
            "forensic_triage_required"
            if decision["compliance_applicable"]
            else "forensic_triage_indicated"
        )
        if decision[triage_key] != triage:
            raise ValueError("forensic triage flag does not match the BOD result")
        if decision["aivss_recommended_forensic_triage_indicated"] != triage:
            raise ValueError("the AIVSS overlay changed a forensic-triage requirement")

    if priority := report.get("priority"):
        severity = report["scores"]["cvss_bte"]
        terms = priority["terms"]
        inverse_levels = {1.0: "high", 0.65: "medium", 0.35: "low"}
        if terms["severity_norm"] != round(severity / 10.0, 4):
            raise ValueError("priority severity does not match CVSS-BTE")
        expected_priority = compute_priority(
            severity=severity,
            business_criticality=inverse_levels[terms["business_criticality"]],
            reach=inverse_levels[terms["reach"]],
            likelihood=terms["likelihood"],
        )
        if priority != expected_priority:
            raise ValueError("priority does not match its reported terms")
