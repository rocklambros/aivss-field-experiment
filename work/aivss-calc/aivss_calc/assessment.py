"""Assembles a complete AIVSS 1.0 assessment report."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import re
from typing import Any

from .ai_metrics import (
    AGENTIC_METRIC_ORDER,
    AGENTIC_METRICS,
    AGENTIC_EFFECT_CLASS_LABELS,
    AIProfile,
    EFFECT_CLASS_STATUS,
    parse_aivss_vector,
    split_ai_vector,
    validate_metric_evidence,
)
from .cvss_score import score_cvss_bte
from .lookup import AIVSS_BASIS, aivss_lookup, cvss_nomenclature
from .decision import ExploitationEvidence, decide
from .exploit_maturity import apply_exploit_maturity, resolve_exploit_maturity
from .macrovector import macrovector, parse_cvss_vector
from .priority import compute_priority
from .taxonomy import normalize_risk_category
from .versions import (
    CALCULATOR_VERSION,
    REPORT_SCHEMA_VERSION,
    RUBRIC_VERSION,
    SPEC_VERSION,
)

VALID_ASSESSOR_KINDS = frozenset({"human", "scanner", "llm_assisted", "imported"})

UNKNOWN_EXPOSURE_SOURCE = (
    "Unknown exposure treated as internal (CISA BOD 26-04 implementation guidance)"
)


@dataclass
class Provenance:
    assessor: str | None = None
    assessor_kind: str = "human"
    tool: str | None = None
    tool_version: str | None = None
    assessed_at: str | None = None

    def __post_init__(self) -> None:
        if self.assessor_kind not in VALID_ASSESSOR_KINDS:
            raise ValueError(
                f"assessor_kind must be one of {sorted(VALID_ASSESSOR_KINDS)}; "
                f"got {self.assessor_kind!r}"
            )
        for name in ("assessor", "tool", "tool_version"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"{name} must be a non-empty string or omitted")
        if self.assessed_at is not None:
            if not isinstance(self.assessed_at, str) or not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
                r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
                self.assessed_at,
            ):
                raise ValueError("assessed_at must be an RFC 3339 timestamp")
            try:
                parsed = datetime.fromisoformat(self.assessed_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("assessed_at must be an RFC 3339 timestamp") from exc
            if parsed.tzinfo is None:
                raise ValueError(
                    "assessed_at must include time and UTC offset in RFC 3339 format"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessor": self.assessor,
            "assessor_kind": self.assessor_kind,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "assessed_at": self.assessed_at,
        }


@dataclass
class OrgContext:
    """Optional, organization-internal priority inputs. All fields are required."""

    business_criticality: str
    reach: str
    likelihood: float


@dataclass
class Assessment:
    finding_id: str
    cvss_vector: str
    asi_category: str
    title: str | None = None
    summary: str | None = None
    aivss_vector: str | None = None
    ai_profile: AIProfile | None = None
    agentic_applicability: dict[str, Any] = field(default_factory=dict)
    metric_evidence: dict[str, dict[str, Any]] = field(default_factory=dict)
    path_id: str | None = None
    evidence: ExploitationEvidence = field(default_factory=ExploitationEvidence)
    org_context: OrgContext | None = None
    provenance: Provenance = field(default_factory=Provenance)
    publicly_exposed: bool | None = None
    publicly_exposed_source: str | None = None
    decision_data_observed_at: str | None = None
    cve_id: str | None = None
    fceb_bod_2604_scope: bool = False
    automatable: bool | None = None
    technical_impact: str | None = None
    vulnrichment_automatable: bool | None = None
    vulnrichment_technical_impact: str | None = None
    include_decision: bool = True
    include_priority: bool = False
    taxonomy_metadata: dict[str, Any] | None = None
    exploit_maturity_unresolved: bool = False


def assessment_from_payload(payload: dict[str, Any]) -> Assessment:
    """Build an Assessment from an input-schema-conforming mapping."""
    org = payload.get("org_context")
    return Assessment(
        finding_id=payload["finding_id"],
        path_id=payload["path_id"],
        title=payload.get("title"),
        summary=payload.get("summary"),
        cvss_vector=payload["cvss_vector"],
        aivss_vector=payload.get("aivss_vector"),
        asi_category=payload["risk_category"],
        agentic_applicability=dict(payload["agentic_applicability"]),
        metric_evidence=dict(payload.get("metric_evidence") or {}),
        evidence=ExploitationEvidence(**dict(payload.get("evidence", {}))),
        org_context=OrgContext(**org) if org else None,
        provenance=Provenance(**dict(payload.get("provenance", {}))),
        publicly_exposed=payload.get("publicly_exposed"),
        publicly_exposed_source=payload.get("publicly_exposed_source"),
        decision_data_observed_at=payload.get("decision_data_observed_at"),
        cve_id=payload.get("cve_id"),
        fceb_bod_2604_scope=payload.get("fceb_bod_2604_scope", False),
        automatable=payload.get("automatable"),
        technical_impact=payload.get("technical_impact"),
        vulnrichment_automatable=payload.get("vulnrichment_automatable"),
        vulnrichment_technical_impact=payload.get("vulnrichment_technical_impact"),
        include_decision=payload.get("include_decision", True),
        include_priority=payload.get("include_priority", False),
        taxonomy_metadata=(
            dict(payload["taxonomy_metadata"])
            if payload.get("taxonomy_metadata") is not None
            else None
        ),
        exploit_maturity_unresolved=payload.get("exploit_maturity_unresolved", False),
    )


def assess(a: Assessment) -> dict[str, Any]:
    """Produce a schema-conforming AIVSS 1.0 report for one exploit path.

    Conformance Level 1 requires the Agentic AI Profile (LC, CP, AP, RH, ES)
    and resolves Exploit Maturity (E) from the evidence ladder before CVSS-BTE
    scoring. AIVSS is read from Lookup
    Table AIVSS (Table 6) and is never lower than CVSS-BTE.
    """
    if not isinstance(a.finding_id, str) or not a.finding_id.strip():
        raise ValueError("finding_id is required")
    if not isinstance(a.path_id, str) or not a.path_id.strip():
        raise ValueError("path_id is required to identify one coherent exploit path")
    if a.finding_id != a.finding_id.strip() or a.path_id != a.path_id.strip():
        raise ValueError(
            "finding_id and path_id must not contain surrounding whitespace"
        )
    for name in ("title", "summary"):
        value = getattr(a, name)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ValueError(f"{name} must be a non-empty string or omitted")
    for name in (
        "fceb_bod_2604_scope",
        "include_decision",
        "include_priority",
        "exploit_maturity_unresolved",
    ):
        if type(getattr(a, name)) is not bool:
            raise ValueError(f"{name} must be true or false")
    if not isinstance(a.metric_evidence, dict):
        raise ValueError("metric_evidence must be an object")
    applicability = a.agentic_applicability
    if not isinstance(applicability, dict) or set(applicability) != {
        "model_directed_goal_pursuit",
        "action_selection_or_sequencing",
        "rationale",
        "evidence_refs",
    }:
        raise ValueError("agentic_applicability must contain the four required fields")
    for name in (
        "model_directed_goal_pursuit",
        "action_selection_or_sequencing",
    ):
        if type(applicability[name]) is not bool:
            raise ValueError(f"agentic_applicability.{name} must be true or false")
        if not applicability[name]:
            raise ValueError(
                "AIVSS is not applicable unless the assessed system performs "
                "model-directed goal pursuit and action selection or sequencing"
            )
    if (
        not isinstance(applicability["rationale"], str)
        or not applicability["rationale"].strip()
        or not isinstance(applicability["evidence_refs"], list)
        or not applicability["evidence_refs"]
        or any(
            not isinstance(ref, str) or not ref.strip()
            for ref in applicability["evidence_refs"]
        )
    ):
        raise ValueError(
            "agentic_applicability requires a non-empty rationale and evidence_refs"
        )
    if not isinstance(a.provenance, Provenance):
        raise ValueError("provenance must be a Provenance record")

    cvss_only, embedded = split_ai_vector(a.cvss_vector)
    profile_sources = sum(
        source is not None for source in (embedded, a.aivss_vector, a.ai_profile)
    )
    if profile_sources > 1:
        raise ValueError(
            "Provide the AIVSS profile exactly once: aivss_vector, ai_profile, "
            "or two-vector display form"
        )
    profile = (
        a.ai_profile
        if a.ai_profile is not None
        else parse_aivss_vector(a.aivss_vector)
        if a.aivss_vector is not None
        else embedded
    )
    if profile is None:
        raise ValueError(
            "Conformance Level 1 requires an Agentic AI Profile "
            "(aivss_vector or ai_profile with LC, CP, AP, RH and ES)"
        )
    validate_metric_evidence(profile, a.metric_evidence)
    if a.provenance.assessed_at is None:
        raise ValueError(
            "provenance.assessed_at is required as an RFC 3339 evidence timestamp"
        )

    # (1) Resolve Exploit Maturity before severity interpolation.
    maturity = resolve_exploit_maturity(
        a.evidence, unresolved=a.exploit_maturity_unresolved
    )
    resolved_vector = apply_exploit_maturity(cvss_only, str(maturity["e"]))
    metrics = parse_cvss_vector(resolved_vector)
    mv = macrovector(metrics)
    cvss_bte = score_cvss_bte(resolved_vector)

    # (2)-(4) Effect Class by the ordered ladder, then the lookup tables.
    ai_class = profile.effect_class()
    uplift = profile.agentic_uplift_u()
    lookup = aivss_lookup(cvss_bte, ai_class)
    class_min, class_max = profile.effect_class_range()
    aivss_min = aivss_lookup(cvss_bte, class_min)["aivss"]
    aivss_max = aivss_lookup(cvss_bte, class_max)["aivss"]

    risk_category = normalize_risk_category(a.asi_category, a.taxonomy_metadata)

    report: dict[str, Any] = {
        "aivss_version": SPEC_VERSION,
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "rubric_version": RUBRIC_VERSION,
        "calculator_version": CALCULATOR_VERSION,
        "specification_status": "v1",
        "finding_id": a.finding_id,
        "path_id": a.path_id,
        "risk_category": risk_category,
        "agentic_applicability": dict(applicability),
        "cvss": {
            "vector": resolved_vector,
            "macrovector": mv,
            "cvss_score": cvss_bte,
            "cvss_bte": cvss_bte,
            "exploit_maturity": {
                "e": maturity["e"],
                "rung": maturity["rung"],
                "rationale": maturity["rationale"],
                "state": maturity["state"],
                "authoritative": maturity["authoritative"],
                "epss": maturity["epss"],
                "epss_date": maturity["epss_date"],
                "input_vector": cvss_only,
            },
        },
        "agentic_ai_profile": {
            "vector": profile.to_vector(),
            "metrics": {
                name: {
                    "value": getattr(profile, name.lower()),
                    "label": AGENTIC_METRICS[name][getattr(profile, name.lower())][0],
                    "evidence": dict(a.metric_evidence[name]),
                }
                for name in AGENTIC_METRIC_ORDER
            },
            "complete": profile.complete,
            "provisional": profile.provisional,
            "agentic_effect_class": ai_class,
            "agentic_effect_class_label": AGENTIC_EFFECT_CLASS_LABELS[ai_class],
            "agentic_effect_class_status": EFFECT_CLASS_STATUS,
            "agentic_uplift_u": uplift,
            "agentic_effect_class_min": class_min,
            "agentic_effect_class_max": class_max,
        },
        "scores": {
            "cvss_score": cvss_bte,
            "cvss_bte": cvss_bte,
            "cvss_nomenclature": cvss_nomenclature(metrics),
            "cvss_band": lookup["cvss_band"],
            "agentic_effect_class": ai_class,
            "provisional": profile.provisional,
            "agentic_uplift_u": uplift,
            "aivss": lookup["aivss"],
            "aivss_min": aivss_min,
            "aivss_max": aivss_max,
            "aivss_band": lookup["aivss_band"],
            "table_cell": lookup["table_cell"],
            "rule": lookup["rule"],
            "status": "normative",
            "basis": AIVSS_BASIS,
        },
        "provenance": a.provenance.to_dict(),
    }
    if a.title is not None:
        report["title"] = a.title
    if a.summary is not None:
        report["summary"] = a.summary

    if a.include_decision:
        # CISA makes a best-effort exposure determination and otherwise treats
        # the asset as internal. Treating unknown exposure as exposed is an
        # organizational policy and must be supplied explicitly.
        publicly_exposed = a.publicly_exposed
        publicly_exposed_source = a.publicly_exposed_source
        if publicly_exposed is None:
            publicly_exposed = False
            publicly_exposed_source = publicly_exposed_source or UNKNOWN_EXPOSURE_SOURCE
        if a.decision_data_observed_at is None:
            raise ValueError(
                "decision_data_observed_at is required when include_decision is true"
            )
        report["decision"] = decide(
            evidence=a.evidence,
            publicly_exposed=publicly_exposed,
            publicly_exposed_source=publicly_exposed_source,
            decision_data_observed_at=a.decision_data_observed_at,
            agentic_effect_class=ai_class,
            automatable=a.automatable,
            technical_impact=a.technical_impact,
            cve_id=a.cve_id,
            fceb_bod_2604_scope=a.fceb_bod_2604_scope,
            vulnrichment_automatable=a.vulnrichment_automatable,
            vulnrichment_technical_impact=a.vulnrichment_technical_impact,
        )

    if a.include_priority:
        if a.org_context is None:
            raise ValueError("org_context is required when include_priority is true")
        report["priority"] = compute_priority(
            severity=cvss_bte,
            business_criticality=a.org_context.business_criticality,
            reach=a.org_context.reach,
            likelihood=a.org_context.likelihood,
        )

    return report
