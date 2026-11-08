"""AIVSS decision support with a separately identified BOD 26-04 result.

BOD 26-04 (June 10, 2026) revoked BOD 22-01 and BOD 19-02 and replaced
CVSS-severity-driven remediation with a four-variable decision model. CISA
publishes three of the four variables for every CVE ID through the Vulnrichment
Program; the fourth (asset exposure) is supplied by the asset owner.

For a CVE, the unmodified BOD result is reported separately from the
non-binding AIVSS overlay. For a non-CVE finding, the same table may
be used only as an explicitly labelled analogy and never as a compliance result.

Timeline table transcribed from the CERT/CC SSVC "CISA BOD 26-04 Response Model"
(cisa:BOD2604:1.0.0), the reference BOD 26-04 itself cites for the Automatable
and Technical Impact decision point definitions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum

BOD_2604_MODEL_VERSION = "cisa:BOD2604:1.0.0"
BOD_2604_DECISION_TABLE_ID = "cisa:DT_BOD2604:1.0.0"
BOD_2604_MODEL_SOURCE_URL = "https://certcc.github.io/SSVC/howto/cisa_response/"
BOD_2604_DIRECTIVE_URL = (
    "https://www.cisa.gov/news-events/directives/"
    "bod-26-04-prioritizing-security-updates-based-risk"
)
BOD_2604_FAQ_URL = (
    "https://www.cisa.gov/news-events/directives/"
    "bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
)
FAQ_MISSING_METADATA_SOURCE = "CISA BOD 26-04 FAQ (missing metadata)"
SSVC_METHODOLOGY_URL = "https://certcc.github.io/SSVC/"
SSVC_DECISION_POINTS: dict[str, str] = {
    "in_kev": "cisa:KEV:1.0.0",
    "publicly_exposed": "cisa:PE:1.0.0",
    "automatable": "ssvc:A:2.0.0",
    "technical_impact": "ssvc:TI:1.0.0",
    "agentic_ai_effect_class": "aivss:effect_class:1.0.0",
}

TIMELINE_LABELS: dict[str, str] = {
    "FSU": "Fix on system upgrade",
    "60D": "Remediate within 60 days",
    "14D": "Remediate within 14 days",
    "3D": "Remediate within 3 days",
    "3DF": "Remediate within 3 days and carry out a forensic triage of the asset",
}

# Ordered least to most urgent. Used for Agentic Effect Class escalation.
TIMELINE_URGENCY: tuple[str, ...] = ("FSU", "60D", "14D", "3D", "3DF")

# All 16 rows of BOD 26-04 Table 1, keyed (in_kev, publicly_exposed, automatable,
# technical_impact). Held as data rather than boolean conditions: for KEV rows the
# 3D/3DF fast tier requires exposure or automatability in addition to KEV (e.g.
# (yes, no, no, total) is 14D, not 3D). Non-KEV rows can still reach 3D (e.g.
# exposed + automatable + total impact).
BOD_2604_TABLE: dict[tuple[bool, bool, bool, str], str] = {
    (False, False, False, "partial"): "FSU",
    (True, False, False, "partial"): "14D",
    (False, True, False, "partial"): "60D",
    (False, False, True, "partial"): "60D",
    (False, False, False, "total"): "FSU",
    (True, True, False, "partial"): "14D",
    (True, False, True, "partial"): "14D",
    (False, True, True, "partial"): "14D",
    (True, False, False, "total"): "14D",
    (False, True, False, "total"): "14D",
    (False, False, True, "total"): "60D",
    (True, True, True, "partial"): "3D",
    (True, True, False, "total"): "3DF",
    (True, False, True, "total"): "3DF",
    (False, True, True, "total"): "3D",
    (True, True, True, "total"): "3DF",
}


class Exploitation(str, Enum):
    """Exploitation state, resolved by the evidence ladder."""

    KNOWN_EXPLOITED = "known_exploited"
    ACTIVE_REPORTED = "active_reported"
    ACTIVE_OBSERVED_LOCAL = "active_observed_local"
    POC = "poc"
    NONE = "no_evidence_supplied"


# Strict precedence, highest authority first. Replaces the withdrawn
# max(ThM_discrete, ThM_EPSS, ThM_KEV) construction: no transforms, no invented
# probabilities, and no rung that lets a weaker source override a stronger one.
EVIDENCE_LADDER: tuple[tuple[str, str], ...] = (
    ("cisa_kev", "CVE is listed in the CISA KEV catalog (authoritative)"),
    ("vulnrichment_active", "CISA Vulnrichment reports Exploitation: active"),
    (
        "observed_local",
        "Exploitation observed and documented by the assessing organization "
        "(non-CVE agentic finding; not CISA-verified)",
    ),
    ("poc", "Public or private proof-of-concept exists"),
    ("none", "No affirmative exploitation evidence was supplied"),
)


@dataclass
class ExploitationEvidence:
    """Inputs to the exploitation evidence ladder."""

    cisa_kev: bool | None = None
    vulnrichment_active: bool = False
    epss: float | None = None
    epss_date: str | None = None
    observed_local: bool = False
    poc: bool = False

    def __post_init__(self) -> None:
        if self.cisa_kev is not None and type(self.cisa_kev) is not bool:
            raise ValueError("cisa_kev must be true, false, or omitted")
        for name in ("vulnrichment_active", "observed_local", "poc"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be true or false")
        if self.epss is not None:
            if isinstance(self.epss, bool) or not isinstance(self.epss, (int, float)):
                raise ValueError("epss must be a number in [0.0, 1.0] or omitted")
            if not 0.0 <= self.epss <= 1.0:
                raise ValueError(f"epss must be in [0.0, 1.0]; got {self.epss}")
            if not isinstance(self.epss_date, str) or not self.epss_date:
                raise ValueError(
                    "epss_date is required whenever epss is supplied: EPSS is revised "
                    "daily and an undated score is not reproducible"
                )
            try:
                if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", self.epss_date):
                    raise ValueError
                date.fromisoformat(self.epss_date)
            except ValueError as exc:
                raise ValueError("epss_date must use YYYY-MM-DD format") from exc
        elif self.epss_date is not None:
            raise ValueError("epss_date must be omitted when epss is omitted")

    def resolve(self) -> dict[str, object]:
        """Walk the factual exploitation ladder.

        EPSS is recorded alongside the result but does not determine exploitation
        state: it is a calibrated forecast, not a factual exploitation signal, and
        must not outrank documented local observation.
        """
        if self.cisa_kev is True:
            rung, state = "cisa_kev", Exploitation.KNOWN_EXPLOITED
        elif self.vulnrichment_active:
            rung, state = "vulnrichment_active", Exploitation.ACTIVE_REPORTED
        elif self.observed_local:
            rung, state = "observed_local", Exploitation.ACTIVE_OBSERVED_LOCAL
        elif self.poc:
            rung, state = "poc", Exploitation.POC
        else:
            rung, state = "none", Exploitation.NONE

        return {
            "rung": rung,
            "rationale": dict(EVIDENCE_LADDER)[rung],
            "state": state.value,
            "authoritative": rung in ("cisa_kev", "vulnrichment_active"),
            "epss": self.epss,
            "epss_date": self.epss_date,
        }


def bod_timeline(
    *,
    in_kev: bool,
    publicly_exposed: bool,
    automatable: bool,
    technical_impact: str,
) -> str:
    """Return the BOD 26-04 Table 1 remediation timeline key."""
    for name, value in (
        ("in_kev", in_kev),
        ("publicly_exposed", publicly_exposed),
        ("automatable", automatable),
    ):
        if type(value) is not bool:
            raise ValueError(f"{name} must be true or false")
    if not isinstance(technical_impact, str):
        raise ValueError("technical_impact must be 'partial' or 'total'")
    impact = technical_impact.strip().lower()
    if impact not in ("partial", "total"):
        raise ValueError(
            f"technical_impact must be 'partial' or 'total'; got {technical_impact!r}"
        )
    return BOD_2604_TABLE[
        (bool(in_kev), bool(publicly_exposed), bool(automatable), impact)
    ]


def advance_timeline(timeline: str, steps: int = 1) -> str:
    """Move toward 3D without adding or removing a forensic-triage duty."""
    if timeline not in TIMELINE_URGENCY:
        raise ValueError(f"unknown timeline {timeline!r}")
    if type(steps) is not int:
        raise ValueError("steps must be an integer")
    if steps <= 0:
        return timeline
    if timeline == "3DF":
        return "3DF"
    index = TIMELINE_URGENCY.index(timeline)
    ceiling = TIMELINE_URGENCY.index("3D")
    return TIMELINE_URGENCY[min(index + steps, ceiling)]


def escalate(timeline: str, agentic_effect_class: str) -> str:
    """Escalate a timeline by one tier when the Agentic Effect Class is A2.

    Escalation stops at 3D. AIVSS never escalates into 3DF, because the forensic
    triage obligation is a CISA determination tied to KEV listing, not something
    a third-party framework may impose.
    """
    if agentic_effect_class not in ("A0", "A1", "A2", "AX"):
        raise ValueError("agentic_effect_class must be A0, A1, A2, or AX")
    return advance_timeline(timeline, 1) if agentic_effect_class == "A2" else timeline


def decide(
    *,
    evidence: ExploitationEvidence,
    publicly_exposed: bool,
    publicly_exposed_source: str,
    decision_data_observed_at: str,
    agentic_effect_class: str = "A0",
    automatable: bool | None = None,
    technical_impact: str | None = None,
    cve_id: str | None = None,
    fceb_bod_2604_scope: bool = False,
    vulnrichment_automatable: bool | None = None,
    vulnrichment_technical_impact: str | None = None,
) -> dict[str, object]:
    """Run BOD decision support plus the non-binding AIVSS overlay.

    BOD defaults apply only to CVEs. Non-CVE findings require explicit analogy
    inputs; AIVSS never derives BOD decision points from RH or CVSS.
    """
    resolved = evidence.resolve()

    if cve_id is not None and not isinstance(cve_id, str):
        raise ValueError("cve_id must be a string or omitted")
    has_cve = bool(cve_id and cve_id.strip())
    normalized_cve = cve_id.strip().upper() if has_cve else None
    if normalized_cve and not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized_cve):
        raise ValueError(f"cve_id must use CVE-YYYY-NNNN format; got {cve_id!r}")
    if type(publicly_exposed) is not bool:
        raise ValueError("publicly_exposed must be true or false")
    if (
        not isinstance(publicly_exposed_source, str)
        or not publicly_exposed_source.strip()
    ):
        raise ValueError("publicly_exposed_source must be a non-empty string")
    if (
        not isinstance(decision_data_observed_at, str)
        or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
            r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
            decision_data_observed_at,
        )
    ):
        raise ValueError("decision_data_observed_at must be an RFC 3339 timestamp")
    try:
        observed_at = datetime.fromisoformat(
            decision_data_observed_at.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError(
            "decision_data_observed_at must be an RFC 3339 timestamp"
        ) from exc
    if observed_at.tzinfo is None:
        raise ValueError("decision_data_observed_at must include a UTC offset")
    if type(fceb_bod_2604_scope) is not bool:
        raise ValueError("fceb_bod_2604_scope must be true or false")
    for name, value in (
        ("automatable", automatable),
        ("vulnrichment_automatable", vulnrichment_automatable),
    ):
        if value is not None and type(value) is not bool:
            raise ValueError(f"{name} must be true, false, or omitted")
    for name, value in (
        ("technical_impact", technical_impact),
        ("vulnrichment_technical_impact", vulnrichment_technical_impact),
    ):
        if value is not None and not isinstance(value, str):
            raise ValueError(f"{name} must be partial, total, or omitted")
    has_vulnrichment = (
        vulnrichment_automatable is not None
        or vulnrichment_technical_impact is not None
    )
    if (
        evidence.cisa_kev or evidence.vulnrichment_active or evidence.epss is not None
    ) and not has_cve:
        raise ValueError("cve_id is required for KEV, Vulnrichment, or EPSS evidence")
    if fceb_bod_2604_scope and not has_cve:
        raise ValueError("cve_id is required for an FCEB BOD 26-04 compliance result")
    if has_cve and evidence.cisa_kev is None:
        raise ValueError("cisa_kev must be explicitly true or false for a CVE decision")
    if has_vulnrichment and not has_cve:
        raise ValueError("CISA Vulnrichment values require cve_id")
    if evidence.cisa_kev is True and (
        vulnrichment_automatable is None
        or vulnrichment_technical_impact is None
    ):
        raise ValueError(
            "KEV-listed CVEs require CISA Vulnrichment Automatable and "
            "Technical Impact values"
        )
    if agentic_effect_class not in ("A0", "A1", "A2", "AX"):
        raise ValueError("agentic_effect_class must be A0, A1, A2, or AX")
    if (
        automatable is not None
        and vulnrichment_automatable is not None
        and automatable != vulnrichment_automatable
    ):
        raise ValueError("supplied automatable conflicts with CISA Vulnrichment")
    if (
        technical_impact is not None
        and vulnrichment_technical_impact is not None
        and technical_impact.strip().lower()
        != vulnrichment_technical_impact.strip().lower()
    ):
        raise ValueError("supplied technical_impact conflicts with CISA Vulnrichment")

    metadata_both_missing = (
        has_cve
        and not evidence.cisa_kev
        and automatable is None
        and vulnrichment_automatable is None
        and technical_impact is None
        and vulnrichment_technical_impact is None
    )

    if vulnrichment_automatable is not None:
        automatable = vulnrichment_automatable
        automatable_source = "CISA Vulnrichment"
    elif automatable is not None:
        automatable_source = "supplied"
    elif metadata_both_missing:
        automatable = False
        automatable_source = FAQ_MISSING_METADATA_SOURCE
    elif has_cve and not evidence.cisa_kev:
        automatable = False
        automatable_source = "BOD 26-04 default (no)"
    elif has_cve:
        raise ValueError(
            "automatable is required for a KEV-listed CVE; CISA publishes "
            "Vulnrichment data for every KEV entry"
        )
    else:
        raise ValueError(
            "automatable is required for a non-CVE BOD-table analogy; "
            "it is not derived from RH"
        )

    if vulnrichment_technical_impact is not None:
        technical_impact = vulnrichment_technical_impact.strip().lower()
        impact_source = "CISA Vulnrichment"
    elif technical_impact is not None:
        technical_impact = technical_impact.strip().lower()
        impact_source = "supplied"
    elif metadata_both_missing:
        technical_impact = "total"
        impact_source = FAQ_MISSING_METADATA_SOURCE
    elif has_cve and not evidence.cisa_kev:
        technical_impact = "total"
        impact_source = "BOD 26-04 default (total)"
    elif has_cve:
        raise ValueError(
            "technical_impact is required for a KEV-listed CVE; CISA publishes "
            "Vulnrichment data for every KEV entry"
        )
    else:
        raise ValueError(
            "technical_impact is required for a non-CVE BOD-table analogy; "
            "it is not derived from CVSS"
        )

    # Missing-metadata rule (CISA BOD 26-04 implementation guidance): for a
    # non-KEV CVE with neither value published, the table is applied with
    # Automatable no and Technical Impact total (14D if exposed, FSU if not).
    base = bod_timeline(
        in_kev=bool(evidence.cisa_kev),
        publicly_exposed=publicly_exposed,
        automatable=bool(automatable),
        technical_impact=technical_impact,
    )
    # AIVSS overlay (organizational, categorical): Effect Class A2 advances the
    # recommendation one tier; it never creates or shortens 3DF. An AX class
    # cannot trigger it and marks the recommendation provisional.
    overlay_triggered = agentic_effect_class == "A2"
    recommended = advance_timeline(base, 1 if overlay_triggered else 0)
    overlay_status = (
        "provisional" if agentic_effect_class == "AX" else "experimental-uncalibrated"
    )

    compliance_applicable = has_cve and fceb_bod_2604_scope
    if compliance_applicable:
        decision_basis = "cisa_bod_26_04"
    elif has_cve:
        decision_basis = "informative_bod_26_04_cve_guidance"
    else:
        decision_basis = "informative_bod_26_04_analogy"

    result: dict[str, object] = {
        "exploitation": resolved,
        "cve_id": normalized_cve,
        "fceb_bod_2604_scope": fceb_bod_2604_scope,
        "ssvc": {
            "methodology": "Stakeholder-Specific Vulnerability Categorization (SSVC)",
            "methodology_url": SSVC_METHODOLOGY_URL,
            "decision_table": BOD_2604_DECISION_TABLE_ID,
            "outcome_namespace": BOD_2604_MODEL_VERSION,
            "decision_table_source": BOD_2604_MODEL_SOURCE_URL,
            "decision_point_namespaces": dict(SSVC_DECISION_POINTS),
            "extension_note": (
                "Agentic AI Effect Class is a transparent fifth SSVC extension "
                "input."
            ),
        },
        "bod_2604_model_version": BOD_2604_MODEL_VERSION,
        "bod_2604_decision_table": BOD_2604_DECISION_TABLE_ID,
        "bod_2604_model_source": BOD_2604_MODEL_SOURCE_URL,
        "bod_2604_directive": BOD_2604_DIRECTIVE_URL,
        "decision_basis": decision_basis,
        "compliance_applicable": compliance_applicable,
        "decision_points": {
            "in_kev": bool(evidence.cisa_kev),
            "publicly_exposed": bool(publicly_exposed),
            "publicly_exposed_source": publicly_exposed_source.strip(),
            "decision_data_observed_at": decision_data_observed_at,
            "automatable": bool(automatable),
            "automatable_source": automatable_source,
            "technical_impact": technical_impact,
            "technical_impact_source": impact_source,
            "agentic_effect_class": agentic_effect_class,
        },
        "aivss_recommended_timeline": recommended,
        "aivss_recommended_label": TIMELINE_LABELS[recommended],
        "overlay_triggered": overlay_triggered,
        "escalated": recommended != base,
        "aivss_recommended_forensic_triage_indicated": base == "3DF",
        "overlay_status": overlay_status,
    }
    if metadata_both_missing:
        result["missing_metadata_faq_applied"] = True
        result["bod_2604_faq_source"] = BOD_2604_FAQ_URL
    if compliance_applicable:
        result.update(
            {
                "bod_2604_timeline": base,
                "bod_2604_label": TIMELINE_LABELS[base],
                "forensic_triage_required": base == "3DF",
                "note": (
                    "bod_2604_timeline is the unmodified compliance result. "
                    "The AIVSS recommendation is a separate, non-binding overlay."
                ),
            }
        )
    elif has_cve:
        result.update(
            {
                "bod_2604_guidance_timeline": base,
                "bod_2604_guidance_label": TIMELINE_LABELS[base],
                "forensic_triage_indicated": base == "3DF",
                "note": (
                    "This CVE-based result uses the BOD 26-04 decision table as "
                    "informative guidance. It is not a compliance deadline because "
                    "FCEB BOD scope was not asserted."
                ),
            }
        )
    else:
        result.update(
            {
                "bod_2604_analogy_timeline": base,
                "bod_2604_analogy_label": TIMELINE_LABELS[base],
                "forensic_triage_indicated": base == "3DF",
                "note": (
                    "This non-CVE result is an informative analogy, not a BOD 26-04 "
                    "compliance deadline. Inputs were supplied explicitly."
                ),
            }
        )
    return result
