"""AIVSS 1.0 reference calculator.

CVSS severity remains independently reproducible as CVSS-BTE. AIVSS 1.0
adds a five-metric agentic profile (LC, CP, AP, RH, ES), derives an Agentic
Effect Class (A0, A1, A2, AX) and reads the AIVSS score from the published
lookup table (Table 6 of the specification).
"""

from .ai_metrics import (
    AGENTIC_EFFECT_CLASS_LABELS,
    AI_METRIC_ORDER,
    AI_METRICS,
    AIProfile,
    classify_rh,
    convert_legacy_vector,
    parse_aivss_vector,
    split_ai_vector,
    validate_metric_evidence,
)
from .lookup import AIVSS_BASIS, TABLE_6, aivss_lookup, cvss_nomenclature
from .assessment import (
    Assessment,
    OrgContext,
    Provenance,
    assess,
    assessment_from_payload,
)
from .decision import (
    BOD_2604_TABLE,
    TIMELINE_LABELS,
    ExploitationEvidence,
    bod_timeline,
    decide,
)
from .cvss_score import score_cvss_bte
from .macrovector import macrovector, macrovector_score, parse_cvss_vector
from .priority import compute_priority, priority_band
from .taxonomy import (
    ASI_TOP_10,
    MAESTRO_EXTENDED_ID,
    V08_CATEGORY_CROSSWALK,
    normalize_asi,
    normalize_risk_category,
)
from .exploit_maturity import apply_exploit_maturity, resolve_exploit_maturity
from .versions import CALCULATOR_VERSION, SPEC_VERSION

__version__ = CALCULATOR_VERSION

__all__ = [
    "AIProfile",
    "AIVSS_BASIS",
    "AGENTIC_EFFECT_CLASS_LABELS",
    "AI_METRICS",
    "AI_METRIC_ORDER",
    "ASI_TOP_10",
    "Assessment",
    "BOD_2604_TABLE",
    "ExploitationEvidence",
    "MAESTRO_EXTENDED_ID",
    "OrgContext",
    "Provenance",
    "SPEC_VERSION",
    "TABLE_6",
    "TIMELINE_LABELS",
    "V08_CATEGORY_CROSSWALK",
    "__version__",
    "aivss_lookup",
    "apply_exploit_maturity",
    "assess",
    "assessment_from_payload",
    "bod_timeline",
    "classify_rh",
    "compute_priority",
    "convert_legacy_vector",
    "cvss_nomenclature",
    "decide",
    "macrovector",
    "macrovector_score",
    "normalize_asi",
    "normalize_risk_category",
    "parse_cvss_vector",
    "priority_band",
    "resolve_exploit_maturity",
    "score_cvss_bte",
    "parse_aivss_vector",
    "split_ai_vector",
    "validate_metric_evidence",
]
