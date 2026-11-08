"""Lookup Table AIVSS (AIVSS 1.0 specification, Section 5.8, Table 6).

AIVSS is read from a published table keyed by the FIRST qualitative band of
CVSS-BTE and the Agentic Effect Class. No arithmetic is performed:

* A0 and AX: AIVSS equals CVSS-BTE unchanged (an AX result is provisional).
* A1 and A2: AIVSS is the higher of the band's cell value and CVSS-BTE.

AIVSS is therefore never lower than CVSS-BTE. That floor is an AIVSS design
choice, not a FIRST requirement. The CVSS v4.0 Extensions Framework (User
Guide, Section 3.11) requires that existing metric definitions are preserved
and that an extension that changes the score stays within 0.0 to 10.0.
"""

from __future__ import annotations

from typing import Any

from .cvss_score import severity_rating
from .macrovector import ENV_REQUIREMENT_METRICS, MODIFIED_METRICS

TABLE_6: dict[str, dict[str, float]] = {
    "None": {"A1": 0.0, "A2": 0.0},
    "Low": {"A1": 5.5, "A2": 7.1},
    "Medium": {"A1": 7.5, "A2": 8.9},
    "High": {"A1": 8.7, "A2": 9.5},
    "Critical": {"A1": 9.7, "A2": 10.0},
}

AIVSS_BASIS = (
    "Lookup Table AIVSS (Table 6): A0 or AX keep CVSS-BTE unchanged; A1 or A2 take "
    "the higher of the band cell and CVSS-BTE. AIVSS is never lower than CVSS-BTE."
)


def aivss_lookup(cvss_bte: float, effect_class: str) -> dict[str, Any]:
    """Return AIVSS for a CVSS-BTE score and Agentic Effect Class."""
    if isinstance(cvss_bte, bool) or not isinstance(cvss_bte, (int, float)):
        raise TypeError("cvss_bte must be a number")
    if effect_class not in ("A0", "A1", "A2", "AX"):
        raise ValueError("effect_class must be A0, A1, A2, or AX")
    band = severity_rating(float(cvss_bte))
    if effect_class in ("A0", "AX"):
        cell = None
        value = float(cvss_bte)
        rule = "cvss_bte_unchanged"
    else:
        cell = TABLE_6[band][effect_class]
        value = max(float(cvss_bte), cell)
        rule = "cell" if cell >= cvss_bte else "cvss_bte_floor"
    return {
        "aivss": value,
        "aivss_band": severity_rating(value),
        "cvss_band": band,
        "table_cell": cell,
        "rule": rule,
    }


def cvss_nomenclature(metrics: dict[str, str]) -> str:
    """FIRST nomenclature for the metric groups actually assessed."""
    threat = metrics.get("E", "X") != "X"
    env_keys = set(ENV_REQUIREMENT_METRICS) | set(MODIFIED_METRICS)
    environmental = any(metrics.get(key, "X") != "X" for key in env_keys)
    if threat and environmental:
        return "CVSS-BTE"
    if threat:
        return "CVSS-BT"
    if environmental:
        return "CVSS-BE"
    return "CVSS-B"
