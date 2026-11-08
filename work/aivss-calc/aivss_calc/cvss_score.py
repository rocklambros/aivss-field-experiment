"""CVSS v4.0 BTE scoring via the Red Hat reference implementation.

The vendored MacroVector lookup table stores each equivalence class's
*highest-severity* score. A specific vector within a class is scored lower via
CVSS v4 interpolation. AIVSS retains that official interpolated score rather
than substituting the MacroVector ceiling.
"""

from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP

from cvss import CVSS4


def round_half_up(value: float, decimals: int = 1) -> float:
    quantum = Decimal(1).scaleb(-decimals)
    return float(Decimal(str(value)).quantize(quantum, rounding=ROUND_HALF_UP))


def severity_rating(score: float) -> str:
    """Return the CVSS v4.0 qualitative severity rating for a score."""
    if not 0.0 <= score <= 10.0:
        raise ValueError(f"CVSS score must be in [0.0, 10.0]; got {score}")
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def score_cvss_bte(cvss_vector: str) -> float:
    """Return the CVSS v4.0 Base+Threat+Environmental score for a vector."""
    try:
        return float(CVSS4(cvss_vector.strip()).scores()[0])
    except Exception as exc:
        raise ValueError(f"Cannot score CVSS vector: {exc}") from exc
