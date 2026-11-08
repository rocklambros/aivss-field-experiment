"""Optional, organization-local, uncalibrated priority experiment.

AIVSS-P is non-portable and must not be used as a standard risk score. Its
likelihood input must be an organization's documented residual likelihood for
the assessed deployment. Because that estimate can overlap CVSS Threat,
Agentic AI reliability, or exposure evidence, adopters must define and test a
local de-duplication policy before operational use.
"""

from __future__ import annotations

import math

CONTEXT_LEVELS: dict[str, float] = {"high": 1.0, "medium": 0.65, "low": 0.35}


def _level(name: str, value: str) -> float:
    key = str(value).strip().lower()
    if key not in CONTEXT_LEVELS:
        raise ValueError(
            f"{name} must be one of {sorted(CONTEXT_LEVELS)}; got {value!r}"
        )
    return CONTEXT_LEVELS[key]


def compute_priority(
    *,
    severity: float,
    business_criticality: str,
    reach: str,
    likelihood: float,
) -> dict[str, object]:
    """AIVSS-P = 100 x geometric_mean(S/10, BI, REACH, L).

    Terms, each pricing one quantity exactly once:
      S/10   the explicitly selected technical-severity input
      BI     business criticality of the affected asset
      REACH  deployment reach
      L      organization-defined residual likelihood after de-duplication

    Every term is required. Unknown organizational context is not a default:
    callers must record the missing input and skip the index instead.
    """
    if isinstance(severity, bool) or not isinstance(severity, (int, float)):
        raise ValueError("severity must be a number in [0.0, 10.0]")
    if isinstance(likelihood, bool) or not isinstance(likelihood, (int, float)):
        raise ValueError("likelihood must be a number in [0.0, 1.0]")
    if not 0.0 <= severity <= 10.0:
        raise ValueError(f"severity must be in [0.0, 10.0]; got {severity}")
    if not 0.0 <= likelihood <= 1.0:
        raise ValueError(f"likelihood must be in [0.0, 1.0]; got {likelihood}")

    bi = _level("business_criticality", business_criticality)
    re = _level("reach", reach)

    terms = {
        "severity_norm": severity / 10.0,
        "business_criticality": bi,
        "reach": re,
        "likelihood": likelihood,
    }

    if any(v <= 0.0 for v in terms.values()):
        score = 0
    else:
        gm = math.exp(sum(math.log(v) for v in terms.values()) / len(terms))
        score = math.floor(100 * gm + 0.5)

    return {
        "aivss_p": score,
        "band": priority_band(score),
        "terms": {k: round(v, 4) for k, v in terms.items()},
        "scope": "organization-internal; not comparable across organizations",
        "status": "organization-local-uncalibrated",
    }


def priority_band(score: int) -> str:
    """Bands set from the output distribution rather than assumed.

    Cut-points are the p90/p65/p35 quantiles of AIVSS-P over a uniform grid of
    severity 4.0-10.0 x business criticality x reach x likelihood (n=10,980),
    giving roughly 10/25/30/35 percent occupancy. That grid over-represents
    high-severity findings relative to a real portfolio, so organizations
    should recalibrate these cut-points against their own corpus before using
    them to drive commitments.
    """
    if score >= 78:
        return "Immediate"
    if score >= 64:
        return "This sprint"
    if score >= 53:
        return "Scheduled"
    return "Backlog"
