"""Annex B -- the withdrawn AIVSS v0.8/v0.9 agentic uplift model. INFORMATIVE ONLY.

Retained solely so organizations holding v0.8 scores can reproduce them and
migrate. The construction risks double-counting, treats ordinal factors as
additive, and creates severity inflation without recalibrating the full scoring
model. It remains only behind the explicit ``legacy`` command for historical
reproduction and is not part of the AIVSS 1.0 model.

Two things changed relative to v0.8:

* The mitigation factor applies to the uplift only, not to the whole sum. This
  repairs a real defect: under v0.8, MF=0.67 could return a score below the CVSS
  base, which is incoherent. The repaired form guarantees
  CVSS_Base <= AIVSS_S <= 10.0.
* The category weight table is withdrawn. Its values were asserted, never
  calibrated, and produced up to a 1.92x spread in the amplification term from
  the risk label alone. The factor mean is now unweighted.
"""

from __future__ import annotations

import math

AMPLIFICATION_FACTOR_NAMES: tuple[str, ...] = (
    "autonomy",
    "tools",
    "language",
    "context",
    "non_determinism",
    "opacity",
    "persistence",
    "identity",
    "multi_agent",
    "self_mod",
)

MITIGATION_FACTORS: dict[str, float] = {
    "none": 1.0,
    "weak": 1.0,
    "partial": 0.83,
    "strong": 0.67,
    "adversarial_tested": 0.50,
}

# Asserted, not calibrated. Note the divergence from CVSS v3.1 Exploit Code
# Maturity (Unproven 0.91, Proof-of-Concept 0.94, Functional 0.97): AIVSS v0.8
# assigned CVSS's *Functional* value to Proof-of-Concept. Preserved unchanged
# here for reproducibility of existing v0.8 scores.
THREAT_MATURITY_VALUES: dict[str, float] = {
    "unreported": 0.50,
    "poc": 0.97,
    "attacked": 1.00,
}


def round_half_up(value: float, decimals: int = 1) -> float:
    multiplier = 10**decimals
    return math.floor(value * multiplier + 0.5) / multiplier


def severity_band(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 0.1:
        return "Low"
    return "None"


def factor_mean(factors: dict[str, float]) -> float:
    """Unweighted mean of the ten amplification factors, in [0, 1].

    Every factor must be present and must be a rubric level. Absent factors are
    an error rather than an implicit 0.0: silently treating a missing assessment
    as "None" under-scores the finding without telling anyone.
    """
    missing = [name for name in AMPLIFICATION_FACTOR_NAMES if name not in factors]
    if missing:
        raise ValueError(
            f"Missing amplification factor(s): {', '.join(sorted(missing))}"
        )
    unknown = set(factors) - set(AMPLIFICATION_FACTOR_NAMES)
    if unknown:
        raise ValueError(
            f"Unknown amplification factor(s): {', '.join(sorted(unknown))}"
        )
    for name in AMPLIFICATION_FACTOR_NAMES:
        if factors[name] not in (0.0, 0.5, 1.0):
            raise ValueError(
                f"Factor {name} must be 0.0, 0.5, or 1.0; got {factors[name]}"
            )
    return sum(factors[name] for name in AMPLIFICATION_FACTOR_NAMES) / len(
        AMPLIFICATION_FACTOR_NAMES
    )


def threat_multiplier(maturity: str) -> float:
    key = str(maturity).strip().lower()
    if key not in THREAT_MATURITY_VALUES:
        raise ValueError(
            f"Unknown threat maturity {maturity!r}; expected one of "
            f"{sorted(THREAT_MATURITY_VALUES)}"
        )
    return THREAT_MATURITY_VALUES[key]


def mitigation_factor(strength: str) -> float:
    key = str(strength).strip().lower()
    if key not in MITIGATION_FACTORS:
        raise ValueError(
            f"Unknown mitigation strength {strength!r}; expected one of "
            f"{sorted(MITIGATION_FACTORS)}"
        )
    return MITIGATION_FACTORS[key]


def validate_cvss_base(cvss_base: float) -> float:
    if not 0.0 <= cvss_base <= 10.0:
        raise ValueError(f"cvss_base must be in [0.0, 10.0]; got {cvss_base}")
    if round(cvss_base, 1) != round(cvss_base, 10):
        raise ValueError(
            f"cvss_base must carry at most one decimal place; got {cvss_base}"
        )
    return cvss_base


def compute_aars(cvss_base: float, factor_sum: float, thm: float) -> float:
    """Agentic amplification term. Not a risk score; never report standalone."""
    return (10.0 - cvss_base) * factor_sum * thm


def compute_severity(cvss_base: float, aars: float, mf: float) -> float:
    """AIVSS_S = CVSS_Base + (AARS x MF), rounded, then floored at CVSS_Base.

    Rounding precedes the floor clamp so that the guarantee survives rounding.
    """
    return max(cvss_base, min(10.0, round_half_up(cvss_base + aars * mf, 1)))


def cvss_sensitivity(factor_sum: float, thm: float, mf: float) -> float:
    """Coefficient on CVSS_Base in the expanded form (1 - k)*C + 10k.

    Exposes how much of the CVSS signal survives. At factor_sum 0.85, thm 0.97,
    mf 1.0 this is 0.1755, meaning a 9.8-point CVSS spread compresses to 1.7
    points. Callers should surface this rather than let it stay implicit.
    """
    return 1.0 - (factor_sum * thm * mf)


def score_legacy(
    *,
    cvss_base: float,
    factors: dict[str, float],
    threat_maturity: str = "poc",
    mitigation_inherent: str = "none",
    mitigation_residual: str | None = None,
) -> dict[str, object]:
    """Reproduce the deprecated uplift score with the mitigation-floor repair."""
    validate_cvss_base(cvss_base)
    fsum = factor_mean(factors)
    thm = threat_multiplier(threat_maturity)
    aars = compute_aars(cvss_base, fsum, thm)

    mf_i = mitigation_factor(mitigation_inherent)
    inherent = compute_severity(cvss_base, aars, mf_i)

    residual = None
    mf_r = None
    if mitigation_residual is not None:
        mf_r = mitigation_factor(mitigation_residual)
        residual = compute_severity(cvss_base, aars, mf_r)

    return {
        "status": "INFORMATIVE -- withdrawn model, deprecated at v1.0",
        "cvss_base": cvss_base,
        "factor_mean": round(fsum, 4),
        "thm": thm,
        "aars": round(aars, 4),
        "mitigation_inherent": mf_i,
        "mitigation_residual": mf_r,
        "aivss_s_inherent": inherent,
        "aivss_s_residual": residual,
        "severity_band": severity_band(inherent),
        "cvss_sensitivity": round(cvss_sensitivity(fsum, thm, mf_i), 4),
        "v08_unrepaired": round_half_up((cvss_base + aars) * mf_i, 1),
    }
