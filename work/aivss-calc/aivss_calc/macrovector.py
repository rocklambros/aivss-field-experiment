"""CVSS v4.0 MacroVector derivation.

The vendored lookup table is cvss_lookup.js from the FIRST CVSS v4.0 calculator
reference implementation (Copyright FIRST, Red Hat, and contributors;
BSD-2-Clause).
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources

# Metric name -> ordered valid values. Order is most severe first where the
# metric is ordinal; "X" (Not Defined) is always permitted for optional groups.
BASE_METRICS: dict[str, tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "AT": ("N", "P"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "P", "A"),
    "VC": ("H", "L", "N"),
    "VI": ("H", "L", "N"),
    "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"),
    "SI": ("H", "L", "N"),
    "SA": ("H", "L", "N"),
}

THREAT_METRICS: dict[str, tuple[str, ...]] = {"E": ("X", "A", "P", "U")}

ENV_REQUIREMENT_METRICS: dict[str, tuple[str, ...]] = {
    "CR": ("X", "H", "M", "L"),
    "IR": ("X", "H", "M", "L"),
    "AR": ("X", "H", "M", "L"),
}

MODIFIED_METRICS: dict[str, tuple[str, ...]] = {
    "MAV": ("X", "N", "A", "L", "P"),
    "MAC": ("X", "L", "H"),
    "MAT": ("X", "N", "P"),
    "MPR": ("X", "N", "L", "H"),
    "MUI": ("X", "N", "P", "A"),
    "MVC": ("X", "H", "L", "N"),
    "MVI": ("X", "H", "L", "N"),
    "MVA": ("X", "H", "L", "N"),
    "MSC": ("X", "H", "L", "N"),
    "MSI": ("X", "S", "H", "L", "N"),
    "MSA": ("X", "S", "H", "L", "N"),
}

SUPPLEMENTAL_METRICS: dict[str, tuple[str, ...]] = {
    "S": ("X", "N", "P"),
    "AU": ("X", "N", "Y"),
    "R": ("X", "A", "U", "I"),
    "V": ("X", "D", "C"),
    "RE": ("X", "L", "M", "H"),
    "U": ("X", "Clear", "Green", "Amber", "Red"),
}

ALL_METRICS: dict[str, tuple[str, ...]] = {
    **BASE_METRICS,
    **THREAT_METRICS,
    **ENV_REQUIREMENT_METRICS,
    **MODIFIED_METRICS,
    **SUPPLEMENTAL_METRICS,
}


@lru_cache(maxsize=1)
def _lookup_table() -> dict[str, float]:
    raw = resources.files(__package__).joinpath("data/cvss_v4_lookup.json").read_text()
    return {k: float(v) for k, v in json.loads(raw).items()}


def parse_cvss_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS v4.0 vector string into a metric dict.

    Raises ValueError on a malformed vector, an unknown metric, an illegal
    value, a duplicate metric, or a missing mandatory Base metric.
    """
    text = vector.strip()
    parts = text.split("/")
    if not parts or parts[0] != "CVSS:4.0":
        raise ValueError(
            f"Vector must begin with 'CVSS:4.0/'; got {parts[0] if parts else ''!r}"
        )

    metrics: dict[str, str] = {}
    metric_order = {name: index for index, name in enumerate(ALL_METRICS)}
    previous_index = -1
    for part in parts[1:]:
        if ":" not in part:
            raise ValueError(
                f"Malformed metric segment {part!r} (expected 'KEY:VALUE')"
            )
        key, _, value = part.partition(":")
        if key not in ALL_METRICS:
            raise ValueError(f"Unknown CVSS v4.0 metric {key!r}")
        if key in metrics:
            raise ValueError(f"Duplicate metric {key!r}")
        current_index = metric_order[key]
        if current_index < previous_index:
            raise ValueError(f"CVSS metric {key!r} is out of specification order")
        if value not in ALL_METRICS[key]:
            raise ValueError(
                f"Illegal value {value!r} for metric {key!r}; "
                f"expected one of {ALL_METRICS[key]}"
            )
        metrics[key] = value
        previous_index = current_index

    missing = [name for name in BASE_METRICS if name not in metrics]
    if missing:
        raise ValueError(f"Missing mandatory Base metric(s): {', '.join(missing)}")
    return metrics


def effective(metrics: dict[str, str], name: str) -> str:
    """Return the effective value of a Base metric, honouring its Modified form."""
    modified = metrics.get(f"M{name}", "X")
    if modified != "X":
        return modified
    return metrics[name]


def macrovector(metrics: dict[str, str]) -> str:
    """Derive the six-digit CVSS v4.0 MacroVector string (EQ1..EQ6)."""
    av, pr, ui = (effective(metrics, m) for m in ("AV", "PR", "UI"))
    ac, at = effective(metrics, "AC"), effective(metrics, "AT")
    vc, vi, va = (effective(metrics, m) for m in ("VC", "VI", "VA"))
    sc, si, sa = (effective(metrics, m) for m in ("SC", "SI", "SA"))

    # MSI/MSA carry a Safety value that has no Base equivalent.
    msi, msa = metrics.get("MSI", "X"), metrics.get("MSA", "X")

    # E:X and CR/IR/AR:X default to the worst case.
    e = metrics.get("E", "X")
    if e == "X":
        e = "A"
    cr = metrics.get("CR", "X")
    ir = metrics.get("IR", "X")
    ar = metrics.get("AR", "X")
    cr = "H" if cr == "X" else cr
    ir = "H" if ir == "X" else ir
    ar = "H" if ar == "X" else ar

    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = 1
    else:
        eq1 = 2

    eq2 = 0 if (ac == "L" and at == "N") else 1

    if vc == "H" and vi == "H":
        eq3 = 0
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = 1
    else:
        eq3 = 2

    if msi == "S" or msa == "S":
        eq4 = 0
    elif sc == "H" or si == "H" or sa == "H":
        eq4 = 1
    else:
        eq4 = 2

    eq5 = {"A": 0, "P": 1, "U": 2}[e]

    eq6 = (
        0
        if (cr == "H" and vc == "H")
        or (ir == "H" and vi == "H")
        or (ar == "H" and va == "H")
        else 1
    )

    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def macrovector_score(mv: str) -> float:
    """Return the CVSS v4.0 score for a MacroVector (the highest-severity vector)."""
    table = _lookup_table()
    if mv not in table:
        raise ValueError(
            f"MacroVector {mv!r} is not a valid CVSS v4.0 equivalence class "
            "(EQ3=2 requires EQ6=1)"
        )
    return table[mv]
