"""OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10) and MAESTRO-extended.

Published December 9, 2025 by the OWASP GenAI Security Project and used as the
AIVSS finding taxonomy. Findings outside ASI01–ASI10 that are validated through
CSA MAESTRO (or equivalent) are recorded as MAESTRO-extended (Section 5.7).
OWASP does not endorse AIVSS v1.
"""

from __future__ import annotations

from typing import Any

ASI_TOP_10: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

MAESTRO_EXTENDED_ID = "MAESTRO-EXTENDED"
MAESTRO_EXTENDED_NAME = "MAESTRO-extended finding"

# Crosswalk from the ten AIVSS Core Risks (v0.5, carried into the withdrawn v0.8
# list). ASI09 and ASI10 have no Core Risk predecessor. "Agent Untraceability"
# has no dedicated ASI category and is outside AIVSS 1.0 severity scoring. The
# "&" spellings are the published Core Risk names; the "and" spellings are kept
# as aliases.
V08_CATEGORY_CROSSWALK: dict[str, str | None] = {
    "Agent Goal and Instruction Manipulation": "ASI01",
    "Agentic AI Tool Misuse": "ASI02",
    "Agent Access Control Violation": "ASI03",
    "Agent Identity Impersonation": "ASI03",
    "Agent Supply Chain and Dependency Risk": "ASI04",
    "Insecure Agent Critical Systems Interaction": "ASI05",
    "Agent Memory and Context Manipulation": "ASI06",
    "Agent Orchestration and Multi-Agent Exploitation": "ASI07",
    "Agent Cascading Failures": "ASI08",
    "Agent Untraceability": None,
    "Agent Goal & Instruction Manipulation": "ASI01",
    "Agent Orchestration & Multi-Agent Exploitation": "ASI07",
    "Agent Memory & Context Manipulation": "ASI06",
    "Agent Supply Chain & Dependency Risk": "ASI04",
}

MAESTRO_LAYERS: frozenset[str] = frozenset(
    {
        "Foundation Models",
        "Data Operations",
        "Agent Frameworks",
        "Deployment Infrastructure",
        "Evaluation and Observability",
        "Security and Compliance",
        "Agent Ecosystem",
    }
)


def normalize_asi(value: str) -> str:
    """Resolve an ASI id or a withdrawn v0.8 category name to an ASI id."""
    candidate = value.strip()
    upper = candidate.upper()
    if upper in ASI_TOP_10:
        return upper
    if candidate in V08_CATEGORY_CROSSWALK:
        mapped = V08_CATEGORY_CROSSWALK[candidate]
        if mapped is None:
            raise ValueError(
                f"v0.8 category {candidate!r} has no ASI equivalent and is "
                "outside AIVSS 1.0 severity scoring"
            )
        return mapped
    raise ValueError(
        f"Unknown risk category {value!r}. Expected one of {sorted(ASI_TOP_10)}, "
        f"{MAESTRO_EXTENDED_ID!r}, or a withdrawn AIVSS v0.8 category name."
    )


def normalize_risk_category(
    value: str,
    taxonomy_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the report risk_category object for ASI or MAESTRO-extended findings."""
    candidate = value.strip()
    upper = candidate.upper().replace("_", "-")
    if upper in ("MAESTRO-EXTENDED", "MAESTROEXTENDED"):
        meta = taxonomy_metadata or {}
        if not isinstance(meta, dict):
            raise ValueError("taxonomy_metadata must be an object for MAESTRO-extended")
        layer = meta.get("maestro_layer")
        description = meta.get("threat_description")
        if not isinstance(layer, str) or not layer.strip():
            raise ValueError(
                "MAESTRO-extended findings require taxonomy_metadata.maestro_layer"
            )
        if layer.strip() not in MAESTRO_LAYERS:
            raise ValueError(
                f"maestro_layer must be one of {sorted(MAESTRO_LAYERS)}; got {layer!r}"
            )
        if not isinstance(description, str) or not description.strip():
            raise ValueError(
                "MAESTRO-extended findings require "
                "taxonomy_metadata.threat_description"
            )
        result: dict[str, Any] = {
            "id": MAESTRO_EXTENDED_ID,
            "name": MAESTRO_EXTENDED_NAME,
            "scheme": "MAESTRO-extended",
            "maestro_layer": layer.strip(),
            "threat_description": description.strip(),
        }
        nearest = meta.get("nearest_asi")
        if nearest is not None:
            result["nearest_asi"] = normalize_asi(str(nearest))
        return result

    if taxonomy_metadata:
        raise ValueError(
            "taxonomy_metadata is only valid with risk_category "
            f"{MAESTRO_EXTENDED_ID!r}"
        )
    asi = normalize_asi(candidate)
    return {
        "id": asi,
        "name": ASI_TOP_10[asi],
        "scheme": "ASI",
    }
