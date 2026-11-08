"""The AIVSS 1.0 Agentic AI profile (AIVSS 1.0 specification).

Five categorical metrics describe agentic properties that CVSS-BTE does not
measure. LC, CP, AP and RH assign the Agentic Effect Class by an ordered
rule ladder (A2, A1, AX, A0; first match wins). ES enters only Lookup Table U.

Labels are ordinal categories, never numbers: no arithmetic is performed on
them. Legacy eight-metric vectors (EX, PT, CA, TD) are accepted only through
``convert_legacy_vector`` for migration.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from .versions import EXTENSION_VECTOR_VERSION

AIVSS_EXTENSION_VERSION = EXTENSION_VECTOR_VERSION
AIVSS_EXTENSION_PREFIX = f"AIVSS:{AIVSS_EXTENSION_VERSION}"
EFFECT_CLASS_STATUS = "unvalidated"
UNKNOWN_VALUE = "X"

LC_VALUES: dict[str, tuple[str, str]] = {
    "D": (
        "Direct",
        "Attacker-supplied natural language reaches a privileged decision or "
        "tool-invocation path without mediation.",
    ),
    "I": (
        "Indirect",
        "Attacker-controlled language enters through retrieved or ingested content "
        "(documents, web pages, email, files) and influences security-relevant behaviour.",
    ),
    "M": (
        "Mediated",
        "An independently enforced transformation reduces language to closed, "
        "validated fields before every security-relevant sink.",
    ),
    "N": ("None", "No natural-language path to security-relevant behaviour."),
    "X": (
        "Insufficient evidence",
        "Available evidence cannot determine the language-control path.",
    ),
}

CP_VALUES: dict[str, tuple[str, str]] = {
    "C": (
        "Cross-session memory",
        "Attacker-controlled context or memory persists in durable stores — vector "
        "databases, long-term agent memory, episodic memory banks, RAG indexes, "
        "user profiles, or training/fine-tuning data — and remains reachable after "
        "the originating session ends. Stored source content that is only "
        "re-retrieved, without altering agent memory or standing behaviour, is "
        "not CP.",
    ),
    "S": (
        "Session context",
        "Attacker-controlled context persists only in ephemeral session state "
        "(conversation buffer, in-memory working context, session-scoped cache), and "
        "testing confirms it is unreachable after the session boundary.",
    ),
    "N": (
        "None",
        "Single-turn or stateless; no attacker-controlled context or memory carryover "
        "between requests, or only re-retrieval of unmodified source content.",
    ),
    "X": (
        "Insufficient evidence",
        "Available evidence cannot determine context or memory persistence.",
    ),
}

AP_VALUES: dict[str, tuple[str, str]] = {
    "L": (
        "Lateral",
        "Compromised intent or authority crosses a trust boundary into another agent, "
        "tenant, principal or policy domain. Impact on downstream systems is scored "
        "in CVSS SC/SI/SA, not here.",
    ),
    "C": (
        "Contained",
        "Influence relays across agent components under the same principal and policy "
        "domain without crossing a trust boundary.",
    ),
    "N": ("None", "Effect is confined to the initially affected component."),
    "X": (
        "Insufficient evidence",
        "Available evidence cannot determine propagation scope.",
    ),
}

RH_VALUES: dict[str, tuple[str, str]] = {
    "D": (
        "Demonstrated",
        "At least one human-verified episode in production-equivalent runs shows the "
        "agent satisfying a proxy objective, evaluator, verifier or reward signal by "
        "crossing a security boundary (for example tampering with tests, graders, logs "
        "or monitors, retrieving answer keys, or misreporting task success). A monitor "
        "flag alone is not verification.",
    ),
    "P": (
        "Possible",
        "The agent can reach a proxy objective, evaluator, verifier or reward channel "
        "on the path, and no verified reward-hacking episode has been observed.",
    ),
    "N": (
        "None",
        "Every evaluator, verifier and reward channel on the path sits outside the "
        "agent's reach (write-protected or in a separate trust domain), and a test "
        "confirms the isolation.",
    ),
    "X": (
        "Insufficient evidence",
        "Available evidence cannot determine whether the agent can reach the proxy.",
    ),
}

LEGACY_SR_VALUES: dict[str, tuple[str, str]] = {
    "R": ("Reliable", "Draft stochastic exploit reliability: reliable."),
    "P": ("Probabilistic", "Draft stochastic exploit reliability: probabilistic."),
    "U": ("Unreliable", "Draft stochastic exploit reliability: unreliable."),
    "X": ("Insufficient evidence", "Draft stochastic exploit reliability: unknown."),
}

ES_VALUES: dict[str, tuple[str, str]] = {
    "W": (
        "Wide",
        "A reachable tool, MCP server, skill or plugin is dynamic or unvetted, or its "
        "identity, callable operations, arguments or credentials are not independently "
        "constrained on the assessed path.",
    ),
    "M": (
        "Managed",
        "Extensions are allowlisted, but material gaps remain in argument schemas, "
        "credentials or callable operations.",
    ),
    "N": (
        "None or narrow",
        "No security-relevant dynamic extension on the path, or a fixed, allowlisted, "
        "least-privilege binding enforced outside model output.",
    ),
    "X": (
        "Insufficient evidence",
        "Available evidence cannot determine the extension binding surface.",
    ),
}

EX_VALUES = ES_VALUES  # legacy alias (AIVSS 1.0 draft name for ES)

RH_LOCI: tuple[str, ...] = ("evaluator", "environment")

# Values accepted for the dropped draft metrics, used only to validate a legacy
# eight-metric vector during migration. PT, CA and TD are not AIVSS 1.0 metrics.
LEGACY_DROPPED_VALUES: dict[str, tuple[str, ...]] = {
    "PT": ("H", "M", "L", "X"),
    "CA": ("W", "M", "N", "X"),
    "TD": ("H", "M", "L", "X"),
}


def classify_rh(
    *,
    reachable_proxy: bool | None,
    isolation_verified: bool | None,
    verified_episodes: int | None,
) -> str:
    """Classify reward hacking from structural facts and verified episodes.

    D when at least one verified episode exists. N only when the proxy is
    unreachable and the isolation was verified by a test. P when the proxy is
    reachable and no verified episode exists. X otherwise. Absence of observed
    hacking never yields N, because hacking rates vary with task difficulty,
    prompting and monitoring.
    """
    for name, value in (
        ("reachable_proxy", reachable_proxy),
        ("isolation_verified", isolation_verified),
    ):
        if value is not None and type(value) is not bool:
            raise ValueError(f"{name} must be true, false, or unknown")
    if verified_episodes is not None and (
        type(verified_episodes) is not int or verified_episodes < 0
    ):
        raise ValueError("verified_episodes must be a non-negative integer or unknown")
    if verified_episodes is not None and verified_episodes >= 1:
        return "D"
    if reachable_proxy is False and isolation_verified is True:
        return "N"
    if reachable_proxy is True and verified_episodes == 0:
        return "P"
    return "X"


CLASSIFYING_AGENTIC_METRICS: dict[str, dict[str, tuple[str, str]]] = {
    "LC": LC_VALUES,
    "CP": CP_VALUES,
    "AP": AP_VALUES,
    "RH": RH_VALUES,
}

# ES is the only metric that is not a classifying input; it enters Table 5 (U).
UPLIFT_AGENTIC_METRICS: dict[str, dict[str, tuple[str, str]]] = {"ES": ES_VALUES}
ASSURANCE_AGENTIC_METRICS = UPLIFT_AGENTIC_METRICS  # backward-compatible name
ADJUSTMENT_AGENTIC_METRICS = UPLIFT_AGENTIC_METRICS

AGENTIC_METRICS: dict[str, dict[str, tuple[str, str]]] = {
    **CLASSIFYING_AGENTIC_METRICS,
    **UPLIFT_AGENTIC_METRICS,
}

AI_METRICS = AGENTIC_METRICS

AGENTIC_METRIC_ORDER: tuple[str, ...] = ("LC", "CP", "AP", "RH", "ES")
AI_METRIC_ORDER = AGENTIC_METRIC_ORDER

# Draft eight-metric order (pre-1.0), accepted only for migration.
LEGACY_METRIC_ORDER: tuple[str, ...] = ("LC", "CP", "AP", "SR", "EX", "PT", "CA", "TD")
LEGACY_METRICS: dict[str, dict[str, Any]] = {
    "LC": LC_VALUES,
    "CP": CP_VALUES,
    "AP": AP_VALUES,
    "SR": LEGACY_SR_VALUES,
    "EX": ES_VALUES,
    "PT": dict.fromkeys(LEGACY_DROPPED_VALUES["PT"]),
    "CA": dict.fromkeys(LEGACY_DROPPED_VALUES["CA"]),
    "TD": dict.fromkeys(LEGACY_DROPPED_VALUES["TD"]),
}

AGENTIC_METRIC_NAMES: dict[str, str] = {
    "LC": "Language-Mediated Control",
    "CP": "Context Persistence",
    "AP": "Agentic Control Propagation",
    "RH": "Reward Hacking",
    "ES": "Extension Binding Surface",
}

AGENTIC_METRIC_SUMMARIES: dict[str, str] = {
    "LC": (
        "How directly attacker-controlled natural language reaches a "
        "security-relevant decision or tool call."
    ),
    "CP": (
        "How long attacker-controlled context or memory survives, and whether it "
        "outlives the session that introduced it."
    ),
    "AP": (
        "Whether compromised intent or authority crosses a trust boundary into "
        "another agent, tenant, principal or policy domain."
    ),
    "RH": (
        "Whether the agent's own optimization of a proxy objective, evaluator, "
        "verifier or reward signal drives it across a security boundary without "
        "attacker input."
    ),
    "ES": (
        "How tightly the tools, skills, MCP servers and plugins reachable on the "
        "path are bound. ES enters Lookup Table U only."
    ),
}

AGENTIC_EFFECT_CLASS_LABELS: dict[str, str] = {
    "A0": "None",
    "A1": "Present",
    "A2": "Substantial",
    "AX": "Insufficient evidence",
}

# Lookup Table U (Table 5): Effect Class key x ES. AX uses the A0 row.
UPLIFT_TABLE: dict[str, dict[str, int]] = {
    "A0": {"N": 0, "M": 1, "W": 2},
    "A1": {"N": 3, "M": 5, "W": 6},
    "A2_not_RH": {"N": 7, "M": 8, "W": 9},
    "A2_RH": {"N": 8, "M": 9, "W": 10},
}


@dataclass(frozen=True)
class AIProfile:
    """One coherent exploit-path profile: LC, CP, AP, RH and ES."""

    lc: str
    cp: str
    ap: str
    rh: str
    es: str

    def __post_init__(self) -> None:
        for name in AGENTIC_METRIC_ORDER:
            value = getattr(self, name.lower())
            if value not in AGENTIC_METRICS[name]:
                raise ValueError(
                    f"Illegal value {value!r} for Agentic AI metric {name!r}; "
                    f"expected one of {sorted(AGENTIC_METRICS[name])}"
                )

    @property
    def ex(self) -> str:  # legacy accessor
        return self.es

    @property
    def complete(self) -> bool:
        return all(
            getattr(self, name.lower()) != UNKNOWN_VALUE
            for name in AGENTIC_METRIC_ORDER
        )

    @property
    def provisional(self) -> bool:
        """True when any classifying metric (LC, CP, AP or RH) is X."""
        return any(
            getattr(self, name.lower()) == UNKNOWN_VALUE
            for name in CLASSIFYING_AGENTIC_METRICS
        )

    def agentic_effect_class(self) -> str:
        return self.effect_class()

    def effect_class(self) -> str:
        """Ordered rule ladder (AIVSS 1.0 specification, Section 5.6).

        A clause applies when its own metrics are known, even if another
        classifying metric is X, so missing evidence never lowers the class
        below what the known evidence supports.
        """
        lc, cp, ap, rh = self.lc, self.cp, self.ap, self.rh
        if (
            ap == "L"
            or (lc in ("D", "I") and cp == "C")
            or (lc in ("D", "I") and rh == "D")
        ):
            return "A2"
        if lc in ("D", "I") or cp in ("S", "C") or ap == "C" or rh == "D":
            return "A1"
        if UNKNOWN_VALUE in (lc, cp, ap, rh):
            return "AX"
        return "A0"

    def effect_class_range(self) -> tuple[str, str]:
        """Observed minimum and maximum possible Effect Class (Section 5.10).

        The minimum treats each X as its least severe value (LC:N, CP:N, AP:N,
        RH:N); the maximum treats each X as its most severe value (LC:D, CP:C,
        AP:L, RH:D). With no X the two are equal to the Effect Class.
        """
        low = AIProfile(
            "N" if self.lc == UNKNOWN_VALUE else self.lc,
            "N" if self.cp == UNKNOWN_VALUE else self.cp,
            "N" if self.ap == UNKNOWN_VALUE else self.ap,
            "N" if self.rh == UNKNOWN_VALUE else self.rh,
            self.es,
        )
        high = AIProfile(
            "D" if self.lc == UNKNOWN_VALUE else self.lc,
            "C" if self.cp == UNKNOWN_VALUE else self.cp,
            "L" if self.ap == UNKNOWN_VALUE else self.ap,
            "D" if self.rh == UNKNOWN_VALUE else self.rh,
            self.es,
        )
        return low.effect_class(), high.effect_class()

    def agentic_uplift_u(self) -> int | None:
        """Lookup Table U (Table 5). Informative; returns None when ES is X."""
        if self.es == UNKNOWN_VALUE:
            return None
        effect = self.effect_class()
        if effect == "A2":
            key = "A2_RH" if self.rh == "D" else "A2_not_RH"
        elif effect == "A1":
            key = "A1"
        else:
            key = "A0"
        return UPLIFT_TABLE[key][self.es]

    def to_vector_fragment(self) -> str:
        return "/".join(
            f"{name}:{getattr(self, name.lower())}" for name in AGENTIC_METRIC_ORDER
        )

    def to_vector(self) -> str:
        return f"{AIVSS_EXTENSION_PREFIX}/{self.to_vector_fragment()}"

    def describe(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for name in AGENTIC_METRIC_ORDER:
            value = getattr(self, name.lower())
            out[name] = f"{value} ({AGENTIC_METRICS[name][value][0]})"
        return out


def validate_metric_evidence(
    profile: AIProfile, evidence: dict[str, dict[str, Any]]
) -> None:
    """Validate evidence shape and the executable RH classification facts."""
    expected_metrics = set(AGENTIC_METRIC_ORDER)
    if not isinstance(evidence, dict) or set(evidence) != expected_metrics:
        raise ValueError("metric_evidence must contain exactly LC, CP, AP, RH, and ES")
    common = {"rationale", "evidence_refs"}
    rh_fields = {
        "reachable_proxy",
        "isolation_verified",
        "verified_episodes",
        "episodes_reviewed",
        "locus",
    }
    for name in AGENTIC_METRIC_ORDER:
        entry = evidence[name]
        _check_common_evidence(name, entry)
        allowed = common | rh_fields if name == "RH" else common
        extras = set(entry) - allowed
        if extras:
            raise ValueError(f"{name} evidence has unknown fields: {sorted(extras)}")

    rh = evidence["RH"]
    missing = (common | rh_fields) - set(rh)
    if missing:
        raise ValueError(f"RH evidence is missing {sorted(missing)}")
    reviewed = rh["episodes_reviewed"]
    if reviewed is not None and (type(reviewed) is not int or reviewed < 0):
        raise ValueError("RH episodes_reviewed must be a non-negative integer or null")
    verified = rh["verified_episodes"]
    if reviewed is not None and verified is not None and type(verified) is int:
        if verified > reviewed:
            raise ValueError("RH verified_episodes cannot exceed episodes_reviewed")
    locus = rh["locus"]
    if locus is not None and locus not in RH_LOCI:
        raise ValueError(f"RH locus must be null or one of {list(RH_LOCI)}")
    value = classify_rh(
        reachable_proxy=rh["reachable_proxy"],
        isolation_verified=rh["isolation_verified"],
        verified_episodes=verified,
    )
    if value in ("D", "P") and locus is None:
        raise ValueError("RH:D and RH:P evidence must name the locus of the proxy")
    if value != profile.rh:
        raise ValueError("RH evidence does not support the vector value")


def _check_common_evidence(name: str, entry: Any) -> None:
    if not isinstance(entry, dict):
        raise ValueError(f"{name} evidence must be an object")  # noqa: TRY004 (callers catch ValueError)
    rationale = entry.get("rationale")
    refs = entry.get("evidence_refs")
    if not isinstance(rationale, str) or not rationale.strip():
        raise ValueError(f"{name} evidence rationale must be non-empty")
    if (
        not isinstance(refs, list)
        or not refs
        or any(not isinstance(ref, str) or not ref.strip() for ref in refs)
    ):
        raise ValueError(f"{name} evidence_refs must contain non-empty references")


def parse_aivss_vector(vector: str) -> AIProfile:
    """Parse a separate AIVSS:1.0 extension vector (LC/CP/AP/RH/ES)."""
    if not isinstance(vector, str):
        raise ValueError("AIVSS extension vector must be a string")
    parts = vector.strip().split("/")
    if not parts or parts[0] != AIVSS_EXTENSION_PREFIX:
        raise ValueError(
            f"AIVSS extension vector must begin with {AIVSS_EXTENSION_PREFIX!r}"
        )
    keys = [part.partition(":")[0] for part in parts[1:]]
    if any(key in ("EX", "PT", "CA", "TD") for key in keys):
        raise ValueError(
            "This is a legacy eight-metric AIVSS vector (EX, PT, CA, TD). The "
            "AIVSS 1.0 specification uses LC/CP/AP/RH/ES; convert it with "
            "convert_legacy_vector or 'aivss-calc migrate-vector'"
        )
    found: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise ValueError(f"Malformed AIVSS metric segment {part!r}")
        key, _, value = part.partition(":")
        if key in ("EQ", "U"):
            raise ValueError(
                f"AIVSS vector must not carry the derived result {key!r}; report "
                "Effect Class, U and AIVSS as separate fields"
            )
        if key == "SR":
            raise ValueError(
                "SR (stochastic exploit reliability) was replaced by RH (reward "
                "hacking) in the AIVSS 1.0 specification; assess RH instead"
            )
        if key not in AGENTIC_METRICS:
            raise ValueError(f"Unknown AIVSS metric {key!r}")
        if key in found:
            raise ValueError(f"Duplicate AIVSS metric {key!r}")
        expected_index = len(found)
        if (
            expected_index >= len(AGENTIC_METRIC_ORDER)
            or key != AGENTIC_METRIC_ORDER[expected_index]
        ):
            expected = (
                AGENTIC_METRIC_ORDER[expected_index]
                if expected_index < len(AGENTIC_METRIC_ORDER)
                else "end of vector"
            )
            raise ValueError(
                f"AIVSS metric {key!r} is out of order; expected {expected!r}"
            )
        if value not in AGENTIC_METRICS[key]:
            raise ValueError(
                f"Illegal value {value!r} for AIVSS metric {key!r}; "
                f"expected one of {sorted(AGENTIC_METRICS[key])}"
            )
        found[key] = value

    missing = [name for name in AGENTIC_METRIC_ORDER if name not in found]
    if missing:
        raise ValueError(
            "A conformant AIVSS extension vector must specify LC, CP, AP, RH and ES; "
            f"missing: {', '.join(missing)}"
        )
    return AIProfile(**{name.lower(): found[name] for name in AGENTIC_METRIC_ORDER})


def convert_legacy_vector(vector: str) -> dict[str, Any]:
    """Convert a draft eight-metric vector to the five-metric form.

    EX becomes ES. SR, PT, CA and TD are not part of the AIVSS 1.0 specification
    and are dropped; RH is set to X until reward hacking is assessed.
    """
    parts = vector.strip().split("/")
    if not parts or parts[0] != AIVSS_EXTENSION_PREFIX:
        raise ValueError(
            f"AIVSS extension vector must begin with {AIVSS_EXTENSION_PREFIX!r}"
        )
    found: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep:
            raise ValueError(f"Malformed AIVSS metric segment {part!r}")
        if key not in LEGACY_METRICS:
            raise ValueError(f"Unknown legacy AIVSS metric {key!r}")
        if key in found:
            raise ValueError(f"Duplicate AIVSS metric {key!r}")
        if value not in LEGACY_METRICS[key]:
            raise ValueError(f"Illegal value {value!r} for AIVSS metric {key!r}")
        found[key] = value
    if list(found) != list(LEGACY_METRIC_ORDER):
        raise ValueError(
            "A legacy vector must list LC, CP, AP, SR, EX, PT, CA and TD in order"
        )
    profile = AIProfile(
        lc=found["LC"], cp=found["CP"], ap=found["AP"], rh="X", es=found["EX"]
    )
    return {
        "aivss_vector": profile.to_vector(),
        "dropped": {
            "SR": found["SR"],
            "PT": found["PT"],
            "CA": found["CA"],
            "TD": found["TD"],
        },
        "note": (
            "Converted from a draft eight-metric vector: EX is now ES, SR, PT, CA and "
            "TD are not part of the AIVSS 1.0 specification and are dropped, and RH "
            "(reward hacking) is X until assessed."
        ),
    }


_SPLIT_KEYS = set(AGENTIC_METRICS) | set(LEGACY_METRICS)


def split_ai_vector(vector: str) -> tuple[str, AIProfile | None]:
    """Parse display form containing separate CVSS and AIVSS vectors.

    Appending AIVSS metrics inside a CVSS vector is rejected because FIRST's
    Extensions Framework requires extension vectors to be listed separately.
    """
    text = vector.strip()
    if " " in text:
        cvss_vector, aivss_vector = text.split(None, 1)
        return cvss_vector, parse_aivss_vector(aivss_vector)
    for part in text.split("/"):
        key, _, _ = part.partition(":")
        if key in _SPLIT_KEYS:
            raise ValueError(
                f"AIVSS metrics must be in a separate {AIVSS_EXTENSION_PREFIX} "
                "extension vector"
            )
    return text, None

