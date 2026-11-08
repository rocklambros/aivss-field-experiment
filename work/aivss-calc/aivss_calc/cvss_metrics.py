"""Plain-language names and descriptions for the CVSS v4.0 metrics.

Paraphrases of the CVSS v4.0 specification, written for assessors reading a
form rather than the standard. The authoritative definitions are FIRST's:
https://www.first.org/cvss/v4.0/specification-document

Allowed values come from `macrovector`; this module only adds wording.
"""

from __future__ import annotations

from typing import Any

from .macrovector import (
    BASE_METRICS,
    ENV_REQUIREMENT_METRICS,
    MODIFIED_METRICS,
    THREAT_METRICS,
)

NOT_DEFINED = "Not Defined"

_PROPERTY = {"C": "confidentiality", "I": "integrity", "A": "availability"}

_VULNERABLE_SUMMARY = {
    "C": "confidentiality of the data the vulnerable component holds",
    "I": "integrity of the data or behaviour the vulnerable component controls",
    "A": "availability of the service the vulnerable component provides",
}

_VULNERABLE_IMPACT_VALUES = {
    "C": {
        "H": ("High", "Total loss: the attacker can read all of the data."),
        "L": ("Low", "Partial loss: some data is exposed, or the attacker cannot choose which."),
        "N": ("None", "No confidentiality is lost."),
    },
    "I": {
        "H": ("High", "Total loss: the attacker can change any data, or changes have serious consequences."),
        "L": ("Low", "Partial loss: limited or unreliable modification, with limited consequences."),
        "N": ("None", "No integrity is lost."),
    },
    "A": {
        "H": ("High", "Total loss: the attacker can deny service completely or at will."),
        "L": ("Low", "Reduced performance or interruptions, but service continues."),
        "N": ("None", "No availability is lost."),
    },
}

_SUBSEQUENT_IMPACT_VALUES = {
    "C": {
        "H": ("High", "Total loss: all of a downstream system's data can be read."),
        "L": ("Low", "Partial loss: some downstream data is exposed, or the attacker cannot choose which."),
        "N": ("None", "No confidentiality is lost beyond the vulnerable component."),
    },
    "I": {
        "H": ("High", "Total loss: the attacker can change any data in a downstream system, or changes have serious consequences."),
        "L": ("Low", "Partial loss: limited or unreliable modification downstream."),
        "N": ("None", "No integrity is lost beyond the vulnerable component."),
    },
    "A": {
        "H": ("High", "Total loss: a downstream service can be denied completely or at will."),
        "L": ("Low", "Downstream performance drops or is interrupted, but service continues."),
        "N": ("None", "No availability is lost beyond the vulnerable component."),
    },
}

SAFETY_VALUE = (
    "Safety",
    "Consequences reach people or physical property (IEC 61508 safety impact).",
)

BASE_METRIC_INFO: dict[str, dict[str, Any]] = {
    "AV": {
        "name": "Attack Vector",
        "summary": "Where the attacker must be to reach the vulnerable component.",
        "values": {
            "N": ("Network", "Reachable remotely across the internet or a routed network."),
            "A": ("Adjacent", "Attacker must be on the same local network, Wi-Fi, Bluetooth range, or VPN."),
            "L": ("Local", "Needs a local account or shell, or a user who runs something for the attacker."),
            "P": ("Physical", "Attacker must physically handle the device."),
        },
    },
    "AC": {
        "name": "Attack Complexity",
        "summary": "Whether the attacker must defeat a security mitigation that is actively resisting them.",
        "values": {
            "L": ("Low", "No mitigation to evade; the attack works repeatedly."),
            "H": ("High", "Attacker must defeat a defence such as ASLR, a signature check, or a per-session token."),
        },
    },
    "AT": {
        "name": "Attack Requirements",
        "summary": "Conditions of the deployment or execution that must hold, beyond the attacker's control.",
        "values": {
            "N": ("None", "No special conditions; the attack works whenever it is attempted."),
            "P": ("Present", "Needs a race window, a specific configuration, or a machine-in-the-middle position."),
        },
    },
    "PR": {
        "name": "Privileges Required",
        "summary": "What access the attacker must already hold before starting.",
        "values": {
            "N": ("None", "No authorisation needed."),
            "L": ("Low", "An ordinary user account, tenant, or basic API credential."),
            "H": ("High", "Administrative or service-level control over the component."),
        },
    },
    "UI": {
        "name": "User Interaction",
        "summary": "Whether someone other than the attacker must do something for the attack to work.",
        "values": {
            "N": ("None", "No other person is involved."),
            "P": ("Passive", "The victim only uses the system normally — for example opening a page or a document the agent then ingests."),
            "A": ("Active", "The victim must take a deliberate, specific action, such as importing a file or confirming a dialog."),
        },
    },
}

for _letter, _metric in (("C", "VC"), ("I", "VI"), ("A", "VA")):
    BASE_METRIC_INFO[_metric] = {
        "name": {"C": "Confidentiality", "I": "Integrity", "A": "Availability"}[_letter],
        "summary": f"Impact on the {_VULNERABLE_SUMMARY[_letter]}.",
        "values": dict(_VULNERABLE_IMPACT_VALUES[_letter]),
    }

for _letter, _metric in (("C", "SC"), ("I", "SI"), ("A", "SA")):
    BASE_METRIC_INFO[_metric] = {
        "name": {"C": "Confidentiality", "I": "Integrity", "A": "Availability"}[_letter],
        "summary": (
            f"Impact on the {_PROPERTY[_letter]} of systems beyond the vulnerable "
            "component — downstream services, other tenants, or the host environment. "
            "For an agent, this is usually where its tool calls and hand-offs land."
        ),
        "values": dict(_SUBSEQUENT_IMPACT_VALUES[_letter]),
    }

THREAT_METRIC_INFO: dict[str, dict[str, Any]] = {
    "E": {
        "name": "Exploit Maturity",
        "summary": "What is known today about exploitation of this finding.",
        "values": {
            "X": (NOT_DEFINED, "Unknown — scored as though attacks were observed (the worst case)."),
            "A": ("Attacked", "Attacks are reported, or ready-made exploitation automation exists."),
            "P": ("Proof of concept", "A proof of concept exists, but no attacks are reported."),
            "U": ("Unreported", "Neither a proof of concept nor an attack has been reported."),
        },
    },
}

_REQUIREMENT_VALUES = {
    "X": (NOT_DEFINED, "Treated as High."),
    "H": ("High", "Loss would be catastrophic for this deployment."),
    "M": ("Medium", "Loss would be serious for this deployment."),
    "L": ("Low", "Loss would have limited consequences for this deployment."),
}

REQUIREMENT_METRIC_INFO: dict[str, dict[str, Any]] = {
    metric: {
        "name": f"{name} Requirement",
        "summary": (
            f"How much this deployment depends on the {_PROPERTY[letter]} of the "
            "affected asset. "
            "Raises or lowers the environmental score."
        ),
        "values": dict(_REQUIREMENT_VALUES),
    }
    for metric, name, letter in (
        ("CR", "Confidentiality", "C"),
        ("IR", "Integrity", "I"),
        ("AR", "Availability", "A"),
    )
}


def _modified_info(metric: str) -> dict[str, Any]:
    """Describe a Modified Base metric in terms of the Base metric it overrides."""
    base = BASE_METRIC_INFO[metric[1:]]
    system = "subsequent system" if metric[1] == "S" else "vulnerable system"
    name = base["name"]
    if metric[1:] in ("VC", "VI", "VA", "SC", "SI", "SA"):
        name = f"{name} ({system})"
    values: dict[str, tuple[str, str]] = {
        "X": (NOT_DEFINED, "Keep the Base value."),
    }
    for code, (label, summary) in base["values"].items():
        values[code] = (label, summary)
    if metric in ("MSI", "MSA"):
        values["S"] = SAFETY_VALUE
    return {
        "name": f"Modified {name}",
        "summary": f"{base['summary']} Overrides the Base value for this deployment only.",
        "values": {code: values[code] for code in MODIFIED_METRICS[metric]},
    }


MODIFIED_METRIC_INFO: dict[str, dict[str, Any]] = {
    metric: _modified_info(metric) for metric in MODIFIED_METRICS
}

CVSS_METRIC_INFO: dict[str, dict[str, Any]] = {
    **BASE_METRIC_INFO,
    **THREAT_METRIC_INFO,
    **REQUIREMENT_METRIC_INFO,
    **MODIFIED_METRIC_INFO,
}

CVSS_GROUP_INFO: dict[str, dict[str, str]] = {
    "base": {
        "title": "Base",
        "summary": (
            "Intrinsic properties of the finding: the same anywhere it is deployed and "
            "at any point in time."
        ),
    },
    "threat": {
        "title": "Threat",
        "summary": "What is known about exploitation activity right now.",
    },
    "environmental": {
        "title": "Environmental",
        "summary": (
            "Your deployment's own context: how much it depends on each security "
            "property, and any Base metric that differs for you."
        ),
    },
}


def cvss_metric_info() -> dict[str, dict[str, Any]]:
    """Return every CVSS metric with its name, summary and value descriptions."""
    return {
        metric: {
            "name": info["name"],
            "summary": info["summary"],
            "values": {
                code: {"label": info["values"][code][0], "summary": info["values"][code][1]}
                for code in values
            },
        }
        for metric, values in (
            *BASE_METRICS.items(),
            *THREAT_METRICS.items(),
            *ENV_REQUIREMENT_METRICS.items(),
            *MODIFIED_METRICS.items(),
        )
        for info in (CVSS_METRIC_INFO[metric],)
    }
