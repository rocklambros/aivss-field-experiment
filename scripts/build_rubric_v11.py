#!/usr/bin/env python3
"""Build the v1.1 assessor rubric pack.

Version: 1.1.0
Owner: Rock Lambros

The pack holds the five AIVSS metric definitions, classify_rh(), and the
effect_class() ladder, copied verbatim from the calculator by AST line range,
plus a labeled paraphrase of the FIRST CVSS v4.0 base metric definitions.
The Table 6 lookup and the uplift table are left out on purpose (premortem
P05): assessors should not see how a letter maps to a score.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CALC = ROOT / "work" / "aivss-calc" / "aivss_calc" / "ai_metrics.py"
OUT = ROOT / "rubric" / "rubric_v1.1.txt"

VALUE_DICTS = ("LC_VALUES", "CP_VALUES", "AP_VALUES", "RH_VALUES", "ES_VALUES", "RH_LOCI")
FUNCTIONS = ("classify_rh",)
METHODS = ("effect_class",)

# Paraphrase of FIRST, "Common Vulnerability Scoring System v4.0: Specification
# Document", Section 2 (Base Metrics). Not verbatim FIRST text, and labeled as such
# in the output, because the experiment makes no network calls to fetch it.
CVSS_V4_BASE = """\
CVSS v4.0 base metrics (paraphrase of FIRST CVSS v4.0 Specification Document, Section 2. Labeled paraphrase, not FIRST's wording.)

Exploitability metrics describe the vulnerable system.
- Attack Vector (AV). N Network: exploitable remotely across the network, including from the internet. A Adjacent: limited to a shared physical or logical adjacent network. L Local: the attacker needs local access to the vulnerable system, for example a local session, or relies on a user on that system to act (such as opening a file or visiting content). P Physical: the attacker must touch or manipulate the device.
- Attack Complexity (AC). L Low: no measurable conditions beyond the attacker's control. H High: success requires evading or defeating a security-enhancing technique, or gathering target-specific secrets.
- Attack Requirements (AT). N None: no deployment or execution conditions beyond the attacker's control. P Present: success depends on specific conditions of the vulnerable system, such as a race window or a particular configuration, that the attacker cannot force.
- Privileges Required (PR). N None: unauthenticated. L Low: basic user privileges. H High: administrative or significant privileges.
- User Interaction (UI). N None: no human other than the attacker takes part. P Passive: a human must take part only in limited, involuntary ways, such as using the system normally. A Active: a human must take specific, conscious actions, such as opening a crafted file, clicking through a prompt, or dismissing a warning.

Impact metrics. Vulnerable system (VC, VI, VA) and subsequent systems (SC, SI, SA).
- Confidentiality: H High: total loss, or loss of specific high-value information. L Low: some loss with limited control over what is obtained. N None.
- Integrity: H High: total loss of protection, or modification with direct serious consequence. L Low: modification possible with limited control or limited consequence. N None.
- Availability: H High: total loss of availability, sustained or persistent. L Low: reduced performance or interruptions. N None.
- The vulnerable system is the system that contains the vulnerability. Subsequent systems are other systems whose confidentiality, integrity, or availability is affected through it.
"""


def _segment(lines: list[str], node: ast.AST) -> str:
    start = node.lineno - 1
    while start > 0 and lines[start - 1].lstrip().startswith("#"):
        start -= 1
    return "".join(lines[start:node.end_lineno])


def build() -> str:
    source = CALC.read_text(encoding="utf-8")
    lines = source.splitlines(keepends=True)
    tree = ast.parse(source)
    found: dict[str, str] = {}
    for node in tree.body:
        name = None
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            target = node.targets[0] if isinstance(node, ast.Assign) else node.target
            name = getattr(target, "id", None)
        elif isinstance(node, ast.FunctionDef):
            name = node.name
        if name in VALUE_DICTS or name in FUNCTIONS:
            found[name] = _segment(lines, node)
        if isinstance(node, ast.ClassDef) and node.name == "AIProfile":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name in METHODS:
                    found[f"AIProfile.{item.name}"] = _segment(lines, item)
    expected = list(VALUE_DICTS) + list(FUNCTIONS) + [f"AIProfile.{m}" for m in METHODS]
    missing = [n for n in expected if n not in found]
    if missing:
        raise SystemExit(f"build_rubric_v11: missing {missing}")
    parts = [
        "AIVSS 1.0 assessor rubric pack, v1.1.\n",
        "Section 1 is copied verbatim from aivss_calc/ai_metrics.py (aivss-calc 1.2.0).\n",
        "Section 2 is a labeled paraphrase of the FIRST CVSS v4.0 base metric definitions.\n\n",
        "== Section 1. AIVSS agentic metrics, reward hacking rule, agent class ladder ==\n\n",
    ]
    parts += [found[n].rstrip("\n") + "\n\n" for n in expected]
    parts += ["== Section 2. CVSS v4.0 base metrics ==\n\n", CVSS_V4_BASE]
    text = "".join(parts)
    for forbidden in ("TABLE_6", "UPLIFT_TABLE", "9.7", "8.9"):
        if forbidden in text:
            raise SystemExit(f"build_rubric_v11: score mapping leaked into rubric ({forbidden})")
    return text


def main() -> int:
    OUT.write_text(build(), encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
