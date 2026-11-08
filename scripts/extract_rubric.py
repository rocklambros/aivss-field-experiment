#!/usr/bin/env python3
"""Extract the AIVSS metric definitions that raters score against.

Version: 1.0.0
Owner: Rock Lambros
Purpose: Copy the *_VALUES dictionaries, classify_rh(), the Effect Class
    ladder, and Lookup Table U verbatim from aivss_calc/ai_metrics.py, plus
    Lookup Table AIVSS from aivss_calc/lookup.py, into rubric/.

The extraction walks the AST and slices the original source by line range, so
the rubric text is byte-identical to the calculator source. A regex or a
hand copy could drift from the code the calculator executes.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

# Top-level names copied from ai_metrics.py, in source order.
AI_METRICS_NAMES = (
    "LC_VALUES",
    "CP_VALUES",
    "AP_VALUES",
    "RH_VALUES",
    "ES_VALUES",
    "RH_LOCI",
    "classify_rh",
    "AGENTIC_METRIC_NAMES",
    "AGENTIC_METRIC_SUMMARIES",
    "AGENTIC_EFFECT_CLASS_LABELS",
    "UPLIFT_TABLE",
)
# Methods copied from the AIProfile class.
AI_PROFILE_METHODS = (
    "provisional",
    "effect_class",
    "effect_class_range",
    "agentic_uplift_u",
)


def _segment(source_lines: list[str], node: ast.AST) -> str:
    """Return the exact source text of a node, with preceding comment lines."""
    start = node.lineno - 1
    if getattr(node, "decorator_list", None):
        start = min(d.lineno for d in node.decorator_list) - 1
    while start > 0 and source_lines[start - 1].lstrip().startswith("#"):
        start -= 1
    return "".join(source_lines[start : node.end_lineno])


def _target_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target = node.targets[0]
        return target.id if isinstance(target, ast.Name) else None
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        return node.name
    return None


def extract(calc_root: Path) -> str:
    ai_path = calc_root / "aivss_calc" / "ai_metrics.py"
    source = ai_path.read_text(encoding="utf-8")
    lines = source.splitlines(keepends=True)
    tree = ast.parse(source)

    found: dict[str, str] = {}
    for node in tree.body:
        name = _target_name(node)
        if name in AI_METRICS_NAMES:
            found[name] = (
                f"# ai_metrics.py lines {node.lineno}-{node.end_lineno}\n"
                + _segment(lines, node)
            )
        if isinstance(node, ast.ClassDef) and node.name == "AIProfile":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name in AI_PROFILE_METHODS:
                    found[f"AIProfile.{item.name}"] = (
                        f"# ai_metrics.py lines {item.lineno}-{item.end_lineno} "
                        f"(method of AIProfile)\n" + _segment(lines, item)
                    )

    expected = list(AI_METRICS_NAMES) + [f"AIProfile.{m}" for m in AI_PROFILE_METHODS]
    missing = [name for name in expected if name not in found]
    if missing:
        # Fail closed: a silent partial rubric would bias the raters.
        raise SystemExit(f"extract_rubric: missing definitions {missing} in {ai_path}")

    out = [
        "# AIVSS 1.0 metric definitions, copied verbatim from the reference calculator\n",
        "# Source: aivss_calc/ai_metrics.py and aivss_calc/lookup.py (aivss-calc 1.2.0)\n",
        "# Do not edit. Regenerate with scripts/extract_rubric.py.\n\n",
    ]
    for name in expected:
        out.append(found[name].rstrip("\n") + "\n\n\n")

    lookup_path = calc_root / "aivss_calc" / "lookup.py"
    out.append("# ---- aivss_calc/lookup.py (complete file) ----\n")
    out.append(lookup_path.read_text(encoding="utf-8"))
    return "".join(out)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: extract_rubric.py <calc_root> <out_file>", file=sys.stderr)
        return 2
    calc_root, out_file = Path(argv[1]), Path(argv[2])
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(extract(calc_root), encoding="utf-8")
    print(f"wrote {out_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
