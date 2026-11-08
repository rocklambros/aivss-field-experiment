"""Command-line interface for the AIVSS 1.0 calculator."""

from __future__ import annotations

import argparse
import json
import sys
from itertools import product
from pathlib import Path
from typing import Any

from . import __version__
from .ai_metrics import (
    AI_METRICS,
    AIProfile,
    convert_legacy_vector,
    parse_aivss_vector,
    split_ai_vector,
)
from .api import decision_report, profile_report, rubric
from .assessment import assess, assessment_from_payload
from .decision import BOD_2604_TABLE, ExploitationEvidence
from .demo_server import run_demo
from .legacy import score_legacy
from .macrovector import _lookup_table
from .priority import compute_priority
from .scenarios import SCENARIOS, scenario_payload
from .taxonomy import ASI_TOP_10
from .validation import validate_assessment_input, validate_report

CLASSIFYING_METRICS = ("LC", "CP", "AP", "RH")
UPLIFT_METRICS = ("ES",)
ALL_AGENTIC_METRICS = CLASSIFYING_METRICS + UPLIFT_METRICS


def _emit(payload: Any, pretty: bool = True) -> None:
    print(json.dumps(payload, indent=2 if pretty else None, sort_keys=False))


def _parse_optional_bool(value: str) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in ("true", "yes", "1"):
        return True
    if lowered in ("false", "no", "0"):
        return False
    raise argparse.ArgumentTypeError(f"expected true/false, got {value!r}")


def _profile_from_args(args: argparse.Namespace) -> AIProfile | None:
    supplied = {k: getattr(args, k.lower(), None) for k in ALL_AGENTIC_METRICS}
    present = {k for k, value in supplied.items() if value is not None}
    if not present:
        return None
    missing = [name for name in ALL_AGENTIC_METRICS if supplied[name] is None]
    if missing:
        raise ValueError(
            "all five AIVSS metrics (LC, CP, AP, RH, ES) are required when flags "
            "are used; "
            f"missing {', '.join(missing)}"
        )
    return AIProfile(**{name.lower(): supplied[name] for name in ALL_AGENTIC_METRICS})


def _resolve_profile(
    args: argparse.Namespace, embedded: AIProfile | None
) -> AIProfile | None:
    flagged = _profile_from_args(args)
    vector_value = getattr(args, "aivss_vector", None)
    vectored = parse_aivss_vector(vector_value) if vector_value else None
    sources = [value for value in (embedded, flagged, vectored) if value is not None]
    if len(sources) > 1:
        raise ValueError(
            "provide the AIVSS profile once, using --aivss-vector, "
            "all five metric flags, or two-vector display form"
        )
    return sources[0] if sources else None


def _add_ai_metric_flags(p: argparse.ArgumentParser) -> None:
    for name in ALL_AGENTIC_METRICS:
        p.add_argument(
            f"--{name.lower()}",
            choices=sorted(AI_METRICS[name]),
            help=f"Agentic AI metric {name}",
        )


def _evidence_from_args(args: argparse.Namespace) -> ExploitationEvidence:
    return ExploitationEvidence(
        cisa_kev=args.kev,
        vulnrichment_active=args.vulnrichment_active,
        epss=args.epss,
        epss_date=args.epss_date,
        observed_local=args.observed_local,
        poc=args.poc,
    )


def _add_evidence_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--kev", type=_parse_optional_bool)
    p.add_argument("--vulnrichment-active", action="store_true")
    p.add_argument("--epss", type=float)
    p.add_argument("--epss-date")
    p.add_argument("--observed-local", action="store_true")
    p.add_argument("--poc", action="store_true")


def cmd_profile(args: argparse.Namespace) -> int:
    cvss_only, embedded = split_ai_vector(args.vector)
    profile = _resolve_profile(args, embedded)
    if profile is None:
        raise ValueError(
            "profile requires a current-version AIVSS vector or all five metric flags"
        )
    _emit(profile_report(cvss_only, profile))
    return 0


def cmd_decide(args: argparse.Namespace) -> int:
    _emit(
        decision_report(
            evidence=_evidence_from_args(args),
            vector=args.vector,
            agentic_effect_class=args.agentic_effect_class,
            publicly_exposed=args.publicly_exposed,
            publicly_exposed_source=args.publicly_exposed_source,
            decision_data_observed_at=args.decision_data_observed_at,
            automatable=args.automatable,
            technical_impact=args.technical_impact,
            cve_id=args.cve_id,
            fceb_bod_2604_scope=args.fceb_bod_2604_scope,
            vulnrichment_automatable=args.vulnrichment_automatable,
            vulnrichment_technical_impact=args.vulnrichment_technical_impact,
        )
    )
    return 0


def cmd_assess(args: argparse.Namespace) -> int:
    with open(args.input, encoding="utf-8") as handle:
        data = json.load(handle)
    validate_assessment_input(data)

    report = assess(assessment_from_payload(data))
    validate_report(report)
    _emit(report)
    return 0


def cmd_priority(args: argparse.Namespace) -> int:
    _emit(
        compute_priority(
            severity=args.severity,
            business_criticality=args.business_criticality,
            reach=args.reach,
            likelihood=args.likelihood,
        )
    )
    return 0


def cmd_legacy(args: argparse.Namespace) -> int:
    with open(args.factors, encoding="utf-8") as handle:
        data = json.load(handle)
    result = score_legacy(
        cvss_base=data["cvss_base"],
        factors=data["factors"],
        threat_maturity=data.get("threat_maturity", "poc"),
        mitigation_inherent=data.get("mitigation_inherent", "none"),
        mitigation_residual=data.get("mitigation_residual"),
    )
    print(
        "WARNING: legacy is for migration comparison only; "
        "must not be used for AIVSS 1.0 compliance.",
        file=sys.stderr,
    )
    _emit(result)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    table = _lookup_table()
    example_failures: list[str] = []
    source_root = Path(__file__).resolve().parent.parent
    examples_dir = source_root / "examples"
    verify_shipped_files = (source_root / "pyproject.toml").is_file()
    for scenario in SCENARIOS:
        try:
            data = scenario_payload(scenario["risk_category"])
            validate_assessment_input(data)
            report = assess(assessment_from_payload(data))
            validate_report(report)
            path = examples_dir / f"{scenario['risk_category'].lower()}-example.json"
            if verify_shipped_files and not path.is_file():
                raise ValueError("shipped example is missing")
            if verify_shipped_files:
                with path.open(encoding="utf-8") as handle:
                    shipped = json.load(handle)
                if shipped != data:
                    raise ValueError("shipped example differs from canonical scenario")
        except Exception as exc:
            example_failures.append(f"{scenario['risk_category']}: {exc}")

    expected_bod_keys = {
        (kev, exposed, automatable, impact)
        for kev, exposed, automatable, impact in product(
            (False, True), (False, True), (False, True), ("partial", "total")
        )
    }
    bod_table_complete = set(BOD_2604_TABLE) == expected_bod_keys
    passed = not example_failures and bod_table_complete
    _emit(
        {
            "passed": passed,
            "macrovectors": len(table),
            "bod_2604_table_rows": len(BOD_2604_TABLE),
            "bod_2604_table_complete": bod_table_complete,
            "validated_scenarios": len(SCENARIOS) - len(example_failures),
            "scenario_failures": example_failures,
        }
    )
    return 0 if passed else 1


def cmd_migrate_vector(args: argparse.Namespace) -> int:
    """Convert a draft eight-metric AIVSS vector to the five-metric form."""
    _emit(convert_legacy_vector(args.vector))
    return 0


def cmd_taxonomy(args: argparse.Namespace) -> int:
    _emit({"OWASP Top 10 for Agentic Applications 2026": ASI_TOP_10})
    return 0


def cmd_rubric(args: argparse.Namespace) -> int:
    """Emit the value sets for the five Agentic AI metrics."""
    _emit(rubric())
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    run_demo(host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aivss-calc")
    parser.add_argument(
        "--version", action="version", version=f"aivss-calc {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("profile")
    p.add_argument("vector")
    p.add_argument("--aivss-vector")
    _add_ai_metric_flags(p)
    p.set_defaults(func=cmd_profile)

    p = sub.add_parser("decide")
    p.add_argument("--vector")
    p.add_argument(
        "--agentic-effect-class",
        choices=("A0", "A1", "A2", "AX"),
        dest="agentic_effect_class",
    )
    p.add_argument("--publicly-exposed", type=_parse_optional_bool)
    p.add_argument("--publicly-exposed-source")
    p.add_argument("--decision-data-observed-at")
    p.add_argument("--cve-id")
    p.add_argument("--fceb-bod-2604-scope", action="store_true")
    p.add_argument("--automatable", type=_parse_optional_bool)
    p.add_argument("--technical-impact", choices=("partial", "total"))
    p.add_argument("--vulnrichment-automatable", type=_parse_optional_bool)
    p.add_argument("--vulnrichment-technical-impact", choices=("partial", "total"))
    _add_evidence_flags(p)
    p.set_defaults(func=cmd_decide)

    p = sub.add_parser("assess")
    p.add_argument("input")
    p.set_defaults(func=cmd_assess)

    p = sub.add_parser("priority")
    p.add_argument("--severity", type=float, required=True)
    p.add_argument(
        "--business-criticality", choices=("high", "medium", "low"), required=True
    )
    p.add_argument("--reach", choices=("high", "medium", "low"), required=True)
    p.add_argument("--likelihood", type=float, required=True)
    p.set_defaults(func=cmd_priority)

    p = sub.add_parser(
        "legacy",
        help=(
            "Migration comparison only (withdrawn v0.x uplift). "
            "Must not be used for AIVSS 1.0 compliance."
        ),
    )
    p.add_argument("--factors", required=True)
    p.set_defaults(func=cmd_legacy)

    p = sub.add_parser("verify")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser(
        "migrate-vector",
        help="Convert a draft eight-metric AIVSS vector (EX/PT/CA/TD; SR, PT, CA and TD are dropped) to LC/CP/AP/RH/ES",
    )
    p.add_argument("vector")
    p.set_defaults(func=cmd_migrate_vector)

    p = sub.add_parser("taxonomy")
    p.set_defaults(func=cmd_taxonomy)

    p = sub.add_parser(
        "rubric", help="List the five Agentic AI metric value sets and definitions"
    )
    p.set_defaults(func=cmd_rubric)

    p = sub.add_parser(
        "demo",
        help="Launch the OWASP ASI Top 10 AIVSS demo dashboard (http server)",
    )
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.set_defaults(func=cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, KeyError, FileNotFoundError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
