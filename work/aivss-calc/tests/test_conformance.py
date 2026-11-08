"""Cross-artifact, schema, CLI, and negative conformance tests."""

from __future__ import annotations

import copy
import json
import pathlib
from itertools import product

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: tomllib is stdlib from 3.11
    import tomli as tomllib

import jsonschema
import pytest

from aivss_calc import Assessment, Provenance, assess, assessment_from_payload
from aivss_calc.ai_metrics import (
    AIVSS_EXTENSION_PREFIX,
    AGENTIC_METRIC_ORDER,
    AGENTIC_METRICS,
    CLASSIFYING_AGENTIC_METRICS,
    UPLIFT_AGENTIC_METRICS,
    AIProfile,
    parse_aivss_vector,
)
from aivss_calc.cli import main
from aivss_calc.scenarios import SCENARIOS, scenario_payload
from aivss_calc.validation import validate_assessment_input, validate_report
from aivss_calc.versions import (
    CALCULATOR_VERSION,
    EXTENSION_VECTOR_VERSION,
    REPORT_SCHEMA_VERSION,
    RUBRIC_VERSION,
    SPEC_VERSION,
)

REPO = pathlib.Path(__file__).resolve().parents[1]
CVSS = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P"
EVIDENCE = scenario_payload("ASI06")["metric_evidence"]


def test_versions_are_consistent_across_package_and_schemas():
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    report_schema = json.loads(
        (REPO / "schemas" / "aivss-report-v1.0.json").read_text(encoding="utf-8")
    )
    manifest = json.loads((REPO / "aivss-extension.json").read_text(encoding="utf-8"))
    assert project["project"]["version"] == CALCULATOR_VERSION
    assert (
        report_schema["properties"]["calculator_version"]["const"] == CALCULATOR_VERSION
    )
    assert report_schema["properties"]["rubric_version"]["const"] == RUBRIC_VERSION
    assert report_schema["properties"]["aivss_version"]["const"] == SPEC_VERSION
    assert (
        report_schema["properties"]["report_schema_version"]["const"]
        == REPORT_SCHEMA_VERSION
    )
    assert report_schema["$defs"]["scores"]["required"] == [
        "cvss_score",
        "cvss_bte",
        "cvss_nomenclature",
        "cvss_band",
        "agentic_effect_class",
        "provisional",
        "agentic_uplift_u",
        "aivss",
        "aivss_min",
        "aivss_max",
        "aivss_band",
        "table_cell",
        "rule",
        "status",
        "basis",
    ]
    assert manifest["version"] == EXTENSION_VECTOR_VERSION
    assert manifest["vector_prefix"] == AIVSS_EXTENSION_PREFIX
    assert manifest["metric_order"] == list(AGENTIC_METRIC_ORDER)
    assert manifest["classifying_metrics"] == list(CLASSIFYING_AGENTIC_METRICS)
    assert manifest["uplift_metrics"] == list(UPLIFT_AGENTIC_METRICS)


def test_every_shipped_example_is_current_and_valid():
    files = sorted((REPO / "examples").glob("asi??-example.json"))
    assert len(files) == len(SCENARIOS) == 10
    for path in files:
        payload = json.loads(path.read_text(encoding="utf-8"))
        validate_assessment_input(payload)
        report = assess(assessment_from_payload(payload))
        validate_report(report)
        expected = scenario_payload(payload["risk_category"])
        assert payload == expected


def test_all_metric_combinations_have_deterministic_completeness_and_class():
    names = list(AGENTIC_METRIC_ORDER)
    for values in product(*(AGENTIC_METRICS[name] for name in names)):
        profile = AIProfile(**dict(zip((name.lower() for name in names), values)))
        assert profile.complete == ("X" not in values)
        assert profile.provisional == ("X" in values[:4])
        effect = profile.effect_class()
        assert effect in ("A0", "A1", "A2", "AX")
        lc, cp, ap, rh = values[:4]
        a2 = ap == "L" or (lc in "DI" and cp == "C") or (lc in "DI" and rh == "D")
        a1 = lc in "DI" or cp in "SC" or ap == "C" or rh == "D"
        if a2:
            assert effect == "A2"
        elif a1:
            assert effect == "A1"
        elif "X" in (lc, cp, ap, rh):
            assert effect == "AX"
        else:
            assert effect == "A0"


def test_unknown_classifying_metric_yields_ax():
    vector = "AIVSS:1.0/LC:X/CP:N/AP:N/RH:N/ES:W"
    report = assess(
        Assessment(
            finding_id="unknown",
            path_id="unknown-path",
            cvss_vector=CVSS,
            aivss_vector=vector,
            asi_category="ASI06",
            agentic_applicability=copy.deepcopy(
                scenario_payload("ASI06")["agentic_applicability"]
            ),
            metric_evidence=copy.deepcopy(EVIDENCE),
            publicly_exposed=True,
            automatable=True,
            technical_impact="total",
            include_decision=False,
            provenance=Provenance(assessed_at="2026-08-27T00:00:00Z"),
        )
    )
    scores = report["scores"]
    assert scores["aivss"] == scores["cvss_bte"]
    assert scores["rule"] == "cvss_bte_unchanged"
    assert scores["provisional"] is True
    assert scores["status"] == "normative"
    assert report["agentic_ai_profile"]["agentic_effect_class"] == "AX"
    assert (
        report["agentic_ai_profile"]["agentic_effect_class_status"]
        == "unvalidated"
    )
    validate_report(report)


def test_semantic_validator_rejects_tampered_score():
    report = assess(assessment_from_payload(scenario_payload("ASI01")))
    tampered = copy.deepcopy(report)
    tampered["scores"]["aivss"] = 1.0
    with pytest.raises(ValueError, match="scores"):
        validate_report(tampered)


def test_input_schema_rejects_missing_evidence_and_extra_fields():
    payload = scenario_payload("ASI01")
    del payload["metric_evidence"]["ES"]
    payload["invented"] = True
    with pytest.raises(Exception):
        validate_assessment_input(payload)


def test_input_without_decision_omits_decision_only_inputs():
    payload = scenario_payload("ASI01")
    payload["include_decision"] = False
    for name in (
        "publicly_exposed",
        "publicly_exposed_source",
        "decision_data_observed_at",
        "automatable",
        "technical_impact",
    ):
        del payload[name]
    validate_assessment_input(payload)


def test_input_semantics_reject_whitespace_only_evidence():
    payload = scenario_payload("ASI01")
    payload["metric_evidence"]["ES"]["rationale"] = "  "
    with pytest.raises(ValueError, match="rationale"):
        validate_assessment_input(payload)


def test_report_validator_rejects_fields_from_another_decision_branch():
    report = assess(assessment_from_payload(scenario_payload("ASI01")))
    report["decision"]["bod_2604_timeline"] = report["decision"][
        "bod_2604_analogy_timeline"
    ]
    report["decision"]["bod_2604_label"] = report["decision"]["bod_2604_analogy_label"]
    with pytest.raises(Exception):
        validate_report(report)


def _input_schema_validator():
    schema = json.loads(
        (REPO / "schemas" / "aivss-assessment-input-v1.0.json").read_text(encoding="utf-8")
    )
    return jsonschema.Draft202012Validator(schema)


@pytest.mark.parametrize("at", ["N", "P"])
def test_input_schema_has_no_rh_agreement_rule_with_at(at):
    payload = scenario_payload("ASI05")
    assert "RH:P" in payload["aivss_vector"]
    payload["cvss_vector"] = payload["cvss_vector"].replace("/AT:N/", f"/AT:{at}/")
    assert _input_schema_validator().is_valid(payload) is True
    validate_assessment_input(payload)


def test_cli_rejects_partial_agentic_flags(capsys):
    assert main(["profile", CVSS, "--es", "W"]) == 2
    assert "all five AIVSS metrics" in capsys.readouterr().err


@pytest.mark.parametrize(
    "missing", ["--business-criticality", "--reach", "--likelihood"]
)
def test_cli_priority_requires_every_org_input(capsys, missing):
    flags = {
        "--business-criticality": "high",
        "--reach": "high",
        "--likelihood": "0.72",
    }
    argv = ["priority", "--severity", "7.8"]
    for flag, value in flags.items():
        if flag != missing:
            argv += [flag, value]
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2
    assert missing in capsys.readouterr().err


def test_cli_priority_with_complete_org_inputs(capsys):
    argv = ["priority", "--severity", "7.8", "--business-criticality", "high"]
    argv += ["--reach", "high", "--likelihood", "0.72"]
    assert main(argv) == 0
    assert json.loads(capsys.readouterr().out)["aivss_p"] == 87


def test_cli_accepts_separate_extension_vector(capsys):
    vector = "AIVSS:1.0/LC:D/CP:C/AP:L/RH:D/ES:W"
    assert main(["profile", CVSS, "--aivss-vector", vector]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["cvss_vector"] == CVSS
    assert output["aivss_vector"] == vector
    assert output["status"] == "normative"
    assert output["cvss_bte"] == 7.8
    assert output["agentic_effect_class"] == "A2"
    assert output["aivss"] == 9.5
    assert output["agentic_uplift_u"] == 10


def test_cli_migrate_vector(capsys):
    legacy = "AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H"
    assert main(["migrate-vector", legacy]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["aivss_vector"] == "AIVSS:1.0/LC:D/CP:C/AP:L/RH:X/ES:W"
    assert output["dropped"] == {"SR": "R", "PT": "H", "CA": "M", "TD": "H"}


def test_cli_profile_rejects_legacy_vector(capsys):
    legacy = "AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H"
    assert main(["profile", CVSS, "--aivss-vector", legacy]) == 2
    assert "migrate-vector" in capsys.readouterr().err


def test_extension_parser_rejects_out_of_order_metrics():
    with pytest.raises(ValueError, match="out of order"):
        parse_aivss_vector("AIVSS:1.0/CP:C/LC:D/AP:L/RH:N/ES:W")
