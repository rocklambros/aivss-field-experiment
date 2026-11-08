"""Tests for the JSON entry points used by the CLI and the web calculator."""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from aivss_calc.api import calculator_catalog, handle_web_request, profile_from_vectors
from aivss_calc.cli import main
from aivss_calc.cvss_score import severity_rating
from aivss_calc.demo_server import _top10_payload
from aivss_calc.scenarios import SCENARIOS
from aivss_calc.web_bundle import manifest, package_zip

OBSERVED_AT = "2026-08-27T00:00:00Z"


def _call(request: dict) -> dict:
    return json.loads(handle_web_request(json.dumps(request)))


def _decision_request(scenario: dict) -> dict:
    return {
        "publicly_exposed": scenario["publicly_exposed"],
        "publicly_exposed_source": "synthetic deployment inventory fixture",
        "decision_data_observed_at": OBSERVED_AT,
        "automatable": scenario["automatable"],
        "technical_impact": scenario["technical_impact"],
        "evidence": scenario["evidence"],
    }


@pytest.mark.parametrize(
    ("score", "rating"),
    [
        (0.0, "None"),
        (0.1, "Low"),
        (3.9, "Low"),
        (4.0, "Medium"),
        (6.9, "Medium"),
        (7.0, "High"),
        (8.9, "High"),
        (9.0, "Critical"),
        (10.0, "Critical"),
    ],
)
def test_severity_rating_bands(score, rating):
    assert severity_rating(score) == rating


@pytest.mark.parametrize("score", [-0.1, 10.1])
def test_severity_rating_rejects_out_of_range(score):
    with pytest.raises(ValueError, match="CVSS score"):
        severity_rating(score)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s["risk_category"])
def test_cli_profile_matches_api(scenario, capsys):
    assert main(
        ["profile", scenario["cvss_vector"], "--aivss-vector", scenario["aivss_vector"]]
    ) == 0
    cli_output = json.loads(capsys.readouterr().out)
    assert cli_output == profile_from_vectors(
        scenario["cvss_vector"], scenario["aivss_vector"]
    )


def test_profile_rejects_embedded_aivss_vector():
    scenario = SCENARIOS[0]
    with pytest.raises(ValueError, match="separately"):
        profile_from_vectors(
            f"{scenario['cvss_vector']} {scenario['aivss_vector']}",
            scenario["aivss_vector"],
        )


def test_web_calculate_matches_dashboard_for_every_scenario():
    rows = {row["asi"]: row for row in _top10_payload()}
    for scenario in SCENARIOS:
        response = _call(
            {
                "op": "calculate",
                "cvss_vector": scenario["cvss_vector"],
                "aivss_vector": scenario["aivss_vector"],
                "decision": _decision_request(scenario),
            }
        )
        assert response["ok"], response
        result = response["result"]
        row = rows[scenario["risk_category"]]
        assert result["profile"]["aivss"] == row["aivss"]
        assert result["profile"]["cvss_bte"] == row["cvss_bte"]
        assert result["profile"]["agentic_uplift_u"] == row["agentic_uplift_u"]
        assert result["profile"]["agentic_effect_class"] == row["agentic_effect_class"]
        decision = result["decision"]
        assert decision["bod_2604_analogy_timeline"] == row["bod_timeline"]
        assert decision["aivss_recommended_timeline"] == row["aivss_recommended_timeline"]
        assert decision["escalated"] == row["escalated"]


def test_web_calculate_without_decision():
    scenario = SCENARIOS[5]
    response = _call(
        {
            "op": "calculate",
            "cvss_vector": scenario["cvss_vector"],
            "aivss_vector": scenario["aivss_vector"],
            "decision": None,
        }
    )
    assert response["ok"]
    assert set(response["result"]) == {"profile"}
    profile = response["result"]["profile"]
    assert profile["cvss_bte"] == 7.8
    assert profile["cvss_band"] == "High"
    assert profile["aivss"] == 9.5
    assert profile["severity_rating"] == "Critical"


def test_web_incomplete_decision_keeps_severity():
    scenario = SCENARIOS[0]
    response = _call(
        {
            "op": "calculate",
            "cvss_vector": scenario["cvss_vector"],
            "aivss_vector": scenario["aivss_vector"],
            "decision": {"decision_data_observed_at": OBSERVED_AT},
        }
    )
    assert response["ok"]
    assert response["result"]["profile"]["cvss_bte"] == 9.2
    assert response["result"]["profile"]["aivss"] == 9.7
    assert "decision" not in response["result"]
    assert response["result"]["decision_error"] == (
        "publicly_exposed must be true or false"
    )


def test_web_kev_listed_cve_uses_vulnrichment_values():
    scenario = SCENARIOS[0]
    response = _call(
        {
            "op": "calculate",
            "cvss_vector": scenario["cvss_vector"],
            "aivss_vector": scenario["aivss_vector"],
            "decision": {
                "publicly_exposed": False,
                "publicly_exposed_source": "asset inventory",
                "decision_data_observed_at": OBSERVED_AT,
                "cve_id": "CVE-2025-32711",
                "fceb_bod_2604_scope": True,
                "vulnrichment_automatable": True,
                "vulnrichment_technical_impact": "total",
                "evidence": {"cisa_kev": True},
            },
        }
    )
    decision = response["result"]["decision"]
    assert decision["decision_basis"] == "cisa_bod_26_04"
    assert decision["bod_2604_timeline"] == "3DF"
    assert decision["decision_points"]["automatable_source"] == "CISA Vulnrichment"


@pytest.mark.parametrize(
    ("request_body", "message"),
    [
        ({"op": "nope"}, "unknown op 'nope'"),
        ({"op": "calculate", "aivss_vector": "AIVSS:1.0"}, "missing field 'cvss_vector'"),
        (
            {
                "op": "calculate",
                "cvss_vector": "CVSS:4.0/AV:Q",
                "aivss_vector": SCENARIOS[0]["aivss_vector"],
            },
            "Illegal value 'Q' for metric 'AV'",
        ),
        (
            {
                "op": "calculate",
                "cvss_vector": SCENARIOS[0]["cvss_vector"],
                "aivss_vector": "AIVSS:1.0/LC:D",
            },
            "must specify LC, CP, AP, RH and ES",
        ),
    ],
)
def test_web_request_errors_are_reported(request_body, message):
    response = _call(request_body)
    assert response["ok"] is False
    assert message in response["error"]


def test_catalog_covers_form_and_presets():
    catalog = calculator_catalog()
    assert _call({"op": "catalog"})["result"] == json.loads(json.dumps(catalog))
    assert list(catalog["metric_names"]) == ["LC", "CP", "AP", "RH", "ES"]
    assert catalog["rubric"]["classifying_metrics"] == ["LC", "CP", "AP", "RH"]
    assert catalog["rubric"]["uplift_metrics"] == ["ES"]
    assert set(catalog["metric_names"]) == set(catalog["rubric"]["metrics"])
    assert list(catalog["cvss_metrics"]["base"]) == [
        "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
    ]
    assert list(catalog["timelines"]) == ["FSU", "60D", "14D", "3D", "3DF"]
    assert [p["id"] for p in catalog["presets"]] == [
        s["risk_category"] for s in SCENARIOS
    ]


def test_web_converts_legacy_vector_and_reports_migration():
    scenario = SCENARIOS[0]
    legacy = "AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H"
    response = _call(
        {
            "op": "calculate",
            "cvss_vector": scenario["cvss_vector"],
            "aivss_vector": legacy,
            "decision": {
                "publicly_exposed": True,
                "publicly_exposed_source": "asset inventory",
                "decision_data_observed_at": OBSERVED_AT,
                "automatable": True,
                "technical_impact": "total",
            },
        }
    )
    assert response["ok"], response
    profile = response["result"]["profile"]
    assert profile["aivss_vector"] == "AIVSS:1.0/LC:D/CP:C/AP:L/RH:X/ES:W"
    assert profile["migration"]["dropped"] == {"SR": "R", "PT": "H", "CA": "M", "TD": "H"}
    assert "agent_untraceability" not in profile["migration"]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("aivss_vector", None, "must be a string"),
        ("aivss_vector", 7, "must be a string"),
    ],
)
def test_web_rejects_malformed_fields_with_an_error_response(field, value, message):
    scenario = SCENARIOS[0]
    request = {
        "op": "calculate",
        "cvss_vector": scenario["cvss_vector"],
        "aivss_vector": scenario["aivss_vector"],
    }
    request[field] = value
    response = _call(request)
    assert response["ok"] is False
    assert message in response["error"]


LEGACY = "AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H"
CONVERTED = "AIVSS:1.0/LC:D/CP:C/AP:L/RH:X/ES:W"


def test_web_reports_migration_for_client_side_conversion():
    response = _call(
        {
            "op": "calculate",
            "cvss_vector": SCENARIOS[0]["cvss_vector"],
            "aivss_vector": CONVERTED,
            "migrated_from": LEGACY,
        }
    )
    assert response["ok"], response
    migration = response["result"]["profile"]["migration"]
    assert migration["aivss_vector"] == CONVERTED
    assert migration["dropped"] == {"SR": "R", "PT": "H", "CA": "M", "TD": "H"}


def test_web_omits_migration_once_metrics_are_edited():
    response = _call(
        {
            "op": "calculate",
            "cvss_vector": SCENARIOS[0]["cvss_vector"],
            "aivss_vector": CONVERTED.replace("ES:W", "ES:M"),
            "migrated_from": LEGACY,
        }
    )
    assert response["ok"], response
    assert "migration" not in response["result"]["profile"]


def test_web_rejects_non_string_migrated_from():
    response = _call(
        {
            "op": "calculate",
            "cvss_vector": SCENARIOS[0]["cvss_vector"],
            "aivss_vector": CONVERTED,
            "migrated_from": 5,
        }
    )
    assert response["ok"] is False
    assert "must be a string" in response["error"]


def test_web_accepts_rh_possible_with_any_at():
    for at in ("N", "P"):
        response = _call(
            {
                "op": "calculate",
                "cvss_vector": f"CVSS:4.0/AV:N/AC:L/AT:{at}/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
                "aivss_vector": "AIVSS:1.0/LC:D/CP:N/AP:N/RH:P/ES:M",
            }
        )
        assert response["ok"] is True


def test_web_rejects_the_retired_sr_metric():
    response = _call(
        {
            "op": "calculate",
            "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            "aivss_vector": "AIVSS:1.0/LC:D/CP:N/AP:N/SR:P/ES:M",
        }
    )
    assert response["ok"] is False
    assert "replaced by RH" in response["error"]


def test_package_zip_contains_importable_sources():
    with zipfile.ZipFile(io.BytesIO(package_zip())) as archive:
        names = set(archive.namelist())
    assert "aivss_calc/api.py" in names
    assert "aivss_calc/data/cvss_v4_lookup.json" in names
    assert not any("__pycache__" in name for name in names)


def test_manifest_pins_installed_cvss_version():
    from importlib import metadata

    assert manifest()["packages"] == [f"cvss=={metadata.version('cvss')}"]


def test_every_cvss_metric_and_value_has_help_text():
    from aivss_calc.cvss_metrics import cvss_metric_info
    from aivss_calc.macrovector import (
        BASE_METRICS,
        ENV_REQUIREMENT_METRICS,
        MODIFIED_METRICS,
        THREAT_METRICS,
    )

    info = cvss_metric_info()
    expected = {
        **BASE_METRICS,
        **THREAT_METRICS,
        **ENV_REQUIREMENT_METRICS,
        **MODIFIED_METRICS,
    }
    assert set(info) == set(expected)
    for metric, values in expected.items():
        entry = info[metric]
        assert entry["name"].strip()
        assert entry["summary"].strip().endswith(".")
        assert list(entry["values"]) == list(values), metric
        for code, value in entry["values"].items():
            assert value["label"].strip(), (metric, code)
            assert value["summary"].strip().endswith("."), (metric, code)


def test_every_agentic_metric_and_decision_input_has_help_text():
    catalog = calculator_catalog()
    for metric in catalog["rubric"]["metrics"]:
        assert catalog["metric_names"][metric].strip()
        assert catalog["metric_summaries"][metric].strip().endswith(".")
    for key, info in catalog["decision_inputs"].items():
        assert info["summary"].strip(), key
        for value, text in info.get("values", {}).items():
            assert text.strip().endswith("."), (key, value)
    assert all(text.strip() for text in catalog["result_info"].values())
    assert set(catalog["cvss_groups"]) == {"base", "threat", "environmental"}
