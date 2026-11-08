"""Conformance and regression tests for the AIVSS 1.0 calculator.

Assertions are exact. A scoring standard whose own tests carry wide tolerances
cannot arbitrate between two implementations that disagree.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from aivss_calc import (
    BOD_2604_TABLE,
    AIProfile,
    Assessment,
    ExploitationEvidence,
    OrgContext,
    Provenance,
    assess,
    assessment_from_payload,
    bod_timeline,
    compute_priority,
    macrovector,
    macrovector_score,
    normalize_asi,
    parse_aivss_vector,
    parse_cvss_vector,
    split_ai_vector,
)
from aivss_calc.ai_metrics import (
    AGENTIC_METRIC_ORDER,
    AGENTIC_METRICS,
    CLASSIFYING_AGENTIC_METRICS,
    UPLIFT_AGENTIC_METRICS,
    UPLIFT_TABLE,
    classify_rh,
    convert_legacy_vector,
    validate_metric_evidence,
)
from aivss_calc.lookup import TABLE_6, aivss_lookup, cvss_nomenclature
from aivss_calc.decision import TIMELINE_URGENCY, advance_timeline, decide, escalate
from aivss_calc.legacy import compute_severity, factor_mean, score_legacy
from aivss_calc.cvss_score import score_cvss_bte
from aivss_calc.macrovector import _lookup_table
from aivss_calc.taxonomy import ASI_TOP_10, V08_CATEGORY_CROSSWALK
from aivss_calc.validation import validate_assessment_input, validate_report

REPO = pathlib.Path(__file__).resolve().parents[1]
SCHEMA = REPO / "schemas" / "aivss-report-v1.0.json"

# CVSS-BTE 7.8 (interpolated), MacroVector ceiling 8.0.
EXAMPLE_VECTOR = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P"
EXAMPLE_CVSS_BTE = 7.8
EXAMPLE_AI = "AIVSS:1.0/LC:D/CP:C/AP:L/RH:N/ES:W"
# Example is A2 (AP:L) in the High band, so Table 6 gives 9.5.
EXAMPLE_AIVSS = 9.5
EXAMPLE_FULL = f"{EXAMPLE_VECTOR} {EXAMPLE_AI}"
DECISION_CONTEXT = {
    "publicly_exposed_source": "test fixture",
    "decision_data_observed_at": "2026-08-27T00:00:00Z",
}
APPLICABILITY = {
    "model_directed_goal_pursuit": True,
    "action_selection_or_sequencing": True,
    "rationale": "Test fixture exercises an agentic path.",
    "evidence_refs": ["test://agentic-applicability"],
}


def metric_evidence(vector: str) -> dict[str, dict]:
    assessed = parse_aivss_vector(vector)
    result = {
        name: {
            "rationale": f"Test evidence for {name}",
            "evidence_refs": [f"test://{name.lower()}"],
        }
        for name in AGENTIC_METRIC_ORDER
    }
    result["RH"].update(
        {
            "D": {
                "reachable_proxy": True,
                "isolation_verified": None,
                "verified_episodes": 4,
                "episodes_reviewed": 30,
                "locus": "environment",
            },
            "P": {
                "reachable_proxy": True,
                "isolation_verified": None,
                "verified_episodes": 0,
                "episodes_reviewed": 30,
                "locus": "environment",
            },
            "N": {
                "reachable_proxy": False,
                "isolation_verified": True,
                "verified_episodes": None,
                "episodes_reviewed": None,
                "locus": None,
            },
            "X": {
                "reachable_proxy": None,
                "isolation_verified": None,
                "verified_episodes": None,
                "episodes_reviewed": None,
                "locus": None,
            },
        }[assessed.rh]
    )
    return result


METRIC_EVIDENCE = metric_evidence(EXAMPLE_AI)


def profile(**overrides: str) -> AIProfile:
    values = {
        "lc": "N",
        "cp": "N",
        "ap": "N",
        "rh": "N",
        "es": "N",
    }
    values.update(overrides)
    return AIProfile(**values)


class TestMacroVectorTable:
    def test_has_270_equivalence_classes(self):
        assert len(_lookup_table()) == 270

    def test_joint_eq3_eq6_constraint(self):
        assert not [k for k in _lookup_table() if k[2] == "2" and k[5] == "0"]

    def test_scores_within_range(self):
        assert all(0.0 <= v <= 10.0 for v in _lookup_table().values())


class TestCvssBte:
    def test_interpolated_score_differs_from_macrovector_ceiling(self):
        metrics = parse_cvss_vector(EXAMPLE_VECTOR)
        assert score_cvss_bte(EXAMPLE_VECTOR) == EXAMPLE_CVSS_BTE
        assert macrovector_score(macrovector(metrics)) == 8.0


class TestAIEffectClass:
    def test_direct_cross_session_case(self):
        """Direct control plus cross-session persistence classifies as A2."""
        assert profile(lc="D", cp="C").effect_class() == "A2"

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"ap": "L"},
            {"lc": "D", "cp": "C"},
            {"lc": "I", "cp": "C"},
            {"lc": "D", "rh": "D"},
            {"lc": "I", "rh": "D"},
        ],
    )
    def test_a2_conditions(self, kwargs):
        assert profile(**kwargs).effect_class() == "A2"

    def test_es_does_not_change_effect_class(self):
        assert profile(lc="I", es="W").effect_class() == "A1"
        assert profile(es="W").effect_class() == "A0"
        assert profile(rh="P", es="W").effect_class() == "A0"

    @pytest.mark.parametrize(
        "kwargs",
        [{"lc": "I"}, {"lc": "D"}, {"cp": "S"}, {"cp": "C"}, {"ap": "C"}, {"rh": "D"}],
    )
    def test_a1_conditions(self, kwargs):
        assert profile(**kwargs).effect_class() == "A1"

    @pytest.mark.parametrize("kwargs", [{"lc": "M"}, {"rh": "P"}, {"lc": "M", "rh": "P"}])
    def test_lc_m_and_rh_possible_alone_do_not_trigger_a1(self, kwargs):
        assert profile(**kwargs).effect_class() == "A0"

    def test_ladder_is_first_match(self):
        """A2 is checked before A1, and both before AX."""
        assert profile(lc="D", cp="C", ap="C").effect_class() == "A2"
        assert profile(lc="I", ap="X").effect_class() == "A1"
        assert profile(ap="L", lc="X").effect_class() == "A2"

    def test_a0_only_when_all_benign(self):
        assert profile().effect_class() == "A0"

    def test_every_combination_yields_a_valid_class(self):
        for lc in "DIMN":
            for cp in "CSN":
                for ap in "LCN":
                    for rh in "DPN":
                        cls = profile(lc=lc, cp=cp, ap=ap, rh=rh).effect_class()
                        assert cls in ("A0", "A1", "A2")

    def test_class_is_monotone_in_each_metric(self):
        """Worsening any single metric must never lower the effect class."""
        order = {"A0": 0, "A1": 1, "A2": 2}
        scales = {"lc": "NMID", "cp": "NSC", "ap": "NCL", "rh": "NPD"}
        for name, scale in scales.items():
            for lc in "DIMN":
                for cp in "CSN":
                    for ap in "LCN":
                        for rh in "DPN":
                            base = {"lc": lc, "cp": cp, "ap": ap, "rh": rh}
                            for i in range(len(scale) - 1):
                                lo = dict(base, **{name: scale[i]})
                                hi = dict(base, **{name: scale[i + 1]})
                                assert (
                                    order[profile(**hi).effect_class()]
                                    >= order[profile(**lo).effect_class()]
                                )

    def test_illegal_value_rejected(self):
        with pytest.raises(ValueError, match="Illegal value"):
            profile(lc="Z")

    def test_unknown_classifying_metric_yields_ax(self):
        assert profile(lc="X").effect_class() == "AX"
        assert profile(lc="X").complete is False
        assert profile(lc="X").provisional is True

    def test_unknown_rh_is_provisional_and_ax_when_nothing_else_applies(self):
        """RH:X with no other agentic uplift is AX; with known uplift it stays put."""
        assert profile(rh="X").effect_class() == "AX"
        assert profile(rh="X").provisional is True
        assert profile(lc="D", rh="X").effect_class() == "A1"
        assert profile(lc="D", rh="X").provisional is True
        assert profile(es="X").provisional is False
        assert profile(es="X").complete is False


class TestLookupTables:
    def test_table_6_cells(self):
        assert TABLE_6 == {
            "None": {"A1": 0.0, "A2": 0.0},
            "Low": {"A1": 5.5, "A2": 7.1},
            "Medium": {"A1": 7.5, "A2": 8.9},
            "High": {"A1": 8.7, "A2": 9.5},
            "Critical": {"A1": 9.7, "A2": 10.0},
        }

    @pytest.mark.parametrize("cls", ["A0", "AX"])
    def test_a0_and_ax_keep_cvss_bte(self, cls):
        result = aivss_lookup(7.8, cls)
        assert result["aivss"] == 7.8
        assert result["table_cell"] is None
        assert result["rule"] == "cvss_bte_unchanged"

    def test_cell_applies_when_higher(self):
        result = aivss_lookup(5.7, "A1")
        assert result["aivss"] == 7.5
        assert result["aivss_band"] == "High"
        assert result["cvss_band"] == "Medium"
        assert result["rule"] == "cell"

    def test_cvss_bte_floor(self):
        """AIVSS is never lower than CVSS-BTE (A1 Critical cell 9.7 < 9.8)."""
        result = aivss_lookup(9.8, "A1")
        assert result["aivss"] == 9.8
        assert result["rule"] == "cvss_bte_floor"

    def test_never_below_cvss_bte_exhaustive(self):
        for tenth in range(101):
            cvss = tenth / 10
            for cls in ("A0", "A1", "A2", "AX"):
                value = aivss_lookup(cvss, cls)["aivss"]
                assert cvss <= value <= 10.0

    def test_uplift_table_5(self):
        assert UPLIFT_TABLE == {
            "A0": {"N": 0, "M": 1, "W": 2},
            "A1": {"N": 3, "M": 5, "W": 6},
            "A2_not_RH": {"N": 7, "M": 8, "W": 9},
            "A2_RH": {"N": 8, "M": 9, "W": 10},
        }
        assert profile(ap="L", rh="D", es="W").agentic_uplift_u() == 10
        assert profile(ap="L", rh="P", es="W").agentic_uplift_u() == 9
        assert profile(lc="X", es="M").agentic_uplift_u() == 1
        assert profile(es="X").agentic_uplift_u() is None

    def test_cvss_nomenclature(self):
        assert cvss_nomenclature(parse_cvss_vector(EXAMPLE_VECTOR)) == "CVSS-BT"
        base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        assert cvss_nomenclature(parse_cvss_vector(base)) == "CVSS-B"
        assert cvss_nomenclature(parse_cvss_vector(base + "/CR:H")) == "CVSS-BE"
        assert cvss_nomenclature(parse_cvss_vector(base + "/E:A/CR:H")) == "CVSS-BTE"


class TestRHClassification:
    def test_verified_episode_yields_demonstrated(self):
        assert (
            classify_rh(reachable_proxy=True, isolation_verified=None, verified_episodes=1)
            == "D"
        )

    def test_unreachable_and_verified_isolation_yields_none(self):
        assert (
            classify_rh(reachable_proxy=False, isolation_verified=True, verified_episodes=None)
            == "N"
        )

    def test_reachable_without_verified_episode_yields_possible(self):
        assert (
            classify_rh(reachable_proxy=True, isolation_verified=None, verified_episodes=0)
            == "P"
        )

    def test_absence_of_observed_hacking_never_yields_none(self):
        """Hacking rates vary with difficulty and prompting, so N needs isolation."""
        assert (
            classify_rh(reachable_proxy=True, isolation_verified=False, verified_episodes=0)
            == "P"
        )
        assert (
            classify_rh(reachable_proxy=None, isolation_verified=None, verified_episodes=0)
            == "X"
        )
        assert (
            classify_rh(reachable_proxy=False, isolation_verified=False, verified_episodes=0)
            == "X"
        )

    def test_unverified_unreachable_claim_is_unknown(self):
        assert (
            classify_rh(reachable_proxy=False, isolation_verified=None, verified_episodes=None)
            == "X"
        )

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"reachable_proxy": "yes", "isolation_verified": None, "verified_episodes": 0},
            {"reachable_proxy": True, "isolation_verified": 1, "verified_episodes": 0},
            {"reachable_proxy": True, "isolation_verified": None, "verified_episodes": -1},
            {"reachable_proxy": True, "isolation_verified": None, "verified_episodes": True},
        ],
    )
    def test_malformed_inputs_are_rejected(self, kwargs):
        with pytest.raises(ValueError):
            classify_rh(**kwargs)

    def test_evidence_must_support_the_vector_value(self):
        assessed = parse_aivss_vector(EXAMPLE_AI)
        evidence = metric_evidence(EXAMPLE_AI)
        validate_metric_evidence(assessed, evidence)
        evidence["RH"]["verified_episodes"] = 2
        evidence["RH"]["reachable_proxy"] = True
        evidence["RH"]["locus"] = "environment"
        with pytest.raises(ValueError, match="does not support"):
            validate_metric_evidence(assessed, evidence)

    def test_demonstrated_and_possible_evidence_must_name_a_locus(self):
        assessed = parse_aivss_vector(EXAMPLE_AI.replace("RH:N", "RH:D"))
        evidence = metric_evidence(EXAMPLE_AI.replace("RH:N", "RH:D"))
        evidence["RH"]["locus"] = None
        with pytest.raises(ValueError, match="locus"):
            validate_metric_evidence(assessed, evidence)

    def test_verified_episodes_cannot_exceed_reviewed(self):
        assessed = parse_aivss_vector(EXAMPLE_AI.replace("RH:N", "RH:D"))
        evidence = metric_evidence(EXAMPLE_AI.replace("RH:N", "RH:D"))
        evidence["RH"]["episodes_reviewed"] = 3
        with pytest.raises(ValueError, match="cannot exceed"):
            validate_metric_evidence(assessed, evidence)

    def test_retired_sr_metric_is_rejected_with_a_pointer_to_rh(self):
        with pytest.raises(ValueError, match="replaced by RH"):
            parse_aivss_vector("AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/ES:W")


class TestMetricPartitions:
    """Five metrics with closed value sets — every code must be assignable."""

    EXPECTED_COUNTS = {"LC": 5, "CP": 4, "AP": 4, "RH": 4, "ES": 4}

    def test_five_metrics_in_fixed_order(self):
        assert AGENTIC_METRIC_ORDER == ("LC", "CP", "AP", "RH", "ES")

    def test_classifying_and_uplift_partition_the_five(self):
        assert set(CLASSIFYING_AGENTIC_METRICS) | set(UPLIFT_AGENTIC_METRICS) == set(
            AGENTIC_METRIC_ORDER
        )
        assert set(CLASSIFYING_AGENTIC_METRICS).isdisjoint(UPLIFT_AGENTIC_METRICS)

    @pytest.mark.parametrize("name,count", list(EXPECTED_COUNTS.items()))
    def test_value_set_size(self, name, count):
        assert len(AGENTIC_METRICS[name]) == count

    def test_every_es_value_parses_in_profile(self):
        for es in AGENTIC_METRICS["ES"]:
            assert profile(es=es).complete == (es != "X")


class TestVectorParsing:
    def test_round_trip(self):
        cvss, parsed = split_ai_vector(EXAMPLE_FULL)
        assert cvss == EXAMPLE_VECTOR
        assert parsed is not None
        assert parsed.to_vector() == EXAMPLE_AI

    def test_no_ai_group_returns_none(self):
        cvss, parsed = split_ai_vector(EXAMPLE_VECTOR)
        assert cvss == EXAMPLE_VECTOR
        assert parsed is None

    def test_partial_ai_group_rejected(self):
        with pytest.raises(ValueError, match="missing"):
            parse_aivss_vector("AIVSS:1.0/LC:D/CP:C")

    def test_legacy_vector_rejected_with_migration_hint(self):
        with pytest.raises(ValueError, match="migrate-vector"):
            parse_aivss_vector("AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H")

    def test_legacy_vector_conversion(self):
        result = convert_legacy_vector("AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H")
        assert result["aivss_vector"] == EXAMPLE_AI.replace("RH:N", "RH:X")
        assert "agent_untraceability" not in result
        assert result["dropped"] == {"SR": "R", "PT": "H", "CA": "M", "TD": "H"}

    @pytest.mark.parametrize("key", ["EQ", "U"])
    def test_derived_results_are_not_vector_metrics(self, key):
        with pytest.raises(ValueError, match="derived result"):
            parse_aivss_vector(f"{EXAMPLE_AI}/{key}:2")

    def test_appended_ai_metrics_are_rejected(self):
        with pytest.raises(ValueError, match="separate"):
            split_ai_vector(f"{EXAMPLE_VECTOR}/LC:D/CP:C/AP:L/RH:N")

    def test_duplicate_ai_metric_rejected(self):
        with pytest.raises(ValueError, match="Duplicate AIVSS metric"):
            parse_aivss_vector("AIVSS:1.0/LC:D/LC:I/CP:C/AP:L/RH:N/ES:W")

    def test_wrong_extension_version_rejected(self):
        with pytest.raises(ValueError, match="must begin"):
            parse_aivss_vector(EXAMPLE_AI.replace("AIVSS:1.0", "AIVSS:2.0"))

    @pytest.mark.parametrize(
        "vector,match",
        [
            ("CVSS:3.1/AV:N", "must begin with"),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/ZZ:Q",
                "Unknown",
            ),
            (
                "CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "Illegal value",
            ),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N",
                "Missing mandatory",
            ),
            (
                "CVSS:4.0/AV:N/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "Duplicate",
            ),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA",
                "Malformed",
            ),
            (
                "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "order",
            ),
        ],
    )
    def test_malformed_vectors_rejected(self, vector, match):
        with pytest.raises(ValueError, match=match):
            parse_cvss_vector(vector)

    def test_modified_metrics_override_base(self):
        base = "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        assert macrovector(parse_cvss_vector(base))[0] == "2"
        assert macrovector(parse_cvss_vector(base + "/MAV:N"))[0] == "0"

    def test_exploit_maturity_defaults_to_worst_case(self):
        base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        assert macrovector(parse_cvss_vector(base))[4] == "0"
        assert macrovector(parse_cvss_vector(base + "/E:U"))[4] == "2"


class TestBOD2604:
    def test_all_sixteen_official_rows_match(self):
        expected = {
            (False, False, False, "partial"): "FSU",
            (True, False, False, "partial"): "14D",
            (False, True, False, "partial"): "60D",
            (False, False, True, "partial"): "60D",
            (False, False, False, "total"): "FSU",
            (True, True, False, "partial"): "14D",
            (True, False, True, "partial"): "14D",
            (False, True, True, "partial"): "14D",
            (True, False, False, "total"): "14D",
            (False, True, False, "total"): "14D",
            (False, False, True, "total"): "60D",
            (True, True, True, "partial"): "3D",
            (True, True, False, "total"): "3DF",
            (True, False, True, "total"): "3DF",
            (False, True, True, "total"): "3D",
            (True, True, True, "total"): "3DF",
        }
        assert BOD_2604_TABLE == expected

    def test_kev_plus_total_without_exposure_or_automation_is_14_days(self):
        """Regression: the fast tier needs exposure or automatability, not just
        KEV plus total impact. Hand-written boolean logic gets this wrong."""
        assert (
            bod_timeline(
                in_kev=True,
                publicly_exposed=False,
                automatable=False,
                technical_impact="total",
            )
            == "14D"
        )

    @pytest.mark.parametrize(
        "args,expected",
        [
            ((False, False, False, "partial"), "FSU"),
            ((False, False, False, "total"), "FSU"),
            ((True, True, True, "total"), "3DF"),
            ((True, True, False, "total"), "3DF"),
            ((True, False, True, "total"), "3DF"),
            ((False, True, True, "total"), "3D"),
            ((True, True, True, "partial"), "3D"),
            ((False, False, True, "total"), "60D"),
            ((False, True, False, "partial"), "60D"),
        ],
    )
    def test_table_rows(self, args, expected):
        kev, exposed, auto, impact = args
        assert (
            bod_timeline(
                in_kev=kev,
                publicly_exposed=exposed,
                automatable=auto,
                technical_impact=impact,
            )
            == expected
        )

    def test_invalid_technical_impact_rejected(self):
        with pytest.raises(ValueError, match="partial.*total"):
            bod_timeline(
                in_kev=False,
                publicly_exposed=False,
                automatable=False,
                technical_impact="high",
            )

    def test_non_boolean_decision_point_rejected(self):
        with pytest.raises(ValueError, match="in_kev must be true or false"):
            bod_timeline(
                in_kev="no",
                publicly_exposed=False,
                automatable=False,
                technical_impact="partial",
            )

    def test_escalation_only_for_a2(self):
        for cls in ("A0", "A1"):
            assert escalate("60D", cls) == "60D"
        assert escalate("60D", "A2") == "14D"

    def test_escalation_never_adds_forensic_triage(self):
        """Forensic triage is a CISA determination; AIVSS must not impose it."""
        for timeline in TIMELINE_URGENCY:
            assert escalate(timeline, "A2") != "3DF" or timeline == "3DF"
        assert escalate("3D", "A2") == "3D"
        assert escalate("3DF", "A2") == "3DF"

    def test_escalation_advances_exactly_one_tier(self):
        assert escalate("FSU", "A2") == "60D"
        assert escalate("14D", "A2") == "3D"

    def test_only_a2_escalates_timeline(self):
        """Only A2 escalates the recommended timeline."""
        assert advance_timeline("60D", 1) == "14D"
        result = decide(
            evidence=ExploitationEvidence(),
            publicly_exposed=False,
            **DECISION_CONTEXT,
            agentic_effect_class="A0",
            automatable=False,
            technical_impact="partial",
        )
        assert result["bod_2604_analogy_timeline"] == "FSU"
        assert result["aivss_recommended_timeline"] == "FSU"
        assert result["overlay_triggered"] is False
        assert result["escalated"] is False

    def test_a2_escalates_timeline_one_tier(self):
        result = decide(
            evidence=ExploitationEvidence(),
            publicly_exposed=False,
            **DECISION_CONTEXT,
            agentic_effect_class="A2",
            automatable=False,
            technical_impact="partial",
        )
        assert result["bod_2604_analogy_timeline"] == "FSU"
        assert result["aivss_recommended_timeline"] == "60D"
        assert result["overlay_triggered"] is True
        assert result["escalated"] is True

    def test_forensic_triage_is_never_removed(self):
        result = decide(
            evidence=ExploitationEvidence(cisa_kev=True),
            cve_id="CVE-2026-12345",
            fceb_bod_2604_scope=True,
            publicly_exposed=True,
            **DECISION_CONTEXT,
            vulnrichment_automatable=True,
            vulnrichment_technical_impact="total",
            agentic_effect_class="A2",
        )
        assert result["bod_2604_timeline"] == "3DF"
        assert result["aivss_recommended_timeline"] == "3DF"
        assert result["forensic_triage_required"] is True
        assert result["aivss_recommended_forensic_triage_indicated"] is True

    def test_ax_overlay_is_provisional_and_never_escalates(self):
        result = decide(
            evidence=ExploitationEvidence(),
            publicly_exposed=True,
            **DECISION_CONTEXT,
            agentic_effect_class="AX",
            automatable=True,
            technical_impact="partial",
        )
        assert result["overlay_status"] == "provisional"
        assert result["overlay_triggered"] is False
        assert result["aivss_recommended_timeline"] == result["bod_2604_analogy_timeline"]


class TestEvidenceLadder:
    def test_kev_outranks_everything(self):
        result = ExploitationEvidence(
            cisa_kev=True, epss=0.01, epss_date="2026-08-27", poc=True
        ).resolve()
        assert result["rung"] == "cisa_kev"
        assert result["authoritative"] is True

    def test_precedence_order(self):
        assert ExploitationEvidence(vulnrichment_active=True, poc=True).resolve()[
            "rung"
        ] == ("vulnrichment_active")
        assert ExploitationEvidence(observed_local=True, poc=True).resolve()[
            "rung"
        ] == ("observed_local")
        assert ExploitationEvidence(poc=True).resolve()["rung"] == "poc"
        assert ExploitationEvidence().resolve()["rung"] == "none"

    def test_epss_does_not_determine_exploitation_state(self):
        result = ExploitationEvidence(epss=0.99, epss_date="2026-08-27").resolve()
        assert result["rung"] == "none"
        assert result["epss"] == 0.99

    def test_observed_local_outranks_epss(self):
        result = ExploitationEvidence(
            epss=0.99, epss_date="2026-08-27", observed_local=True
        ).resolve()
        assert result["rung"] == "observed_local"

    def test_locally_observed_is_not_authoritative(self):
        assert (
            ExploitationEvidence(observed_local=True).resolve()["authoritative"]
            is False
        )

    def test_epss_requires_an_observation_date(self):
        with pytest.raises(ValueError, match="epss_date is required"):
            ExploitationEvidence(epss=0.42)

    def test_epss_used_as_published(self):
        """No transform: the raw probability is carried through unchanged."""
        assert (
            ExploitationEvidence(epss=0.42, epss_date="2026-08-27").resolve()["epss"]
            == 0.42
        )

    def test_epss_range_validated(self):
        with pytest.raises(ValueError, match=r"\[0.0, 1.0\]"):
            ExploitationEvidence(epss=1.5, epss_date="2026-08-27")

    def test_epss_date_is_strict_iso_date(self):
        with pytest.raises(ValueError, match="YYYY-MM-DD"):
            ExploitationEvidence(epss=0.42, epss_date="20260827")

    def test_evidence_flags_are_strict_booleans(self):
        with pytest.raises(ValueError, match="cisa_kev must be true, false, or omitted"):
            ExploitationEvidence(cisa_kev="yes")

    def test_non_cve_requires_explicit_analogy_inputs(self):
        with pytest.raises(ValueError, match="automatable is required"):
            decide(
                evidence=ExploitationEvidence(),
                publicly_exposed=True,
                **DECISION_CONTEXT,
                agentic_effect_class="A0",
            )

    def test_cve_missing_metadata_uses_automatable_no_and_total_impact(self):
        """Non-KEV CVE with no published values: Automatable no, Technical Impact
        total, so an exposed asset resolves to 14D."""
        result = decide(
            evidence=ExploitationEvidence(cisa_kev=False),
            publicly_exposed=True,
            **DECISION_CONTEXT,
            agentic_effect_class="A0",
            cve_id="CVE-2024-0001",
        )
        assert result["missing_metadata_faq_applied"] is True
        assert result["decision_points"]["automatable_source"] == (
            "CISA BOD 26-04 FAQ (missing metadata)"
        )
        assert result["decision_points"]["technical_impact_source"] == (
            "CISA BOD 26-04 FAQ (missing metadata)"
        )
        assert result["decision_points"]["automatable"] is False
        assert result["decision_points"]["technical_impact"] == "total"
        assert result["bod_2604_guidance_timeline"] == "14D"
        assert result["compliance_applicable"] is False
        assert result["decision_basis"] == "informative_bod_26_04_cve_guidance"

    def test_cve_missing_metadata_not_exposed_is_fsu(self):
        result = decide(
            evidence=ExploitationEvidence(cisa_kev=False),
            publicly_exposed=False,
            **DECISION_CONTEXT,
            agentic_effect_class="A0",
            cve_id="CVE-2024-0001",
        )
        assert result["bod_2604_guidance_timeline"] == "FSU"
        assert result["missing_metadata_faq_applied"] is True

    def test_cve_missing_metadata_with_fceb_scope(self):
        result = decide(
            evidence=ExploitationEvidence(cisa_kev=False),
            publicly_exposed=True,
            **DECISION_CONTEXT,
            agentic_effect_class="A0",
            cve_id="CVE-2024-0001",
            fceb_bod_2604_scope=True,
        )
        assert result["bod_2604_timeline"] == "14D"
        assert result["missing_metadata_faq_applied"] is True

    def test_kev_requires_published_metadata_instead_of_defaults(self):
        with pytest.raises(ValueError, match="require CISA Vulnrichment"):
            decide(
                evidence=ExploitationEvidence(cisa_kev=True),
                publicly_exposed=True,
                **DECISION_CONTEXT,
                cve_id="CVE-2026-12345",
            )

    def test_non_cve_result_is_never_labelled_compliance(self):
        result = decide(
            evidence=ExploitationEvidence(),
            publicly_exposed=False,
            **DECISION_CONTEXT,
            automatable=False,
            technical_impact="partial",
        )
        assert result["decision_basis"] == "informative_bod_26_04_analogy"
        assert result["compliance_applicable"] is False
        assert "bod_2604_timeline" not in result

    def test_unmodified_bod_timeline_always_reported(self):
        result = decide(
            evidence=ExploitationEvidence(cisa_kev=True),
            cve_id="CVE-2026-12345",
            fceb_bod_2604_scope=True,
            publicly_exposed=False,
            **DECISION_CONTEXT,
            agentic_effect_class="A2",
            vulnrichment_automatable=False,
            vulnrichment_technical_impact="partial",
        )
        assert result["bod_2604_timeline"] == "14D"
        assert result["aivss_recommended_timeline"] == "3D"
        assert result["escalated"] is True


class TestTaxonomy:
    def test_ten_asi_categories(self):
        assert len(ASI_TOP_10) == 10
        assert list(ASI_TOP_10) == [f"ASI{i:02d}" for i in range(1, 11)]

    def test_v08_crosswalk_resolves(self):
        assert normalize_asi("Agentic AI Tool Misuse") == "ASI02"
        assert normalize_asi("asi06") == "ASI06"

    def test_untraceability_has_no_asi_successor(self):
        with pytest.raises(ValueError, match="outside AIVSS 1.0"):
            normalize_asi("Agent Untraceability")

    def test_every_crosswalk_target_is_valid(self):
        for target in V08_CATEGORY_CROSSWALK.values():
            assert target is None or target in ASI_TOP_10

    def test_unknown_category_rejected(self):
        with pytest.raises(ValueError, match="Unknown risk category"):
            normalize_asi("Not A Category")


MEDIUM_CONTEXT = {"business_criticality": "medium", "reach": "medium", "likelihood": 0.5}


class TestPriority:
    def test_geometric_mean(self):
        result = compute_priority(
            severity=8.0, business_criticality="high", reach="high", likelihood=0.72
        )
        assert result["aivss_p"] == 87

    def test_zero_likelihood_yields_zero(self):
        context = {**MEDIUM_CONTEXT, "likelihood": 0.0}
        assert compute_priority(severity=10.0, **context)["aivss_p"] == 0

    def test_maximum_reaches_100(self):
        assert (
            compute_priority(
                severity=10.0, business_criticality="high", reach="high", likelihood=1.0
            )["aivss_p"]
            == 100
        )

    def test_critical_severity_with_median_context_is_not_backlogged(self):
        """The withdrawn Track P returned 'Track' here, which was indefensible."""
        result = compute_priority(severity=9.5, **MEDIUM_CONTEXT)
        assert result["band"] != "Backlog"

    def test_monotone_in_every_term(self):
        base = compute_priority(severity=5.0, **MEDIUM_CONTEXT)["aivss_p"]
        assert compute_priority(severity=6.0, **MEDIUM_CONTEXT)["aivss_p"] > base
        higher_likelihood = {**MEDIUM_CONTEXT, "likelihood": 0.6}
        assert compute_priority(severity=5.0, **higher_likelihood)["aivss_p"] > base
        high_criticality = {**MEDIUM_CONTEXT, "business_criticality": "high"}
        assert compute_priority(severity=5.0, **high_criticality)["aivss_p"] > base
        high_reach = {**MEDIUM_CONTEXT, "reach": "high"}
        assert compute_priority(severity=5.0, **high_reach)["aivss_p"] > base

    def test_invalid_inputs_rejected(self):
        with pytest.raises(ValueError):
            compute_priority(severity=11.0, **MEDIUM_CONTEXT)
        with pytest.raises(ValueError):
            compute_priority(severity=5.0, **{**MEDIUM_CONTEXT, "likelihood": 2.0})
        with pytest.raises(ValueError, match="business_criticality"):
            compute_priority(
                severity=5.0, **{**MEDIUM_CONTEXT, "business_criticality": "critical"}
            )

    @pytest.mark.parametrize("missing", sorted(MEDIUM_CONTEXT))
    def test_unknown_context_is_not_defaulted(self, missing):
        """Unknown organizational inputs must be recorded, never filled in (Section 16)."""
        context = {k: v for k, v in MEDIUM_CONTEXT.items() if k != missing}
        with pytest.raises(TypeError, match=missing):
            compute_priority(severity=5.0, **context)
        with pytest.raises(TypeError, match=missing):
            OrgContext(**context)


class TestLegacyAnnexB:
    ALL_FACTORS = {
        name: 0.5
        for name in (
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
    }

    def test_floor_guarantee_exhaustive(self):
        """AIVSS_S >= CVSS_Base for every combination, including after rounding."""
        for c in range(0, 101):
            cvss = c / 10
            for fs in (0.0, 0.1, 0.35, 0.5, 0.85, 1.0):
                for thm in (0.50, 0.97, 1.00):
                    for mf in (1.0, 0.83, 0.67, 0.50):
                        aars = (10.0 - cvss) * fs * thm
                        score = compute_severity(cvss, aars, mf)
                        assert cvss <= score <= 10.0

    def test_v08_defect_is_repaired(self):
        result = score_legacy(
            cvss_base=9.0,
            factors={**self.ALL_FACTORS, **{k: 0.0 for k in self.ALL_FACTORS}},
            threat_maturity="poc",
            mitigation_inherent="strong",
        )
        assert result["v08_unrepaired"] < result["cvss_base"]
        assert result["aivss_s_inherent"] >= result["cvss_base"]

    def test_missing_factor_is_an_error(self):
        with pytest.raises(ValueError, match="Missing amplification factor"):
            factor_mean({"autonomy": 1.0})

    def test_unknown_factor_is_an_error(self):
        with pytest.raises(ValueError, match="Unknown amplification factor"):
            factor_mean({**self.ALL_FACTORS, "bogus": 1.0})

    def test_non_rubric_value_is_an_error(self):
        with pytest.raises(ValueError, match="must be 0.0, 0.5, or 1.0"):
            factor_mean({**self.ALL_FACTORS, "autonomy": 0.65})

    def test_unknown_enum_values_are_errors(self):
        with pytest.raises(ValueError, match="Unknown threat maturity"):
            score_legacy(
                cvss_base=5.0, factors=self.ALL_FACTORS, threat_maturity="typo"
            )
        with pytest.raises(ValueError, match="Unknown mitigation strength"):
            score_legacy(
                cvss_base=5.0, factors=self.ALL_FACTORS, mitigation_inherent="storng"
            )

    def test_cvss_base_precision_validated(self):
        with pytest.raises(ValueError, match="one decimal place"):
            score_legacy(cvss_base=6.14, factors=self.ALL_FACTORS)

    def test_no_category_weights(self):
        """The uncalibrated category weight table is withdrawn."""
        import aivss_calc.legacy as legacy

        assert not hasattr(legacy, "OWASP_CATEGORIES")

    def test_cvss_sensitivity_is_reported(self):
        result = score_legacy(
            cvss_base=6.1,
            factors={k: 1.0 for k in self.ALL_FACTORS},
            threat_maturity="poc",
        )
        assert result["cvss_sensitivity"] == pytest.approx(0.03, abs=0.001)


class TestEndToEnd:
    def _assessment(self, **overrides):
        defaults = dict(
            finding_id="AIVSS-EX-001",
            path_id="AIVSS-EX-001-PATH-1",
            cvss_vector=EXAMPLE_VECTOR,
            aivss_vector=EXAMPLE_AI,
            asi_category="ASI06",
            agentic_applicability=dict(APPLICABILITY),
            metric_evidence=dict(METRIC_EVIDENCE),
            evidence=ExploitationEvidence(poc=True),
            publicly_exposed=True,
            publicly_exposed_source="test fixture",
            decision_data_observed_at="2026-08-27T00:00:00Z",
            automatable=True,
            technical_impact="total",
            org_context=OrgContext(
                business_criticality="high", reach="high", likelihood=0.72
            ),
            include_priority=True,
            provenance=Provenance(
                assessor="test",
                tool="aivss-calc",
                tool_version="1.0.0",
                assessed_at="2026-08-27T00:00:00Z",
            ),
        )
        if "aivss_vector" in overrides and "metric_evidence" not in overrides:
            overrides["metric_evidence"] = metric_evidence(overrides["aivss_vector"])
        defaults.update(overrides)
        return assess(Assessment(**defaults))

    def test_aivss_is_read_from_table_6(self):
        report = self._assessment()
        assert report["cvss"]["cvss_bte"] == EXAMPLE_CVSS_BTE
        scores = report["scores"]
        assert scores["cvss_bte"] == EXAMPLE_CVSS_BTE
        assert scores["cvss_nomenclature"] == "CVSS-BT"
        assert scores["cvss_band"] == "High"
        assert scores["agentic_effect_class"] == "A2"
        assert scores["table_cell"] == EXAMPLE_AIVSS
        assert scores["aivss"] == EXAMPLE_AIVSS
        assert scores["aivss_band"] == "Critical"
        assert scores["rule"] == "cell"
        assert scores["agentic_uplift_u"] == 9
        assert scores["provisional"] is False
        assert scores["status"] == "normative"

    def test_vectors_are_separate(self):
        report = self._assessment()
        assert report["cvss"]["vector"] == EXAMPLE_VECTOR
        assert report["agentic_ai_profile"]["vector"] == EXAMPLE_AI
        assert "vector" not in report

    def test_a0_is_value_based_not_presence_based(self):
        benign = "AIVSS:1.0/LC:N/CP:N/AP:N/RH:N/ES:W"
        report = self._assessment(aivss_vector=benign)
        assert report["agentic_ai_profile"]["agentic_effect_class"] == "A0"
        assert report["scores"]["aivss"] == EXAMPLE_CVSS_BTE
        assert report["scores"]["rule"] == "cvss_bte_unchanged"
        assert report["scores"]["agentic_uplift_u"] == 2

    def test_rh_demonstrated_with_direct_language_control_is_a2(self):
        report = self._assessment(aivss_vector="AIVSS:1.0/LC:D/CP:N/AP:N/RH:D/ES:W")
        assert report["agentic_ai_profile"]["agentic_effect_class"] == "A2"
        assert report["scores"]["agentic_uplift_u"] == 10
        validate_report(report)

    def test_rh_demonstrated_alone_is_a1_without_attacker_input(self):
        report = self._assessment(aivss_vector="AIVSS:1.0/LC:N/CP:N/AP:N/RH:D/ES:M")
        assert report["agentic_ai_profile"]["agentic_effect_class"] == "A1"
        assert report["scores"]["agentic_uplift_u"] == 5
        validate_report(report)

    def test_rh_has_no_agreement_rule_with_cvss_attack_requirements(self):
        for at in ("N", "P"):
            report = self._assessment(
                cvss_vector=EXAMPLE_VECTOR.replace("/AT:N/", f"/AT:{at}/"),
                aivss_vector="AIVSS:1.0/LC:D/CP:C/AP:L/RH:P/ES:W",
            )
            assert report["agentic_ai_profile"]["agentic_effect_class"] == "A2"
            assert report["scores"]["agentic_uplift_u"] == 9

    def test_assess_without_profile_rejected(self):
        with pytest.raises(ValueError, match="Conformance Level 1 requires"):
            assess(
                Assessment(
                    finding_id="x",
                    path_id="x-path",
                    cvss_vector=EXAMPLE_VECTOR,
                    asi_category="ASI06",
                    agentic_applicability=dict(APPLICABILITY),
                    include_decision=False,
                    provenance=Provenance(assessed_at="2026-08-27T00:00:00Z"),
                )
            )

    def test_assess_resolves_exploit_maturity_from_evidence(self):
        report = assess(
            Assessment(
                finding_id="x",
                path_id="x-path",
                cvss_vector="CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:U",
                aivss_vector=EXAMPLE_AI,
                asi_category="ASI06",
                agentic_applicability=dict(APPLICABILITY),
                metric_evidence=dict(METRIC_EVIDENCE),
                evidence=ExploitationEvidence(poc=True),
                include_decision=False,
                provenance=Provenance(assessed_at="2026-08-27T00:00:00Z"),
            )
        )
        assert report["cvss"]["exploit_maturity"]["e"] == "P"
        assert report["cvss"]["vector"].endswith("/E:P")
        assert report["cvss"]["exploit_maturity"]["rung"] == "poc"

    def test_assess_observed_local_sets_e_attacked(self):
        report = assess(
            Assessment(
                finding_id="x",
                path_id="x-path",
                cvss_vector=EXAMPLE_VECTOR,
                aivss_vector=EXAMPLE_AI,
                asi_category="ASI06",
                agentic_applicability=dict(APPLICABILITY),
                metric_evidence=dict(METRIC_EVIDENCE),
                evidence=ExploitationEvidence(observed_local=True),
                include_decision=False,
                provenance=Provenance(assessed_at="2026-08-27T00:00:00Z"),
            )
        )
        assert report["cvss"]["exploit_maturity"]["e"] == "A"
        assert "/E:A" in report["cvss"]["vector"]

    def test_maestro_extended_taxonomy(self):
        report = assess(
            Assessment(
                finding_id="maestro-1",
                path_id="maestro-1-path",
                cvss_vector=EXAMPLE_VECTOR,
                aivss_vector=EXAMPLE_AI,
                asi_category="MAESTRO-EXTENDED",
                taxonomy_metadata={
                    "maestro_layer": "Agent Frameworks",
                    "threat_description": "Planner bypasses tool allowlist via hidden capability.",
                    "nearest_asi": "ASI02",
                },
                agentic_applicability=dict(APPLICABILITY),
                metric_evidence=dict(METRIC_EVIDENCE),
                evidence=ExploitationEvidence(poc=True),
                include_decision=False,
                provenance=Provenance(assessed_at="2026-08-27T00:00:00Z"),
            )
        )
        assert report["risk_category"]["id"] == "MAESTRO-EXTENDED"
        assert report["risk_category"]["scheme"] == "MAESTRO-extended"
        assert report["risk_category"]["maestro_layer"] == "Agent Frameworks"
        assert report["risk_category"]["nearest_asi"] == "ASI02"
        validate_report(report)

    def test_priority_omitted_when_not_requested(self):
        assert "priority" not in self._assessment(include_priority=False)

    def test_decision_treats_unknown_publicly_exposed_as_internal(self):
        report = assess(
            Assessment(
                finding_id="x",
                path_id="x-path",
                cvss_vector=EXAMPLE_VECTOR,
                aivss_vector=EXAMPLE_AI,
                asi_category="ASI06",
                agentic_applicability=dict(APPLICABILITY),
                metric_evidence=dict(METRIC_EVIDENCE),
                include_decision=True,
                automatable=False,
                technical_impact="partial",
                decision_data_observed_at="2026-08-27T00:00:00Z",
                provenance=Provenance(assessed_at="2026-08-27T00:00:00Z"),
            )
        )
        assert report["decision"]["decision_points"]["publicly_exposed"] is False
        assert "Unknown exposure treated as internal" in report["decision"][
            "decision_points"
        ]["publicly_exposed_source"]

    def test_report_validates_against_schema(self):
        validate_report(self._assessment())

    def test_shipped_example_validates_against_schema(self):
        example = pathlib.Path(__file__).parents[1] / "examples" / "asi06-example.json"
        data = json.loads(example.read_text(encoding="utf-8"))
        validate_assessment_input(data)
        report = assess(assessment_from_payload(data))
        validate_report(report)
        assert report["scores"]["cvss_bte"] == EXAMPLE_CVSS_BTE
        assert report["scores"]["aivss"] == EXAMPLE_AIVSS


from aivss_calc.api import profile_report  # noqa: E402


class TestReviewRevision:
    """Behavior added in calculator 1.2.0 (review revision of the specification)."""

    def test_official_asi_names(self):
        assert ASI_TOP_10 == {
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

    def test_ten_core_risks_resolve_under_published_names(self):
        published = {
            "Agentic AI Tool Misuse": "ASI02",
            "Agent Access Control Violation": "ASI03",
            "Agent Cascading Failures": "ASI08",
            "Agent Orchestration & Multi-Agent Exploitation": "ASI07",
            "Agent Identity Impersonation": "ASI03",
            "Agent Memory & Context Manipulation": "ASI06",
            "Insecure Agent Critical Systems Interaction": "ASI05",
            "Agent Supply Chain & Dependency Risk": "ASI04",
            "Agent Goal & Instruction Manipulation": "ASI01",
        }
        for name, asi in published.items():
            assert normalize_asi(name) == asi
        assert V08_CATEGORY_CROSSWALK["Agent Untraceability"] is None

    def test_effect_class_range_without_unknowns_is_exact(self):
        p = profile(lc="D", cp="C", ap="N", rh="D", es="M")
        assert p.effect_class_range() == (p.effect_class(), p.effect_class())

    def test_effect_class_range_with_unknown_rh(self):
        p = profile(lc="D", cp="N", ap="N", rh="X", es="M")
        assert p.effect_class() == "A1"
        assert p.effect_class_range() == ("A1", "A2")

    def test_effect_class_range_all_unknown(self):
        p = profile(lc="X", cp="X", ap="X", rh="X", es="X")
        assert p.effect_class() == "AX"
        assert p.effect_class_range() == ("A0", "A2")

    def test_profile_report_publishes_cvss_score_and_range(self):
        result = profile_report(
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:N/E:U",
            profile(lc="I", cp="N", ap="N", rh="P", es="M"),
        )
        assert result["cvss_score"] == result["cvss_bte"] == 6.4
        assert result["agentic_effect_class"] == "A1"
        assert result["aivss"] == 7.5
        assert result["aivss_min"] == result["aivss_max"] == 7.5

    def test_profile_report_publishes_uncertain_range(self):
        result = profile_report(
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:N/E:U",
            profile(lc="D", cp="N", ap="N", rh="X", es="M"),
        )
        assert result["agentic_effect_class"] == "A1"
        assert result["agentic_effect_class_min"] == "A1"
        assert result["agentic_effect_class_max"] == "A2"
        assert result["aivss_min"] == 7.5
        assert result["aivss_max"] == 8.9
