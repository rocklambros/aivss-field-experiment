#!/usr/bin/env python3
"""Generate inputs and summaries from the single canonical scenario catalog."""

from __future__ import annotations

import json
from pathlib import Path

from aivss_calc import __version__, assess, assessment_from_payload
from aivss_calc.scenarios import SCENARIOS, scenario_payload
from aivss_calc.validation import validate_assessment_input, validate_report

EXAMPLES = Path(__file__).parent


def main() -> None:
    results = []
    for scenario in SCENARIOS:
        payload = scenario_payload(scenario["risk_category"], tool_version=__version__)
        validate_assessment_input(payload)
        path = EXAMPLES / f"{scenario['risk_category'].lower()}-example.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

        report = assess(assessment_from_payload(payload))
        validate_report(report)
        if scenario["risk_category"] == "ASI06":
            report_path = EXAMPLES / "asi06-report.json"
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        decision = report["decision"]
        results.append(
            {
                "asi": scenario["risk_category"],
                "name": report["risk_category"]["name"],
                "title": scenario["title"],
                "cvss_vector": report["cvss"]["vector"],
                "aivss_vector": report["agentic_ai_profile"]["vector"],
                "cvss_score": report["scores"]["cvss_score"],
                "cvss_bte": report["scores"]["cvss_bte"],
                "cvss_nomenclature": report["scores"]["cvss_nomenclature"],
                "aivss": report["scores"]["aivss"],
                "aivss_band": report["scores"]["aivss_band"],
                "agentic_uplift_u": report["scores"]["agentic_uplift_u"],
                "status": report["scores"]["status"],
                "agentic_effect_class": report["agentic_ai_profile"][
                    "agentic_effect_class"
                ],
                "agentic_effect_class_status": report["agentic_ai_profile"][
                    "agentic_effect_class_status"
                ],
                "decision_basis": decision["decision_basis"],
                "ssvc_decision_table": decision.get("ssvc", {}).get("decision_table"),
                "bod_timeline": decision.get("bod_2604_analogy_timeline")
                or decision.get("bod_2604_guidance_timeline")
                or decision.get("bod_2604_timeline"),
                "analogy_timeline": decision.get("bod_2604_analogy_label"),
                "experimental_overlay_status": decision["overlay_status"],
                "experimental_aivss_timeline": decision["aivss_recommended_label"],
                "overlay_triggered": decision.get("overlay_triggered"),
            }
        )

    summary_path = EXAMPLES / "asi-top10-summary.json"
    summary_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
