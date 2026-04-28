from __future__ import annotations

import json
import unittest
from pathlib import Path

from hybrid_siem.calibration import calibrate_rule_thresholds_from_normal
from hybrid_siem.evaluation import generate_evaluation_bundle
from hybrid_siem.scenarios import build_scenario_feature_sets


class TestCalibrationEvaluation(unittest.TestCase):
    def setUp(self) -> None:
        self.output_dir = Path(__file__).resolve().parent.parent / "data" / "generated" / "evaluation_test"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def test_threshold_calibration_returns_ordered_thresholds(self) -> None:
        scenarios = dict(build_scenario_feature_sets())
        normal_records = scenarios[next(definition for definition in scenarios if definition.name == "normal_typo")]

        # Duplicate a few normal records to make percentile statistics less brittle.
        expanded_normal_records = normal_records * 12
        report = calibrate_rule_thresholds_from_normal(expanded_normal_records, source_label="normal_typo_baseline")

        thresholds = report.thresholds
        self.assertLessEqual(thresholds.failed_count_low, thresholds.failed_count_medium)
        self.assertLessEqual(thresholds.failed_count_medium, thresholds.failed_count_high)
        self.assertLessEqual(thresholds.request_rate_low, thresholds.request_rate_medium)
        self.assertLessEqual(thresholds.request_rate_medium, thresholds.request_rate_high)
        self.assertGreaterEqual(thresholds.inter_arrival_fast_low, thresholds.inter_arrival_fast_medium)
        self.assertGreaterEqual(thresholds.inter_arrival_fast_medium, thresholds.inter_arrival_fast_high)

    def test_evaluation_bundle_writes_report_and_thresholds(self) -> None:
        feature_sets = build_scenario_feature_sets()
        normal_records = []
        attack_records = []
        for definition, records in feature_sets:
            if definition.name == "normal_typo":
                normal_records.extend(records * 12)
            else:
                attack_records.extend(records)

        summary, artifacts = generate_evaluation_bundle(
            normal_records=normal_records,
            attack_records=attack_records,
            output_dir=self.output_dir,
            normal_label="normal_scenarios",
            attack_label="attack_scenarios",
            histogram_bins=5,
        )

        self.assertTrue(artifacts.report_path.exists())
        self.assertTrue(artifacts.thresholds_path.exists())
        self.assertTrue(artifacts.summary_path.exists())
        self.assertGreaterEqual(len(artifacts.trace_paths), 4)
        self.assertGreater(len(summary.scenarios), 0)

        with artifacts.thresholds_path.open("r", encoding="utf-8") as handle:
            threshold_payload = json.load(handle)
        self.assertIn("thresholds", threshold_payload)
        self.assertIn("failed_count_low", threshold_payload["thresholds"])
        self.assertFalse(any("Slow brute force never reached medium risk." == issue for issue in summary.weaknesses))

        scenario_by_name = {scenario.definition.name: scenario for scenario in summary.scenarios}
        slow_track = [
            decision.risk_score
            for decision in scenario_by_name["slow_bruteforce"].decisions
            if decision.feature_record.ip == "203.0.113.8"
        ]
        self.assertGreaterEqual(max(slow_track), 60.0)
        self.assertLess(slow_track[-1], max(slow_track))


if __name__ == "__main__":
    unittest.main()
