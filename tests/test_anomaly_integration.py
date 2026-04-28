from __future__ import annotations

import unittest
from datetime import datetime
from pathlib import Path

from hybrid_siem.anomaly import DEFAULT_ANOMALY_FEATURES, IsolationForestConfig, fit_isolation_forest, load_isolation_forest
from hybrid_siem.features import build_feature_records
from hybrid_siem.parsers import parse_auth_log_file
from hybrid_siem.pipeline import process_feature_records
from hybrid_siem.scenarios import build_scenario_feature_sets
from hybrid_siem.synthetic import SyntheticSshLogGenerator


class TestIsolationForestIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.output_dir = Path(__file__).resolve().parent.parent / "data" / "generated"
        cls.output_dir.mkdir(parents=True, exist_ok=True)
        cls.auth_path = cls.output_dir / "test_anomaly_auth.log"
        cls.auth_path.unlink(missing_ok=True)

        generator = SyntheticSshLogGenerator(seed=33, behavior_profile="mixed")
        generator.build_auth_log(
            output_path=cls.auth_path,
            target_feature_rows=500,
            start_time=datetime(2026, 1, 1, 0, 0, 0),
        )

        cls.training_records = build_feature_records(
            parse_auth_log_file(cls.auth_path, reference_time=datetime(2026, 2, 1, 0, 0, 0))
        )
        cls.detector = fit_isolation_forest(
            cls.training_records,
            config=IsolationForestConfig(
                contamination=0.03,
                n_estimators=100,
                smoothing_alpha=0.40,
            ),
            source_label="synthetic_mixed",
        )
        cls.scenario_records = {
            definition.name: records
            for definition, records in build_scenario_feature_sets(reference_time=datetime(2026, 4, 28, 12, 0, 0))
        }

    def test_training_uses_reduced_feature_space_and_normal_subset(self) -> None:
        report = self.detector.training_report

        self.assertEqual(report.feature_names, DEFAULT_ANOMALY_FEATURES)
        self.assertNotIn("request_rate", report.feature_names)
        self.assertLess(report.trained_row_count, report.baseline_row_count)
        self.assertGreater(report.trained_row_count, 100)

    def test_anomaly_scores_stay_low_for_normal_and_rise_for_attacks(self) -> None:
        normal_user_scores = self.detector.score_records(self.scenario_records["normal_user"])
        normal_typo_scores = self.detector.score_records(self.scenario_records["normal_typo"])
        slow_scores = self.detector.score_records(self.scenario_records["slow_bruteforce"])
        aggressive_scores = self.detector.score_records(self.scenario_records["aggressive_bruteforce"])
        distributed_scores = self.detector.score_records(self.scenario_records["distributed_attack"])

        self.assertLess(max(score.smoothed_score for score in normal_user_scores), 0.10)
        self.assertLess(max(score.smoothed_score for score in normal_typo_scores), 0.20)
        self.assertGreater(max(score.smoothed_score for score in slow_scores), 0.05)
        self.assertGreater(max(score.smoothed_score for score in aggressive_scores), max(score.smoothed_score for score in slow_scores))
        self.assertGreater(max(score.smoothed_score for score in aggressive_scores), 0.20)

        distributed_tracks: dict[str, list[float]] = {}
        for score in distributed_scores:
            distributed_tracks.setdefault(score.ip, []).append(score.smoothed_score)

        self.assertTrue(any(max(track) > 0.05 for track in distributed_tracks.values()))

    def test_pipeline_attaches_smoothed_anomaly_scores(self) -> None:
        decisions = process_feature_records(
            self.scenario_records["slow_bruteforce"],
            anomaly_detector=self.detector,
        )

        self.assertTrue(all(decision.anomaly_score is not None for decision in decisions))
        self.assertTrue(all(decision.raw_anomaly_score is not None for decision in decisions))
        self.assertGreater(max(decision.anomaly_score or 0.0 for decision in decisions), decisions[-1].anomaly_score or 0.0)

    def test_model_can_be_saved_and_loaded(self) -> None:
        model_path = self.output_dir / "test_isolation_forest.pkl"
        saved_path = self.detector.save(model_path)
        loaded = load_isolation_forest(saved_path)

        original_scores = [score.smoothed_score for score in self.detector.score_records(self.scenario_records["aggressive_bruteforce"])]
        loaded_scores = [score.smoothed_score for score in loaded.score_records(self.scenario_records["aggressive_bruteforce"])]

        self.assertEqual(original_scores, loaded_scores)


if __name__ == "__main__":
    unittest.main()
