from __future__ import annotations

import csv
import unittest
from datetime import datetime
from pathlib import Path

from hybrid_siem.synthetic import SyntheticSshLogGenerator, build_synthetic_training_corpus


class TestSyntheticCorpus(unittest.TestCase):
    def setUp(self) -> None:
        self.output_dir = Path(__file__).resolve().parent.parent / "data" / "generated"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def test_auth_log_generation_creates_parseable_output(self) -> None:
        auth_path = self.output_dir / "test_synthetic_auth.log"
        auth_path.unlink(missing_ok=True)

        generator = SyntheticSshLogGenerator(seed=7, behavior_profile="mixed")
        result = generator.build_auth_log(
            output_path=auth_path,
            target_feature_rows=120,
            start_time=datetime(2026, 1, 1, 0, 0, 0),
        )

        self.assertTrue(auth_path.exists())
        self.assertGreater(result.feature_rows_emitted, 0)
        self.assertGreater(result.parsed_line_count, result.feature_rows_emitted)

    def test_honeypot_profile_creates_attack_heavy_dataset(self) -> None:
        auth_path = self.output_dir / "test_honeypot_auth.log"
        dataset_path = self.output_dir / "test_honeypot_features.csv"
        auth_path.unlink(missing_ok=True)
        dataset_path.unlink(missing_ok=True)

        result = build_synthetic_training_corpus(
            auth_log_path=auth_path,
            dataset_path=dataset_path,
            target_csv_size_mb=0.03,
            seed=17,
            start_time=datetime(2026, 1, 1, 0, 0, 0),
            behavior_profile="honeypot",
        )

        self.assertEqual(result.behavior_profile, "honeypot")
        self.assertTrue(dataset_path.exists())

        with dataset_path.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))

        high_fail_ratio_rows = sum(float(row["failed_ratio"]) >= 0.9 for row in rows)
        high_user_variance_rows = sum(int(row["username_variance"]) >= 3 for row in rows)
        self.assertGreater(high_fail_ratio_rows / len(rows), 0.55)
        self.assertGreater(high_user_variance_rows, 0)

    def test_full_synthetic_corpus_builder_hits_target_size(self) -> None:
        auth_path = self.output_dir / "test_large_synthetic_auth.log"
        dataset_path = self.output_dir / "test_large_synthetic_features.csv"
        auth_path.unlink(missing_ok=True)
        dataset_path.unlink(missing_ok=True)

        result = build_synthetic_training_corpus(
            auth_log_path=auth_path,
            dataset_path=dataset_path,
            target_csv_size_mb=0.05,
            seed=11,
            start_time=datetime(2026, 1, 1, 0, 0, 0),
            behavior_profile="mixed",
        )

        self.assertTrue(auth_path.exists())
        self.assertTrue(dataset_path.exists())
        self.assertGreaterEqual(result.dataset_size_bytes, int(0.05 * 1024 * 1024))
        self.assertGreater(result.dataset_result.feature_rows, 0)

        with dataset_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            rows = list(reader)

        self.assertIn("failed_count", rows[0])
        self.assertGreater(len({row["ip"] for row in rows}), 40)
        self.assertGreater(len({row["timestamp"] for row in rows}), 50)


if __name__ == "__main__":
    unittest.main()
