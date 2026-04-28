from __future__ import annotations

import unittest
from datetime import datetime
from pathlib import Path

from hybrid_siem.features import build_feature_records
from hybrid_siem.parsers import parse_auth_log_lines
from hybrid_siem.pipeline import process_feature_records
from hybrid_siem.synthetic import SyntheticSshLogGenerator
from hybrid_siem.validation import validate_feature_records


class TestDetectionPipeline(unittest.TestCase):
    def setUp(self) -> None:
        self.reference_time = datetime(2026, 4, 28, 12, 0, 0)
        self.output_dir = Path(__file__).resolve().parent.parent / "data" / "generated"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _build_records(self, lines: list[str]) -> list:
        events = parse_auth_log_lines(lines, reference_time=self.reference_time)
        return build_feature_records(events, window_seconds=60)

    def test_typo_login_stays_below_high_risk(self) -> None:
        lines = [
            "Apr 28 10:00:01 ubuntu sshd[4101]: Failed password for analyst from 10.24.10.9 port 50001 ssh2",
            "Apr 28 10:00:10 ubuntu sshd[4101]: Accepted password for analyst from 10.24.10.9 port 50001 ssh2",
        ]

        decisions = process_feature_records(self._build_records(lines))

        self.assertEqual(len(decisions), 1)
        self.assertLess(decisions[0].risk_score, 30)
        self.assertEqual(decisions[0].action, "normal")

    def test_slow_attack_is_detected(self) -> None:
        lines = [
            "Apr 28 11:00:01 ubuntu sshd[4201]: Failed password for root from 203.0.113.8 port 60001 ssh2",
            "Apr 28 11:00:32 ubuntu sshd[4202]: Failed password for root from 203.0.113.8 port 60002 ssh2",
            "Apr 28 11:01:05 ubuntu sshd[4203]: Failed password for root from 203.0.113.8 port 60003 ssh2",
            "Apr 28 11:01:36 ubuntu sshd[4204]: Failed password for root from 203.0.113.8 port 60004 ssh2",
            "Apr 28 11:02:08 ubuntu sshd[4205]: Failed password for root from 203.0.113.8 port 60005 ssh2",
            "Apr 28 11:02:40 ubuntu sshd[4206]: Failed password for root from 203.0.113.8 port 60006 ssh2",
            "Apr 28 11:03:10 ubuntu sshd[4207]: Failed password for root from 203.0.113.8 port 60007 ssh2",
            "Apr 28 11:03:42 ubuntu sshd[4208]: Failed password for root from 203.0.113.8 port 60008 ssh2",
        ]

        decisions = process_feature_records(self._build_records(lines))
        attacker_decisions = [decision for decision in decisions if decision.feature_record.ip == "203.0.113.8"]

        self.assertEqual(len(attacker_decisions), 4)
        self.assertGreaterEqual(attacker_decisions[-1].risk_score, 60)
        self.assertEqual(attacker_decisions[-1].action, "rate_limit")

    def test_distributed_attack_increases_risk_gradually(self) -> None:
        lines = [
            "Apr 28 12:00:01 ubuntu sshd[4301]: Failed password for root from 198.51.100.21 port 61001 ssh2",
            "Apr 28 12:00:12 ubuntu sshd[4302]: Failed password for admin from 198.51.100.21 port 61002 ssh2",
            "Apr 28 12:00:03 ubuntu sshd[4303]: Failed password for root from 198.51.100.22 port 62001 ssh2",
            "Apr 28 12:00:14 ubuntu sshd[4304]: Failed password for admin from 198.51.100.22 port 62002 ssh2",
            "Apr 28 12:00:05 ubuntu sshd[4305]: Failed password for root from 198.51.100.23 port 63001 ssh2",
            "Apr 28 12:00:16 ubuntu sshd[4306]: Failed password for admin from 198.51.100.23 port 63002 ssh2",
            "Apr 28 12:01:02 ubuntu sshd[4307]: Failed password for root from 198.51.100.21 port 61003 ssh2",
            "Apr 28 12:01:14 ubuntu sshd[4308]: Failed password for admin from 198.51.100.21 port 61004 ssh2",
            "Apr 28 12:01:04 ubuntu sshd[4309]: Failed password for root from 198.51.100.22 port 62003 ssh2",
            "Apr 28 12:01:16 ubuntu sshd[4310]: Failed password for admin from 198.51.100.22 port 62004 ssh2",
            "Apr 28 12:01:06 ubuntu sshd[4311]: Failed password for root from 198.51.100.23 port 63003 ssh2",
            "Apr 28 12:01:18 ubuntu sshd[4312]: Failed password for admin from 198.51.100.23 port 63004 ssh2",
            "Apr 28 12:02:02 ubuntu sshd[4313]: Failed password for root from 198.51.100.21 port 61005 ssh2",
            "Apr 28 12:02:14 ubuntu sshd[4314]: Failed password for admin from 198.51.100.21 port 61006 ssh2",
            "Apr 28 12:02:04 ubuntu sshd[4315]: Failed password for root from 198.51.100.22 port 62005 ssh2",
            "Apr 28 12:02:16 ubuntu sshd[4316]: Failed password for admin from 198.51.100.22 port 62006 ssh2",
            "Apr 28 12:02:06 ubuntu sshd[4317]: Failed password for root from 198.51.100.23 port 63005 ssh2",
            "Apr 28 12:02:18 ubuntu sshd[4318]: Failed password for admin from 198.51.100.23 port 63006 ssh2",
        ]

        decisions = process_feature_records(self._build_records(lines))
        tracked = [decision for decision in decisions if decision.feature_record.ip == "198.51.100.21"]

        self.assertEqual(len(tracked), 3)
        self.assertLess(tracked[0].risk_score, tracked[1].risk_score)
        self.assertLess(tracked[1].risk_score, tracked[2].risk_score)
        self.assertEqual(tracked[-1].action, "rate_limit")

    def test_validation_report_checks_feature_distribution(self) -> None:
        auth_path = self.output_dir / "validation_synthetic_auth.log"
        auth_path.unlink(missing_ok=True)

        generator = SyntheticSshLogGenerator(seed=21, behavior_profile="mixed")
        generator.build_auth_log(
            output_path=auth_path,
            target_feature_rows=600,
            start_time=datetime(2026, 1, 1, 0, 0, 0),
        )

        with auth_path.open("r", encoding="utf-8") as handle:
            records = build_feature_records(parse_auth_log_lines(handle, reference_time=datetime(2026, 2, 1, 0, 0, 0)))

        report = validate_feature_records(records)

        self.assertGreater(report.row_count, 200)
        self.assertIn("event_count", report.distributions)
        self.assertGreater(report.timeline.suspicious_rows, 0)
        self.assertTrue(report.timeline.appears_interleaved)


if __name__ == "__main__":
    unittest.main()
