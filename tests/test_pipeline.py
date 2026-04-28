from __future__ import annotations

import unittest
from datetime import datetime
from pathlib import Path

from hybrid_siem.features import build_feature_records
from hybrid_siem.parsers import parse_auth_log_file


class TestHybridSiemPipeline(unittest.TestCase):
    def setUp(self) -> None:
        self.reference_time = datetime(2026, 4, 28, 12, 0, 0)
        self.sample_log = Path(__file__).resolve().parent.parent / "data" / "samples" / "auth.log"

    def test_parser_extracts_expected_attempts(self) -> None:
        events = parse_auth_log_file(self.sample_log, reference_time=self.reference_time)

        self.assertEqual(len(events), 14)
        self.assertEqual(sum(event.is_attempt for event in events), 11)
        self.assertEqual(events[0].ip, "192.168.56.10")
        self.assertEqual(events[0].username, "admin")
        self.assertEqual(events[0].outcome, "failure")
        self.assertEqual(events[8].outcome, "success")
        self.assertEqual(events[-1].event_type, "preauth_disconnect")

    def test_feature_extraction_groups_per_window_and_ip(self) -> None:
        events = parse_auth_log_file(self.sample_log, reference_time=self.reference_time)
        records = build_feature_records(events, window_seconds=60)
        record_map = {(record.timestamp.isoformat(sep=" "), record.ip): record for record in records}

        self.assertEqual(len(records), 5)

        hot_ip = record_map[("2026-04-28 10:00:00", "192.168.56.10")]
        self.assertEqual(hot_ip.failed_count, 5)
        self.assertEqual(hot_ip.username_variance, 3)
        self.assertAlmostEqual(hot_ip.request_rate, 0.0833, places=4)
        self.assertAlmostEqual(hot_ip.inter_arrival_avg, 9.75, places=2)
        self.assertAlmostEqual(hot_ip.failed_ratio, 1.0, places=4)

        guest_ip = record_map[("2026-04-28 10:01:00", "172.16.0.7")]
        self.assertEqual(guest_ip.failed_count, 2)
        self.assertEqual(guest_ip.total_attempts, 2)
        self.assertEqual(guest_ip.username_variance, 1)
        self.assertAlmostEqual(guest_ip.inter_arrival_avg, 3.0, places=2)


if __name__ == "__main__":
    unittest.main()
