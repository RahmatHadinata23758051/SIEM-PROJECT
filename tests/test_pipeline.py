from __future__ import annotations

import unittest
from datetime import datetime
from pathlib import Path

from hybrid_siem.features import build_feature_records
from hybrid_siem.normalization import build_canonical_attempts
from hybrid_siem.parsers import parse_auth_log_file


class TestHybridSiemPipeline(unittest.TestCase):
    def setUp(self) -> None:
        self.reference_time = datetime(2026, 4, 28, 12, 0, 0)
        self.sample_log = Path(__file__).resolve().parent.parent / "data" / "samples" / "auth.log"

    def test_parser_extracts_expected_attempts(self) -> None:
        events = parse_auth_log_file(self.sample_log, reference_time=self.reference_time)
        canonical_attempts = build_canonical_attempts(events)

        self.assertEqual(len(events), 14)
        self.assertEqual(sum(event.is_attempt for event in events), 13)
        self.assertEqual(len(canonical_attempts), 12)
        self.assertEqual(events[0].ip, "192.168.56.10")
        self.assertEqual(events[0].username, "admin")
        self.assertEqual(events[0].outcome, "failure")
        self.assertEqual(events[8].outcome, "success")
        self.assertEqual(events[-1].event_type, "preauth_disconnect")

        guest_attempt = next(
            attempt
            for attempt in canonical_attempts
            if attempt.ip == "172.16.0.7" and attempt.port == 60001
        )
        self.assertEqual(guest_attempt.outcome, "failure")
        self.assertEqual(guest_attempt.event_count, 2)
        self.assertEqual(guest_attempt.source_event_types, ("invalid_user", "failed_password"))

    def test_feature_extraction_groups_per_window_and_ip(self) -> None:
        events = parse_auth_log_file(self.sample_log, reference_time=self.reference_time)
        records = build_feature_records(events, window_seconds=60)
        record_map = {(record.timestamp.isoformat(sep=" "), record.ip): record for record in records}

        self.assertEqual(len(records), 5)

        hot_ip = record_map[("2026-04-28 10:00:00", "192.168.56.10")]
        self.assertEqual(hot_ip.failed_count, 5)
        self.assertEqual(hot_ip.event_count, 5)
        self.assertEqual(hot_ip.username_variance, 3)
        self.assertAlmostEqual(hot_ip.request_rate, 0.0833, places=4)
        self.assertAlmostEqual(hot_ip.inter_arrival_avg, 9.75, places=2)
        self.assertAlmostEqual(hot_ip.failed_ratio, 1.0, places=4)

        guest_ip = record_map[("2026-04-28 10:01:00", "172.16.0.7")]
        self.assertEqual(guest_ip.failed_count, 3)
        self.assertEqual(guest_ip.total_attempts, 3)
        self.assertEqual(guest_ip.event_count, 4)
        self.assertEqual(guest_ip.username_variance, 1)
        self.assertAlmostEqual(guest_ip.request_rate, 0.05, places=4)
        self.assertAlmostEqual(guest_ip.inter_arrival_avg, 4.5, places=2)

        success_ip = record_map[("2026-04-28 10:00:00", "10.10.10.4")]
        self.assertEqual(success_ip.event_count, 1)
        self.assertIsNone(success_ip.inter_arrival_avg)


if __name__ == "__main__":
    unittest.main()
