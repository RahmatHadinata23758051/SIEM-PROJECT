from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from hybrid_siem.features import build_feature_records
from hybrid_siem.models import FeatureRecord
from hybrid_siem.parsers import parse_auth_log_lines


@dataclass(slots=True, frozen=True)
class ScenarioDefinition:
    name: str
    description: str
    expected_action_ceiling: str | None = None
    expected_peak_action: str | None = None
    expected_final_action: str | None = None
    log_lines: tuple[str, ...] = tuple()


def _scenario_lines() -> list[ScenarioDefinition]:
    return [
        ScenarioDefinition(
            name="normal_typo",
            description="Normal user with a single typo followed by a successful login.",
            expected_action_ceiling="monitor",
            expected_final_action="normal",
            log_lines=(
                "Apr 28 09:00:01 ubuntu sshd[5101]: Failed password for analyst from 10.24.10.9 port 50001 ssh2",
                "Apr 28 09:00:12 ubuntu sshd[5101]: Accepted password for analyst from 10.24.10.9 port 50001 ssh2",
                "Apr 28 09:08:15 ubuntu sshd[5102]: Accepted publickey for analyst from 10.24.10.9 port 50002 ssh2",
            ),
        ),
        ScenarioDefinition(
            name="slow_bruteforce",
            description="Low-and-slow repeated failed logins across consecutive windows.",
            expected_peak_action="rate_limit",
            expected_final_action="monitor",
            log_lines=(
                "Apr 28 10:00:01 ubuntu sshd[5201]: Failed password for root from 203.0.113.8 port 60001 ssh2",
                "Apr 28 10:00:32 ubuntu sshd[5202]: Failed password for root from 203.0.113.8 port 60002 ssh2",
                "Apr 28 10:01:05 ubuntu sshd[5203]: Failed password for root from 203.0.113.8 port 60003 ssh2",
                "Apr 28 10:01:36 ubuntu sshd[5204]: Failed password for root from 203.0.113.8 port 60004 ssh2",
                "Apr 28 10:02:08 ubuntu sshd[5205]: Failed password for root from 203.0.113.8 port 60005 ssh2",
                "Apr 28 10:02:40 ubuntu sshd[5206]: Failed password for root from 203.0.113.8 port 60006 ssh2",
                "Apr 28 10:05:10 ubuntu sshd[5207]: Failed password for root from 203.0.113.8 port 60007 ssh2",
            ),
        ),
        ScenarioDefinition(
            name="aggressive_bruteforce",
            description="High-rate brute force that should spike risk quickly and later decay after a quiet gap.",
            expected_peak_action="block",
            expected_final_action="rate_limit",
            log_lines=(
                "Apr 28 11:00:01 ubuntu sshd[5301]: Failed password for invalid user admin from 198.51.100.50 port 61001 ssh2",
                "Apr 28 11:00:03 ubuntu sshd[5302]: Failed password for root from 198.51.100.50 port 61002 ssh2",
                "Apr 28 11:00:05 ubuntu sshd[5303]: Failed password for invalid user oracle from 198.51.100.50 port 61003 ssh2",
                "Apr 28 11:00:07 ubuntu sshd[5304]: Failed password for root from 198.51.100.50 port 61004 ssh2",
                "Apr 28 11:00:09 ubuntu sshd[5305]: Failed password for invalid user test from 198.51.100.50 port 61005 ssh2",
                "Apr 28 11:00:11 ubuntu sshd[5306]: Failed password for root from 198.51.100.50 port 61006 ssh2",
                "Apr 28 11:00:13 ubuntu sshd[5307]: Failed password for invalid user support from 198.51.100.50 port 61007 ssh2",
                "Apr 28 11:00:15 ubuntu sshd[5308]: Failed password for root from 198.51.100.50 port 61008 ssh2",
                "Apr 28 11:12:15 ubuntu sshd[5309]: Failed password for root from 198.51.100.50 port 61009 ssh2",
                "Apr 28 11:12:30 ubuntu sshd[5310]: Accepted publickey for ops-01 from 198.51.100.50 port 61010 ssh2",
            ),
        ),
        ScenarioDefinition(
            name="distributed_attack",
            description="Multiple IPs probing the same account family over several windows.",
            expected_peak_action="rate_limit",
            expected_final_action="rate_limit",
            log_lines=(
                "Apr 28 12:00:01 ubuntu sshd[5401]: Failed password for root from 198.51.100.21 port 62001 ssh2",
                "Apr 28 12:00:12 ubuntu sshd[5402]: Failed password for admin from 198.51.100.21 port 62002 ssh2",
                "Apr 28 12:00:03 ubuntu sshd[5403]: Failed password for root from 198.51.100.22 port 62003 ssh2",
                "Apr 28 12:00:14 ubuntu sshd[5404]: Failed password for admin from 198.51.100.22 port 62004 ssh2",
                "Apr 28 12:00:05 ubuntu sshd[5405]: Failed password for root from 198.51.100.23 port 62005 ssh2",
                "Apr 28 12:00:16 ubuntu sshd[5406]: Failed password for admin from 198.51.100.23 port 62006 ssh2",
                "Apr 28 12:01:02 ubuntu sshd[5407]: Failed password for root from 198.51.100.21 port 62007 ssh2",
                "Apr 28 12:01:14 ubuntu sshd[5408]: Failed password for admin from 198.51.100.21 port 62008 ssh2",
                "Apr 28 12:01:04 ubuntu sshd[5409]: Failed password for root from 198.51.100.22 port 62009 ssh2",
                "Apr 28 12:01:16 ubuntu sshd[5410]: Failed password for admin from 198.51.100.22 port 62010 ssh2",
                "Apr 28 12:01:06 ubuntu sshd[5411]: Failed password for root from 198.51.100.23 port 62011 ssh2",
                "Apr 28 12:01:18 ubuntu sshd[5412]: Failed password for admin from 198.51.100.23 port 62012 ssh2",
                "Apr 28 12:02:02 ubuntu sshd[5413]: Failed password for root from 198.51.100.21 port 62013 ssh2",
                "Apr 28 12:02:14 ubuntu sshd[5414]: Failed password for admin from 198.51.100.21 port 62014 ssh2",
                "Apr 28 12:02:04 ubuntu sshd[5415]: Failed password for root from 198.51.100.22 port 62015 ssh2",
                "Apr 28 12:02:16 ubuntu sshd[5416]: Failed password for admin from 198.51.100.22 port 62016 ssh2",
                "Apr 28 12:02:06 ubuntu sshd[5417]: Failed password for root from 198.51.100.23 port 62017 ssh2",
                "Apr 28 12:02:18 ubuntu sshd[5418]: Failed password for admin from 198.51.100.23 port 62018 ssh2",
            ),
        ),
    ]


def build_scenario_feature_sets(reference_time: datetime | None = None) -> list[tuple[ScenarioDefinition, list[FeatureRecord]]]:
    reference_time = reference_time or datetime(2026, 4, 28, 12, 0, 0)
    feature_sets: list[tuple[ScenarioDefinition, list[FeatureRecord]]] = []
    for definition in _scenario_lines():
        events = parse_auth_log_lines(definition.log_lines, reference_time=reference_time)
        records = build_feature_records(events, window_seconds=60)
        feature_sets.append((definition, records))
    return feature_sets
