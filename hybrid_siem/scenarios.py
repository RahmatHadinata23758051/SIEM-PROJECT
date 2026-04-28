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
            name="normal_user",
            description="Normal user with successful logins spread across separate windows.",
            expected_action_ceiling="normal",
            expected_final_action="normal",
            log_lines=(
                "Apr 28 08:15:04 ubuntu sshd[5001]: Accepted publickey for analyst from 10.24.10.9 port 49001 ssh2",
                "Apr 28 08:17:18 ubuntu sshd[5002]: Accepted publickey for analyst from 10.24.10.9 port 49002 ssh2",
                "Apr 28 08:24:11 ubuntu sshd[5003]: Accepted password for analyst from 10.24.10.9 port 49003 ssh2",
            ),
        ),
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
        ScenarioDefinition(
            name="low_and_slow_distributed",
            description="Adversarial: Many IPs attacking slowly and independently to stay under threshold.",
            expected_peak_action="monitor",
            expected_final_action="monitor",
            log_lines=(
                # 10 different IPs, each attacking very slowly (1 failure per 3-4 minutes)
                "Apr 28 13:00:01 ubuntu sshd[5501]: Failed password for root from 192.0.2.1 port 63001 ssh2",
                "Apr 28 13:03:22 ubuntu sshd[5502]: Failed password for root from 192.0.2.2 port 63002 ssh2",
                "Apr 28 13:06:45 ubuntu sshd[5503]: Failed password for root from 192.0.2.3 port 63003 ssh2",
                "Apr 28 13:10:10 ubuntu sshd[5504]: Failed password for root from 192.0.2.4 port 63004 ssh2",
                "Apr 28 13:13:35 ubuntu sshd[5505]: Failed password for root from 192.0.2.5 port 63005 ssh2",
                "Apr 28 13:16:58 ubuntu sshd[5506]: Failed password for root from 192.0.2.6 port 63006 ssh2",
                "Apr 28 13:20:20 ubuntu sshd[5507]: Failed password for root from 192.0.2.7 port 63007 ssh2",
                "Apr 28 13:23:42 ubuntu sshd[5508]: Failed password for root from 192.0.2.8 port 63008 ssh2",
                "Apr 28 13:27:05 ubuntu sshd[5509]: Failed password for root from 192.0.2.9 port 63009 ssh2",
                "Apr 28 13:30:28 ubuntu sshd[5510]: Failed password for root from 192.0.2.10 port 63010 ssh2",
            ),
        ),
        ScenarioDefinition(
            name="username_reuse_attack",
            description="Adversarial: Low variance in usernames, high persistence, mimics credential stuffing.",
            expected_peak_action="rate_limit",
            expected_final_action="rate_limit",
            log_lines=(
                # Same 2-3 usernames tried repeatedly over long period
                "Apr 28 14:00:01 ubuntu sshd[5601]: Failed password for admin from 203.0.113.10 port 64001 ssh2",
                "Apr 28 14:00:18 ubuntu sshd[5602]: Failed password for root from 203.0.113.10 port 64002 ssh2",
                "Apr 28 14:00:35 ubuntu sshd[5603]: Failed password for admin from 203.0.113.10 port 64003 ssh2",
                "Apr 28 14:00:52 ubuntu sshd[5604]: Failed password for root from 203.0.113.10 port 64004 ssh2",
                "Apr 28 14:01:09 ubuntu sshd[5605]: Failed password for admin from 203.0.113.10 port 64005 ssh2",
                "Apr 28 14:01:26 ubuntu sshd[5606]: Failed password for root from 203.0.113.10 port 64006 ssh2",
                "Apr 28 14:02:05 ubuntu sshd[5607]: Failed password for admin from 203.0.113.10 port 64007 ssh2",
                "Apr 28 14:02:22 ubuntu sshd[5608]: Failed password for root from 203.0.113.10 port 64008 ssh2",
            ),
        ),
        ScenarioDefinition(
            name="human_like_attack",
            description="Adversarial: Random delays, mix of success and failures to mimic human behavior.",
            expected_peak_action="rate_limit",
            expected_final_action="monitor",
            log_lines=(
                # Mix of successful and failed attempts with varying intervals
                "Apr 28 15:00:05 ubuntu sshd[5701]: Accepted password for user01 from 198.51.100.99 port 65001 ssh2",
                "Apr 28 15:02:47 ubuntu sshd[5702]: Failed password for user01 from 198.51.100.99 port 65002 ssh2",
                "Apr 28 15:03:20 ubuntu sshd[5703]: Accepted password for user01 from 198.51.100.99 port 65003 ssh2",
                "Apr 28 15:05:55 ubuntu sshd[5704]: Failed password for user02 from 198.51.100.99 port 65004 ssh2",
                "Apr 28 15:06:12 ubuntu sshd[5705]: Failed password for user02 from 198.51.100.99 port 65005 ssh2",
                "Apr 28 15:08:40 ubuntu sshd[5706]: Accepted password for user01 from 198.51.100.99 port 65006 ssh2",
                "Apr 28 15:10:15 ubuntu sshd[5707]: Failed password for admin from 198.51.100.99 port 65007 ssh2",
                "Apr 28 15:12:38 ubuntu sshd[5708]: Failed password for admin from 198.51.100.99 port 65008 ssh2",
                "Apr 28 15:15:42 ubuntu sshd[5709]: Accepted password for user01 from 198.51.100.99 port 65009 ssh2",
            ),
        ),
        ScenarioDefinition(
            name="mimic_normal_traffic",
            description="Adversarial: Intersperse attack with legitimate activity to evade detection.",
            expected_peak_action="monitor",
            expected_final_action="normal",
            log_lines=(
                # Legitimate activity mixed with attack attempts
                "Apr 28 16:00:10 ubuntu sshd[5801]: Accepted publickey for analyst from 203.0.113.15 port 66001 ssh2",
                "Apr 28 16:01:02 ubuntu sshd[5802]: Failed password for attacker from 203.0.113.15 port 66002 ssh2",
                "Apr 28 16:02:15 ubuntu sshd[5803]: Accepted publickey for analyst from 203.0.113.15 port 66003 ssh2",
                "Apr 28 16:03:20 ubuntu sshd[5804]: Failed password for attacker from 203.0.113.15 port 66004 ssh2",
                "Apr 28 16:04:30 ubuntu sshd[5805]: Accepted password for analyst from 203.0.113.15 port 66005 ssh2",
                "Apr 28 16:05:45 ubuntu sshd[5806]: Failed password for attacker from 203.0.113.15 port 66006 ssh2",
                "Apr 28 16:07:00 ubuntu sshd[5807]: Accepted publickey for analyst from 203.0.113.15 port 66007 ssh2",
            ),
        ),
        # Edge Case Scenarios
        ScenarioDefinition(
            name="burst_attack_very_short",
            description="Edge Case: Extreme burst (20 failures in <30 seconds) then silence.",
            expected_peak_action="block",
            expected_final_action="normal",
            log_lines=(
                # Rapid-fire failures (should spike anomaly score)
                "Apr 28 17:00:01 ubuntu sshd[5901]: Failed password for root from 210.0.0.1 port 70001 ssh2",
                "Apr 28 17:00:02 ubuntu sshd[5902]: Failed password for root from 210.0.0.1 port 70002 ssh2",
                "Apr 28 17:00:03 ubuntu sshd[5903]: Failed password for root from 210.0.0.1 port 70003 ssh2",
                "Apr 28 17:00:04 ubuntu sshd[5904]: Failed password for root from 210.0.0.1 port 70004 ssh2",
                "Apr 28 17:00:05 ubuntu sshd[5905]: Failed password for root from 210.0.0.1 port 70005 ssh2",
                "Apr 28 17:00:06 ubuntu sshd[5906]: Failed password for root from 210.0.0.1 port 70006 ssh2",
                "Apr 28 17:00:07 ubuntu sshd[5907]: Failed password for root from 210.0.0.1 port 70007 ssh2",
                "Apr 28 17:00:08 ubuntu sshd[5908]: Failed password for root from 210.0.0.1 port 70008 ssh2",
                "Apr 28 17:00:09 ubuntu sshd[5909]: Failed password for root from 210.0.0.1 port 70009 ssh2",
                "Apr 28 17:00:10 ubuntu sshd[5910]: Failed password for root from 210.0.0.1 port 70010 ssh2",
                "Apr 28 17:00:11 ubuntu sshd[5911]: Failed password for root from 210.0.0.1 port 70011 ssh2",
                # Then silence for 10 minutes - should decay
                "Apr 28 17:10:20 ubuntu sshd[5912]: Accepted password for ubuntu from 10.10.10.5 port 70012 ssh2",
            ),
        ),
        ScenarioDefinition(
            name="successful_logins_only",
            description="Edge Case: Repeated successful logins (same user, different sessions).",
            expected_peak_action="normal",
            expected_final_action="normal",
            log_lines=(
                # High-frequency successful logins - should NOT trigger attack
                "Apr 28 18:00:05 ubuntu sshd[6001]: Accepted password for devops from 10.20.20.5 port 71001 ssh2",
                "Apr 28 18:00:15 ubuntu sshd[6002]: Accepted password for devops from 10.20.20.5 port 71002 ssh2",
                "Apr 28 18:00:25 ubuntu sshd[6003]: Accepted password for devops from 10.20.20.5 port 71003 ssh2",
                "Apr 28 18:00:35 ubuntu sshd[6004]: Accepted password for devops from 10.20.20.5 port 71004 ssh2",
                "Apr 28 18:00:45 ubuntu sshd[6005]: Accepted password for devops from 10.20.20.5 port 71005 ssh2",
                "Apr 28 18:00:55 ubuntu sshd[6006]: Accepted password for devops from 10.20.20.5 port 71006 ssh2",
                "Apr 28 18:01:05 ubuntu sshd[6007]: Accepted password for devops from 10.20.20.5 port 71007 ssh2",
            ),
        ),
        ScenarioDefinition(
            name="single_user_rotating_ips",
            description="Edge Case: Same user from many different IPs (legitimat mobile scenario).",
            expected_peak_action="monitor",
            expected_final_action="normal",
            log_lines=(
                # Same user, many different IPs - could be mobile user or compromised account
                "Apr 28 19:00:05 ubuntu sshd[6101]: Accepted password for alice from 203.1.1.1 port 72001 ssh2",
                "Apr 28 19:05:10 ubuntu sshd[6102]: Accepted password for alice from 203.1.1.2 port 72002 ssh2",
                "Apr 28 19:10:15 ubuntu sshd[6103]: Accepted password for alice from 203.1.1.3 port 72003 ssh2",
                "Apr 28 19:15:20 ubuntu sshd[6104]: Accepted password for alice from 203.1.1.4 port 72004 ssh2",
                "Apr 28 19:20:25 ubuntu sshd[6105]: Accepted password for alice from 203.1.1.5 port 72005 ssh2",
            ),
        ),
        ScenarioDefinition(
            name="high_noise_random_activity",
            description="Edge Case: Many events but random/inconsistent pattern (high entropy).",
            expected_peak_action="monitor",
            expected_final_action="normal",
            log_lines=(
                # Random mix of users, outcomes, timing - should not cluster as attack
                "Apr 28 20:00:01 ubuntu sshd[6201]: Accepted password for user1 from 210.1.1.1 port 73001 ssh2",
                "Apr 28 20:00:10 ubuntu sshd[6202]: Failed password for user2 from 210.1.1.2 port 73002 ssh2",
                "Apr 28 20:00:15 ubuntu sshd[6203]: Accepted publickey for user3 from 210.1.1.3 port 73003 ssh2",
                "Apr 28 20:00:25 ubuntu sshd[6204]: Failed password for user4 from 210.1.1.4 port 73004 ssh2",
                "Apr 28 20:00:30 ubuntu sshd[6205]: Accepted password for user5 from 210.1.1.5 port 73005 ssh2",
                "Apr 28 20:00:40 ubuntu sshd[6206]: Failed password for user6 from 210.1.1.6 port 73006 ssh2",
                "Apr 28 20:00:50 ubuntu sshd[6207]: Accepted publickey for user7 from 210.1.1.7 port 73007 ssh2",
                "Apr 28 20:01:00 ubuntu sshd[6208]: Failed password for user8 from 210.1.1.8 port 73008 ssh2",
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
