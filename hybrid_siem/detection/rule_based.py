from __future__ import annotations

from dataclasses import dataclass

from hybrid_siem.models import FeatureRecord


@dataclass(slots=True, frozen=True)
class RuleThresholds:
    failed_count_low: int = 2
    failed_count_medium: int = 5
    failed_count_high: int = 10
    request_rate_low: float = 0.04
    request_rate_medium: float = 0.10
    request_rate_high: float = 0.18
    username_variance_low: int = 2
    username_variance_medium: int = 4
    username_variance_high: int = 7
    failed_ratio_low: float = 0.60
    failed_ratio_medium: float = 0.85
    failed_ratio_high: float = 0.98
    event_count_low: int = 3
    event_count_medium: int = 6
    event_count_high: int = 12
    inter_arrival_fast_low: float = 6.0
    inter_arrival_fast_medium: float = 3.0
    inter_arrival_fast_high: float = 1.5
    slow_attack_failed_count: int = 2
    slow_attack_failed_ratio: float = 0.90
    slow_attack_request_rate_max: float = 0.05
    slow_attack_inter_arrival_min: float = 15.0


@dataclass(slots=True, frozen=True)
class RuleDetectionResult:
    timestamp: object
    ip: str
    rule_score: int
    level: str
    reasons: tuple[str, ...]


def _score_positive(value: float, low: float, medium: float, high: float, scores: tuple[int, int, int]) -> int:
    if value >= high:
        return scores[2]
    if value >= medium:
        return scores[1]
    if value >= low:
        return scores[0]
    return 0


def _score_reverse(value: float | None, low: float, medium: float, high: float, scores: tuple[int, int, int]) -> int:
    if value is None or value <= 0:
        return 0
    if value <= high:
        return scores[2]
    if value <= medium:
        return scores[1]
    if value <= low:
        return scores[0]
    return 0


def _classify_rule_level(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 60:
        return "medium"
    if score >= 30:
        return "low"
    return "normal"


def score_feature_record(
    record: FeatureRecord,
    thresholds: RuleThresholds | None = None,
) -> RuleDetectionResult:
    thresholds = thresholds or RuleThresholds()
    score = 0
    reasons: list[str] = []

    failed_score = _score_positive(
        record.failed_count,
        thresholds.failed_count_low,
        thresholds.failed_count_medium,
        thresholds.failed_count_high,
        scores=(12, 24, 34),
    )
    if failed_score:
        score += failed_score
        reasons.append(f"failed_count={record.failed_count}")

    rate_score = _score_positive(
        record.request_rate,
        thresholds.request_rate_low,
        thresholds.request_rate_medium,
        thresholds.request_rate_high,
        scores=(8, 16, 24),
    )
    if rate_score:
        score += rate_score
        reasons.append(f"request_rate={record.request_rate}")

    variance_score = _score_positive(
        record.username_variance,
        thresholds.username_variance_low,
        thresholds.username_variance_medium,
        thresholds.username_variance_high,
        scores=(6, 12, 18),
    )
    if variance_score:
        score += variance_score
        reasons.append(f"username_variance={record.username_variance}")

    ratio_score = _score_positive(
        record.failed_ratio,
        thresholds.failed_ratio_low,
        thresholds.failed_ratio_medium,
        thresholds.failed_ratio_high,
        scores=(8, 14, 20),
    )
    if ratio_score:
        score += ratio_score
        reasons.append(f"failed_ratio={record.failed_ratio}")

    event_score = _score_positive(
        record.event_count,
        thresholds.event_count_low,
        thresholds.event_count_medium,
        thresholds.event_count_high,
        scores=(4, 8, 12),
    )
    if event_score:
        score += event_score
        reasons.append(f"event_count={record.event_count}")

    inter_arrival_score = _score_reverse(
        record.inter_arrival_avg,
        thresholds.inter_arrival_fast_low,
        thresholds.inter_arrival_fast_medium,
        thresholds.inter_arrival_fast_high,
        scores=(4, 8, 12),
    )
    if inter_arrival_score:
        score += inter_arrival_score
        reasons.append(f"inter_arrival_avg={record.inter_arrival_avg}")

    slow_attack_match = (
        record.failed_count >= thresholds.slow_attack_failed_count
        and record.failed_ratio >= thresholds.slow_attack_failed_ratio
        and record.request_rate <= thresholds.slow_attack_request_rate_max
        and (record.inter_arrival_avg or 0) >= thresholds.slow_attack_inter_arrival_min
    )
    if slow_attack_match:
        score += 18
        reasons.append("slow_attack_pattern")

    single_username_pressure = (
        record.failed_count >= 4 and record.username_variance == 1 and record.failed_ratio >= 0.9
    )
    if single_username_pressure:
        score += 10
        reasons.append("single_username_pressure")

    distributed_pattern = (
        record.failed_count >= 2 and record.username_variance >= 2 and record.failed_ratio >= 0.9
    )
    if distributed_pattern:
        score += 8
        reasons.append("distributed_pattern")

    rule_score = min(100, score)
    return RuleDetectionResult(
        timestamp=record.timestamp,
        ip=record.ip,
        rule_score=rule_score,
        level=_classify_rule_level(rule_score),
        reasons=tuple(reasons),
    )
