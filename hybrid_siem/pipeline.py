from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable

from hybrid_siem.decision import DecisionOutcome, decide_action
from hybrid_siem.detection import RuleThresholds, score_feature_record
from hybrid_siem.models import FeatureRecord
from hybrid_siem.risk import RiskScoreResult, RiskWeights, compute_risk_score
from hybrid_siem.watchlist import WatchlistEntry, WatchlistManager

if TYPE_CHECKING:
    from hybrid_siem.anomaly import AnomalyScore, IsolationForestAnomalyDetector


@dataclass(slots=True, frozen=True)
class PipelineDecision:
    feature_record: FeatureRecord
    rule_score: int
    anomaly_score: float | None
    raw_anomaly_score: float | None
    risk_score: float
    risk_level: str
    watchlist_entry: WatchlistEntry
    action: str
    reasons: tuple[str, ...]


def _extract_anomaly_scores(score_payload: float | AnomalyScore | None) -> tuple[float | None, float | None]:
    if score_payload is None:
        return None, None
    if hasattr(score_payload, "smoothed_score") and hasattr(score_payload, "anomaly_score"):
        return float(score_payload.smoothed_score), float(score_payload.anomaly_score)

    score_value = float(score_payload)
    return score_value, score_value


def process_feature_records(
    records: Iterable[FeatureRecord],
    thresholds: RuleThresholds | None = None,
    weights: RiskWeights | None = None,
    watchlist: WatchlistManager | None = None,
    anomaly_scores: dict[tuple[str, object], float | AnomalyScore] | None = None,
    anomaly_detector: IsolationForestAnomalyDetector | None = None,
) -> list[PipelineDecision]:
    thresholds = thresholds or RuleThresholds()
    weights = weights or RiskWeights()
    watchlist = watchlist or WatchlistManager()
    ordered_records = sorted(records, key=lambda item: (item.timestamp, item.ip))
    anomaly_scores = anomaly_scores or {}

    if anomaly_detector is not None and not anomaly_scores:
        anomaly_scores = anomaly_detector.score_lookup(ordered_records)

    decisions: list[PipelineDecision] = []
    for record in ordered_records:
        rule_result = score_feature_record(record, thresholds=thresholds)
        anomaly_score, raw_anomaly_score = _extract_anomaly_scores(anomaly_scores.get((record.ip, record.timestamp)))
        risk_result: RiskScoreResult = compute_risk_score(
            rule_score=rule_result.rule_score,
            anomaly_score=anomaly_score,
            weights=weights,
        )
        watchlist_entry = watchlist.update(
            ip=record.ip,
            observed_at=record.timestamp,
            observed_risk_score=risk_result.risk_score,
        )
        decision: DecisionOutcome = decide_action(
            risk_score=watchlist_entry.current_risk_score,
            watchlist_entry=watchlist_entry,
        )
        decisions.append(
            PipelineDecision(
                feature_record=record,
                rule_score=rule_result.rule_score,
                anomaly_score=anomaly_score,
                raw_anomaly_score=raw_anomaly_score,
                risk_score=watchlist_entry.current_risk_score,
                risk_level=watchlist_entry.status,
                watchlist_entry=watchlist_entry,
                action=decision.action,
                reasons=rule_result.reasons,
            )
        )

    return decisions
