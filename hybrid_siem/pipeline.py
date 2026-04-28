from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from hybrid_siem.decision import DecisionOutcome, decide_action
from hybrid_siem.detection import RuleThresholds, score_feature_record
from hybrid_siem.models import FeatureRecord
from hybrid_siem.risk import RiskScoreResult, RiskWeights, compute_risk_score
from hybrid_siem.watchlist import WatchlistEntry, WatchlistManager


@dataclass(slots=True, frozen=True)
class PipelineDecision:
    feature_record: FeatureRecord
    rule_score: int
    risk_score: float
    risk_level: str
    watchlist_entry: WatchlistEntry
    action: str
    reasons: tuple[str, ...]


def process_feature_records(
    records: Iterable[FeatureRecord],
    thresholds: RuleThresholds | None = None,
    weights: RiskWeights | None = None,
    watchlist: WatchlistManager | None = None,
    anomaly_scores: dict[tuple[str, object], float] | None = None,
) -> list[PipelineDecision]:
    thresholds = thresholds or RuleThresholds()
    weights = weights or RiskWeights()
    watchlist = watchlist or WatchlistManager()
    anomaly_scores = anomaly_scores or {}

    decisions: list[PipelineDecision] = []
    for record in sorted(records, key=lambda item: (item.timestamp, item.ip)):
        rule_result = score_feature_record(record, thresholds=thresholds)
        anomaly_score = anomaly_scores.get((record.ip, record.timestamp))
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
                risk_score=watchlist_entry.current_risk_score,
                risk_level=watchlist_entry.status,
                watchlist_entry=watchlist_entry,
                action=decision.action,
                reasons=rule_result.reasons,
            )
        )

    return decisions
