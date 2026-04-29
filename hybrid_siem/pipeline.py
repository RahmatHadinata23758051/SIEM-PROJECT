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
    """Complete decision output with explainability.
    
    Attributes:
        feature_record: Input feature record
        rule_score: Rule-based detection score (0-100)
        anomaly_score: Smoothed anomaly score (0-1)
        raw_anomaly_score: Raw anomaly score before smoothing
        risk_score: Final aggregated risk score (0-100)
        risk_level: Risk level classification (normal/low/medium/high)
        watchlist_entry: Updated watchlist entry with history
        action: Decision action (monitor/rate_limit/block)
        reasons: Tuple of explanatory reasons for the decision
        scoring_method: Method used for risk scoring (linear/adaptive/boosted/sigmoid)
        temporal_insight: Additional temporal insight if available
    """
    feature_record: FeatureRecord
    rule_score: int
    anomaly_score: float | None
    raw_anomaly_score: float | None
    risk_score: float
    risk_level: str
    watchlist_entry: WatchlistEntry
    action: str
    reasons: tuple[str, ...]
    confidence: float = 1.0
    scoring_method: str = "linear"
    temporal_insight: str = ""


def _extract_anomaly_scores(score_payload: float | AnomalyScore | None) -> tuple[float | None, float | None]:
    """Extract smoothed and raw anomaly scores from payload."""
    if score_payload is None:
        return None, None
    if hasattr(score_payload, "smoothed_score") and hasattr(score_payload, "anomaly_score"):
        return float(score_payload.smoothed_score), float(score_payload.anomaly_score)

    score_value = float(score_payload)
    return score_value, score_value


def _build_explanations(
    record: FeatureRecord,
    rule_score: int,
    anomaly_score: float | None,
    risk_result: RiskScoreResult,
    watchlist_entry: WatchlistEntry,
) -> tuple[str, ...]:
    """Build human-readable explanations for the decision.
    
    Args:
        record: Feature record with metrics
        rule_score: Rule-based score
        anomaly_score: Anomaly score
        risk_result: Risk computation result
        watchlist_entry: Watchlist entry with history
    
    Returns:
        Tuple of explanation strings
    """
    reasons: list[str] = []
    
    # Rule-based explanations
    if rule_score >= 70:
        reasons.append(f"High rule score: {rule_score}")
        if record.failed_count >= 4:
            reasons.append(f"Failed attempts: {record.failed_count}")
        if record.request_rate >= 0.08:
            reasons.append(f"High request rate: {record.request_rate:.3f}")
        if record.failed_ratio >= 0.8:
            reasons.append(f"High failed ratio: {record.failed_ratio:.2f}")
    elif rule_score >= 50:
        reasons.append(f"Medium rule score: {rule_score}")
    
    # Anomaly-based explanations
    if anomaly_score is not None and anomaly_score >= 0.6:
        reasons.append(f"Anomalous pattern detected: {anomaly_score:.3f}")
    
    # Scoring method explanation
    if risk_result.scoring_method == "boosted":
        reasons.append("Non-linear boost applied (rule + anomaly agreement)")
    elif risk_result.scoring_method == "adaptive":
        reasons.append("Adaptive weighting applied based on signal strength")
    
    # Watchlist history explanations
    if watchlist_entry.strike_count >= 3:
        reasons.append(f"Repeat offender: {watchlist_entry.strike_count} strikes recorded")
    if watchlist_entry.repeat_incidents >= 2:
        reasons.append(f"Multiple high-risk periods detected: {watchlist_entry.repeat_incidents}")
    if watchlist_entry.adaptive_sensitivity > 1.5:
        reasons.append(f"Elevated sensitivity due to history ({watchlist_entry.adaptive_sensitivity:.1f}x)")
    
    # Persistence/activity pattern
    if record.event_count >= 6:
        reasons.append(f"Sustained activity: {record.event_count} events in window")
    if record.username_variance <= 2:
        reasons.append(f"Low username diversity: {record.username_variance} unique users")
    
    # Final risk level explanation
    if watchlist_entry.status == "high":
        reasons.append(f"BLOCKED: High risk status with score {watchlist_entry.current_risk_score}")
    elif watchlist_entry.status == "medium":
        reasons.append(f"RATE LIMITED: Medium risk status with score {watchlist_entry.current_risk_score}")
    elif watchlist_entry.status == "low":
        reasons.append(f"MONITORED: Low risk status with score {watchlist_entry.current_risk_score}")
    
    return tuple(reasons) if reasons else ("No anomalies detected",)


from hybrid_siem.correlation.engine import CorrelationEngine

def process_feature_records(
    records: Iterable[FeatureRecord],
    thresholds: RuleThresholds | None = None,
    weights: RiskWeights | None = None,
    watchlist: WatchlistManager | None = None,
    anomaly_scores: dict[tuple[str, object], float | AnomalyScore] | None = None,
    anomaly_detector: IsolationForestAnomalyDetector | None = None,
    correlation_engine: CorrelationEngine | None = None,
) -> list[PipelineDecision]:
    """Process feature records through the complete pipeline.
    
    Args:
        records: Iterable of feature records
        thresholds: Rule-based detection thresholds
        weights: Risk weighting configuration
        watchlist: Watchlist manager
        anomaly_scores: Pre-computed anomaly scores
        anomaly_detector: Anomaly detector for scoring
        correlation_engine: Cross-source correlation engine
    
    Returns:
        List of pipeline decisions with full explanations
    """
    thresholds = thresholds or RuleThresholds()
    weights = weights or RiskWeights()
    watchlist = watchlist or WatchlistManager()
    correlation_engine = correlation_engine or CorrelationEngine()
    ordered_records = sorted(records, key=lambda item: (item.timestamp, item.ip))
    anomaly_scores = anomaly_scores or {}

    if anomaly_detector is not None and not anomaly_scores:
        anomaly_scores = anomaly_detector.score_lookup(ordered_records)

    decisions: list[PipelineDecision] = []
    for record in ordered_records:
        rule_result = score_feature_record(record, thresholds=thresholds)
        anomaly_score, raw_anomaly_score = _extract_anomaly_scores(anomaly_scores.get((record.ip, record.timestamp)))
        
        # Cross-source correlation
        correlation_penalty, correlation_reasons = correlation_engine.evaluate(record)
        
        risk_result: RiskScoreResult = compute_risk_score(
            rule_score=rule_result.rule_score,
            anomaly_score=anomaly_score,
            weights=weights,
        )
        
        # Apply correlation penalty
        final_risk_score = min(risk_result.risk_score + correlation_penalty, 100.0)
        
        watchlist_entry = watchlist.update(
            ip=record.ip,
            observed_at=record.timestamp,
            observed_risk_score=final_risk_score,
        )
        decision: DecisionOutcome = decide_action(
            risk_score=watchlist_entry.current_risk_score,
            watchlist_entry=watchlist_entry,
            anomaly_score=anomaly_score,
            rule_score=rule_result.rule_score,
        )
        
        # Build comprehensive explanations
        reasons = list(_build_explanations(
            record,
            rule_result.rule_score,
            anomaly_score,
            risk_result,
            watchlist_entry,
        ))
        if correlation_reasons:
            reasons.extend(correlation_reasons)
        if decision.action == "escalate_manual_review":
            reasons.append(f"Low confidence ({decision.confidence:.2f}) — escalated for manual review")
        reasons = tuple(reasons)
        
        # Compute temporal insight (if applicable)
        temporal_insight = ""
        if record.event_count >= 10:
            temporal_insight = "High event concentration in single window"
        elif watchlist_entry.repeat_incidents >= 2 and watchlist_entry.strike_count >= 3:
            temporal_insight = "Patterns of recurring attacks detected"
        
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
                reasons=reasons,
                confidence=decision.confidence,
                scoring_method=risk_result.scoring_method,
                temporal_insight=temporal_insight,
            )
        )

    return decisions
