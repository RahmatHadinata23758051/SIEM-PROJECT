from __future__ import annotations

from dataclasses import dataclass

from hybrid_siem.watchlist import WatchlistEntry


@dataclass(slots=True, frozen=True)
class DecisionOutcome:
    action: str
    reason: str
    confidence: float = 1.0


def _compute_confidence(risk_score: float, anomaly_score: float | None, rule_score: int) -> float:
    """Compute decision confidence based on signal agreement.
    
    - High confidence when rule-based and anomaly signals agree.
    - Low confidence in borderline zones or when signals disagree.
    """
    # Borderline risk zones = low confidence
    if 35 <= risk_score <= 55:
        base_confidence = 0.4
    elif 55 < risk_score <= 70:
        base_confidence = 0.65
    else:
        base_confidence = 0.9

    # Boost confidence when both signals agree
    if anomaly_score is not None:
        rule_high = rule_score >= 50
        anomaly_high = anomaly_score >= 0.5
        if rule_high == anomaly_high:
            base_confidence = min(1.0, base_confidence + 0.15)
        else:
            # Signals disagree → drop confidence
            base_confidence = max(0.0, base_confidence - 0.2)

    return round(base_confidence, 3)


def decide_action(
    risk_score: float,
    watchlist_entry: WatchlistEntry,
    anomaly_score: float | None = None,
    rule_score: int = 0,
) -> DecisionOutcome:
    """Determine action with confidence-aware logic.
    
    If confidence < 0.5 and the decision is in a borderline zone,
    escalate to manual review instead of auto-deciding.
    """
    confidence = _compute_confidence(risk_score, anomaly_score, rule_score)

    if risk_score >= 80 or watchlist_entry.strike_count >= 3:
        return DecisionOutcome(action="block", reason="high_risk_or_repeat_offender", confidence=confidence)

    if risk_score >= 60 or (watchlist_entry.strike_count >= 1 and risk_score >= 45):
        return DecisionOutcome(action="rate_limit", reason="elevated_risk", confidence=confidence)

    # Unknown zone: borderline risk + low confidence → escalate
    if 30 <= risk_score < 60 and confidence < 0.5:
        return DecisionOutcome(action="escalate_manual_review", reason="low_confidence_borderline", confidence=confidence)

    if risk_score >= 30 or watchlist_entry.status in {"low", "medium", "high"}:
        return DecisionOutcome(action="monitor", reason="suspicious_activity", confidence=confidence)

    return DecisionOutcome(action="normal", reason="baseline_activity", confidence=confidence)

