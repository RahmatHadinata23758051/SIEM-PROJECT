from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class RiskWeights:
    rule_weight: float = 0.75
    anomaly_weight: float = 0.25


@dataclass(slots=True, frozen=True)
class RiskScoreResult:
    risk_score: float
    level: str
    rule_score: float
    anomaly_score: float | None


def classify_risk_level(risk_score: float) -> str:
    if risk_score >= 80:
        return "high"
    if risk_score >= 60:
        return "medium"
    if risk_score >= 30:
        return "low"
    return "normal"


def compute_risk_score(
    rule_score: float,
    anomaly_score: float | None = None,
    weights: RiskWeights | None = None,
) -> RiskScoreResult:
    weights = weights or RiskWeights()
    if anomaly_score is None:
        combined = rule_score
    else:
        combined = (rule_score * weights.rule_weight) + ((anomaly_score * 100.0) * weights.anomaly_weight)

    bounded_score = max(0.0, min(100.0, round(combined, 2)))
    return RiskScoreResult(
        risk_score=bounded_score,
        level=classify_risk_level(bounded_score),
        rule_score=rule_score,
        anomaly_score=anomaly_score,
    )
