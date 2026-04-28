from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class RiskWeights:
    """Non-linear risk weighting configuration.
    
    Attributes:
        rule_weight: Baseline weight for rule-based score (default 1.0)
        anomaly_weight: Baseline weight for anomaly score (default 0.3)
        boost_threshold_rule: Rule score threshold for conditional boost (default 70)
        boost_threshold_anomaly: Anomaly score threshold for conditional boost (default 0.7)
        boost_amount: Non-linear boost when both rules trigger (default 20 points)
        adaptive_boost: Enable adaptive weighting based on signal strength (default True)
        use_sigmoid: Use sigmoid function for smooth non-linear combination (default False)
    """
    rule_weight: float = 1.00
    anomaly_weight: float = 0.30
    boost_threshold_rule: float = 70.0
    boost_threshold_anomaly: float = 0.7
    boost_amount: float = 20.0
    adaptive_boost: bool = True
    use_sigmoid: bool = False

    def validate(self) -> None:
        if self.rule_weight < 0 or self.anomaly_weight < 0:
            raise ValueError("risk weights must be non-negative")
        if self.rule_weight == 0 and self.anomaly_weight == 0:
            raise ValueError("at least one risk weight must be greater than zero")
        if not 0.0 <= self.boost_threshold_anomaly <= 1.0:
            raise ValueError("boost_threshold_anomaly must be between 0 and 1")


@dataclass(slots=True, frozen=True)
class RiskScoreResult:
    risk_score: float
    level: str
    rule_score: float
    anomaly_score: float | None
    scoring_method: str = "linear"  # 'linear', 'boosted', 'adaptive', 'sigmoid'


def classify_risk_level(risk_score: float) -> str:
    if risk_score >= 80:
        return "high"
    if risk_score >= 60:
        return "medium"
    if risk_score >= 30:
        return "low"
    return "normal"


def _sigmoid(x: float, steepness: float = 0.05) -> float:
    """Smooth sigmoid function for non-linear transformation."""
    return 1.0 / (1.0 + math.exp(-steepness * x))


def _compute_adaptive_weights(
    rule_score: float, anomaly_score: float | None
) -> tuple[float, float]:
    """
    Compute adaptive weights based on signal strength.
    
    - If rule weak (< 50) but anomaly strong: boost anomaly weight
    - If anomaly weak (< 0.5) but rule strong: boost rule weight
    - Otherwise: use default weights
    """
    if anomaly_score is None:
        return 1.0, 0.0
    
    rule_weak = rule_score < 50.0
    anomaly_weak = anomaly_score < 0.5
    
    if rule_weak and not anomaly_weak:
        # Rule weak, anomaly strong → trust anomaly more
        return 0.5, 1.5
    elif anomaly_weak and not rule_weak:
        # Anomaly weak, rule strong → trust rule more
        return 1.5, 0.3
    else:
        # Normal case
        return 1.0, 0.3


def compute_risk_score(
    rule_score: float,
    anomaly_score: float | None = None,
    weights: RiskWeights | None = None,
) -> RiskScoreResult:
    """
    Compute risk score with non-linear, adaptive, and conditional boosting strategies.
    
    Args:
        rule_score: Rule-based detection score (0-100)
        anomaly_score: Anomaly detection score (0-1, optional)
        weights: Configuration for risk computation
    
    Returns:
        RiskScoreResult with risk score, level, and scoring method used
    """
    weights = weights or RiskWeights()
    weights.validate()
    
    if anomaly_score is None:
        return RiskScoreResult(
            risk_score=max(0.0, min(100.0, round(rule_score, 2))),
            level=classify_risk_level(rule_score),
            rule_score=rule_score,
            anomaly_score=None,
            scoring_method="linear",
        )
    
    bounded_anomaly = max(0.0, min(1.0, anomaly_score))
    anomaly_as_score = bounded_anomaly * 100.0
    
    # Step 1: Determine which scoring method to use
    if weights.use_sigmoid:
        # Sigmoid combination for smooth non-linear blending
        # Normalize inputs to [-50, 50] range for sigmoid
        rule_normalized = rule_score - 50.0
        anomaly_normalized = (anomaly_as_score - 50.0)
        
        # Apply sigmoid transformation
        rule_transformed = 50.0 + 50.0 * _sigmoid(rule_normalized / 10.0)
        anomaly_transformed = 50.0 + 50.0 * _sigmoid(anomaly_normalized / 10.0)
        
        combined = (
            (rule_transformed * weights.rule_weight) +
            (anomaly_transformed * weights.anomaly_weight)
        ) / (weights.rule_weight + weights.anomaly_weight)
        scoring_method = "sigmoid"
    
    elif weights.adaptive_boost:
        # Adaptive weighting based on signal strength
        adapted_rule_w, adapted_anomaly_w = _compute_adaptive_weights(rule_score, bounded_anomaly)
        combined = (
            (rule_score * adapted_rule_w * weights.rule_weight) +
            (anomaly_as_score * adapted_anomaly_w * weights.anomaly_weight)
        ) / (adapted_rule_w * weights.rule_weight + adapted_anomaly_w * weights.anomaly_weight)
        scoring_method = "adaptive"
    
    else:
        # Linear base combination
        combined = (rule_score * weights.rule_weight) + (anomaly_as_score * weights.anomaly_weight)
        scoring_method = "linear"
    
    # Step 2: Conditional boosting (if both rule and anomaly agree on high risk)
    if (rule_score >= weights.boost_threshold_rule and
        bounded_anomaly >= weights.boost_threshold_anomaly):
        combined += weights.boost_amount
        scoring_method = "boosted"
    
    bounded_score = max(0.0, min(100.0, round(combined, 2)))
    
    return RiskScoreResult(
        risk_score=bounded_score,
        level=classify_risk_level(bounded_score),
        rule_score=rule_score,
        anomaly_score=anomaly_score,
        scoring_method=scoring_method,
    )
