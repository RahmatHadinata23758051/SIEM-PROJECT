"""Real log validation and failure case discovery.

This module analyzes real SSH logs to identify:
- Distributional changes vs synthetic data
- False positive cases (normal but high risk)
- False negative cases (suspicious but low risk)
- Confidence metrics for decisions
"""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from hybrid_siem.models import FeatureRecord
from hybrid_siem.pipeline import PipelineDecision


@dataclass(slots=True, frozen=True)
class FailureCase:
    """Identified failure or edge case.
    
    Attributes:
        timestamp: When this occurred
        ip: Source IP
        case_type: 'false_positive', 'false_negative', 'low_confidence', 'unusual_pattern'
        risk_score: Decision risk score
        rule_score: Rule-based score
        anomaly_score: Anomaly score
        description: Human-readable explanation
        evidence: Key metrics that triggered this classification
    """
    timestamp: datetime
    ip: str
    case_type: str
    risk_score: float
    rule_score: int
    anomaly_score: float | None
    description: str
    evidence: str


@dataclass(slots=True, frozen=True)
class ConfidenceMetrics:
    """Confidence assessment for a decision.
    
    Attributes:
        agreement: 1.0 if rule and anomaly agree, 0.0 if opposite
        stability: Based on consistency with previous windows
        signal_strength: How extreme are the signal values
        composite_confidence: Weighted combination (0-1 scale)
    """
    agreement: float
    stability: float
    signal_strength: float
    composite_confidence: float


@dataclass(slots=True, frozen=True)
class ValidationSummary:
    """Summary of validation analysis.
    
    Attributes:
        total_decisions: Total feature windows analyzed
        failure_cases: List of identified failure cases
        mean_confidence: Average confidence across decisions
        high_confidence_ratio: Fraction with confidence > 0.8
        distribution_shift: Detected changes from baseline
        key_findings: Important insights
    """
    total_decisions: int
    failure_cases: list[FailureCase]
    mean_confidence: float
    high_confidence_ratio: float
    distribution_shift: dict[str, str]
    key_findings: list[str]


def _classify_activity_likelihood(
    decision: PipelineDecision,
) -> tuple[str, str]:
    """Classify whether activity is likely normal or attack.
    
    Returns:
        (likelihood, confidence_label)
    """
    # High number of accepted auth relative to failures = likely normal
    feature_record = decision.feature_record
    
    # If risk is very high (>90), likely attack
    if decision.risk_score >= 90:
        return "likely_attack", "high"
    
    # If risk is very low (<20), likely normal
    if decision.risk_score < 20:
        return "likely_normal", "high"
    
    # Use feature patterns for uncertain cases
    if feature_record.failed_ratio < 0.2:
        return "likely_normal", "medium"
    
    if feature_record.failed_ratio > 0.8:
        return "likely_attack", "medium"
    
    # Burst of failures
    if feature_record.failed_count >= 8 and feature_record.request_rate >= 0.1:
        return "likely_attack", "medium"
    
    # Default: unknown
    return "unknown", "low"


def _compute_confidence_metrics(
    decision: PipelineDecision,
    previous_decision: PipelineDecision | None = None,
) -> ConfidenceMetrics:
    """Compute confidence score for a decision.
    
    Args:
        decision: Current pipeline decision
        previous_decision: Previous decision (for stability check)
    
    Returns:
        ConfidenceMetrics with component scores
    """
    # 1. Agreement: Rule and anomaly consistency
    rule_high = decision.rule_score >= 70
    anomaly_high = decision.anomaly_score is not None and decision.anomaly_score >= 0.7
    
    if (rule_high and anomaly_high) or (not rule_high and not anomaly_high):
        agreement = 1.0
    else:
        agreement = 0.3  # Disagreement reduces confidence
    
    # 2. Stability: Consistency with previous window
    if previous_decision is not None:
        risk_diff = abs(decision.risk_score - previous_decision.risk_score)
        # If change < 10 points, high stability
        stability = max(0.0, 1.0 - (risk_diff / 100.0))
    else:
        stability = 0.5  # No previous data, medium stability
    
    # 3. Signal strength: How extreme are the values?
    # High signal = clear decision, low signal = ambiguous
    rule_extremity = min(1.0, max(decision.rule_score / 100.0, 1.0 - decision.rule_score / 100.0))
    
    if decision.anomaly_score is not None:
        anomaly_extremity = min(1.0, max(decision.anomaly_score, 1.0 - decision.anomaly_score))
        signal_strength = (rule_extremity + anomaly_extremity) / 2.0
    else:
        signal_strength = rule_extremity
    
    # Composite confidence: weighted combination
    composite = (agreement * 0.4) + (stability * 0.3) + (signal_strength * 0.3)
    
    return ConfidenceMetrics(
        agreement=round(agreement, 2),
        stability=round(stability, 2),
        signal_strength=round(signal_strength, 2),
        composite_confidence=round(composite, 2),
    )


def analyze_decisions(
    decisions: Iterable[PipelineDecision],
) -> tuple[list[FailureCase], list[ConfidenceMetrics]]:
    """Analyze decisions to identify failures and compute confidence.
    
    Args:
        decisions: Stream of pipeline decisions
    
    Returns:
        (failure_cases, confidence_metrics)
    """
    failure_cases: list[FailureCase] = []
    confidence_metrics: list[ConfidenceMetrics] = []
    
    decisions_list = sorted(decisions, key=lambda d: (d.feature_record.ip, d.feature_record.timestamp))
    
    prev_decision: PipelineDecision | None = None
    
    for decision in decisions_list:
        # Compute confidence
        conf = _compute_confidence_metrics(decision, prev_decision)
        confidence_metrics.append(conf)
        
        # Classify likelihood
        likelihood, confidence_label = _classify_activity_likelihood(decision)
        
        # Identify failure cases
        record = decision.feature_record
        
        # Case 1: False Positive (likely normal but flagged as high risk)
        if likelihood == "likely_normal" and decision.risk_score >= 60:
            failure_cases.append(
                FailureCase(
                    timestamp=record.timestamp,
                    ip=record.ip,
                    case_type="false_positive",
                    risk_score=decision.risk_score,
                    rule_score=decision.rule_score,
                    anomaly_score=decision.anomaly_score,
                    description=f"Normal activity flagged as high risk (score={decision.risk_score})",
                    evidence=f"failed_ratio={record.failed_ratio:.2f}, event_count={record.event_count}, action={decision.action}",
                )
            )
        
        # Case 2: False Negative (likely attack but low risk)
        if likelihood == "likely_attack" and decision.risk_score < 40:
            failure_cases.append(
                FailureCase(
                    timestamp=record.timestamp,
                    ip=record.ip,
                    case_type="false_negative",
                    risk_score=decision.risk_score,
                    rule_score=decision.rule_score,
                    anomaly_score=decision.anomaly_score,
                    description=f"Suspicious activity missed (score={decision.risk_score})",
                    evidence=f"failed_count={record.failed_count}, failed_ratio={record.failed_ratio:.2f}, action={decision.action}",
                )
            )
        
        # Case 3: Low Confidence (disagreement between rule and anomaly)
        if conf.composite_confidence < 0.5:
            failure_cases.append(
                FailureCase(
                    timestamp=record.timestamp,
                    ip=record.ip,
                    case_type="low_confidence",
                    risk_score=decision.risk_score,
                    rule_score=decision.rule_score,
                    anomaly_score=decision.anomaly_score,
                    description=f"Low confidence decision (confidence={conf.composite_confidence})",
                    evidence=f"rule_score={decision.rule_score}, anomaly_score={decision.anomaly_score}, agreement={conf.agreement}",
                )
            )
        
        # Case 4: Unusual pattern (extreme values in feature space)
        if record.failed_count >= 10 or record.request_rate >= 0.3 or record.username_variance <= 1:
            if likelihood == "unknown":
                failure_cases.append(
                    FailureCase(
                        timestamp=record.timestamp,
                        ip=record.ip,
                        case_type="unusual_pattern",
                        risk_score=decision.risk_score,
                        rule_score=decision.rule_score,
                        anomaly_score=decision.anomaly_score,
                        description=f"Unusual pattern detected (score={decision.risk_score})",
                        evidence=f"failed_count={record.failed_count}, request_rate={record.request_rate:.3f}, variance={record.username_variance}",
                    )
                )
        
        prev_decision = decision
    
    return failure_cases, confidence_metrics


def write_validation_traces(
    decisions: Iterable[PipelineDecision],
    output_path: Path,
) -> None:
    """Write detailed validation traces to CSV.
    
    Args:
        decisions: Stream of pipeline decisions
        output_path: Path to write CSV
    """
    decisions_list = sorted(decisions, key=lambda d: (d.feature_record.ip, d.feature_record.timestamp))
    
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp", "ip", "failed_count", "request_rate", "username_variance",
            "failed_ratio", "event_count", "rule_score", "anomaly_score", "risk_score",
            "action", "confidence_score", "agreement", "stability", "signal_strength",
            "reasons_summary"
        ])
        
        prev_decision: PipelineDecision | None = None
        
        for decision in decisions_list:
            record = decision.feature_record
            conf = _compute_confidence_metrics(decision, prev_decision)
            
            reasons_str = " | ".join(decision.reasons) if decision.reasons else "no_reasons"
            
            writer.writerow([
                record.timestamp.isoformat(sep=" "),
                record.ip,
                record.failed_count,
                round(record.request_rate, 3),
                record.username_variance,
                round(record.failed_ratio, 2),
                record.event_count,
                decision.rule_score,
                round(decision.anomaly_score, 3) if decision.anomaly_score else "None",
                round(decision.risk_score, 2),
                decision.action,
                conf.composite_confidence,
                conf.agreement,
                conf.stability,
                conf.signal_strength,
                reasons_str[:100],  # Truncate for readability
            ])
            
            prev_decision = decision


def generate_validation_summary(
    decisions: Iterable[PipelineDecision],
    failure_cases: list[FailureCase],
    confidence_metrics: list[ConfidenceMetrics],
) -> ValidationSummary:
    """Generate summary of validation analysis.
    
    Args:
        decisions: All decisions analyzed
        failure_cases: Identified failures
        confidence_metrics: Confidence scores
    
    Returns:
        ValidationSummary with analysis results
    """
    decisions_list = list(decisions)
    total = len(decisions_list)
    
    # Compute statistics
    mean_confidence = (
        sum(c.composite_confidence for c in confidence_metrics) / len(confidence_metrics)
        if confidence_metrics else 0.0
    )
    high_confidence_count = sum(1 for c in confidence_metrics if c.composite_confidence > 0.8)
    high_confidence_ratio = high_confidence_count / len(confidence_metrics) if confidence_metrics else 0.0
    
    # Classify failure cases
    fp_count = sum(1 for f in failure_cases if f.case_type == "false_positive")
    fn_count = sum(1 for f in failure_cases if f.case_type == "false_negative")
    lc_count = sum(1 for f in failure_cases if f.case_type == "low_confidence")
    up_count = sum(1 for f in failure_cases if f.case_type == "unusual_pattern")
    
    # Distribution shift detection (compare with calibration data)
    mean_risk = sum(d.risk_score for d in decisions_list) / total if total > 0 else 0
    mean_failed_ratio = sum(d.feature_record.failed_ratio for d in decisions_list) / total if total > 0 else 0
    
    distribution_shift = {}
    if mean_risk > 60:
        distribution_shift["risk_elevation"] = f"Mean risk {mean_risk:.1f} (higher than typical synthetic)"
    if mean_failed_ratio > 0.7:
        distribution_shift["failure_heavy"] = f"Mean failed_ratio {mean_failed_ratio:.2f}"
    
    # Key findings
    findings: list[str] = [
        f"Analyzed {total} feature windows across {len(set(d.feature_record.ip for d in decisions_list))} unique IPs",
        f"Mean confidence: {mean_confidence:.2f}, High confidence ratio: {high_confidence_ratio:.1%}",
        f"Failure cases: {len(failure_cases)} ({fp_count} FP, {fn_count} FN, {lc_count} low-conf, {up_count} unusual)",
    ]
    
    if mean_confidence < 0.6:
        findings.append("⚠️  Low average confidence - system decision quality is questionable")
    
    if fp_count > total * 0.1:
        findings.append(f"⚠️  High false positive rate ({fp_count}/{total}) - too aggressive?")
    
    if fn_count > total * 0.05:
        findings.append(f"⚠️  False negatives detected - system missing real threats")
    
    return ValidationSummary(
        total_decisions=total,
        failure_cases=failure_cases,
        mean_confidence=round(mean_confidence, 2),
        high_confidence_ratio=round(high_confidence_ratio, 2),
        distribution_shift=distribution_shift,
        key_findings=findings,
    )
