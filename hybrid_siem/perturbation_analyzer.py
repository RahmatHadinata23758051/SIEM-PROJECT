"""Perturbation analysis for anomaly model sensitivity testing."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import numpy as np

from hybrid_siem.models import FeatureRecord


@dataclass(slots=True, frozen=True)
class PerturbationResult:
    """Result of perturbing one feature.
    
    Attributes:
        feature_name: Name of feature that was perturbed
        baseline_score: Original anomaly score
        perturbed_scores: Anomaly scores after perturbation
        sensitivity: How much the score changed (std of differences)
        max_change: Maximum change observed
        significance: Whether sensitivity is high (>0.1) or low
    """
    feature_name: str
    baseline_score: float
    perturbed_scores: tuple[float, ...]
    sensitivity: float
    max_change: float
    significance: str


class PerturbationAnalyzer:
    """Analyze anomaly model sensitivity through feature perturbation."""
    
    def __init__(self, perturbation_magnitudes: tuple[float, ...] = (0.5, 1.5, 2.0)):
        """Initialize with perturbation magnitudes.
        
        Args:
            perturbation_magnitudes: Multipliers to apply to feature values
        """
        self.perturbation_magnitudes = perturbation_magnitudes
    
    def analyze_feature_sensitivity(
        self,
        record: FeatureRecord,
        anomaly_detector,
    ) -> list[PerturbationResult]:
        """Analyze sensitivity of anomaly score to each feature.
        
        Args:
            record: Feature record to analyze
            anomaly_detector: Fitted anomaly detector
        
        Returns:
            List of perturbation results for each feature
        """
        results: list[PerturbationResult] = []
        
        # Get baseline score
        baseline_scores = anomaly_detector.score_lookup([record])
        baseline_score = baseline_scores.get((record.ip, record.timestamp), 0.0)
        if hasattr(baseline_score, "smoothed_score"):
            baseline_score = baseline_score.smoothed_score
        
        # Features to analyze
        features_to_test = [
            ("failed_count", record.failed_count),
            ("request_rate", record.request_rate),
            ("username_variance", record.username_variance),
            ("inter_arrival_avg", record.inter_arrival_avg),
            ("failed_ratio", record.failed_ratio),
            ("event_count", record.event_count),
        ]
        
        for feature_name, feature_value in features_to_test:
            if feature_value is None:
                continue
            
            perturbed_scores: list[float] = []
            
            for magnitude in self.perturbation_magnitudes:
                # Create perturbed record
                perturbed_value = feature_value * magnitude
                
                # Create modified record
                perturbed_record = _create_perturbed_record(record, feature_name, perturbed_value)
                
                # Score the perturbed record
                perturbed_score_dict = anomaly_detector.score_lookup([perturbed_record])
                perturbed_score = perturbed_score_dict.get((perturbed_record.ip, perturbed_record.timestamp), 0.0)
                
                if hasattr(perturbed_score, "smoothed_score"):
                    perturbed_score = perturbed_score.smoothed_score
                
                perturbed_scores.append(float(perturbed_score))
            
            # Calculate sensitivity
            perturbed_array = np.array(perturbed_scores)
            sensitivity = float(np.std(perturbed_array))
            max_change = float(np.max(np.abs(perturbed_array - baseline_score)))
            
            # Determine significance
            significance = "high" if sensitivity > 0.1 else "low"
            
            results.append(
                PerturbationResult(
                    feature_name=feature_name,
                    baseline_score=round(baseline_score, 3),
                    perturbed_scores=tuple(round(s, 3) for s in perturbed_scores),
                    sensitivity=round(sensitivity, 3),
                    max_change=round(max_change, 3),
                    significance=significance,
                )
            )
        
        return results


def _create_perturbed_record(
    original: FeatureRecord,
    feature_name: str,
    new_value: float,
) -> FeatureRecord:
    """Create a copy of record with one feature perturbed.
    
    Args:
        original: Original feature record
        feature_name: Name of feature to change
        new_value: New value for the feature
    
    Returns:
        Modified FeatureRecord
    """
    if feature_name == "failed_count":
        return FeatureRecord(
            timestamp=original.timestamp,
            ip=original.ip,
            failed_count=int(max(0, new_value)),
            request_rate=original.request_rate,
            username_variance=original.username_variance,
            inter_arrival_avg=original.inter_arrival_avg,
            failed_ratio=original.failed_ratio,
            event_count=original.event_count,
            total_attempts=original.total_attempts,
        )
    elif feature_name == "request_rate":
        return FeatureRecord(
            timestamp=original.timestamp,
            ip=original.ip,
            failed_count=original.failed_count,
            request_rate=max(0.0, new_value),
            username_variance=original.username_variance,
            inter_arrival_avg=original.inter_arrival_avg,
            failed_ratio=original.failed_ratio,
            event_count=original.event_count,
            total_attempts=original.total_attempts,
        )
    elif feature_name == "username_variance":
        return FeatureRecord(
            timestamp=original.timestamp,
            ip=original.ip,
            failed_count=original.failed_count,
            request_rate=original.request_rate,
            username_variance=int(max(1, new_value)),
            inter_arrival_avg=original.inter_arrival_avg,
            failed_ratio=original.failed_ratio,
            event_count=original.event_count,
            total_attempts=original.total_attempts,
        )
    elif feature_name == "inter_arrival_avg":
        return FeatureRecord(
            timestamp=original.timestamp,
            ip=original.ip,
            failed_count=original.failed_count,
            request_rate=original.request_rate,
            username_variance=original.username_variance,
            inter_arrival_avg=max(0.0, new_value) if new_value is not None else None,
            failed_ratio=original.failed_ratio,
            event_count=original.event_count,
            total_attempts=original.total_attempts,
        )
    elif feature_name == "failed_ratio":
        return FeatureRecord(
            timestamp=original.timestamp,
            ip=original.ip,
            failed_count=original.failed_count,
            request_rate=original.request_rate,
            username_variance=original.username_variance,
            inter_arrival_avg=original.inter_arrival_avg,
            failed_ratio=max(0.0, min(1.0, new_value)),
            event_count=original.event_count,
            total_attempts=original.total_attempts,
        )
    elif feature_name == "event_count":
        return FeatureRecord(
            timestamp=original.timestamp,
            ip=original.ip,
            failed_count=original.failed_count,
            request_rate=original.request_rate,
            username_variance=original.username_variance,
            inter_arrival_avg=original.inter_arrival_avg,
            failed_ratio=original.failed_ratio,
            event_count=int(max(0, new_value)),
            total_attempts=original.total_attempts,
        )
    else:
        return original
