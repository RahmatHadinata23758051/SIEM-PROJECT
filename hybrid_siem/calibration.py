from __future__ import annotations

from dataclasses import asdict, dataclass
from statistics import median
from typing import Any

import numpy as np

from hybrid_siem.detection import RuleThresholds
from hybrid_siem.models import FeatureRecord

FEATURE_NAMES = (
    "failed_count",
    "request_rate",
    "username_variance",
    "inter_arrival_avg",
    "failed_ratio",
    "event_count",
)


@dataclass(slots=True, frozen=True)
class FeatureStats:
    mean: float
    median: float
    std: float
    percentiles: dict[int, float]
    histogram_counts: tuple[int, ...]
    histogram_edges: tuple[float, ...]


@dataclass(slots=True, frozen=True)
class DatasetFeatureAnalysis:
    label: str
    row_count: int
    feature_stats: dict[str, FeatureStats]


@dataclass(slots=True, frozen=True)
class CorrelationReport:
    feature_to_feature: dict[str, dict[str, float]]
    feature_to_risk: dict[str, float]


@dataclass(slots=True, frozen=True)
class ThresholdCalibrationReport:
    thresholds: RuleThresholds
    source_label: str
    baseline_row_count: int
    calibrated_row_count: int
    selection_strategy: str
    percentiles_used: dict[str, dict[int, float]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_label": self.source_label,
            "baseline_row_count": self.baseline_row_count,
            "calibrated_row_count": self.calibrated_row_count,
            "selection_strategy": self.selection_strategy,
            "thresholds": asdict(self.thresholds),
            "percentiles_used": self.percentiles_used,
        }


def _extract_feature_values(records: list[FeatureRecord], feature_name: str) -> list[float]:
    values: list[float] = []
    for record in records:
        value = getattr(record, feature_name)
        if value is None:
            continue
        values.append(float(value))
    return values


def _build_feature_stats(values: list[float], histogram_bins: int) -> FeatureStats:
    if not values:
        return FeatureStats(
            mean=0.0,
            median=0.0,
            std=0.0,
            percentiles={50: 0.0, 75: 0.0, 90: 0.0, 95: 0.0, 99: 0.0},
            histogram_counts=tuple(0 for _ in range(histogram_bins)),
            histogram_edges=tuple(0.0 for _ in range(histogram_bins + 1)),
        )

    array = np.asarray(values, dtype=float)
    histogram_counts, histogram_edges = np.histogram(array, bins=histogram_bins)
    percentiles = {bucket: float(np.percentile(array, bucket)) for bucket in (50, 75, 90, 95, 99)}
    return FeatureStats(
        mean=float(np.mean(array)),
        median=float(median(values)),
        std=float(np.std(array)),
        percentiles=percentiles,
        histogram_counts=tuple(int(value) for value in histogram_counts.tolist()),
        histogram_edges=tuple(float(value) for value in histogram_edges.tolist()),
    )


def analyze_feature_distribution(
    records: list[FeatureRecord],
    label: str,
    histogram_bins: int = 10,
) -> DatasetFeatureAnalysis:
    if histogram_bins <= 0:
        raise ValueError("histogram_bins must be greater than zero")

    feature_stats = {
        feature_name: _build_feature_stats(_extract_feature_values(records, feature_name), histogram_bins)
        for feature_name in FEATURE_NAMES
    }
    return DatasetFeatureAnalysis(label=label, row_count=len(records), feature_stats=feature_stats)


def select_likely_normal_records(records: list[FeatureRecord]) -> list[FeatureRecord]:
    if not records:
        return []

    conservative = [
        record
        for record in records
        if record.failed_ratio <= 0.25
        and record.failed_count <= 2
        and record.username_variance <= 2
        and record.event_count <= 3
        and (record.inter_arrival_avg is None or record.inter_arrival_avg >= 8.0)
    ]
    if len(conservative) >= max(50, int(len(records) * 0.05)):
        return conservative

    fallback = [
        record
        for record in records
        if record.failed_ratio <= 0.5
        and record.failed_count <= 4
        and record.username_variance <= 3
        and record.event_count <= 5
    ]
    return fallback or list(records)


def calibrate_rule_thresholds_from_normal(
    normal_records: list[FeatureRecord],
    source_label: str = "normal",
) -> ThresholdCalibrationReport:
    if not normal_records:
        raise ValueError("normal_records must not be empty")

    calibrated_records = select_likely_normal_records(normal_records)
    percentiles_used = {
        feature_name: analyze_feature_distribution(calibrated_records, source_label).feature_stats[feature_name].percentiles
        for feature_name in FEATURE_NAMES
    }
    request_rate_p = percentiles_used["request_rate"]
    failed_count_p = percentiles_used["failed_count"]
    username_variance_p = percentiles_used["username_variance"]
    failed_ratio_p = percentiles_used["failed_ratio"]
    event_count_p = percentiles_used["event_count"]

    inter_arrival_values = _extract_feature_values(calibrated_records, "inter_arrival_avg")
    if inter_arrival_values:
        inter_arrival_fast_low = float(np.percentile(inter_arrival_values, 10))
        inter_arrival_fast_medium = float(np.percentile(inter_arrival_values, 5))
        inter_arrival_fast_high = float(np.percentile(inter_arrival_values, 1))
    else:
        inter_arrival_fast_low = 6.0
        inter_arrival_fast_medium = 3.0
        inter_arrival_fast_high = 1.5

    thresholds = RuleThresholds(
        failed_count_low=max(2, int(np.ceil(failed_count_p[95]))),
        failed_count_medium=max(4, int(np.ceil(max(failed_count_p[99], failed_count_p[95] + 2)))),
        failed_count_high=max(8, int(np.ceil(max(failed_count_p[99] * 1.5, failed_count_p[95] + 6)))),
        request_rate_low=round(max(0.04, request_rate_p[95]), 4),
        request_rate_medium=round(max(0.08, request_rate_p[99], request_rate_p[95] * 1.5), 4),
        request_rate_high=round(max(0.16, request_rate_p[99] * 2, request_rate_p[95] * 2), 4),
        username_variance_low=max(2, int(np.ceil(max(2.0, username_variance_p[95])))),
        username_variance_medium=max(4, int(np.ceil(max(username_variance_p[99] + 1, username_variance_p[95] + 2)))),
        username_variance_high=max(8, int(np.ceil(max(username_variance_p[99] + 4, username_variance_p[95] + 6)))),
        failed_ratio_low=round(min(0.85, max(0.6, failed_ratio_p[95] + 0.2)), 4),
        failed_ratio_medium=round(min(0.95, max(0.8, failed_ratio_p[99] + 0.3)), 4),
        failed_ratio_high=round(min(0.99, max(0.92, failed_ratio_p[99] + 0.45)), 4),
        event_count_low=max(3, int(np.ceil(max(3.0, event_count_p[95])))),
        event_count_medium=max(6, int(np.ceil(max(event_count_p[99] + 2, event_count_p[95] + 4)))),
        event_count_high=max(12, int(np.ceil(max(event_count_p[99] * 2, event_count_p[95] + 10)))),
        inter_arrival_fast_low=round(min(12.0, max(6.0, inter_arrival_fast_low)), 4),
        inter_arrival_fast_medium=round(min(6.0, max(3.0, inter_arrival_fast_medium)), 4),
        inter_arrival_fast_high=round(min(3.0, max(1.0, inter_arrival_fast_high)), 4),
        slow_attack_failed_count=max(2, min(4, int(np.ceil(max(2.0, failed_count_p[95]))))),
        slow_attack_failed_ratio=round(min(0.95, max(0.8, failed_ratio_p[90] + 0.2)), 4),
        slow_attack_request_rate_max=round(max(0.05, request_rate_p[50], request_rate_p[75]), 4),
        slow_attack_inter_arrival_min=round(min(20.0, max(10.0, float(np.percentile(inter_arrival_values, 50)))), 4)
        if inter_arrival_values
        else 15.0,
    )
    return ThresholdCalibrationReport(
        thresholds=thresholds,
        source_label=source_label,
        baseline_row_count=len(normal_records),
        calibrated_row_count=len(calibrated_records),
        selection_strategy="likely_normal_subset",
        percentiles_used=percentiles_used,
    )


def compute_feature_correlations(
    records: list[FeatureRecord],
    risk_scores: list[float] | None = None,
) -> CorrelationReport:
    if not records:
        return CorrelationReport(feature_to_feature={}, feature_to_risk={})

    feature_arrays = {
        feature_name: np.asarray(
            [
                float(getattr(record, feature_name))
                for record in records
                if getattr(record, feature_name) is not None
            ],
            dtype=float,
        )
        for feature_name in FEATURE_NAMES
    }

    feature_to_feature: dict[str, dict[str, float]] = {}
    for left_name in FEATURE_NAMES:
        feature_to_feature[left_name] = {}
        left_values = np.asarray(
            [float(getattr(record, left_name) or 0.0) for record in records],
            dtype=float,
        )
        for right_name in FEATURE_NAMES:
            right_values = np.asarray(
                [float(getattr(record, right_name) or 0.0) for record in records],
                dtype=float,
            )
            correlation = float(np.corrcoef(left_values, right_values)[0, 1]) if len(records) > 1 else 0.0
            feature_to_feature[left_name][right_name] = 0.0 if np.isnan(correlation) else round(correlation, 4)

    feature_to_risk: dict[str, float] = {}
    if risk_scores is not None and len(risk_scores) == len(records) and len(records) > 1:
        risk_array = np.asarray(risk_scores, dtype=float)
        for feature_name in FEATURE_NAMES:
            feature_values = np.asarray(
                [float(getattr(record, feature_name) or 0.0) for record in records],
                dtype=float,
            )
            correlation = float(np.corrcoef(feature_values, risk_array)[0, 1])
            feature_to_risk[feature_name] = 0.0 if np.isnan(correlation) else round(correlation, 4)
    else:
        feature_to_risk = {feature_name: 0.0 for feature_name in FEATURE_NAMES}

    return CorrelationReport(feature_to_feature=feature_to_feature, feature_to_risk=feature_to_risk)
