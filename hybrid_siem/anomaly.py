from __future__ import annotations

import math
import pickle
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler, StandardScaler

from hybrid_siem.calibration import select_likely_normal_records
from hybrid_siem.models import FeatureRecord

ANOMALY_FEATURE_CANDIDATES = (
    "failed_count",
    "username_variance",
    "inter_arrival_avg",
    "failed_ratio",
    "event_count",
)

DEFAULT_ANOMALY_FEATURES = (
    "failed_count",
    "username_variance",
    "inter_arrival_avg",
    "failed_ratio",
)


@dataclass(slots=True, frozen=True)
class IsolationForestConfig:
    feature_names: tuple[str, ...] = DEFAULT_ANOMALY_FEATURES
    include_event_count: bool = False
    scaler: str = "standard"
    contamination: float = 0.03
    n_estimators: int = 200
    smoothing_alpha: float = 0.35
    smoothing_window_seconds: int = 60
    normalization_low_quantile: float = 0.75
    normalization_high_quantile: float = 0.995
    random_state: int = 42

    def __post_init__(self) -> None:
        if not 0.0 < self.contamination < 0.5:
            raise ValueError("contamination must be between 0 and 0.5")
        if self.n_estimators <= 0:
            raise ValueError("n_estimators must be greater than zero")
        if self.scaler not in {"standard", "minmax"}:
            raise ValueError("scaler must be either 'standard' or 'minmax'")
        if not 0.0 < self.smoothing_alpha <= 1.0:
            raise ValueError("smoothing_alpha must be between 0 and 1")
        if self.smoothing_window_seconds <= 0:
            raise ValueError("smoothing_window_seconds must be greater than zero")
        if not 0.0 <= self.normalization_low_quantile < self.normalization_high_quantile <= 1.0:
            raise ValueError("normalization quantiles must satisfy 0 <= low < high <= 1")


@dataclass(slots=True, frozen=True)
class AnomalyTrainingReport:
    source_label: str
    baseline_row_count: int
    trained_row_count: int
    selection_strategy: str
    feature_names: tuple[str, ...]
    imputation_values: dict[str, float]
    scaler: str
    contamination: float
    n_estimators: int
    smoothing_alpha: float
    normalization_low_quantile: float
    normalization_high_quantile: float

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True, frozen=True)
class AnomalyScore:
    ip: str
    timestamp: datetime
    raw_model_score: float
    anomaly_score: float
    smoothed_score: float


@dataclass(slots=True)
class IsolationForestAnomalyDetector:
    config: IsolationForestConfig
    training_report: AnomalyTrainingReport
    scaler: StandardScaler | MinMaxScaler
    estimator: IsolationForest
    normalization_min: float
    normalization_max: float

    def score_records(self, records: Iterable[FeatureRecord]) -> list[AnomalyScore]:
        ordered_records = sorted(records, key=lambda item: (item.timestamp, item.ip))
        if not ordered_records:
            return []

        matrix = _build_feature_matrix(
            ordered_records,
            feature_names=self.training_report.feature_names,
            imputation_values=self.training_report.imputation_values,
        )
        scaled_matrix = self.scaler.transform(matrix)
        raw_scores = -self.estimator.score_samples(scaled_matrix)
        normalized_scores = _normalize_scores(raw_scores, self.normalization_min, self.normalization_max)
        smoothed_scores = _smooth_scores(
            ordered_records,
            normalized_scores,
            alpha=self.config.smoothing_alpha,
            window_seconds=self.config.smoothing_window_seconds,
        )

        return [
            AnomalyScore(
                ip=record.ip,
                timestamp=record.timestamp,
                raw_model_score=round(float(raw_score), 6),
                anomaly_score=round(float(normalized_score), 4),
                smoothed_score=round(float(smoothed_score), 4),
            )
            for record, raw_score, normalized_score, smoothed_score in zip(
                ordered_records,
                raw_scores,
                normalized_scores,
                smoothed_scores,
            )
        ]

    def score_lookup(self, records: Iterable[FeatureRecord]) -> dict[tuple[str, datetime], AnomalyScore]:
        return {
            (score.ip, score.timestamp): score
            for score in self.score_records(records)
        }

    def save(self, output_path: str | Path) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as handle:
            pickle.dump(self, handle)
        return path

    @classmethod
    def load(cls, model_path: str | Path) -> IsolationForestAnomalyDetector:
        path = Path(model_path)
        with path.open("rb") as handle:
            model = pickle.load(handle)
        if not isinstance(model, cls):
            raise TypeError(f"Expected {cls.__name__} payload, received {type(model)!r}")
        return model


def _resolve_feature_names(config: IsolationForestConfig) -> tuple[str, ...]:
    requested_names = list(config.feature_names)
    if config.include_event_count and "event_count" not in requested_names:
        requested_names.append("event_count")

    feature_names: list[str] = []
    for feature_name in requested_names:
        if feature_name not in ANOMALY_FEATURE_CANDIDATES:
            raise ValueError(
                "feature_names must only include minimally redundant anomaly features: "
                f"{ANOMALY_FEATURE_CANDIDATES}"
            )
        if feature_name not in feature_names:
            feature_names.append(feature_name)

    if not feature_names:
        raise ValueError("feature_names must not be empty")
    return tuple(feature_names)


def _build_imputation_values(records: list[FeatureRecord], feature_names: tuple[str, ...]) -> dict[str, float]:
    imputation_values: dict[str, float] = {}
    for feature_name in feature_names:
        values = [
            float(value)
            for record in records
            if (value := getattr(record, feature_name)) is not None
        ]
        imputation_values[feature_name] = float(np.median(values)) if values else 0.0
    return imputation_values


def _build_feature_matrix(
    records: list[FeatureRecord],
    feature_names: tuple[str, ...],
    imputation_values: dict[str, float],
) -> np.ndarray:
    return np.asarray(
        [
            [
                float(imputation_values[feature_name] if getattr(record, feature_name) is None else getattr(record, feature_name))
                for feature_name in feature_names
            ]
            for record in records
        ],
        dtype=float,
    )


def _build_scaler(scaler_name: str) -> StandardScaler | MinMaxScaler:
    if scaler_name == "minmax":
        return MinMaxScaler()
    return StandardScaler()


def _normalization_bounds(
    raw_scores: np.ndarray,
    threshold_raw_score: float,
    low_quantile: float,
    high_quantile: float,
) -> tuple[float, float]:
    del high_quantile
    lower = max(threshold_raw_score, float(np.quantile(raw_scores, low_quantile)))
    upper = float(np.max(raw_scores))
    if upper <= lower:
        upper = float(np.quantile(raw_scores, 1.0))
    if upper <= lower:
        upper = lower + 1e-6
    return lower, upper


def _normalize_scores(raw_scores: np.ndarray, lower: float, upper: float) -> np.ndarray:
    return np.clip((raw_scores - lower) / max(1e-6, upper - lower), 0.0, 1.0)


def _smooth_scores(
    records: list[FeatureRecord],
    normalized_scores: np.ndarray,
    alpha: float,
    window_seconds: int,
) -> list[float]:
    smoothed: list[float] = []
    state_by_ip: dict[str, tuple[datetime, float]] = {}

    for record, score in zip(records, normalized_scores):
        previous = state_by_ip.get(record.ip)
        if previous is None:
            smoothed_score = float(score)
        else:
            previous_timestamp, previous_score = previous
            gap_seconds = max(0.0, (record.timestamp - previous_timestamp).total_seconds())
            gap_units = max(1.0, gap_seconds / float(window_seconds))
            effective_alpha = 1.0 - math.pow(1.0 - alpha, gap_units)
            smoothed_score = (effective_alpha * float(score)) + ((1.0 - effective_alpha) * previous_score)

        state_by_ip[record.ip] = (record.timestamp, smoothed_score)
        smoothed.append(smoothed_score)

    return smoothed


def fit_isolation_forest(
    records: Iterable[FeatureRecord],
    config: IsolationForestConfig | None = None,
    source_label: str = "normal_like",
) -> IsolationForestAnomalyDetector:
    record_list = list(records)
    if not record_list:
        raise ValueError("records must not be empty")

    config = config or IsolationForestConfig()
    feature_names = _resolve_feature_names(config)
    training_records = select_likely_normal_records(record_list)
    imputation_values = _build_imputation_values(training_records, feature_names)
    training_matrix = _build_feature_matrix(training_records, feature_names, imputation_values)

    scaler = _build_scaler(config.scaler)
    scaled_training_matrix = scaler.fit_transform(training_matrix)
    estimator = IsolationForest(
        contamination=config.contamination,
        n_estimators=config.n_estimators,
        random_state=config.random_state,
    )
    estimator.fit(scaled_training_matrix)

    raw_training_scores = -estimator.score_samples(scaled_training_matrix)
    threshold_raw_score = -float(estimator.offset_)
    normalization_min, normalization_max = _normalization_bounds(
        raw_training_scores,
        threshold_raw_score=threshold_raw_score,
        low_quantile=config.normalization_low_quantile,
        high_quantile=config.normalization_high_quantile,
    )

    training_report = AnomalyTrainingReport(
        source_label=source_label,
        baseline_row_count=len(record_list),
        trained_row_count=len(training_records),
        selection_strategy="likely_normal_subset",
        feature_names=feature_names,
        imputation_values={key: round(value, 6) for key, value in imputation_values.items()},
        scaler=config.scaler,
        contamination=config.contamination,
        n_estimators=config.n_estimators,
        smoothing_alpha=config.smoothing_alpha,
        normalization_low_quantile=config.normalization_low_quantile,
        normalization_high_quantile=config.normalization_high_quantile,
    )
    return IsolationForestAnomalyDetector(
        config=config,
        training_report=training_report,
        scaler=scaler,
        estimator=estimator,
        normalization_min=normalization_min,
        normalization_max=normalization_max,
    )


def load_isolation_forest(model_path: str | Path) -> IsolationForestAnomalyDetector:
    return IsolationForestAnomalyDetector.load(model_path)
