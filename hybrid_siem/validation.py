from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from statistics import fmean, pstdev

from hybrid_siem.models import FeatureRecord

VALIDATION_FEATURES = (
    "failed_count",
    "request_rate",
    "username_variance",
    "inter_arrival_avg",
    "failed_ratio",
    "event_count",
)


@dataclass(slots=True, frozen=True)
class FeatureDistribution:
    mean: float
    std: float
    minimum: float
    maximum: float
    histogram: tuple[int, ...]


@dataclass(slots=True, frozen=True)
class TimelineValidation:
    suspicious_rows: int
    spread_ratio: float
    max_bucket_ratio: float
    appears_interleaved: bool


@dataclass(slots=True, frozen=True)
class DatasetValidationReport:
    row_count: int
    unique_ips: int
    unique_timestamps: int
    distributions: dict[str, FeatureDistribution]
    timeline: TimelineValidation

    def render(self) -> str:
        lines = [
            f"rows={self.row_count}",
            f"unique_ips={self.unique_ips}",
            f"unique_timestamps={self.unique_timestamps}",
            (
                "timeline="
                f"suspicious_rows={self.timeline.suspicious_rows} "
                f"spread_ratio={self.timeline.spread_ratio:.3f} "
                f"max_bucket_ratio={self.timeline.max_bucket_ratio:.3f} "
                f"interleaved={self.timeline.appears_interleaved}"
            ),
        ]
        for feature_name, distribution in self.distributions.items():
            lines.append(
                (
                    f"{feature_name}: mean={distribution.mean:.4f} std={distribution.std:.4f} "
                    f"min={distribution.minimum:.4f} max={distribution.maximum:.4f} "
                    f"hist={list(distribution.histogram)}"
                )
            )
        return "\n".join(lines)


def _histogram(values: list[float], bins: int) -> tuple[int, ...]:
    if not values:
        return tuple(0 for _ in range(bins))

    low = min(values)
    high = max(values)
    if low == high:
        histogram = [0 for _ in range(bins)]
        histogram[-1] = len(values)
        return tuple(histogram)

    width = (high - low) / bins
    histogram = [0 for _ in range(bins)]
    for value in values:
        index = min(bins - 1, int((value - low) / width))
        histogram[index] += 1
    return tuple(histogram)


def _distribution(values: list[float], bins: int) -> FeatureDistribution:
    return FeatureDistribution(
        mean=fmean(values) if values else 0.0,
        std=pstdev(values) if len(values) > 1 else 0.0,
        minimum=min(values) if values else 0.0,
        maximum=max(values) if values else 0.0,
        histogram=_histogram(values, bins),
    )


def validate_feature_records(
    records: list[FeatureRecord],
    histogram_bins: int = 5,
) -> DatasetValidationReport:
    if histogram_bins <= 0:
        raise ValueError("histogram_bins must be greater than zero")

    if not records:
        empty_distribution = {name: _distribution([], histogram_bins) for name in VALIDATION_FEATURES}
        return DatasetValidationReport(
            row_count=0,
            unique_ips=0,
            unique_timestamps=0,
            distributions=empty_distribution,
            timeline=TimelineValidation(suspicious_rows=0, spread_ratio=0.0, max_bucket_ratio=0.0, appears_interleaved=True),
        )

    distributions = {
        "failed_count": _distribution([float(record.failed_count) for record in records], histogram_bins),
        "request_rate": _distribution([record.request_rate for record in records], histogram_bins),
        "username_variance": _distribution([float(record.username_variance) for record in records], histogram_bins),
        "inter_arrival_avg": _distribution(
            [record.inter_arrival_avg for record in records if record.inter_arrival_avg is not None],
            histogram_bins,
        ),
        "failed_ratio": _distribution([record.failed_ratio for record in records], histogram_bins),
        "event_count": _distribution([float(record.event_count) for record in records], histogram_bins),
    }

    suspicious_records = [
        record
        for record in records
        if record.failed_ratio >= 0.9 or record.failed_count >= 5 or record.username_variance >= 4
    ]
    timestamps = sorted(record.timestamp for record in records)
    suspicious_timestamps = sorted(record.timestamp for record in suspicious_records)

    if len(suspicious_timestamps) >= 2 and len(timestamps) >= 2:
        total_span = max(1.0, (timestamps[-1] - timestamps[0]).total_seconds())
        suspicious_span = (suspicious_timestamps[-1] - suspicious_timestamps[0]).total_seconds()
        spread_ratio = round(suspicious_span / total_span, 4)
    else:
        spread_ratio = 1.0 if suspicious_timestamps else 0.0

    buckets: dict[str, int] = {}
    for timestamp in suspicious_timestamps:
        bucket_minute = (timestamp.minute // 15) * 15
        bucket_key = timestamp.replace(minute=bucket_minute, second=0, microsecond=0).strftime("%Y-%m-%d %H:%M")
        buckets[bucket_key] = buckets.get(bucket_key, 0) + 1

    max_bucket_ratio = round(max(buckets.values()) / len(suspicious_timestamps), 4) if suspicious_timestamps else 0.0
    appears_interleaved = spread_ratio >= 0.55 and max_bucket_ratio <= 0.55 if suspicious_timestamps else True

    return DatasetValidationReport(
        row_count=len(records),
        unique_ips=len({record.ip for record in records}),
        unique_timestamps=len({record.timestamp for record in records}),
        distributions=distributions,
        timeline=TimelineValidation(
            suspicious_rows=len(suspicious_records),
            spread_ratio=spread_ratio,
            max_bucket_ratio=max_bucket_ratio,
            appears_interleaved=appears_interleaved,
        ),
    )


def load_feature_records_from_csv(dataset_path: str | Path, window_seconds: int = 60) -> list[FeatureRecord]:
    path = Path(dataset_path)
    records: list[FeatureRecord] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            inter_arrival_raw = row.get("inter_arrival_avg")
            inter_arrival_avg = float(inter_arrival_raw) if inter_arrival_raw not in {None, ""} else None
            inferred_total_attempts = max(1, int(round(float(row["request_rate"]) * window_seconds)))
            event_count_raw = row.get("event_count")
            event_count = int(event_count_raw) if event_count_raw not in {None, ""} else inferred_total_attempts
            records.append(
                FeatureRecord(
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    ip=row["ip"],
                    failed_count=int(row["failed_count"]),
                    request_rate=float(row["request_rate"]),
                    username_variance=int(row["username_variance"]),
                    inter_arrival_avg=inter_arrival_avg,
                    failed_ratio=float(row["failed_ratio"]),
                    event_count=event_count,
                    total_attempts=inferred_total_attempts,
                )
            )
    return records
