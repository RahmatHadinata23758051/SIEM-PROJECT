from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from hybrid_siem.features import build_feature_records
from hybrid_siem.normalization import build_canonical_attempts
from hybrid_siem.parsers import parse_auth_log_file


@dataclass(slots=True, frozen=True)
class DatasetBuildResult:
    parsed_events: int
    counted_attempts: int
    feature_rows: int
    output_path: Path


def write_feature_dataset(rows: list[dict[str, str | int | float]], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "timestamp",
        "ip",
        "failed_count",
        "request_rate",
        "username_variance",
        "inter_arrival_avg",
        "failed_ratio",
        "event_count",
    ]

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return path


def generate_feature_dataset(
    input_path: str | Path,
    output_path: str | Path,
    window_seconds: int = 60,
    reference_time: datetime | None = None,
) -> DatasetBuildResult:
    events = parse_auth_log_file(input_path, reference_time=reference_time)
    canonical_attempts = build_canonical_attempts(events)
    feature_records = build_feature_records(canonical_attempts, window_seconds=window_seconds)
    rows = [record.as_dict() for record in feature_records]
    written_path = write_feature_dataset(rows, output_path)

    return DatasetBuildResult(
        parsed_events=len(events),
        counted_attempts=len(canonical_attempts),
        feature_rows=len(feature_records),
        output_path=written_path,
    )
