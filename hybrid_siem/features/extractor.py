from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterable

from hybrid_siem.models import FeatureRecord, SshAuthAttempt, SshAuthEvent
from hybrid_siem.normalization import build_canonical_attempts


def _floor_window(timestamp: datetime, window_seconds: int) -> datetime:
    day_start = timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
    seconds_since_day_start = int((timestamp - day_start).total_seconds())
    floored_seconds = seconds_since_day_start - (seconds_since_day_start % window_seconds)
    return day_start + timedelta(seconds=floored_seconds)


def build_feature_records(
    events: Iterable[SshAuthEvent] | Iterable[SshAuthAttempt],
    window_seconds: int = 60,
) -> list[FeatureRecord]:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than zero")

    event_list = list(events)
    if not event_list:
        return []

    if isinstance(event_list[0], SshAuthEvent):
        attempts = build_canonical_attempts(event_list)
    else:
        attempts = sorted(event_list, key=lambda item: item.timestamp)

    grouped: dict[tuple[datetime, str], list[SshAuthAttempt]] = defaultdict(list)
    for attempt in sorted(attempts, key=lambda item: item.timestamp):
        window_start = _floor_window(attempt.timestamp, window_seconds)
        grouped[(window_start, attempt.ip)].append(attempt)

    features: list[FeatureRecord] = []
    for (window_start, ip), window_attempts in sorted(grouped.items(), key=lambda item: (item[0][0], item[0][1])):
        ordered_attempts = sorted(window_attempts, key=lambda item: item.timestamp)
        total_attempts = len(ordered_attempts)
        failed_count = sum(attempt.outcome == "failure" for attempt in ordered_attempts)
        usernames = {attempt.primary_username for attempt in ordered_attempts if attempt.primary_username}
        event_count = sum(attempt.event_count for attempt in ordered_attempts)

        if total_attempts > 1:
            deltas = [
                (current.timestamp - previous.timestamp).total_seconds()
                for previous, current in zip(ordered_attempts, ordered_attempts[1:])
            ]
            inter_arrival_avg = round(sum(deltas) / len(deltas), 4)
        else:
            inter_arrival_avg = None

        features.append(
            FeatureRecord(
                timestamp=window_start,
                ip=ip,
                failed_count=failed_count,
                request_rate=round(total_attempts / window_seconds, 4),
                username_variance=len(usernames),
                inter_arrival_avg=inter_arrival_avg,
                failed_ratio=round(failed_count / total_attempts, 4),
                event_count=event_count,
                total_attempts=total_attempts,
            )
        )

    return features
