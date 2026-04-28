from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterable

from hybrid_siem.models import FeatureRecord, SshAuthEvent


def _floor_window(timestamp: datetime, window_seconds: int) -> datetime:
    day_start = timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
    seconds_since_day_start = int((timestamp - day_start).total_seconds())
    floored_seconds = seconds_since_day_start - (seconds_since_day_start % window_seconds)
    return day_start + timedelta(seconds=floored_seconds)


def build_feature_records(
    events: Iterable[SshAuthEvent],
    window_seconds: int = 60,
) -> list[FeatureRecord]:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than zero")

    grouped: dict[tuple[datetime, str], list[SshAuthEvent]] = defaultdict(list)

    for event in sorted(events, key=lambda item: item.timestamp):
        if not event.is_attempt or not event.ip:
            continue

        window_start = _floor_window(event.timestamp, window_seconds)
        grouped[(window_start, event.ip)].append(event)

    features: list[FeatureRecord] = []
    for (window_start, ip), window_events in sorted(grouped.items(), key=lambda item: (item[0][0], item[0][1])):
        ordered_events = sorted(window_events, key=lambda item: item.timestamp)
        total_attempts = len(ordered_events)
        failed_count = sum(event.outcome == "failure" for event in ordered_events)
        usernames = {event.username for event in ordered_events if event.username}

        if total_attempts > 1:
            deltas = [
                (current.timestamp - previous.timestamp).total_seconds()
                for previous, current in zip(ordered_events, ordered_events[1:])
            ]
            inter_arrival_avg = round(sum(deltas) / len(deltas), 4)
        else:
            inter_arrival_avg = float(window_seconds)

        features.append(
            FeatureRecord(
                timestamp=window_start,
                ip=ip,
                failed_count=failed_count,
                request_rate=round(total_attempts / window_seconds, 4),
                username_variance=len(usernames),
                inter_arrival_avg=inter_arrival_avg,
                failed_ratio=round(failed_count / total_attempts, 4),
                total_attempts=total_attempts,
            )
        )

    return features
