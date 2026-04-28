from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True, frozen=True)
class SshAuthEvent:
    line_number: int
    timestamp: datetime
    host: str
    process: str
    pid: int | None
    event_type: str
    outcome: str
    ip: str | None
    username: str | None
    port: int | None
    raw_message: str
    is_attempt: bool


@dataclass(slots=True, frozen=True)
class FeatureRecord:
    timestamp: datetime
    ip: str
    failed_count: int
    request_rate: float
    username_variance: int
    inter_arrival_avg: float
    failed_ratio: float
    total_attempts: int

    def as_dict(self) -> dict[str, str | int | float]:
        return {
            "timestamp": self.timestamp.isoformat(sep=" "),
            "ip": self.ip,
            "failed_count": self.failed_count,
            "request_rate": self.request_rate,
            "username_variance": self.username_variance,
            "inter_arrival_avg": self.inter_arrival_avg,
            "failed_ratio": self.failed_ratio,
        }
