from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True, frozen=True)
class SIEMEvent:
    timestamp: datetime
    ip: str | None
    source_type: str
    event_type: str
    raw_message: str

@dataclass(slots=True, frozen=True)
class SshAuthEvent(SIEMEvent):
    line_number: int
    host: str
    process: str
    pid: int | None
    session_id: str | None
    outcome: str
    username: str | None
    port: int | None
    is_attempt: bool

@dataclass(slots=True, frozen=True)
class NginxAccessEvent(SIEMEvent):
    method: str
    endpoint: str
    status_code: int
    user_agent: str

@dataclass(slots=True, frozen=True)
class SyslogEvent(SIEMEvent):
    host: str
    process: str
    severity: str

@dataclass(slots=True, frozen=True)
class SshAuthAttempt:
    attempt_id: str
    timestamp: datetime
    ip: str
    port: int | None
    session_id: str | None
    outcome: str
    primary_username: str | None
    usernames: tuple[str, ...]
    source_event_types: tuple[str, ...]
    event_count: int

@dataclass(slots=True, frozen=True)
class FeatureRecord:
    timestamp: datetime
    ip: str
    
    # SSH Features
    ssh_failed_count: int = 0
    ssh_request_rate: float = 0.0
    ssh_username_variance: int = 0
    ssh_inter_arrival_avg: float | None = None
    ssh_failed_ratio: float = 0.0
    ssh_total_attempts: int = 0
    
    # HTTP/Nginx Features
    http_404_count: int = 0
    http_request_rate: float = 0.0
    http_unique_endpoints: int = 0
    http_total_requests: int = 0
    
    # Global/Combined Features (Maintained for backward compatibility)
    failed_count: int = 0
    request_rate: float = 0.0
    username_variance: int = 0
    inter_arrival_avg: float | None = None
    failed_ratio: float = 0.0
    event_count: int = 0
    total_attempts: int = 0

    def as_dict(self) -> dict[str, str | int | float | None]:
        return {
            "timestamp": self.timestamp.isoformat(sep=" "),
            "ip": self.ip,
            "failed_count": self.failed_count,
            "request_rate": self.request_rate,
            "username_variance": self.username_variance,
            "inter_arrival_avg": self.inter_arrival_avg,
            "failed_ratio": self.failed_ratio,
            "event_count": self.event_count,
            "ssh_failed_count": self.ssh_failed_count,
            "http_404_count": self.http_404_count,
            "http_total_requests": self.http_total_requests,
        }
