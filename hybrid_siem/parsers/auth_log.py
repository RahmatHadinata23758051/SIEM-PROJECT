from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

from hybrid_siem.models import SshAuthEvent

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^\[:]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

IP_FRAGMENT = r"(?P<ip>[0-9A-Fa-f:.]+)"


@dataclass(frozen=True)
class EventPattern:
    event_type: str
    regex: re.Pattern[str]
    outcome: str
    is_attempt: bool


EVENT_PATTERNS = [
    EventPattern(
        event_type="failed_password",
        regex=re.compile(
            rf"^Failed password for invalid user (?P<username>\S+) from {IP_FRAGMENT} port (?P<port>\d+)"
        ),
        outcome="failure",
        is_attempt=True,
    ),
    EventPattern(
        event_type="failed_password",
        regex=re.compile(
            rf"^Failed password for (?P<username>\S+) from {IP_FRAGMENT} port (?P<port>\d+)"
        ),
        outcome="failure",
        is_attempt=True,
    ),
    EventPattern(
        event_type="accepted_auth",
        regex=re.compile(
            rf"^Accepted (?P<method>\S+) for (?P<username>\S+) from {IP_FRAGMENT} port (?P<port>\d+)"
        ),
        outcome="success",
        is_attempt=True,
    ),
    EventPattern(
        event_type="invalid_user",
        regex=re.compile(rf"^Invalid user (?P<username>\S+) from {IP_FRAGMENT} port (?P<port>\d+)"),
        outcome="neutral",
        is_attempt=False,
    ),
    EventPattern(
        event_type="pam_auth_failure",
        regex=re.compile(
            rf"^pam_unix\(sshd:auth\): authentication failure;.*rhost={IP_FRAGMENT}\s+user=(?P<username>\S*)"
        ),
        outcome="failure",
        is_attempt=False,
    ),
    EventPattern(
        event_type="preauth_disconnect",
        regex=re.compile(
            rf"^(?:Connection closed by|Disconnected from) "
            rf"(?:(?:authenticating|invalid) user )?(?P<username>\S+) {IP_FRAGMENT} port (?P<port>\d+)"
        ),
        outcome="neutral",
        is_attempt=False,
    ),
    EventPattern(
        event_type="client_disconnect",
        regex=re.compile(rf"^Received disconnect from {IP_FRAGMENT} port (?P<port>\d+)"),
        outcome="neutral",
        is_attempt=False,
    ),
]


def _build_timestamp(month: str, day: str, clock: str, reference_time: datetime) -> datetime:
    month_number = MONTHS[month]
    hour, minute, second = map(int, clock.split(":"))
    candidate = datetime(reference_time.year, month_number, int(day), hour, minute, second)
    if candidate - reference_time > timedelta(days=1):
        return candidate.replace(year=reference_time.year - 1)
    return candidate


def _normalize_ip(ip: str | None) -> str | None:
    if not ip:
        return None

    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


def _parse_message(
    line_number: int,
    timestamp: datetime,
    host: str,
    process: str,
    pid: int | None,
    message: str,
) -> SshAuthEvent | None:
    for pattern in EVENT_PATTERNS:
        match = pattern.regex.search(message)
        if not match:
            continue

        groups = match.groupdict()
        username = groups.get("username") or None
        ip = _normalize_ip(groups.get("ip"))
        port = int(groups["port"]) if groups.get("port") else None

        return SshAuthEvent(
            line_number=line_number,
            timestamp=timestamp,
            host=host,
            process=process,
            pid=pid,
            event_type=pattern.event_type,
            outcome=pattern.outcome,
            ip=ip,
            username=username,
            port=port,
            raw_message=message,
            is_attempt=pattern.is_attempt and ip is not None,
        )

    return None


def parse_auth_log_lines(
    lines: Iterable[str],
    reference_time: datetime | None = None,
) -> list[SshAuthEvent]:
    reference_time = reference_time or datetime.now()
    events: list[SshAuthEvent] = []

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue

        match = SYSLOG_PATTERN.match(line)
        if not match:
            continue

        process = match.group("process")
        if process != "sshd":
            continue

        timestamp = _build_timestamp(
            month=match.group("month"),
            day=match.group("day"),
            clock=match.group("clock"),
            reference_time=reference_time,
        )
        pid = int(match.group("pid")) if match.group("pid") else None
        event = _parse_message(
            line_number=line_number,
            timestamp=timestamp,
            host=match.group("host"),
            process=process,
            pid=pid,
            message=match.group("message"),
        )
        if event:
            events.append(event)

    return events


def parse_auth_log_file(
    file_path: str | Path,
    reference_time: datetime | None = None,
) -> list[SshAuthEvent]:
    path = Path(file_path)
    with path.open("r", encoding="utf-8") as handle:
        return parse_auth_log_lines(handle, reference_time=reference_time)
