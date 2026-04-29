from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

from hybrid_siem.models import SyslogEvent

# Example log line:
# Oct 10 13:55:36 server kernel: [  123.456] firewall blocked connection from 192.168.1.10
SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<process>[^\[:]+)(?:\[\d+\])?:\s+(?P<message>.*)$"
)

IP_PATTERN = re.compile(r"(?P<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)")

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

def _build_timestamp(month: str, day: str, clock: str, reference_time: datetime) -> datetime:
    month_number = MONTHS[month]
    hour, minute, second = map(int, clock.split(":"))
    candidate = datetime(reference_time.year, month_number, int(day), hour, minute, second)
    if candidate - reference_time > timedelta(days=1):
        return candidate.replace(year=reference_time.year - 1)
    return candidate

def parse_syslog_lines(lines: Iterable[str], reference_time: datetime | None = None) -> list[SyslogEvent]:
    reference_time = reference_time or datetime.now()
    events: list[SyslogEvent] = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        match = SYSLOG_PATTERN.match(line)
        if not match:
            continue

        timestamp = _build_timestamp(
            month=match.group("month"),
            day=match.group("day"),
            clock=match.group("clock"),
            reference_time=reference_time,
        )
        
        message = match.group("message")
        ip_match = IP_PATTERN.search(message)
        ip = ip_match.group("ip") if ip_match else None

        events.append(
            SyslogEvent(
                source_type="syslog",
                timestamp=timestamp,
                ip=ip,
                event_type="syslog_entry",
                raw_message=line,
                host=match.group("host"),
                process=match.group("process"),
                severity="info", # Simplified severity parsing
            )
        )

    return events

def parse_syslog_file(file_path: str | Path, reference_time: datetime | None = None) -> list[SyslogEvent]:
    path = Path(file_path)
    with path.open("r", encoding="utf-8") as handle:
        return parse_syslog_lines(handle, reference_time=reference_time)
