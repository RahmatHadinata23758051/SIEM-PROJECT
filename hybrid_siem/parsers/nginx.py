from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterable

from hybrid_siem.models import NginxAccessEvent

# Example log line:
# 192.168.1.10 - - [10/Oct/2023:13:55:36 -0700] "GET /api/data HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
NGINX_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<endpoint>\S+) \S+" (?P<status>\d{3}) \S+ "[^"]*" "(?P<user_agent>[^"]*)"'
)

def _parse_nginx_timestamp(ts_str: str) -> datetime:
    # 10/Oct/2023:13:55:36 -0700
    try:
        # Strip timezone for simplicity in this SIEM, or parse it properly
        ts_str = ts_str.split(" ")[0]
        return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return datetime.utcnow()

def parse_nginx_log_lines(lines: Iterable[str]) -> list[NginxAccessEvent]:
    events: list[NginxAccessEvent] = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        match = NGINX_PATTERN.match(line)
        if not match:
            continue

        timestamp = _parse_nginx_timestamp(match.group("timestamp"))
        
        events.append(
            NginxAccessEvent(
                source_type="nginx_access",
                timestamp=timestamp,
                ip=match.group("ip"),
                event_type="http_request",
                raw_message=line,
                method=match.group("method"),
                endpoint=match.group("endpoint"),
                status_code=int(match.group("status")),
                user_agent=match.group("user_agent"),
            )
        )

    return events

def parse_nginx_log_file(file_path: str | Path) -> list[NginxAccessEvent]:
    path = Path(file_path)
    with path.open("r", encoding="utf-8") as handle:
        return parse_nginx_log_lines(handle)
