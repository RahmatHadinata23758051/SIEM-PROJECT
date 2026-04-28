from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from hybrid_siem.risk import classify_risk_level


@dataclass(slots=True, frozen=True)
class WatchlistEntry:
    ip: str
    current_risk_score: float
    strike_count: int
    last_seen: datetime
    status: str


def _decay_rate_for_status(status: str) -> float:
    if status == "high":
        return 2.0
    if status == "medium":
        return 10.0
    if status == "low":
        return 5.0
    return 20.0


class WatchlistManager:
    def __init__(self) -> None:
        self._entries: dict[str, WatchlistEntry] = {}

    @property
    def entries(self) -> dict[str, WatchlistEntry]:
        return dict(self._entries)

    def get(self, ip: str) -> WatchlistEntry | None:
        return self._entries.get(ip)

    def update(self, ip: str, observed_at: datetime, observed_risk_score: float) -> WatchlistEntry:
        previous = self._entries.get(ip)
        decayed_score = 0.0
        strike_count = 0

        if previous:
            elapsed_minutes = max(0.0, (observed_at - previous.last_seen).total_seconds() / 60.0)
            decay = _decay_rate_for_status(previous.status) * elapsed_minutes
            decayed_score = max(0.0, previous.current_risk_score - decay)
            strike_count = previous.strike_count

        if observed_risk_score >= 30:
            current_risk_score = min(100.0, max(observed_risk_score, decayed_score + (observed_risk_score * 0.35)))
        else:
            current_risk_score = max(observed_risk_score, decayed_score)

        if observed_risk_score >= 80:
            strike_count += 1

        status = classify_risk_level(current_risk_score)
        entry = WatchlistEntry(
            ip=ip,
            current_risk_score=round(current_risk_score, 2),
            strike_count=strike_count,
            last_seen=observed_at,
            status=status,
        )
        self._entries[ip] = entry
        return entry
