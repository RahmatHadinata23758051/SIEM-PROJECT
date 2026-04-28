from __future__ import annotations

from dataclasses import dataclass

from hybrid_siem.watchlist import WatchlistEntry


@dataclass(slots=True, frozen=True)
class DecisionOutcome:
    action: str
    reason: str


def decide_action(risk_score: float, watchlist_entry: WatchlistEntry) -> DecisionOutcome:
    if risk_score >= 80 or watchlist_entry.strike_count >= 3:
        return DecisionOutcome(action="block", reason="high_risk_or_repeat_offender")
    if risk_score >= 60 or (watchlist_entry.strike_count >= 1 and risk_score >= 45):
        return DecisionOutcome(action="rate_limit", reason="elevated_risk")
    if risk_score >= 30 or watchlist_entry.status in {"low", "medium", "high"}:
        return DecisionOutcome(action="monitor", reason="suspicious_activity")
    return DecisionOutcome(action="normal", reason="baseline_activity")
