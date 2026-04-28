from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from hybrid_siem.risk import classify_risk_level


@dataclass(slots=True, frozen=True)
class WatchlistEntry:
    """Watchlist entry with adaptive scoring based on history.
    
    Attributes:
        ip: Source IP address
        current_risk_score: Current aggregated risk score (0-100)
        strike_count: Number of times IP hit high risk (>= 80)
        last_seen: Last observation timestamp
        status: Risk level (normal, low, medium, high)
        historical_peak: Highest risk score ever observed
        repeat_incidents: Number of separate high-risk periods observed
        adaptive_sensitivity: Multiplier for sensitivity based on history (1.0-3.0)
    """
    ip: str
    current_risk_score: float
    strike_count: int
    last_seen: datetime
    status: str
    historical_peak: float = 0.0
    repeat_incidents: int = 0
    adaptive_sensitivity: float = 1.0


def _decay_rate_for_status(status: str) -> float:
    """Base decay rate per minute for each risk status."""
    if status == "high":
        return 2.0
    if status == "medium":
        return 10.0
    if status == "low":
        return 5.0
    return 20.0


def _compute_adaptive_sensitivity(strike_count: int, repeat_incidents: int) -> float:
    """Compute adaptive sensitivity multiplier based on history.
    
    IP with multiple incidents of high risk becomes more sensitive to future spikes.
    Base sensitivity: 1.0
    With 3+ strikes or 2+ repeat incidents: up to 3.0x multiplier
    """
    base = 1.0
    strike_multiplier = min(1.0, (strike_count - 1) * 0.15) if strike_count >= 3 else 0.0
    repeat_multiplier = min(1.0, repeat_incidents * 0.5)
    return base + strike_multiplier + repeat_multiplier


class WatchlistManager:
    """Adaptive watchlist manager with history tracking and sensitivity adjustment."""
    
    def __init__(self) -> None:
        """Initialize watchlist with empty entries."""
        self._entries: dict[str, WatchlistEntry] = {}

    @property
    def entries(self) -> dict[str, WatchlistEntry]:
        """Get current watchlist entries."""
        return dict(self._entries)

    def get(self, ip: str) -> WatchlistEntry | None:
        """Get entry for a specific IP."""
        return self._entries.get(ip)

    def update(
        self,
        ip: str,
        observed_at: datetime,
        observed_risk_score: float,
    ) -> WatchlistEntry:
        """Update watchlist entry with new observation.
        
        Args:
            ip: Source IP address
            observed_at: Observation timestamp
            observed_risk_score: Newly observed risk score
        
        Returns:
            Updated WatchlistEntry
        """
        previous = self._entries.get(ip)
        decayed_score = 0.0
        strike_count = 0
        historical_peak = observed_risk_score
        repeat_incidents = 0
        was_in_recovery = False

        if previous:
            historical_peak = max(observed_risk_score, previous.historical_peak)
            repeat_incidents = previous.repeat_incidents
            strike_count = previous.strike_count
            
            # Calculate decay based on time elapsed and previous status
            elapsed_minutes = max(0.0, (observed_at - previous.last_seen).total_seconds() / 60.0)
            decay = _decay_rate_for_status(previous.status) * elapsed_minutes
            decayed_score = max(0.0, previous.current_risk_score - decay)
            
            # Detect when entering a new incident (recovery followed by spike)
            was_in_recovery = previous.status in ("low", "normal") and previous.current_risk_score < 30
        
        # Compute adaptive sensitivity based on history
        adaptive_sensitivity = _compute_adaptive_sensitivity(strike_count, repeat_incidents)
        
        # Apply adaptive sensitivity: boost risk if IP has bad history
        adjusted_observed_score = observed_risk_score * adaptive_sensitivity
        adjusted_observed_score = min(100.0, adjusted_observed_score)
        
        # Score aggregation
        if adjusted_observed_score >= 30:
            current_risk_score = min(
                100.0,
                max(
                    adjusted_observed_score,
                    decayed_score + (adjusted_observed_score * 0.35),
                ),
            )
        else:
            current_risk_score = max(adjusted_observed_score, decayed_score)

        # Track high-risk incidents
        old_status = previous.status if previous else "normal"
        new_status = classify_risk_level(current_risk_score)
        
        # Increment strike count when entering high risk
        if adjusted_observed_score >= 80:
            strike_count += 1
        
        # Track repeat incidents: when transitioning from low/normal back to medium+
        if was_in_recovery and new_status in ("medium", "high"):
            repeat_incidents += 1

        entry = WatchlistEntry(
            ip=ip,
            current_risk_score=round(current_risk_score, 2),
            strike_count=strike_count,
            last_seen=observed_at,
            status=new_status,
            historical_peak=round(historical_peak, 2),
            repeat_incidents=repeat_incidents,
            adaptive_sensitivity=round(adaptive_sensitivity, 2),
        )
        self._entries[ip] = entry
        return entry
