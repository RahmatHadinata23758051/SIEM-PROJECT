"""Temporal feature computation for advanced risk analysis.

This module computes time-based features that capture patterns not visible
in a single window, such as persistence, burst behavior, and rolling aggregations.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from hybrid_siem.models import FeatureRecord


@dataclass(slots=True, frozen=True)
class TemporalFeatures:
    """Extended temporal features for a given IP.
    
    Attributes:
        ip: Source IP address
        timestamp: Current window timestamp
        rolling_failed_count_5m: Sum of failed_count over last 5 minutes (5 windows)
        rolling_request_rate_5m: Average request_rate over last 5 minutes
        persistence_score: How long activity has been observed (0-100 scale)
        burst_score: Sudden spike detection (0-100 scale)
        activity_duration_seconds: Total duration of observed activity
        quiet_period_seconds: Seconds since last activity before this window
    """
    ip: str
    timestamp: datetime
    rolling_failed_count_5m: int
    rolling_request_rate_5m: float
    persistence_score: float
    burst_score: float
    activity_duration_seconds: int
    quiet_period_seconds: int


class TemporalFeatureComputer:
    """Compute temporal features for a stream of feature records."""
    
    def __init__(self, window_seconds: int = 60, lookback_windows: int = 5):
        """Initialize temporal feature computer.
        
        Args:
            window_seconds: Size of each feature window (typically 60)
            lookback_windows: Number of past windows to aggregate (5 = 5 minutes)
        """
        self.window_seconds = window_seconds
        self.lookback_windows = lookback_windows
        self.lookback_duration = timedelta(seconds=window_seconds * lookback_windows)
    
    def compute(
        self, records: Iterable[FeatureRecord]
    ) -> dict[tuple[str, datetime], TemporalFeatures]:
        """Compute temporal features for all records.
        
        Args:
            records: Stream of feature records sorted by (ip, timestamp)
        
        Returns:
            Dictionary mapping (ip, timestamp) to TemporalFeatures
        """
        temporal_map: dict[tuple[str, datetime], TemporalFeatures] = {}
        
        # Group records by IP for easier windowing
        ip_records: dict[str, list[FeatureRecord]] = {}
        for record in records:
            if record.ip not in ip_records:
                ip_records[record.ip] = []
            ip_records[record.ip].append(record)
        
        # Compute temporal features for each IP
        for ip, records_for_ip in ip_records.items():
            records_for_ip.sort(key=lambda r: r.timestamp)
            temporal_features_for_ip = self._compute_for_ip(ip, records_for_ip)
            for features in temporal_features_for_ip:
                temporal_map[(ip, features.timestamp)] = features
        
        return temporal_map
    
    def _compute_for_ip(
        self, ip: str, records: list[FeatureRecord]
    ) -> list[TemporalFeatures]:
        """Compute temporal features for a specific IP."""
        temporal_features: list[TemporalFeatures] = []
        
        for i, current_record in enumerate(records):
            # Find records within lookback window
            cutoff_time = current_record.timestamp - self.lookback_duration
            lookback_records = [r for r in records[:i+1] if r.timestamp >= cutoff_time]
            
            # Rolling aggregations (5-minute window)
            rolling_failed_count = sum(r.failed_count for r in lookback_records)
            rolling_request_rate = (
                sum(r.request_rate for r in lookback_records) / len(lookback_records)
                if lookback_records else 0.0
            )
            
            # Persistence: how long has this IP been observed?
            if len(records) >= 2:
                activity_duration = (current_record.timestamp - records[0].timestamp).total_seconds()
            else:
                activity_duration = 0
            
            # Cap persistence at reasonable value (8 hours = 28800 seconds)
            persistence_score = min(100.0, (activity_duration / 28800.0) * 100.0)
            
            # Burst detection: compare current failed_count to rolling average
            rolling_avg_failed = (
                rolling_failed_count / len(lookback_records)
                if lookback_records else 0
            )
            burst_ratio = (
                (current_record.failed_count / rolling_avg_failed)
                if rolling_avg_failed > 0 else 1.0
            )
            # Burst score: how much did it spike? 0-100 scale
            burst_score = min(100.0, max(0.0, (burst_ratio - 1.0) * 50.0))
            
            # Quiet period: time since last observation before this window
            if i > 0:
                prev_record = records[i - 1]
                quiet_period = (current_record.timestamp - prev_record.timestamp).total_seconds()
            else:
                quiet_period = 0
            
            temporal_features.append(
                TemporalFeatures(
                    ip=ip,
                    timestamp=current_record.timestamp,
                    rolling_failed_count_5m=rolling_failed_count,
                    rolling_request_rate_5m=rolling_request_rate,
                    persistence_score=persistence_score,
                    burst_score=burst_score,
                    activity_duration_seconds=int(activity_duration),
                    quiet_period_seconds=int(quiet_period),
                )
            )
        
        return temporal_features
