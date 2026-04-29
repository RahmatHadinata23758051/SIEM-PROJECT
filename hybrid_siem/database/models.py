"""SQLAlchemy ORM models for the Hybrid SIEM persistence layer."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hybrid_siem.database.core import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class EventLog(Base):
    """Raw normalized SIEM events from all sources."""

    __tablename__ = "event_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)  # auth_log|nginx|syslog
    ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_message: Mapped[str] = mapped_column(Text, nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_event_logs_ip_ts", "ip", "timestamp"),
    )


class FeatureSnapshot(Base):
    """Extracted feature records per IP per time window."""

    __tablename__ = "feature_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False)
    ip: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    request_rate: Mapped[float] = mapped_column(Float, default=0.0)
    username_variance: Mapped[int] = mapped_column(Integer, default=0)
    inter_arrival_avg: Mapped[float | None] = mapped_column(Float, nullable=True)
    failed_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    total_attempts: Mapped[int] = mapped_column(Integer, default=0)
    ssh_failed_count: Mapped[int] = mapped_column(Integer, default=0)
    http_404_count: Mapped[int] = mapped_column(Integer, default=0)
    http_total_requests: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_feature_snapshots_ip_ts", "ip", "timestamp"),
    )


class DecisionLog(Base):
    """Persisted pipeline decisions for historical analysis."""

    __tablename__ = "decision_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False)
    ip: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    rule_score: Mapped[int] = mapped_column(Integer, nullable=False)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    scoring_method: Mapped[str] = mapped_column(String(32), default="linear")
    reasons: Mapped[str] = mapped_column(Text, default="")  # JSON-encoded list
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_decision_logs_ip_ts", "ip", "timestamp"),
        Index("ix_decision_logs_risk_level", "risk_level"),
    )


class AlertRecord(Base):
    """Alert lifecycle table — TRIGGERED → ACKNOWLEDGED → RESOLVED."""

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ip: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)  # LOW|MEDIUM|HIGH|CRITICAL
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="TRIGGERED")  # TRIGGERED|ACKNOWLEDGED|RESOLVED
    triggered_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    events_correlated: Mapped[int] = mapped_column(Integer, default=1)
    description: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index("ix_alerts_ip_state", "ip", "state"),
        Index("ix_alerts_triggered_at", "triggered_at"),
    )
