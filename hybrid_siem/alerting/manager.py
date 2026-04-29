"""Alert lifecycle manager for Hybrid SIEM.

Handles:
- Alert severity mapping (LOW / MEDIUM / HIGH / CRITICAL)
- Alert grouping / deduplication (avoid alert spam)
- Alert state machine: TRIGGERED → ACKNOWLEDGED → RESOLVED
- Optional: webhook / Telegram notification hooks
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Callable, Coroutine, Any


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertState(str, Enum):
    TRIGGERED = "TRIGGERED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


@dataclass
class Alert:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ip: str = ""
    severity: AlertSeverity = AlertSeverity.MEDIUM
    state: AlertState = AlertState.TRIGGERED
    triggered_at: datetime = field(default_factory=datetime.utcnow)
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None
    events_correlated: int = 1
    description: str = ""
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ip": self.ip,
            "severity": self.severity.value,
            "state": self.state.value,
            "triggered_at": self.triggered_at.isoformat() + "Z",
            "acknowledged_at": self.acknowledged_at.isoformat() + "Z" if self.acknowledged_at else None,
            "resolved_at": self.resolved_at.isoformat() + "Z" if self.resolved_at else None,
            "events_correlated": self.events_correlated,
            "description": self.description,
            "updated_at": self.updated_at.isoformat() + "Z",
        }


def _risk_to_severity(risk_score: float, action: str) -> AlertSeverity:
    """Map pipeline risk score and action to alert severity."""
    if action == "block" or risk_score >= 90:
        return AlertSeverity.CRITICAL
    if risk_score >= 75:
        return AlertSeverity.HIGH
    if risk_score >= 50:
        return AlertSeverity.MEDIUM
    return AlertSeverity.LOW


# Type alias for a notification hook
NotificationHook = Callable[[Alert], Coroutine[Any, Any, None]]


class AlertManager:
    """In-memory alert manager with grouping, dedup, and lifecycle management.

    - Groups alerts per IP — one ACTIVE alert per IP at a time.
    - Auto-resolves alerts after `auto_resolve_minutes` of inactivity.
    - Calls registered async notification hooks on state changes.
    """

    def __init__(
        self,
        auto_resolve_minutes: int = 30,
        min_risk_for_alert: float = 40.0,
    ) -> None:
        self.auto_resolve_minutes = auto_resolve_minutes
        self.min_risk_for_alert = min_risk_for_alert
        # ip → active alert
        self._active_alerts: dict[str, Alert] = {}
        # All alerts (for history)
        self._all_alerts: list[Alert] = []
        # Registered notification hooks
        self._hooks: list[NotificationHook] = []

    def register_hook(self, hook: NotificationHook) -> None:
        self._hooks.append(hook)

    async def _notify(self, alert: Alert) -> None:
        for hook in self._hooks:
            try:
                await hook(alert)
            except Exception as exc:
                print(f"[AlertManager] Hook error: {exc}")

    def process_decision(
        self,
        ip: str,
        risk_score: float,
        action: str,
        reasons: tuple[str, ...],
        timestamp: datetime | None = None,
    ) -> Alert | None:
        """Evaluate a pipeline decision and emit or update an alert if needed.

        Returns the affected Alert, or None if no alert was triggered.
        """
        ts = timestamp or datetime.utcnow()

        if risk_score < self.min_risk_for_alert and action not in ("block", "rate_limit", "escalate_manual_review"):
            # Auto-resolve an existing alert that has calmed down
            if ip in self._active_alerts:
                existing = self._active_alerts.pop(ip)
                existing.state = AlertState.RESOLVED
                existing.resolved_at = ts
                existing.updated_at = ts
                asyncio.create_task(self._notify(existing))
            return None

        severity = _risk_to_severity(risk_score, action)
        description = "; ".join(reasons[:5]) if reasons else f"{action.upper()} — risk {risk_score:.1f}"

        # Dedup: update existing active alert for this IP
        if ip in self._active_alerts:
            existing = self._active_alerts[ip]
            existing.events_correlated += 1
            existing.updated_at = ts
            # Escalate severity only (never downgrade)
            severities = [AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]
            if severities.index(severity) > severities.index(existing.severity):
                existing.severity = severity
                existing.description = description
                asyncio.create_task(self._notify(existing))
            return existing

        # New alert
        new_alert = Alert(
            ip=ip,
            severity=severity,
            state=AlertState.TRIGGERED,
            triggered_at=ts,
            description=description,
        )
        self._active_alerts[ip] = new_alert
        self._all_alerts.append(new_alert)
        asyncio.create_task(self._notify(new_alert))
        return new_alert

    def acknowledge(self, alert_id: str) -> Alert | None:
        """Move an alert to ACKNOWLEDGED state."""
        for alert in self._all_alerts:
            if alert.id == alert_id and alert.state == AlertState.TRIGGERED:
                alert.state = AlertState.ACKNOWLEDGED
                alert.acknowledged_at = datetime.utcnow()
                alert.updated_at = datetime.utcnow()
                return alert
        return None

    def resolve(self, alert_id: str) -> Alert | None:
        """Move an alert to RESOLVED state."""
        for alert in self._all_alerts:
            if alert.id == alert_id and alert.state != AlertState.RESOLVED:
                alert.state = AlertState.RESOLVED
                alert.resolved_at = datetime.utcnow()
                alert.updated_at = datetime.utcnow()
                ip = alert.ip
                if self._active_alerts.get(ip) and self._active_alerts[ip].id == alert_id:
                    del self._active_alerts[ip]
                return alert
        return None

    def auto_resolve_stale(self) -> list[Alert]:
        """Resolve alerts that have been inactive for auto_resolve_minutes."""
        cutoff = datetime.utcnow() - timedelta(minutes=self.auto_resolve_minutes)
        resolved = []
        for ip, alert in list(self._active_alerts.items()):
            if alert.updated_at < cutoff and alert.state == AlertState.TRIGGERED:
                alert.state = AlertState.RESOLVED
                alert.resolved_at = datetime.utcnow()
                alert.updated_at = datetime.utcnow()
                del self._active_alerts[ip]
                resolved.append(alert)
        return resolved

    def active_alerts(self) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._active_alerts.values()]

    def all_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._all_alerts[-limit:]]

    def stats(self) -> dict[str, int]:
        total = len(self._all_alerts)
        active = len(self._active_alerts)
        return {
            "total": total,
            "active": active,
            "resolved": total - active,
            "critical": sum(1 for a in self._all_alerts if a.severity == AlertSeverity.CRITICAL),
            "high": sum(1 for a in self._all_alerts if a.severity == AlertSeverity.HIGH),
            "medium": sum(1 for a in self._all_alerts if a.severity == AlertSeverity.MEDIUM),
            "low": sum(1 for a in self._all_alerts if a.severity == AlertSeverity.LOW),
        }


# ---------------------------------------------------------------------------
# Optional notification hooks
# ---------------------------------------------------------------------------

async def telegram_hook(alert: Alert) -> None:
    """Send alert to Telegram Bot.
    
    Set environment variables:
        TELEGRAM_BOT_TOKEN
        TELEGRAM_CHAT_ID
    """
    import aiohttp
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return
    emoji = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(alert.severity.value, "⚠️")
    text = (
        f"{emoji} *SIEM ALERT — {alert.severity.value}*\n"
        f"IP: `{alert.ip}`\n"
        f"Action: `{alert.state.value}`\n"
        f"Details: {alert.description[:200]}\n"
        f"Time: {alert.triggered_at.strftime('%Y-%m-%d %H:%M:%S')} UTC"
    )
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        async with aiohttp.ClientSession() as session:
            await session.post(url, json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"})
    except Exception as exc:
        print(f"[TelegramHook] Failed to send: {exc}")


async def webhook_hook(alert: Alert) -> None:
    """Send alert as JSON POST to a generic webhook URL.
    
    Set environment variable: SIEM_WEBHOOK_URL
    """
    import aiohttp
    url = os.environ.get("SIEM_WEBHOOK_URL")
    if not url:
        return
    try:
        async with aiohttp.ClientSession() as session:
            await session.post(url, json=alert.to_dict(), timeout=aiohttp.ClientTimeout(total=5))
    except Exception as exc:
        print(f"[WebhookHook] Failed to send: {exc}")
