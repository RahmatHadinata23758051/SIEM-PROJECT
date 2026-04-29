from __future__ import annotations

import asyncio
import hashlib
import io
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Literal

import matplotlib
import matplotlib.pyplot as plt
import jwt
from fastapi import FastAPI, HTTPException, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from hybrid_siem.alerting import AlertManager
from hybrid_siem.anomaly import IsolationForestConfig, fit_isolation_forest
from hybrid_siem.calibration import select_likely_normal_records
from hybrid_siem.correlation.engine import CorrelationEngine
from hybrid_siem.detection import RuleThresholds
from hybrid_siem.features import build_feature_records
from hybrid_siem.models import FeatureRecord, SshAuthEvent
from hybrid_siem.parsers import parse_auth_log_file
from hybrid_siem.pipeline import PipelineDecision, process_feature_records
from hybrid_siem.risk import RiskWeights
from hybrid_siem.watchlist import WatchlistManager

matplotlib.use("Agg")

app = FastAPI(title="Aegis AI SIEM Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "aegis_super_secret_key"


def utc_now() -> datetime:
    return datetime.utcnow()


def iso_utc(value: datetime) -> str:
    return value.isoformat() + "Z"


class LoginRequest(BaseModel):
    username: str
    password: str


class BlockIPRequest(BaseModel):
    ip: str
    reason: str | None = None
    source: str = "ui"


class EnforcePolicyRequest(BaseModel):
    ip: str
    action: Literal["monitor", "rate_limit", "block"] = "rate_limit"
    reason: str | None = None
    source: str = "ui"


@dataclass(slots=True)
class PolicyOverride:
    ip: str
    action: str
    reason: str
    source: str
    created_at: datetime


@dataclass(slots=True)
class StreamRuntimeStats:
    total_connections: int = 0
    total_disconnects: int = 0
    total_batches_sent: int = 0
    total_events_sent: int = 0
    broadcast_errors: int = 0
    last_batch_at: datetime | None = None
    queue_drops: int = 0


# ---------------------------------------------------------
# Circuit Breaker for WebSocket streaming
# ---------------------------------------------------------
_QUEUE_MAX_SIZE = 50     # max pending batches before dropping (backpressure)
_CIRCUIT_OPEN_THRESHOLD = 10   # consecutive broadcast errors before opening circuit
_CIRCUIT_RESET_SECONDS = 30    # seconds to wait before re-trying after circuit opens


@dataclass(slots=True)
class CircuitBreaker:
    """Simple circuit breaker to protect WebSocket broadcast."""
    failure_count: int = 0
    is_open: bool = False
    opened_at: datetime | None = None

    def record_failure(self) -> None:
        self.failure_count += 1
        if self.failure_count >= _CIRCUIT_OPEN_THRESHOLD:
            self.is_open = True
            self.opened_at = utc_now()
            print(f"[CircuitBreaker] OPEN — too many broadcast errors ({self.failure_count})")

    def record_success(self) -> None:
        self.failure_count = 0
        if self.is_open:
            self.is_open = False
            print("[CircuitBreaker] CLOSED — broadcast recovered")

    def should_allow(self) -> bool:
        if not self.is_open:
            return True
        # Half-open: try again after reset window
        elapsed = (utc_now() - self.opened_at).total_seconds() if self.opened_at else 999
        if elapsed >= _CIRCUIT_RESET_SECONDS:
            self.is_open = False
            self.failure_count = 0
            print("[CircuitBreaker] HALF-OPEN — retrying")
            return True
        return False


@app.post("/api/auth/login")
async def login(req: LoginRequest):
    if req.username == "admin" and req.password == "admin":
        token = jwt.encode(
            {"sub": req.username, "exp": utc_now().timestamp() + 3600},
            SECRET_KEY,
            algorithm="HS256",
        )
        return {"token": token}
    raise HTTPException(status_code=401, detail="Invalid credentials")


# ---------------------------------------------------------
# Global Runtime State
# ---------------------------------------------------------
thresholds = RuleThresholds()
weights = RiskWeights()
stream_watchlist = WatchlistManager()
correlation_engine = CorrelationEngine()
alert_manager = AlertManager()
circuit_breaker = CircuitBreaker()
backend_started_at = utc_now()

# Async backpressure queue — event batches enqueued here before broadcast
_event_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=_QUEUE_MAX_SIZE)

anomaly_model = None
parsed_auth_events: list[SshAuthEvent] = []
real_feature_records: List[FeatureRecord] = []
manual_overrides: dict[str, PolicyOverride] = {}
runtime_stats = StreamRuntimeStats()
_stream_position = 0


def load_real_data() -> None:
    """Load real data from auth log and train anomaly model."""
    global anomaly_model, parsed_auth_events, real_feature_records, _stream_position

    parsed_auth_events = []
    real_feature_records = []
    anomaly_model = None
    _stream_position = 0

    log_path = Path("data/samples/auth.log")
    if not log_path.exists():
        print(f"[WARN] Log file not found at {log_path}")
        return

    print(f"[INFO] Loading real auth log from {log_path}")

    try:
        parsed_auth_events = parse_auth_log_file(log_path)
        print(f"[OK] Parsed {len(parsed_auth_events)} events")
    except Exception as exc:
        print(f"[WARN] Failed to parse log: {exc}")
        return

    try:
        real_feature_records = build_feature_records(parsed_auth_events)
        print(f"[OK] Extracted {len(real_feature_records)} feature records")
    except Exception as exc:
        print(f"[WARN] Failed to extract features: {exc}")
        return

    if not real_feature_records:
        print("[WARN] No feature records available for model training")
        return

    try:
        normal_records = select_likely_normal_records(real_feature_records)
        print(f"[OK] Selected {len(normal_records)} normal records for training")
        config = IsolationForestConfig()
        anomaly_model = fit_isolation_forest(normal_records, config=config, source_label="real_auth_log")
        print("[OK] Anomaly model trained successfully")
    except Exception as exc:
        print(f"[WARN] Failed to train model: {exc}")


def get_stream_records(count: int) -> List[FeatureRecord]:
    """Return a stable rotating slice of real records for streaming."""
    global _stream_position

    if not real_feature_records:
        return []

    records: list[FeatureRecord] = []
    for _ in range(min(count, len(real_feature_records))):
        records.append(real_feature_records[_stream_position % len(real_feature_records)])
        _stream_position += 1
    return records


def _score_records(
    records: list[FeatureRecord],
    *,
    watchlist: WatchlistManager | None = None,
) -> list[PipelineDecision]:
    if not records or anomaly_model is None:
        return []

    anomaly_scores = anomaly_model.score_lookup(records)
    return process_feature_records(
        records=records,
        thresholds=thresholds,
        weights=weights,
        watchlist=watchlist,
        anomaly_scores=anomaly_scores,
    )


def _compute_snapshot_decisions() -> list[PipelineDecision]:
    """Compute deterministic decisions for the current dataset."""
    if not real_feature_records or anomaly_model is None:
        return []
    return _score_records(real_feature_records, watchlist=WatchlistManager())


def _stable_event_id(record: FeatureRecord) -> str:
    digest = hashlib.sha1(f"{record.ip}|{record.timestamp.isoformat()}".encode("utf-8")).hexdigest()[:16]
    return f"evt-{digest}"


def _serialize_override(override: PolicyOverride) -> dict[str, str]:
    return {
        "action": override.action,
        "reason": override.reason,
        "source": override.source,
        "created_at": iso_utc(override.created_at),
    }


def _apply_manual_override(payload: dict[str, Any], ip: str) -> dict[str, Any]:
    override = manual_overrides.get(ip)
    if override is None:
        payload["manual_override"] = None
        return payload

    reasons = list(payload.get("reasons") or [])
    reasons.insert(0, f"Manual policy override: {override.action.upper()} ({override.reason})")
    payload["reasons"] = reasons[:10]
    payload["manual_override"] = _serialize_override(override)

    if override.action == "block":
        payload["risk_score"] = max(float(payload["risk_score"]), 95.0)
        payload["risk_level"] = "high"
        payload["action"] = "block"
    elif override.action == "rate_limit":
        payload["risk_score"] = max(float(payload["risk_score"]), 70.0)
        payload["risk_level"] = "high" if payload["risk_level"] == "high" else "medium"
        payload["action"] = "rate_limit"
    return payload


def decision_to_dict(decision: PipelineDecision) -> Dict[str, Any]:
    """Convert PipelineDecision to API response dict."""
    payload: dict[str, Any] = {
        "id": _stable_event_id(decision.feature_record),
        "timestamp": iso_utc(decision.feature_record.timestamp),
        "ip": decision.feature_record.ip,
        "rule_score": round(decision.rule_score, 2),
        "anomaly_score": round(decision.anomaly_score or 0.0, 3),
        "raw_anomaly_score": round(decision.raw_anomaly_score or 0.0, 3),
        "risk_score": round(decision.risk_score, 2),
        "risk_level": decision.risk_level,
        "action": decision.action,
        "confidence": round(decision.confidence, 3),
        "reasons": list(decision.reasons),
        "scoring_method": decision.scoring_method,
        "temporal_insight": decision.temporal_insight,
        "failed_count": decision.feature_record.failed_count,
        "request_rate": round(decision.feature_record.request_rate, 3),
        "username_variance": decision.feature_record.username_variance,
        "failed_ratio": round(decision.feature_record.failed_ratio, 3),
        "event_count": decision.feature_record.event_count,
        "total_attempts": decision.feature_record.total_attempts,
        "strike_count": decision.watchlist_entry.strike_count,
        "repeat_incidents": decision.watchlist_entry.repeat_incidents,
        "adaptive_sensitivity": round(decision.watchlist_entry.adaptive_sensitivity, 3),
    }
    return _apply_manual_override(payload, decision.feature_record.ip)


def _serialized_snapshot() -> list[dict[str, Any]]:
    return [decision_to_dict(decision) for decision in _compute_snapshot_decisions()]


def _ip_payloads(ip: str) -> list[dict[str, Any]]:
    payloads = [payload for payload in _serialized_snapshot() if payload["ip"] == ip]
    return sorted(payloads, key=lambda item: item["timestamp"], reverse=True)


def _build_telemetry_points() -> list[dict[str, Any]]:
    decisions = _compute_snapshot_decisions()
    if not decisions:
        return []

    buckets: dict[datetime, dict[str, Any]] = {}
    for decision in decisions:
        timestamp = decision.feature_record.timestamp.replace(second=0, microsecond=0)
        payload = decision_to_dict(decision)
        bucket = buckets.setdefault(
            timestamp,
            {
                "volume": 0,
                "risk_total": 0.0,
                "points": 0,
                "active_ips": set(),
            },
        )
        bucket["volume"] += decision.feature_record.event_count
        bucket["risk_total"] += float(payload["risk_score"])
        bucket["points"] += 1
        bucket["active_ips"].add(decision.feature_record.ip)

    points: list[dict[str, Any]] = []
    for timestamp, bucket in sorted(buckets.items()):
        volume = int(bucket["volume"])
        avg_risk = round(bucket["risk_total"] / max(bucket["points"], 1), 2)
        points.append(
            {
                "time": timestamp.strftime("%H:%M"),
                "timestamp": iso_utc(timestamp),
                "volume": volume,
                "risk": avg_risk,
                "event_rate_per_sec": round(volume / 60.0, 3),
                "active_ips": len(bucket["active_ips"]),
            }
        )
    return points


def _build_debug_payload() -> dict[str, Any]:
    telemetry = _build_telemetry_points()
    latest_point = telemetry[-1] if telemetry else None
    decisions = _serialized_snapshot()
    return {
        "backend_started_at": iso_utc(backend_started_at),
        "model_loaded": anomaly_model is not None,
        "records_loaded": len(real_feature_records),
        "parsed_events_loaded": len(parsed_auth_events),
        "unique_ips": len({record.ip for record in real_feature_records}),
        "active_connections": len(manager.active_connections),
        "total_connections": runtime_stats.total_connections,
        "total_disconnects": runtime_stats.total_disconnects,
        "total_batches_sent": runtime_stats.total_batches_sent,
        "total_events_sent": runtime_stats.total_events_sent,
        "broadcast_errors": runtime_stats.broadcast_errors,
        "stream_position": _stream_position,
        "last_batch_at": iso_utc(runtime_stats.last_batch_at) if runtime_stats.last_batch_at else None,
        "event_rate_per_sec": latest_point["event_rate_per_sec"] if latest_point else 0.0,
        "latest_volume": latest_point["volume"] if latest_point else 0,
        "latest_risk": latest_point["risk"] if latest_point else 0.0,
        "manual_overrides": {ip: _serialize_override(override) for ip, override in manual_overrides.items()},
        "decision_count": len(decisions),
    }


def _build_report_index() -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    decisions = _serialized_snapshot()
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for payload in decisions:
        report_date = payload["timestamp"][:10]
        grouped[report_date].append(payload)

    summaries: list[dict[str, Any]] = []
    details: dict[str, dict[str, Any]] = {}

    for report_date, payloads in sorted(grouped.items(), reverse=True):
        report_id = f"daily-{report_date.replace('-', '')}"
        unique_ips = sorted({payload["ip"] for payload in payloads})
        high_count = sum(1 for payload in payloads if payload["risk_level"] == "high")
        medium_count = sum(1 for payload in payloads if payload["risk_level"] == "medium")
        incident_count = high_count + medium_count
        top_events = sorted(payloads, key=lambda item: item["risk_score"], reverse=True)[:10]

        summary = {
            "id": report_id,
            "date": report_date,
            "label": report_date,
            "status": "Ready",
            "incident_count": incident_count,
            "high_risk_count": high_count,
            "medium_risk_count": medium_count,
            "baseline_count": sum(1 for payload in payloads if payload["risk_level"] in {"low", "normal"}),
            "unique_ip_count": len(unique_ips),
            "generated_at": iso_utc(utc_now()),
        }
        detail = {
            **summary,
            "unique_ips": unique_ips,
            "top_events": top_events,
            "manual_overrides": {ip: _serialize_override(override) for ip, override in manual_overrides.items()},
        }
        summaries.append(summary)
        details[report_id] = detail

    return summaries, details


def _render_report_pdf(report: dict[str, Any]) -> bytes:
    fig = plt.figure(figsize=(8.27, 11.69))
    gs = fig.add_gridspec(2, 1, height_ratios=[1.2, 1.0])
    summary_ax = fig.add_subplot(gs[0])
    chart_ax = fig.add_subplot(gs[1])

    summary_ax.axis("off")
    lines = [
        "Hybrid SIEM Daily Report",
        f"Report ID: {report['id']}",
        f"Date: {report['date']}",
        f"Generated: {report['generated_at']}",
        f"Unique IPs: {report['unique_ip_count']}",
        f"Incidents (medium/high): {report['incident_count']}",
        f"High Risk: {report['high_risk_count']}",
        f"Medium Risk: {report['medium_risk_count']}",
        f"Baseline: {report['baseline_count']}",
        "",
        "Top IPs:",
    ]
    lines.extend([f"- {event['ip']} ({event['action']}, risk={event['risk_score']})" for event in report["top_events"][:5]])
    summary_ax.text(0.02, 0.98, "\n".join(lines), va="top", ha="left", family="monospace", fontsize=10)

    labels = ["High", "Medium", "Baseline"]
    values = [report["high_risk_count"], report["medium_risk_count"], report["baseline_count"]]
    colors = ["#ef4444", "#f59e0b", "#60a5fa"]
    chart_ax.bar(labels, values, color=colors)
    chart_ax.set_title("Risk Distribution")
    chart_ax.set_ylabel("Window Count")
    chart_ax.grid(axis="y", alpha=0.2)

    buffer = io.BytesIO()
    fig.tight_layout()
    fig.savefig(buffer, format="pdf")
    plt.close(fig)
    buffer.seek(0)
    return buffer.getvalue()


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        runtime_stats.total_connections += 1

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            runtime_stats.total_disconnects += 1

    async def broadcast(self, message: Any):
        disconnected = []
        batch_size = len(message.get("data", [])) if isinstance(message, dict) else 0
        runtime_stats.total_batches_sent += 1
        runtime_stats.total_events_sent += batch_size
        runtime_stats.last_batch_at = utc_now()

        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                runtime_stats.broadcast_errors += 1
                disconnected.append(connection)

        for connection in disconnected:
            self.disconnect(connection)


manager = ConnectionManager()


async def event_producer():
    """Produce scored decision batches and put them into the async queue (backpressure)."""
    while True:
        await asyncio.sleep(2)
        if not manager.active_connections:
            continue

        records = get_stream_records(count=2)
        if not records:
            continue

        try:
            decisions = _score_records(records, watchlist=stream_watchlist)
            payload = [decision_to_dict(decision) for decision in decisions]

            # Feed alert manager
            for d in decisions:
                alert_manager.process_decision(
                    ip=d.feature_record.ip,
                    risk_score=d.risk_score,
                    action=d.action,
                    reasons=d.reasons,
                    timestamp=d.feature_record.timestamp,
                )

            batch = {
                "type": "events_batch",
                "data": payload,
                "timestamp": iso_utc(utc_now()),
            }

            # Backpressure: drop oldest if queue full
            if _event_queue.full():
                try:
                    _event_queue.get_nowait()
                    runtime_stats.queue_drops += 1
                except asyncio.QueueEmpty:
                    pass

            _event_queue.put_nowait(batch)

        except Exception as exc:
            print(f"[WARN] Error processing records: {exc}")


async def event_consumer():
    """Consume batches from queue and broadcast via WebSocket with circuit breaker."""
    while True:
        batch = await _event_queue.get()

        if not circuit_breaker.should_allow():
            _event_queue.task_done()
            continue

        try:
            await manager.broadcast(batch)
            circuit_breaker.record_success()
        except Exception as exc:
            print(f"[WARN] Broadcast error: {exc}")
            circuit_breaker.record_failure()
        finally:
            _event_queue.task_done()


async def alert_auto_resolve_task():
    """Periodically auto-resolve stale alerts."""
    while True:
        await asyncio.sleep(60)
        resolved = alert_manager.auto_resolve_stale()
        if resolved:
            print(f"[AlertManager] Auto-resolved {len(resolved)} stale alerts")


@app.on_event("startup")
async def startup_event():
    # Initialize SQLite/PostgreSQL tables
    try:
        from hybrid_siem.database import init_db
        await init_db()
        print("[OK] Database initialized")
    except Exception as exc:
        print(f"[WARN] Database init failed: {exc}")

    load_real_data()
    asyncio.create_task(event_producer())
    asyncio.create_task(event_consumer())
    asyncio.create_task(alert_auto_resolve_task())


@app.websocket("/api/stream")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time event streaming."""
    await manager.connect(websocket)
    try:
        if anomaly_model is not None and real_feature_records:
            initial_records = get_stream_records(min(10, len(real_feature_records)))
            initial_decisions = _score_records(initial_records, watchlist=WatchlistManager())
            initial_payload = [decision_to_dict(decision) for decision in initial_decisions]
            await websocket.send_json(
                {
                    "type": "initial_batch",
                    "data": initial_payload,
                    "timestamp": iso_utc(utc_now()),
                }
            )

        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as exc:
        print(f"[WARN] WebSocket error: {exc}")
        manager.disconnect(websocket)


@app.post("/api/actions/block-ip")
async def block_ip(request: BlockIPRequest):
    manual_overrides[request.ip] = PolicyOverride(
        ip=request.ip,
        action="block",
        reason=request.reason or "Blocked from dashboard",
        source=request.source,
        created_at=utc_now(),
    )
    return {
        "ok": True,
        "ip": request.ip,
        "override": _serialize_override(manual_overrides[request.ip]),
    }


@app.post("/api/actions/enforce-policy")
async def enforce_policy(request: EnforcePolicyRequest):
    if request.action == "monitor":
        removed = manual_overrides.pop(request.ip, None)
        return {
            "ok": True,
            "ip": request.ip,
            "cleared": removed is not None,
            "action": "monitor",
        }

    manual_overrides[request.ip] = PolicyOverride(
        ip=request.ip,
        action=request.action,
        reason=request.reason or "Policy enforced from dashboard",
        source=request.source,
        created_at=utc_now(),
    )
    return {
        "ok": True,
        "ip": request.ip,
        "override": _serialize_override(manual_overrides[request.ip]),
    }


@app.get("/api/metrics")
async def get_metrics():
    payloads = _serialized_snapshot()
    high = sum(1 for payload in payloads if payload["risk_level"] == "high")
    elevated = sum(1 for payload in payloads if payload["risk_level"] == "medium")
    baseline = sum(1 for payload in payloads if payload["risk_level"] in ("low", "normal"))
    total = len(payloads)

    if total == 0:
        return {
            "status": "NOMINAL",
            "events_24h": "0",
            "events_trend": 0.0,
            "active_suspicious_ips": 0,
            "critical_nodes_isolated": 0,
            "high_risk_count": 0,
            "elevated_anomaly_count": 0,
            "baseline_count": 0,
        }

    if high / total > 0.15:
        status = "CRITICAL"
    elif elevated / total > 0.10:
        status = "ELEVATED"
    else:
        status = "NOMINAL"

    return {
        "status": status,
        "events_24h": str(total),
        "events_trend": 0.0,
        "active_suspicious_ips": len({payload["ip"] for payload in payloads}),
        "critical_nodes_isolated": high,
        "high_risk_count": high,
        "elevated_anomaly_count": elevated,
        "baseline_count": baseline,
    }


@app.get("/api/network-nodes")
async def get_network_nodes():
    payloads = _serialized_snapshot()
    grouped: Dict[str, Dict[str, Any]] = {}
    for payload in payloads:
        ip = payload["ip"]
        stats = grouped.setdefault(
            ip,
            {
                "risk_scores": [],
                "actions": [],
                "event_count": 0,
                "risk_level": "normal",
            },
        )
        stats["risk_scores"].append(payload["risk_score"])
        stats["actions"].append(payload["action"])
        stats["event_count"] += 1
        if payload["risk_level"] == "high" or (payload["risk_level"] == "medium" and stats["risk_level"] != "high"):
            stats["risk_level"] = payload["risk_level"]

    nodes = []
    for index, (ip, stats) in enumerate(sorted(grouped.items(), key=lambda item: sum(item[1]["risk_scores"]) / len(item[1]["risk_scores"]), reverse=True)[:10]):
        avg_risk = sum(stats["risk_scores"]) / max(len(stats["risk_scores"]), 1)
        action = "block" if "block" in stats["actions"] else ("rate_limit" if "rate_limit" in stats["actions"] else "monitor")
        nodes.append(
            {
                "id": f"node-{index}",
                "ip": ip,
                "risk_level": stats["risk_level"],
                "risk_score": round(avg_risk, 1),
                "action": action,
                "event_count": stats["event_count"],
                "label": ip,
                "country": "UNK",
            }
        )
    return nodes


@app.get("/api/hunting-results")
async def get_hunting_results():
    results = _serialized_snapshot()
    if not results:
        return []

    first_seen_by_ip: dict[str, str] = {}
    enriched: list[dict[str, Any]] = []
    for payload in sorted(results, key=lambda item: item["timestamp"]):
        ip = payload["ip"]
        first_seen_by_ip.setdefault(ip, payload["timestamp"])
        enriched.append(
            {
                **payload,
                "first_seen": first_seen_by_ip[ip],
                "last_seen": payload["timestamp"],
            }
        )
    return sorted(enriched, key=lambda item: item["risk_score"], reverse=True)[:50]


@app.get("/api/ip/{ip}/history")
async def get_ip_history(ip: str):
    payloads = _ip_payloads(ip)
    return {
        "ip": ip,
        "history": payloads,
        "manual_override": _serialize_override(manual_overrides[ip]) if ip in manual_overrides else None,
    }


@app.get("/api/ip/{ip}/timeline")
async def get_ip_timeline(ip: str):
    payloads = list(reversed(_ip_payloads(ip)))
    points = [
        {
            "id": payload["id"],
            "timestamp": payload["timestamp"],
            "risk_score": payload["risk_score"],
            "rule_score": payload["rule_score"],
            "anomaly_score": payload["anomaly_score"],
            "action": payload["action"],
            "risk_level": payload["risk_level"],
            "event_count": payload["event_count"],
            "failed_count": payload["failed_count"],
            "request_rate": payload["request_rate"],
            "username_variance": payload["username_variance"],
            "failed_ratio": payload["failed_ratio"],
        }
        for payload in payloads
    ]
    return {
        "ip": ip,
        "timeline": points,
        "manual_override": _serialize_override(manual_overrides[ip]) if ip in manual_overrides else None,
    }


@app.get("/api/telemetry")
async def get_telemetry():
    return _build_telemetry_points()


@app.get("/api/debug")
async def get_debug():
    return _build_debug_payload()


@app.get("/api/reports")
async def get_reports():
    summaries, _ = _build_report_index()
    return summaries


@app.get("/api/reports/{report_id}.json")
async def get_report_json(report_id: str):
    _, details = _build_report_index()
    report = details.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@app.get("/api/reports/{report_id}.pdf")
async def get_report_pdf(report_id: str):
    _, details = _build_report_index()
    report = details.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    pdf_bytes = _render_report_pdf(report)
    headers = {"Content-Disposition": f'attachment; filename="{report_id}.pdf"'}
    return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("hybrid_siem.api:app", host="127.0.0.1", port=8001, reload=True)


# ---------------------------------------------------------------------------
# Alert Management Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/alerts")
async def get_alerts():
    """Return all active alerts."""
    return alert_manager.active_alerts()


@app.get("/api/alerts/all")
async def get_all_alerts(limit: int = 100):
    """Return full alert history (paginated)."""
    return alert_manager.all_alerts(limit=limit)


@app.get("/api/alerts/stats")
async def get_alert_stats():
    """Return alert count stats by severity and state."""
    return alert_manager.stats()


class AlertActionRequest(BaseModel):
    alert_id: str


@app.post("/api/alerts/acknowledge")
async def acknowledge_alert(req: AlertActionRequest):
    alert = alert_manager.acknowledge(req.alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found or already resolved")
    return alert.to_dict()


@app.post("/api/alerts/resolve")
async def resolve_alert(req: AlertActionRequest):
    alert = alert_manager.resolve(req.alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert.to_dict()


@app.get("/api/system/health")
async def get_system_health():
    """Return runtime health including circuit breaker and queue status."""
    return {
        "status": "ok",
        "queue_size": _event_queue.qsize(),
        "queue_capacity": _QUEUE_MAX_SIZE,
        "queue_drops": runtime_stats.queue_drops,
        "circuit_breaker_open": circuit_breaker.is_open,
        "circuit_breaker_failures": circuit_breaker.failure_count,
        "active_ws_connections": len(manager.active_connections),
        "total_batches_sent": runtime_stats.total_batches_sent,
        "total_events_sent": runtime_stats.total_events_sent,
        "broadcast_errors": runtime_stats.broadcast_errors,
        "alert_stats": alert_manager.stats(),
        "model_loaded": anomaly_model is not None,
        "records_loaded": len(real_feature_records),
    }
