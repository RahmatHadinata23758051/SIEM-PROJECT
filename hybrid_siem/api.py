import asyncio
import random
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any
import json

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt

# Import from the hybrid_siem pipeline
from hybrid_siem.models import FeatureRecord
from hybrid_siem.pipeline import process_feature_records, PipelineDecision
from hybrid_siem.risk import RiskWeights
from hybrid_siem.detection import RuleThresholds
from hybrid_siem.watchlist import WatchlistManager
from hybrid_siem.parsers import parse_auth_log_file
from hybrid_siem.features import build_feature_records
from hybrid_siem.anomaly import fit_isolation_forest, IsolationForestConfig
from hybrid_siem.calibration import select_likely_normal_records

app = FastAPI(title="Aegis AI SIEM Backend")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "aegis_super_secret_key"

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/auth/login")
async def login(req: LoginRequest):
    if req.username == "admin" and req.password == "admin":
        token = jwt.encode(
            {"sub": req.username, "exp": datetime.utcnow().timestamp() + 3600}, 
            SECRET_KEY, 
            algorithm="HS256"
        )
        return {"token": token}
    raise HTTPException(status_code=401, detail="Invalid credentials")


# ---------------------------------------------------------
# Global Pipeline State (Load at startup)
# ---------------------------------------------------------
watchlist = WatchlistManager()
thresholds = RuleThresholds()
weights = RiskWeights()

# Anomaly model (loaded at startup)
anomaly_model = None
# Real feature records from log
real_feature_records: List[FeatureRecord] = []
# Track position for streaming
_stream_position = 0


def load_real_data():
    """Load real data from auth log and train anomaly model."""
    global anomaly_model, real_feature_records
    
    log_path = Path("data/samples/auth.log")
    if not log_path.exists():
        print(f"[WARN] Log file not found at {log_path}, using synthetic data fallback")
        return
    
    print(f"[INFO] Loading real auth log from {log_path}")
    
    # Parse log
    try:
        events = parse_auth_log_file(log_path)
        print(f"[OK] Parsed {len(events)} events")
    except Exception as e:
        print(f"[WARN] Failed to parse log: {e}")
        return
    
    # Extract features
    try:
        real_feature_records = build_feature_records(events)
        print(f"[OK] Extracted {len(real_feature_records)} feature records")
    except Exception as e:
        print(f"[WARN] Failed to extract features: {e}")
        return
    
    # Train anomaly model
    try:
        normal_records = select_likely_normal_records(real_feature_records)
        print(f"[OK] Selected {len(normal_records)} normal records for training")
        
        config = IsolationForestConfig()
        anomaly_model = fit_isolation_forest(normal_records, config=config)
        print(f"[OK] Anomaly model trained successfully")
    except Exception as e:
        print(f"[WARN] Failed to train model: {e}")
        return


def get_real_or_fallback_records(count: int) -> List[FeatureRecord]:
    """Get real records (cycling) or fallback to synthetic."""
    global _stream_position
    
    if not real_feature_records:
        # Fallback: generate synthetic
        return [generate_random_feature_record() for _ in range(count)]
    
    # Cycle through real records
    records = []
    for _ in range(count):
        records.append(real_feature_records[_stream_position % len(real_feature_records)])
        _stream_position += 1
    
    return records


def generate_random_feature_record() -> FeatureRecord:
    """Fallback: Generate synthetic feature record."""
    SUSPICIOUS_IPS = [
        '203.0.113.45', '185.220.101.12', '45.33.32.156', '198.51.100.77',
        '91.108.4.200',  '162.158.92.10',  '104.21.16.35',  '172.67.200.4',
        '77.88.55.60',   '8.8.8.8', '185.15.58.22', '210.10.5.44',
    ]
    return FeatureRecord(
        ip=random.choice(SUSPICIOUS_IPS),
        timestamp=datetime.utcnow(),
        failed_count=random.randint(0, 20),
        request_rate=round(random.uniform(0.0, 0.2), 3),
        username_variance=random.randint(1, 8),
        inter_arrival_avg=round(random.uniform(0.1, 5.0), 2),
        failed_ratio=round(random.uniform(0.0, 1.0), 2),
        event_count=random.randint(1, 15),
        total_attempts=random.randint(1, 30)
    )

def decision_to_dict(decision: PipelineDecision) -> Dict[str, Any]:
    """Convert PipelineDecision to API response dict."""
    return {
        "id": f"evt-{int(time.time()*1000)}-{random.randint(1000,9999)}",
        "timestamp": decision.feature_record.timestamp.isoformat() + "Z",
        "ip": decision.feature_record.ip,
        "rule_score": round(decision.rule_score, 2),
        "anomaly_score": round(decision.anomaly_score or 0.0, 3),
        "raw_anomaly_score": round(decision.raw_anomaly_score or 0.0, 3),
        "risk_score": round(decision.risk_score, 2),
        "risk_level": decision.risk_level,
        "action": decision.action,
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

# Connection Manager for WebSockets
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Any):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()

# Background task to stream real events
async def event_generator():
    """Continuously stream PipelineDecision events from real data."""
    while True:
        await asyncio.sleep(2)  # 2 seconds interval
        if manager.active_connections and anomaly_model:
            # Get batch of records (real or fallback)
            batch_size = random.randint(1, 3)
            records = get_real_or_fallback_records(batch_size)
            
            # Get anomaly scores
            anomaly_scores = anomaly_model.score_lookup(records)
            
            # Process through pipeline
            try:
                decisions = process_feature_records(
                    records=records,
                    weights=weights,
                    anomaly_scores=anomaly_scores,
                )
                
                payload = [decision_to_dict(d) for d in decisions]
                await manager.broadcast({
                    "type": "events_batch",
                    "data": payload,
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                })
            except Exception as e:
                print(f"[WARN] Error processing records: {e}")

@app.on_event("startup")
async def startup_event():
    """Load real data and start event streaming."""
    load_real_data()
    asyncio.create_task(event_generator())


@app.websocket("/api/stream")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time event streaming."""
    await manager.connect(websocket)
    try:
        # Send initial batch of real data
        if anomaly_model and real_feature_records:
            initial_records = get_real_or_fallback_records(10)
            anomaly_scores = anomaly_model.score_lookup(initial_records)
            
            initial_decisions = process_feature_records(
                records=initial_records,
                weights=weights,
                anomaly_scores=anomaly_scores,
            )
            
            initial_payload = [decision_to_dict(d) for d in initial_decisions]
            await websocket.send_json({
                "type": "initial_batch",
                "data": initial_payload,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
        
        # Keep connection open
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"[WARN] WebSocket error: {e}")
        manager.disconnect(websocket)


# REST endpoints for other data
@app.get("/api/metrics")
async def get_metrics():
    """Get system-wide metrics based on real data."""
    if not anomaly_model or not real_feature_records:
        # Fallback
        high = random.randint(15, 45)
        elevated = random.randint(60, 110)
        baseline = random.randint(180, 280)
        total = high + elevated + baseline
        risk_score = (high / total) * 100
        return {
            "status": "CRITICAL" if risk_score > 15 else ("ELEVATED" if risk_score > 10 else "NOMINAL"),
            "events_24h": f"{(random.randint(900, 1400) / 1000):.2f}B",
            "events_trend": round(random.uniform(-5, 25), 1),
            "active_suspicious_ips": total,
            "critical_nodes_isolated": high,
            "high_risk_count": high,
            "elevated_anomaly_count": elevated,
            "baseline_count": baseline,
        }
    
    # Real data analysis
    try:
        anomaly_scores = anomaly_model.score_lookup(real_feature_records)
        decisions = process_feature_records(
            records=real_feature_records,
            weights=weights,
            anomaly_scores=anomaly_scores,
        )
        
        high = sum(1 for d in decisions if d.risk_level == 'high')
        elevated = sum(1 for d in decisions if d.risk_level == 'medium')
        baseline = sum(1 for d in decisions if d.risk_level in ('low', 'normal'))
        total = len(decisions)
        
        return {
            "status": "CRITICAL" if high / max(total, 1) > 0.15 else ("ELEVATED" if elevated / max(total, 1) > 0.10 else "NOMINAL"),
            "events_24h": f"{total/1000:.2f}B",
            "events_trend": round((high / max(total, 1)) * 100, 1),
            "active_suspicious_ips": len(set(d.feature_record.ip for d in decisions)),
            "critical_nodes_isolated": high,
            "high_risk_count": high,
            "elevated_anomaly_count": elevated,
            "baseline_count": baseline,
        }
    except Exception as e:
        print(f"[WARN] Error computing metrics: {e}")
        return {"status": "ERROR", "error": str(e)}

@app.get("/api/network-nodes")
async def get_network_nodes():
    """Get network nodes from real data."""
    if not anomaly_model or not real_feature_records:
        # Fallback
        SUSPICIOUS_IPS = [
            '203.0.113.45', '185.220.101.12', '45.33.32.156', '198.51.100.77',
            '91.108.4.200',  '162.158.92.10',  '104.21.16.35',  '172.67.200.4',
            '77.88.55.60',   '8.8.8.8', '185.15.58.22', '210.10.5.44',
        ]
        COUNTRIES = ['RU', 'CN', 'US', 'KR', 'DE', 'NL', 'BR', 'ID', 'IN', 'UA']
        nodes = []
        for i in range(10):
            score = round(random.uniform(0, 100), 1)
            level = "high" if score >= 85 else ("medium" if score >= 65 else ("low" if score >= 40 else "normal"))
            action = "block" if level == "high" else ("rate_limit" if level == "medium" else "monitor")
            
            nodes.append({
                "id": f"node-{i}",
                "ip": random.choice(SUSPICIOUS_IPS),
                "risk_level": level,
                "risk_score": score,
                "action": action,
                "event_count": random.randint(1, 50),
                "label": f"Node-{str(i+1).zfill(2)}",
                "country": random.choice(COUNTRIES)
            })
        return nodes
    
    # Real data: group by IP
    try:
        anomaly_scores = anomaly_model.score_lookup(real_feature_records)
        decisions = process_feature_records(
            records=real_feature_records,
            weights=weights,
            anomaly_scores=anomaly_scores,
        )
        
        # Aggregate by IP
        ip_stats: Dict[str, Dict[str, Any]] = {}
        for d in decisions:
            ip = d.feature_record.ip
            if ip not in ip_stats:
                ip_stats[ip] = {
                    "risk_scores": [],
                    "actions": [],
                    "event_count": 0,
                    "risk_level": "normal"
                }
            ip_stats[ip]["risk_scores"].append(d.risk_score)
            ip_stats[ip]["actions"].append(d.action)
            ip_stats[ip]["event_count"] += 1
        
        # Convert to nodes
        nodes = []
        COUNTRIES = ['RU', 'CN', 'US', 'KR', 'DE', 'NL', 'BR', 'ID', 'IN', 'UA']
        for i, (ip, stats) in enumerate(list(ip_stats.items())[:10]):
            avg_risk = sum(stats["risk_scores"]) / len(stats["risk_scores"])
            most_severe_action = "block" if "block" in stats["actions"] else ("rate_limit" if "rate_limit" in stats["actions"] else "monitor")
            
            risk_level = "high" if avg_risk >= 85 else ("medium" if avg_risk >= 65 else ("low" if avg_risk >= 40 else "normal"))
            
            nodes.append({
                "id": f"node-{i}",
                "ip": ip,
                "risk_level": risk_level,
                "risk_score": round(avg_risk, 1),
                "action": most_severe_action,
                "event_count": stats["event_count"],
                "label": f"IP-{ip.split('.')[-1]}",
                "country": random.choice(COUNTRIES)
            })
        
        return nodes
    except Exception as e:
        print(f"[WARN] Error computing network nodes: {e}")
        return []

@app.get("/api/hunting-results")
async def get_hunting_results():
    """Get threat hunting results from real data."""
    if not anomaly_model or not real_feature_records:
        # Fallback
        records = [generate_random_feature_record() for _ in range(15)]
        decisions = process_feature_records(
            records, 
            weights=weights,
            anomaly_scores={ (r.ip, r.timestamp): random.uniform(0.1, 0.9) for r in records }
        )
        
        results = []
        for d in decisions:
            res = decision_to_dict(d)
            res["first_seen"] = (datetime.utcnow() - timedelta(hours=random.randint(1, 72))).isoformat() + "Z"
            res["last_seen"] = res["timestamp"]
            results.append(res)
            
        results.sort(key=lambda x: x["risk_score"], reverse=True)
        return results
    
    # Real data hunting results
    try:
        anomaly_scores = anomaly_model.score_lookup(real_feature_records)
        decisions = process_feature_records(
            records=real_feature_records,
            weights=weights,
            anomaly_scores=anomaly_scores,
        )
        
        results = []
        ip_first_seen: Dict[str, datetime] = {}
        
        for d in decisions:
            ip = d.feature_record.ip
            if ip not in ip_first_seen:
                ip_first_seen[ip] = d.feature_record.timestamp
            
            res = decision_to_dict(d)
            res["first_seen"] = ip_first_seen[ip].isoformat() + "Z"
            res["last_seen"] = d.feature_record.timestamp.isoformat() + "Z"
            results.append(res)
        
        results.sort(key=lambda x: x["risk_score"], reverse=True)
        return results[:50]  # Limit to top 50
    except Exception as e:
        print(f"[WARN] Error computing hunting results: {e}")
        return []

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("hybrid_siem.api:app", host="127.0.0.1", port=8001, reload=True)
