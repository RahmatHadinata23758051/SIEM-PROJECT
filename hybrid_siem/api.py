import asyncio
import random
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any

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
# Simulated Data & Pipeline State
# ---------------------------------------------------------
watchlist = WatchlistManager()
thresholds = RuleThresholds()
weights = RiskWeights()

SUSPICIOUS_IPS = [
    '203.0.113.45', '185.220.101.12', '45.33.32.156', '198.51.100.77',
    '91.108.4.200',  '162.158.92.10',  '104.21.16.35',  '172.67.200.4',
    '77.88.55.60',   '8.8.8.8', '185.15.58.22', '210.10.5.44',
]

def generate_random_feature_record() -> FeatureRecord:
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
    return {
        "id": f"evt-{int(time.time()*1000)}-{random.randint(1000,9999)}",
        "timestamp": decision.feature_record.timestamp.isoformat() + "Z",
        "ip": decision.feature_record.ip,
        "rule_score": decision.rule_score,
        "anomaly_score": decision.anomaly_score or 0.0,
        "raw_anomaly_score": decision.raw_anomaly_score or 0.0,
        "risk_score": decision.risk_score,
        "risk_level": decision.risk_level,
        "action": decision.action,
        "reasons": list(decision.reasons),
        "scoring_method": decision.scoring_method,
        "temporal_insight": decision.temporal_insight,
        "failed_count": decision.feature_record.failed_count,
        "request_rate": decision.feature_record.request_rate,
        "username_variance": decision.feature_record.username_variance,
        "failed_ratio": decision.feature_record.failed_ratio,
        "event_count": decision.feature_record.event_count,
        "total_attempts": decision.feature_record.total_attempts,
        "strike_count": decision.watchlist_entry.strike_count,
        "repeat_incidents": decision.watchlist_entry.repeat_incidents,
        "adaptive_sensitivity": decision.watchlist_entry.adaptive_sensitivity,
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

# Background task to push events to WebSocket
async def event_generator():
    while True:
        await asyncio.sleep(2) # 2 seconds interval
        if manager.active_connections:
            # Generate a batch of events (e.g. 1-3 events per tick)
            batch_size = random.randint(1, 3)
            records = [generate_random_feature_record() for _ in range(batch_size)]
            decisions = process_feature_records(
                records=records,
                thresholds=thresholds,
                weights=weights,
                watchlist=watchlist,
                # Simulate a pre-computed anomaly score for now
                anomaly_scores={ (r.ip, r.timestamp): random.uniform(0.1, 0.9) for r in records }
            )
            
            payload = [decision_to_dict(d) for d in decisions]
            await manager.broadcast({"type": "events_batch", "data": payload})

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(event_generator())


@app.websocket("/api/events")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial batch
        records = [generate_random_feature_record() for _ in range(10)]
        decisions = process_feature_records(records, thresholds, weights, watchlist, anomaly_scores={ (r.ip, r.timestamp): random.uniform(0.1, 0.9) for r in records })
        initial_payload = [decision_to_dict(d) for d in decisions]
        await websocket.send_json({"type": "initial_batch", "data": initial_payload})
        
        while True:
            # keep connection open
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# REST endpoints for other data
@app.get("/api/metrics")
async def get_metrics():
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

@app.get("/api/network-nodes")
async def get_network_nodes():
    nodes = []
    countries = ['RU', 'CN', 'US', 'KR', 'DE', 'NL', 'BR', 'ID', 'IN', 'UA']
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
            "country": random.choice(countries)
        })
    return nodes

@app.get("/api/hunting-results")
async def get_hunting_results():
    records = [generate_random_feature_record() for _ in range(15)]
    decisions = process_feature_records(records, thresholds, weights, watchlist, anomaly_scores={ (r.ip, r.timestamp): random.uniform(0.1, 0.9) for r in records })
    
    results = []
    for d in decisions:
        res = decision_to_dict(d)
        res["first_seen"] = (datetime.utcnow() - timedelta(hours=random.randint(1, 72))).isoformat() + "Z"
        res["last_seen"] = res["timestamp"]
        results.append(res)
        
    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("hybrid_siem.api:app", host="127.0.0.1", port=8000, reload=True)
