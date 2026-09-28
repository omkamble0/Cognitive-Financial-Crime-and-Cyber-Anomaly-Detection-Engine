import os
import io
import sys
import time
import json
import asyncio
import joblib
import numpy as np
import pandas as pd
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, UploadFile, File, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

# Local engines
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from src.engine.rules import HybridRuleEngine, ActionDecision
from src.engine.explainability import ExplainabilityEngine
from src.engine.universal_detector import UniversalDetector
from src.engine.audit_ledger import CryptographicAuditLedger
from src.engine.carding_sentinel import CardingSentinel
from src.streaming.redis_feature_store import RedisFeatureStore
from src.db.database import (
    init_database, register_user, authenticate_user,
    get_user_by_token, list_registered_users, logout_session,
    get_database_status
)

app = FastAPI(
    title="AegisFlow — Cognitive Financial Crime & Cyber-Anomaly Detection Engine",
    description="Cognitive Financial Crime & Cyber-Anomaly Detection Platform by Om Kamble",
    version="2.2.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

@app.on_event("startup")
def on_startup():
    init_database()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
MODEL_PATH = os.path.join(PROJECT_ROOT, "src", "model", "rf_model.pkl")
SCALER_PATH = os.path.join(PROJECT_ROOT, "src", "model", "scaler.pkl")
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
FEATURE_COLUMNS = [f"V{i}" for i in range(1, 29)] + ["scaled_amount", "scaled_time"]

# Engines
rule_engine = HybridRuleEngine()
explain_engine = ExplainabilityEngine()
feature_store = RedisFeatureStore()
universal_detector = UniversalDetector()
audit_ledger = CryptographicAuditLedger()
carding_sentinel = CardingSentinel()

# Cached analyzed dataset for CSV download
last_analyzed_dataframe: Optional[pd.DataFrame] = None

# Load model and scaler
model = None
scaler = None

try:
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        print("[OK] AegisFlow ML Model and Scaler loaded successfully.")
    else:
        print(f"[!] Warning: Model or Scaler not found at {MODEL_PATH} / {SCALER_PATH}")
except Exception as e:
    print(f"[!] Error loading model artifacts: {e}")

# In-Memory Telemetry Stats
telemetry = {
    "total_scanned": 0,
    "total_approved": 0,
    "total_challenged": 0,
    "total_blocked": 0,
    "total_volume_usd": 0.0,
    "latencies_ms": [],
    "recent_events": []
}

active_connections: List[WebSocket] = []


async def broadcast_event(event: Dict[str, Any]):
    disconnected = []
    for connection in active_connections:
        try:
            await connection.send_json(event)
        except Exception:
            disconnected.append(connection)
    for conn in disconnected:
        if conn in active_connections:
            active_connections.remove(conn)


class Transaction(BaseModel):
    transaction_id: Optional[str] = None
    user_id: Optional[str] = "user_default"
    V1: Optional[float] = 0.0
    V2: Optional[float] = 0.0
    V3: Optional[float] = 0.0
    V4: Optional[float] = 0.0
    V5: Optional[float] = 0.0
    V6: Optional[float] = 0.0
    V7: Optional[float] = 0.0
    V8: Optional[float] = 0.0
    V9: Optional[float] = 0.0
    V10: Optional[float] = 0.0
    V11: Optional[float] = 0.0
    V12: Optional[float] = 0.0
    V13: Optional[float] = 0.0
    V14: Optional[float] = 0.0
    V15: Optional[float] = 0.0
    V16: Optional[float] = 0.0
    V17: Optional[float] = 0.0
    V18: Optional[float] = 0.0
    V19: Optional[float] = 0.0
    V20: Optional[float] = 0.0
    V21: Optional[float] = 0.0
    V22: Optional[float] = 0.0
    V23: Optional[float] = 0.0
    V24: Optional[float] = 0.0
    V25: Optional[float] = 0.0
    V26: Optional[float] = 0.0
    V27: Optional[float] = 0.0
    V28: Optional[float] = 0.0
    Amount: Optional[float] = None
    Time: Optional[float] = None
    scaled_amount: Optional[float] = None
    scaled_time: Optional[float] = None
    device_trust_score: Optional[float] = 1.0
    ip_address: Optional[str] = "192.168.1.100"
    card_identifier: Optional[str] = None
    bin_number: Optional[str] = "411111"

    class Config:
        extra = "allow"


def build_feature_dataframe(tx_dict: Dict[str, Any]) -> pd.DataFrame:
    features = []
    for i in range(1, 29):
        val = tx_dict.get(f"V{i}", tx_dict.get(f"v{i}", 0.0))
        features.append(float(val if val is not None else 0.0))

    if "scaled_amount" in tx_dict and tx_dict["scaled_amount"] is not None and \
       "scaled_time" in tx_dict and tx_dict["scaled_time"] is not None:
        scaled_amount = float(tx_dict["scaled_amount"])
        scaled_time = float(tx_dict["scaled_time"])
    else:
        raw_amount = float(tx_dict.get("Amount", tx_dict.get("amount", 0.0)) or 0.0)
        raw_time = float(tx_dict.get("Time", tx_dict.get("time", 0.0)) or 0.0)
        if scaler is not None:
            try:
                scaled_df = pd.DataFrame([[raw_amount, raw_time]], columns=['Amount', 'Time'])
                scaled_vals = scaler.transform(scaled_df)[0]
                scaled_amount = float(scaled_vals[0])
                scaled_time = float(scaled_vals[1])
            except Exception:
                scaled_amount = 0.0
                scaled_time = 0.0
        else:
            scaled_amount = 0.0
            scaled_time = 0.0

    features.append(scaled_amount)
    features.append(scaled_time)
    return pd.DataFrame([features], columns=FEATURE_COLUMNS)


def evaluate_single_transaction(tx_dict: Dict[str, Any]) -> Dict[str, Any]:
    start_time = time.perf_counter()
    txn_id = tx_dict.get("transaction_id") or f"TXN_{int(time.time()*1000)%1000000}"
    user_id = tx_dict.get("user_id", "user_default")
    raw_amount = float(tx_dict.get("Amount", tx_dict.get("amount", 0.0)) or 0.0)
    device_trust = float(tx_dict.get("device_trust_score", 1.0) or 1.0)
    client_ip = tx_dict.get("ip_address") or tx_dict.get("client_ip") or "192.168.1.100"
    card_id = tx_dict.get("card_identifier") or tx_dict.get("card_id") or f"card_{user_id}"
    bin_num = tx_dict.get("bin_number") or tx_dict.get("bin") or (card_id[:6] if len(card_id) >= 6 else "411111")

    # 1. Cyber Botnet & Carding Sentinel Evaluation (Micro-auth / Card testing)
    carding_eval = carding_sentinel.evaluate_request(
        ip_address=client_ip,
        amount=raw_amount,
        card_identifier=card_id,
        bin_number=bin_num,
        device_trust=device_trust
    )

    # 2. Sliding-Window Velocity Profiling
    velocity_profile = feature_store.record_transaction(
        user_id=user_id,
        txn_id=txn_id,
        amount=raw_amount
    )

    # 3. Extract ML Features & Predict Probabilities
    X = build_feature_dataframe(tx_dict)
    ml_score = float(model.predict_proba(X)[0, 1]) if model is not None else 0.0

    # 4. Hybrid Decision Rule Engine with Cyber Threat Inputs
    rule_res = rule_engine.evaluate(
        ml_score=ml_score,
        amount=raw_amount,
        user_velocity_1m=velocity_profile["velocity_1m"],
        user_velocity_1h=velocity_profile["velocity_1h"],
        user_avg_amount=velocity_profile["avg_amount"],
        device_trust_score=device_trust,
        carding_threat_score=carding_eval.threat_score,
        carding_rules=carding_eval.triggered_rules
    )

    # 5. Explainable AI Feature Attribution
    reasons = explain_engine.explain(tx_dict, ml_score)
    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    # 6. Cryptographic Tamper-Proof Audit Ledger Recording (PCI-DSS 10.x / SHA-256)
    audit_block = audit_ledger.record_decision(
        txn_id=txn_id,
        user_id=user_id,
        amount=raw_amount,
        decision=rule_res.decision.value,
        risk_score=rule_res.risk_score,
        triggered_rules=rule_res.triggered_rules
    )

    # 7. Update Telemetry
    telemetry["total_scanned"] += 1
    telemetry["total_volume_usd"] += raw_amount
    telemetry["latencies_ms"].append(latency_ms)
    if len(telemetry["latencies_ms"]) > 500:
        telemetry["latencies_ms"].pop(0)

    if rule_res.decision == ActionDecision.BLOCK:
        telemetry["total_blocked"] += 1
    elif rule_res.decision in (ActionDecision.CHALLENGE_2FA, ActionDecision.MANUAL_REVIEW):
        telemetry["total_challenged"] += 1
    else:
        telemetry["total_approved"] += 1

    result = {
        "transaction_id": txn_id,
        "user_id": user_id,
        "amount": raw_amount,
        "fraud_score": round(ml_score, 4),
        "risk_score": rule_res.risk_score,
        "is_fraud": bool(rule_res.risk_score >= 0.5),
        "decision": rule_res.decision.value,
        "risk_level": rule_res.risk_level,
        "recommendation": rule_res.recommendation,
        "triggered_rules": rule_res.triggered_rules,
        "explainability": reasons,
        "velocity_metrics": velocity_profile,
        "cyber_intel": {
            "ip_address": client_ip,
            "card_identifier": card_id,
            "threat_level": carding_eval.threat_level,
            "threat_score": carding_eval.threat_score,
            "is_bot_attack": carding_eval.is_bot_attack,
            "unique_cards_60s": carding_eval.unique_cards_in_window
        },
        "audit_ledger": {
            "block_index": audit_block["index"],
            "block_hash": audit_block["block_hash"],
            "prev_hash": audit_block["prev_hash"],
            "signature": audit_block["signature"]
        },
        "latency_ms": latency_ms,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    telemetry["recent_events"].insert(0, result)
    if len(telemetry["recent_events"]) > 50:
        telemetry["recent_events"].pop()

    return result


# ==========================================
# UNIVERSAL DATASET INGESTION ENDPOINTS
# ==========================================

@app.post("/api/v1/upload-dataset")
async def upload_and_analyze_dataset(file: UploadFile = File(...)):
    """Accept CSV, TSV, Excel, or JSON file, auto-detect schema, and run adaptive anomaly & fraud analysis."""
    global last_analyzed_dataframe
    try:
        content = await file.read()
        filename = file.filename or "uploaded_dataset.csv"
        filename_lower = filename.lower()

        if filename_lower.endswith(".json"):
            df = pd.read_json(io.BytesIO(content))
        elif filename_lower.endswith((".xlsx", ".xls")):
            df = pd.read_excel(io.BytesIO(content))
        elif filename_lower.endswith((".tsv", ".tab")):
            df = pd.read_csv(io.BytesIO(content), sep="\t")
        else:
            df = pd.read_csv(io.BytesIO(content))

        if df.empty:
            raise HTTPException(status_code=400, detail="Uploaded dataset contains 0 rows.")

        analysis = universal_detector.analyze_dataset(df)
        analysis["metadata"]["filename"] = filename

        # Enrich and store for export
        scored_df = df.copy()
        scored_records = analysis["scored_records"]
        if len(scored_records) == len(scored_df):
            scored_df["aegis_risk_score"] = [r["risk_score"] for r in scored_records]
            scored_df["aegis_decision"] = [r["decision"] for r in scored_records]
            scored_df["aegis_risk_level"] = [r["risk_level"] for r in scored_records]
            scored_df["aegis_reasons"] = ["; ".join(r["reasons"]) for r in scored_records]
        last_analyzed_dataframe = scored_df

        return analysis
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Dataset processing error: {str(e)}")


@app.get("/api/v1/sample-dataset/{dataset_type}")
def get_sample_dataset_analysis(dataset_type: str):
    """Load pre-packaged financial datasets for one-click testing."""
    global last_analyzed_dataframe
    file_map = {
        "creditcard": "sample_creditcard_pca.csv",
        "ecommerce": "sample_ecommerce_orders.csv",
        "wire": "sample_p2p_wire_transfers.csv"
    }
    filename = file_map.get(dataset_type, "sample_creditcard_pca.csv")
    filepath = os.path.join(DATA_DIR, filename)

    if not os.path.exists(filepath):
        # Generate on demand
        from data.sample_datasets import generate_samples
        generate_samples()

    df = pd.read_csv(filepath)
    analysis = universal_detector.analyze_dataset(df)
    analysis["metadata"]["filename"] = filename

    # Cache for CSV export
    scored_df = df.copy()
    scored_records = analysis["scored_records"]
    if len(scored_records) == len(scored_df):
        scored_df["aegis_risk_score"] = [r["risk_score"] for r in scored_records]
        scored_df["aegis_decision"] = [r["decision"] for r in scored_records]
        scored_df["aegis_risk_level"] = [r["risk_level"] for r in scored_records]
        scored_df["aegis_reasons"] = ["; ".join(r["reasons"]) for r in scored_records]
    last_analyzed_dataframe = scored_df

    return analysis


@app.get("/api/v1/export-analyzed-csv")
def export_analyzed_csv():
    """Export the most recently analyzed dataset with calculated risk scores and reason codes."""
    global last_analyzed_dataframe
    if last_analyzed_dataframe is None or last_analyzed_dataframe.empty:
        raise HTTPException(status_code=404, detail="No analyzed dataset available for export.")

    stream = io.StringIO()
    last_analyzed_dataframe.to_csv(stream, index=False)
    response = Response(content=stream.getvalue(), media_type="text/csv")
    response.headers["Content-Disposition"] = f"attachment; filename=aegisflow_risk_analysis_{int(time.time())}.csv"
    return response


# ==========================================
# REAL-TIME REST & WEBSOCKET ENDPOINTS
# ==========================================

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "engine": "AegisFlow Cognitive v2.2 Enterprise",
        "author": "Om Kamble",
        "model": "RandomForestClassifier (100 Trees, Balanced)",
        "universal_detector": "Active (Isolation Forest + Statistical EVT)",
        "security": "PCI-DSS 10.x SHA-256 Merkle Ledger + Botnet Sentinel Active"
    }


@app.post("/predict")
@app.post("/api/v1/predict")
async def predict_transaction(tx: Transaction):
    if model is None:
        raise HTTPException(status_code=503, detail="ML Model not available.")
    
    res = evaluate_single_transaction(tx.model_dump())
    await broadcast_event(res)
    return res


@app.post("/predict/batch")
@app.post("/api/v1/predict/batch")
def predict_batch(transactions: List[Transaction]):
    if model is None:
        raise HTTPException(status_code=503, detail="ML Model not available.")

    results = [evaluate_single_transaction(tx.model_dump()) for tx in transactions]
    return {
        "count": len(results),
        "predictions": results,
        "avg_latency_ms": round(sum(r["latency_ms"] for r in results) / (len(results) or 1), 2)
    }


@app.get("/api/v1/stats")
def get_stats():
    lats = telemetry["latencies_ms"] or [2.5]
    return {
        "total_scanned": telemetry["total_scanned"],
        "total_approved": telemetry["total_approved"],
        "total_challenged": telemetry["total_challenged"],
        "total_blocked": telemetry["total_blocked"],
        "fraud_rate_pct": round((telemetry["total_blocked"] / (telemetry["total_scanned"] or 1)) * 100, 2),
        "total_volume_usd": round(telemetry["total_volume_usd"], 2),
        "avg_latency_ms": round(sum(lats) / len(lats), 2),
        "p95_latency_ms": round(float(np.percentile(lats, 95)), 2),
        "recent_events": telemetry["recent_events"][:15]
    }


@app.post("/api/v1/simulate")
async def trigger_simulation(count: int = 10, fraud_ratio: float = 0.3):
    generated = []
    for idx in range(count):
        is_synthetic_fraud = (idx % max(1, int(1 / (fraud_ratio or 0.1)))) == 0
        user_id = f"user_{np.random.randint(100, 999)}"
        amount = round(float(np.random.exponential(180) + 10) if not is_synthetic_fraud else float(np.random.uniform(900, 4500)), 2)

        tx_payload = {f"V{i}": float(np.random.normal(0, 1.0)) for i in range(1, 29)}
        if is_synthetic_fraud:
            tx_payload["V14"] = float(np.random.uniform(-7.5, -4.0))
            tx_payload["V12"] = float(np.random.uniform(-6.0, -3.5))
            tx_payload["V10"] = float(np.random.uniform(-5.0, -2.5))
            tx_payload["V4"] = float(np.random.uniform(3.0, 6.5))

        tx_payload["Amount"] = amount
        tx_payload["Time"] = float(time.time() % 172800)
        tx_payload["user_id"] = user_id
        tx_payload["transaction_id"] = f"SIM_{int(time.time()*1000)%1000000}_{idx}"
        tx_payload["device_trust_score"] = 0.2 if is_synthetic_fraud else 0.95

        res = evaluate_single_transaction(tx_payload)
        await broadcast_event(res)
        generated.append(res)
        await asyncio.sleep(0.04)

    return {"message": f"Successfully simulated {count} transactions", "samples": generated}


@app.get("/api/v1/sample/{sample_type}")
def get_sample_transaction(sample_type: str):
    if sample_type == "fraud":
        return {
            "transaction_id": f"DEMO_FRAUD_{int(time.time())}",
            "user_id": "victim_usr_4401",
            "V1": -3.0435, "V2": -3.1573, "V3": 1.0884, "V4": 2.2886, "V5": 1.3598,
            "V6": -1.0648, "V7": 0.3255, "V8": -0.0677, "V9": -0.2709, "V10": -0.8385,
            "V11": -0.4145, "V12": -0.5031, "V13": 0.6765, "V14": -6.4441, "V15": -0.6608,
            "V16": -0.9254, "V17": -2.7700, "V18": -0.8426, "V19": 0.3597, "V20": 2.1023,
            "V21": 0.6616, "V22": 0.4354, "V23": 1.3759, "V24": -0.2938, "V25": 0.2797,
            "V26": -0.1453, "V27": -0.2527, "V28": 0.0357,
            "Amount": 1850.00,
            "Time": 406.0,
            "device_trust_score": 0.15
        }
    return {
        "transaction_id": f"DEMO_LEGIT_{int(time.time())}",
        "user_id": "trusted_usr_9021",
        "V1": -1.3598, "V2": -0.0728, "V3": 2.5363, "V4": 1.3782, "V5": -0.3383,
        "V6": 0.4624, "V7": 0.2396, "V8": 0.0987, "V9": 0.3638, "V10": 0.0903,
        "V11": -0.5516, "V12": -0.6178, "V13": -0.9913, "V14": -0.3112, "V15": 1.4682,
        "V16": -0.4704, "V17": 0.2079, "V18": 0.0258, "V19": 0.4037, "V20": 0.2514,
        "V21": -0.0183, "V22": 0.2778, "V23": -0.1105, "V24": 0.0669, "V25": 0.1285,
        "V26": 0.0110, "V27": 0.2785, "V28": 0.0638,
        "Amount": 149.62,
        "Time": 0.0,
        "device_trust_score": 0.98
    }


# ==========================================
# CYBERSECURITY & AUDIT LEDGER ENDPOINTS
# ==========================================

@app.get("/api/v1/security/audit-ledger")
def get_audit_ledger(limit: int = 25):
    """Retrieve cryptographic audit ledger chain and verification summary."""
    return {
        "status": "success",
        "summary": audit_ledger.verify_integrity(),
        "recent_blocks": audit_ledger.get_recent_blocks(limit=limit)
    }


@app.post("/api/v1/security/audit-ledger/verify")
def verify_audit_ledger():
    """Run full SHA-256 Merkle chain verification for non-repudiation and PCI-DSS compliance."""
    return audit_ledger.verify_integrity()


@app.post("/api/v1/security/audit-ledger/simulate-tamper")
def simulate_audit_tamper(block_index: Optional[int] = None):
    """Simulate malicious database tampering to demonstrate zero-trust tamper detection."""
    return audit_ledger.simulate_tampering(block_index)


@app.post("/api/v1/security/audit-ledger/restore")
def restore_audit_ledger():
    """Recalculate cryptographic hash chain and restore verified status."""
    return audit_ledger.restore_and_reseal()


@app.get("/api/v1/security/bot-sentinel/stats")
def get_bot_sentinel_stats():
    """Retrieve active carding threats, quarantined IPs, and botnet telemetry."""
    return carding_sentinel.get_security_telemetry()


@app.post("/api/v1/security/bot-sentinel/simulate-carding-attack")
async def simulate_carding_attack(botnet_size: int = 6):
    """Simulate a rapid-fire distributed card-testing bot attack from a malicious IP."""
    attacker_ip = f"185.220.101.{np.random.randint(10, 99)}"
    results = []
    for i in range(botnet_size):
        stolen_card = f"4532_8890_{np.random.randint(1000, 9999)}"
        tx = {
            "transaction_id": f"BOT_ATTACK_{int(time.time()*1000)%100000}_{i+1}",
            "user_id": f"bot_victim_{i+1}",
            "ip_address": attacker_ip,
            "card_identifier": stolen_card,
            "bin_number": "453288",
            "Amount": round(float(np.random.uniform(0.75, 2.50)), 2),
            "device_trust_score": 0.15,
            "Time": float(time.time() % 86400)
        }
        for j in range(1, 29):
            tx[f"V{j}"] = float(np.random.normal(0, 0.4))

        res = evaluate_single_transaction(tx)
        await broadcast_event(res)
        results.append(res)
        await asyncio.sleep(0.08)

    return {
        "status": "simulated",
        "attacker_ip": attacker_ip,
        "cards_tested": botnet_size,
        "results": results
    }


@app.websocket("/ws/stream")
async def websocket_stream(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)


# ==========================================
# AUTHENTICATION & USER MANAGEMENT ENDPOINTS
# ==========================================
class LoginPayload(BaseModel):
    username_or_email: str
    password: str

class RegisterPayload(BaseModel):
    username: str
    email: str
    full_name: str
    password: str
    role: Optional[str] = "Risk Analyst"


@app.post("/api/v1/auth/login")
def api_login(payload: LoginPayload):
    user = authenticate_user(payload.username_or_email, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username/email or password.")
    return user


@app.post("/api/v1/auth/register")
def api_register(payload: RegisterPayload):
    try:
        user = register_user(
            username=payload.username,
            email=payload.email,
            full_name=payload.full_name,
            password=payload.password,
            role=payload.role or "Risk Analyst"
        )
        return user
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/auth/me")
def api_get_me(token: Optional[str] = None):
    if not token:
        raise HTTPException(status_code=401, detail="Missing authorization token.")
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session token.")
    return user


@app.get("/api/v1/auth/users")
def api_get_all_users():
    return list_registered_users()


@app.get("/api/v1/auth/db-status")
def api_get_db_status():
    return get_database_status()


@app.post("/api/v1/auth/logout")
def api_logout(token: Optional[str] = None):
    if token:
        logout_session(token)
    return {"status": "logged_out"}


# Mount Web Dashboard UI
DASHBOARD_DIR = os.path.join(PROJECT_ROOT, "dashboard")
if os.path.exists(DASHBOARD_DIR):
    app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")

    @app.get("/")
    @app.get("/dashboard")
    def serve_dashboard():
        return FileResponse(
            os.path.join(DASHBOARD_DIR, "index.html"),
            headers={"Cache-Control": "no-cache, no-store, must-revalidate, max-age=0"}
        )