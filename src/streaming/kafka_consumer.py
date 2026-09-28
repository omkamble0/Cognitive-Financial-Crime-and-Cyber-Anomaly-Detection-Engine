import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from kafka import KafkaConsumer, KafkaProducer

# Ensure current directory is in path for redis_feature_store import
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from redis_feature_store import RedisFeatureStore

# Resolve model and scaler paths relative to project root or current directory
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
MODEL_PATH = os.path.join(PROJECT_ROOT, "src", "model", "rf_model.pkl")
SCALER_PATH = os.path.join(PROJECT_ROOT, "src", "model", "scaler.pkl")
FEATURE_COLUMNS = [f"V{i}" for i in range(1, 29)] + ["scaled_amount", "scaled_time"]


def load_model():
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        raise FileNotFoundError(f"Model or Scaler not found at {MODEL_PATH} / {SCALER_PATH}")
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    return model, scaler


def extract_features(tx: dict, scaler) -> pd.DataFrame:
    """Extract features in exact model training order: V1..V28, scaled_amount, scaled_time."""
    features = []
    # 1. Numerical V1 through V28
    for i in range(1, 29):
        val = tx.get(f"V{i}", tx.get(f"v{i}", 0.0))
        try:
            features.append(float(val))
        except (ValueError, TypeError):
            features.append(0.0)

    # 2. Scale Amount and Time (Scaler expects ['Amount', 'Time'])
    if "scaled_amount" in tx and "scaled_time" in tx:
        scaled_amount = float(tx["scaled_amount"])
        scaled_time = float(tx["scaled_time"])
    else:
        raw_amount = float(tx.get("Amount", tx.get("amount", 0.0)))
        raw_time = float(tx.get("Time", tx.get("time", 0.0)))
        try:
            scaled_df = pd.DataFrame([[raw_amount, raw_time]], columns=['Amount', 'Time'])
            scaled_vals = scaler.transform(scaled_df)[0]
            scaled_amount = float(scaled_vals[0])
            scaled_time = float(scaled_vals[1])
        except Exception:
            scaled_amount = 0.0
            scaled_time = 0.0

    features.append(scaled_amount)
    features.append(scaled_time)
    return pd.DataFrame([features], columns=FEATURE_COLUMNS)


def main():
    bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092").split(',')
    print(f"[*] Connecting to Kafka at {bootstrap_servers}...")

    model, scaler = load_model()
    print("[*] Model and Scaler loaded successfully.")

    consumer = KafkaConsumer(
        'transactions',
        bootstrap_servers=bootstrap_servers,
        value_deserializer=lambda v: json.loads(v.decode('utf-8')),
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        group_id='fraud_detector_group'
    )

    producer = KafkaProducer(
        bootstrap_servers=bootstrap_servers,
        value_serializer=lambda v: json.dumps(v).encode('utf-8')
    )

    rfs = RedisFeatureStore()
    print("[*] Consumer listening on topic 'transactions'...")

    for msg in consumer:
        try:
            tx = msg.value
            user_id = tx.get("user_id", "unknown")
            txn_id = tx.get("transaction_id", f"txn_{msg.offset}")

            # Extract 30 features matching trained column names
            X = extract_features(tx, scaler)
            score = float(model.predict_proba(X)[0, 1])
            is_fraud = bool(score >= 0.5)

            # Update feature store with recent transaction stats
            rfs.upsert_user_features(user_id, {
                "last_txn_id": txn_id,
                "last_score": score,
                "amount": tx.get("Amount", 0.0)
            })

            out = {
                "transaction_id": txn_id,
                "user_id": user_id,
                "fraud_score": round(score, 6),
                "is_fraud": is_fraud,
                "amount": tx.get("Amount", 0.0)
            }

            producer.send("fraud_scores", out)
            status_tag = "🚨 [FRAUD DETECTED]" if is_fraud else "✅ [LEGITIMATE]"
            print(f"{status_tag} Txn: {txn_id} | User: {user_id} | Score: {score:.4f} | Amount: ${tx.get('Amount', 0.0):.2f}")

        except Exception as e:
            print(f"[!] Error processing message: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
