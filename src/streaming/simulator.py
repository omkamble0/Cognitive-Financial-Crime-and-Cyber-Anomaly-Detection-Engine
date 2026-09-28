"""
AegisFlow Synthetic Stream Simulator & Stress Benchmark CLI
Generates realistic streaming credit card events with customizable fraud injection rates.
"""

import os
import sys
import time
import json
import argparse
import urllib.request
import numpy as np


def run_simulator(target_url: str = "http://127.0.0.1:8000/api/v1/predict", count: int = 100, pause: float = 0.1, fraud_rate: float = 0.15):
    print("=" * 70)
    print(" [*] AegisFlow AI Stream Simulator & Stress Test Engine")
    print(f" Target Endpoint : {target_url}")
    print(f" Transactions    : {count}")
    print(f" Target Fraud %  : {fraud_rate * 100:.1f}%")
    print(f" Interval        : {pause}s")
    print("=" * 70)

    blocked = 0
    approved = 0
    challenged = 0
    latencies = []

    for i in range(1, count + 1):
        is_fraud = np.random.rand() < fraud_rate
        user_id = f"user_{np.random.randint(100, 500)}"
        txn_id = f"SIM_{int(time.time()*1000)%1000000}_{i}"
        amount = round(float(np.random.uniform(850, 4200) if is_fraud else np.random.exponential(120) + 5), 2)

        payload = {f"V{k}": float(np.random.normal(0, 1.0)) for k in range(1, 29)}
        if is_fraud:
            payload["V14"] = float(np.random.uniform(-7.0, -3.5))
            payload["V12"] = float(np.random.uniform(-5.5, -2.8))
            payload["V10"] = float(np.random.uniform(-4.8, -2.0))
            payload["V4"] = float(np.random.uniform(2.8, 6.0))
            payload["device_trust_score"] = 0.15
        else:
            payload["device_trust_score"] = 0.98

        payload["Amount"] = amount
        payload["Time"] = float(time.time() % 172800)
        payload["user_id"] = user_id
        payload["transaction_id"] = txn_id

        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                target_url,
                data=req_data,
                headers={"Content-Type": "application/json"}
            )
            t0 = time.perf_counter()
            with urllib.request.urlopen(req) as response:
                t_elapsed = (time.perf_counter() - t0) * 1000
                res = json.loads(response.read().decode("utf-8"))
                latencies.append(t_elapsed)

                decision = res.get("decision", "UNKNOWN")
                risk_score = res.get("risk_score", 0.0)

                if decision == "BLOCK":
                    blocked += 1
                    status = "[BLOCKED]"
                elif decision in ("CHALLENGE_2FA", "MANUAL_REVIEW"):
                    challenged += 1
                    status = "[CHALLENGE]"
                else:
                    approved += 1
                    status = "[APPROVED]"

                print(f"[{i:03d}/{count}] {status:<11} Txn: {txn_id} | User: {user_id} | Amt: ${amount:>7.2f} | Risk: {risk_score:.3f} | Latency: {t_elapsed:.1f}ms")

        except Exception as e:
            print(f"[!] Request error: {e}")

        time.sleep(pause)

    print("\n" + "=" * 70)
    print(" [*] Benchmark Summary")
    print(f" Total Processed  : {count}")
    print(f" Authorized       : {approved} ({approved/count*100:.1f}%)")
    print(f" Challenged (2FA) : {challenged} ({challenged/count*100:.1f}%)")
    print(f" Intercepted Fraud: {blocked} ({blocked/count*100:.1f}%)")
    if latencies:
        print(f" Latency SLA      : Avg {np.mean(latencies):.2f}ms | p95 {np.percentile(latencies, 95):.2f}ms | Min {np.min(latencies):.2f}ms")
    print("=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AegisFlow Synthetic Transaction Stream Simulator")
    parser.add_argument("--url", default="http://127.0.0.1:8000/api/v1/predict", help="Prediction API URL")
    parser.add_argument("--count", type=int, default=30, help="Number of transactions")
    parser.add_argument("--pause", type=float, default=0.15, help="Delay between transactions in seconds")
    parser.add_argument("--fraud-rate", type=float, default=0.20, help="Fraction of fraudulent transactions")
    args = parser.parse_args()

    run_simulator(
        target_url=args.url,
        count=args.count,
        pause=args.pause,
        fraud_rate=args.fraud_rate
    )
