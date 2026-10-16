"""
AegisFlow — Continuous Multi-Threaded Global Transaction Streamer
Author: Om Kamble

Multi-threaded background event streaming engine:
1. Synthesizes realistic continuous financial transactions across 7 currencies and 6 schemes.
2. Supports dynamic TPS scaling (1 to 50+ TPS) with thread-safe control.
3. Automatically evaluates transactions through the cognitive pipeline and broadcasts
   real-time payloads over active WebSocket connections.
4. Allows on-demand injection of cyber attack shocks (Carding Probes, Geo-Arbitrage, Structuring).
"""

import time
import math
import random
import threading
import asyncio
from typing import Dict, Any, List, Optional
from collections import deque


class ContinuousTransactionStreamer:
    def __init__(self, broadcast_callback=None):
        self.is_running = False
        self.target_tps: float = 2.0  # Default 2 transactions per second
        self.fraud_ratio: float = 0.08  # 8% baseline anomalies
        self.total_streamed: int = 0
        self.total_blocked: int = 0
        self.total_challenged: int = 0
        self.total_approved: int = 0
        self.active_shock: str = "NOMINAL"
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.broadcast_callback = broadcast_callback
        self.recent_history = deque(maxlen=100)

        # Multi-currency & Multi-scheme generation pools
        self.currencies = ["USD", "EUR", "GBP", "INR", "JPY", "CAD", "AUD"]
        self.scheme_profiles = [
            ("RUPAY", "card_rupay", "INR", 500, 15000),
            ("AMEX", "card_amex", "USD", 45, 2500),
            ("PRIVATE_CORP", "card_corp_fleet", "USD", 250, 9500),
            ("STORE_CLOSED_LOOP", "card_store_retail", "USD", 15, 650),
            ("VIRTUAL_TOKEN", "card_vtoken_dpan", "EUR", 20, 800),
            ("VISA", "card_visa", "USD", 25, 1200),
            ("MASTERCARD", "card_mc", "GBP", 30, 1500)
        ]
        self.merchants = [
            "ApexRetail_Global", "CloudServices_AWS", "ShellFuelCenter",
            "QuickDine_Bistro", "MetroTransit_Pass", "LuxuryGoods_Personal",
            "DarkStore_66", "FlightExpress_Air", "CryptoExchange_Direct"
        ]
        self.countries = ["US", "IN", "GB", "DE", "FR", "JP", "CA", "AU", "SG"]

    def set_broadcast_callback(self, callback):
        self.broadcast_callback = callback

    def start(self, tps: float = 2.0, fraud_ratio: float = 0.08) -> Dict[str, Any]:
        """Starts the background streaming daemon."""
        if self.is_running:
            self.target_tps = max(0.5, min(50.0, float(tps)))
            self.fraud_ratio = max(0.0, min(1.0, float(fraud_ratio)))
            return self.get_status()

        self.target_tps = max(0.5, min(50.0, float(tps)))
        self.fraud_ratio = max(0.0, min(1.0, float(fraud_ratio)))
        self.is_running = True
        self._stop_event.clear()

        self._thread = threading.Thread(target=self._run_stream_loop, daemon=True, name="AegisFlowStreamerThread")
        self._thread.start()
        return self.get_status()

    def stop(self) -> Dict[str, Any]:
        """Stops the streaming daemon."""
        self.is_running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        return self.get_status()

    def set_rate(self, tps: float) -> Dict[str, Any]:
        """Adjusts the streaming speed in real time."""
        self.target_tps = max(0.5, min(50.0, float(tps)))
        return self.get_status()

    def inject_shock(self, shock_name: str) -> Dict[str, Any]:
        """Injects a specific cyber scenario shock."""
        shocks = ("NOMINAL", "CARDING_BURST", "HOLIDAY_SURGE", "IMPOSSIBLE_TRAVEL", "BSA_STRUCTURING")
        shock_upper = shock_name.upper()
        self.active_shock = shock_upper if shock_upper in shocks else "NOMINAL"
        return {
            "status": "shock_injected",
            "active_shock": self.active_shock,
            "target_tps": self.target_tps
        }

    def _generate_synthetic_transaction(self) -> Dict[str, Any]:
        """Generates a realistic multi-scheme, multi-currency transaction payload."""
        now = time.time()
        is_fraud = random.random() < self.fraud_ratio

        # Handle active shock modifiers
        if self.active_shock == "CARDING_BURST":
            is_fraud = random.random() < 0.65
        elif self.active_shock == "HOLIDAY_SURGE":
            is_fraud = random.random() < 0.03

        # Select scheme and profile
        scheme_tuple = random.choice(self.scheme_profiles)
        scheme_code, prefix, default_curr, min_amt, max_amt = scheme_tuple
        currency = random.choice(self.currencies) if random.random() < 0.3 else default_curr

        card_num = f"{prefix}_{random.randint(1000, 9999)}"
        mcht = random.choice(self.merchants)
        if is_fraud and random.random() < 0.4:
            mcht = "DarkStore_66"

        # Amount generation
        if self.active_shock == "CARDING_BURST":
            raw_amount = round(random.uniform(0.50, 2.75), 2)  # Micro-auth probing
        elif self.active_shock == "BSA_STRUCTURING" and is_fraud:
            raw_amount = round(random.uniform(9750.0, 9990.0), 2)  # Under $10k reporting
        elif is_fraud:
            raw_amount = round(random.uniform(max_amt * 0.8, max_amt * 2.5), 2)
        else:
            raw_amount = round(random.uniform(min_amt, max_amt * 0.35), 2)

        client_ip = f"198.51.{random.randint(10, 100)}.{random.randint(2, 250)}"
        if self.active_shock == "CARDING_BURST":
            client_ip = "198.51.100.88"  # Probing bot IP

        # Generate PCA vectors
        v14 = round(random.uniform(-4.5, -1.8), 2) if is_fraud else round(random.uniform(-0.8, 0.8), 2)
        v12 = round(random.uniform(-3.8, -1.5), 2) if is_fraud else round(random.uniform(-0.6, 0.6), 2)
        v4 = round(random.uniform(1.8, 4.2), 2) if is_fraud else round(random.uniform(-0.5, 1.2), 2)
        v10 = round(random.uniform(-3.0, -1.0), 2) if is_fraud else round(random.uniform(-0.7, 0.7), 2)
        v17 = round(random.uniform(-3.5, -1.2), 2) if is_fraud else round(random.uniform(-0.5, 0.5), 2)

        device_trust = round(random.uniform(0.05, 0.35), 2) if is_fraud else round(random.uniform(0.80, 1.0), 2)

        payload = {
            "transaction_id": f"TXN_{int(now * 1000) % 10000000}",
            "user_id": f"usr_{random.randint(1000, 9999)}",
            "card_identifier": card_num,
            "scheme": scheme_code,
            "currency": currency,
            "Amount": raw_amount,
            "merchant_id": mcht,
            "ip_address": client_ip,
            "device_trust_score": device_trust,
            "Time": 0.0,
            "V14": v14,
            "V12": v12,
            "V4": v4,
            "V10": v10,
            "V17": v17
        }
        for i in range(1, 29):
            if f"V{i}" not in payload:
                payload[f"V{i}"] = round(random.gauss(0.0, 0.5), 3)

        return payload

    def _run_stream_loop(self):
        """Worker thread loop executing at target TPS."""
        # Delayed import to avoid circular dependency
        from src.api.main import evaluate_single_transaction

        while not self._stop_event.is_set() and self.is_running:
            start_t = time.perf_counter()
            try:
                tx_payload = self._generate_synthetic_transaction()
                result = evaluate_single_transaction(tx_payload)

                self.total_streamed += 1
                dec = result.get("decision", "APPROVE")
                if dec == "BLOCK":
                    self.total_blocked += 1
                elif dec in ("CHALLENGE_2FA", "MANUAL_REVIEW"):
                    self.total_challenged += 1
                else:
                    self.total_approved += 1

                self.recent_history.append(result)

                # Broadcast to connected WebSockets
                if self.broadcast_callback:
                    try:
                        self.broadcast_callback(result)
                    except Exception:
                        pass

            except Exception as e:
                print(f"[!] Streamer worker error: {e}")

            # Dynamic pacing
            sleep_sec = 1.0 / max(0.5, self.target_tps)
            elapsed = time.perf_counter() - start_t
            remaining = sleep_sec - elapsed
            if remaining > 0:
                self._stop_event.wait(timeout=remaining)

    def get_status(self) -> Dict[str, Any]:
        """Returns real-time status and throughput telemetry."""
        return {
            "is_running": self.is_running,
            "target_tps": round(self.target_tps, 1),
            "fraud_ratio": round(self.fraud_ratio, 3),
            "total_streamed": self.total_streamed,
            "total_blocked": self.total_blocked,
            "total_challenged": self.total_challenged,
            "total_approved": self.total_approved,
            "active_shock": self.active_shock,
            "recent_count": len(self.recent_history)
        }


# Global singleton instance
continuous_streamer = ContinuousTransactionStreamer()
