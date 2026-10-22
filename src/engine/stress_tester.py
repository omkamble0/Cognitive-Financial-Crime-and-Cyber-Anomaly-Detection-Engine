"""
AegisFlow AI — High-Scale Financial SLA Stress Testing Engine
Author: Om Kamble

Executes concurrent multi-threaded high-throughput load tests to stress-test
the AegisFlow inference pipeline, feature stores, and policy engine under
heavy production traffic (1,000 - 10,000 req bursts).
"""

import time
import numpy as np
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


class HighScaleStressRunner:
    def __init__(self, target_eval_func=None):
        self.target_eval_func = target_eval_func

    def run_stress_test(
        self,
        num_requests: int = 500,
        concurrency: int = 8,
        sla_threshold_ms: float = 3.5
    ) -> Dict[str, Any]:
        """
        Executes concurrent load bursts against the AegisFlow pipeline
        and computes financial SLA compliance metrics.
        """
        if self.target_eval_func is None:
            from src.api.main import evaluate_single_transaction
            self.target_eval_func = evaluate_single_transaction

        latencies_ms: List[float] = []
        decisions: Dict[str, int] = {"APPROVE": 0, "CHALLENGE_2FA": 0, "BLOCK": 0, "MANUAL_REVIEW": 0}
        success_count = 0
        error_count = 0

        # Generate synthetic realistic payloads
        sample_payloads = []
        for i in range(num_requests):
            is_anomaly = (i % 25 == 0)
            user_idx = i % 50
            payload = {
                "transaction_id": f"STRESS_{i:06d}",
                "user_id": f"usr_stress_{user_idx:03d}",
                "merchant_id": f"merchant_retail_{i % 15}",
                "ip_address": f"198.51.{1 + (user_idx % 200)}.{1 + (user_idx % 250)}",
                "Amount": round(float(4800.0 if is_anomaly else 35.0 + (i % 60)), 2),
                "currency": "USD",
                "card_identifier": f"4111{user_idx:04d}0000{user_idx:02d}",
                "V14": float(-6.5 if is_anomaly else 0.15),
                "V12": float(-4.5 if is_anomaly else 0.08),
                "V4": float(2.8 if is_anomaly else -0.15)
            }
            sample_payloads.append(payload)

        start_wall = time.perf_counter()

        def _execute_single(payload):
            t0 = time.perf_counter()
            try:
                res = self.target_eval_func(payload)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                return True, elapsed_ms, res.get("decision", "APPROVE")
            except Exception as e:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                return False, elapsed_ms, "ERROR"

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(_execute_single, p) for p in sample_payloads]
            for fut in as_completed(futures):
                ok, elapsed, dec = fut.result()
                latencies_ms.append(elapsed)
                if ok:
                    success_count += 1
                    decisions[dec] = decisions.get(dec, 0) + 1
                else:
                    error_count += 1

        total_wall_sec = max(0.001, time.perf_counter() - start_wall)
        throughput_tps = round(num_requests / total_wall_sec, 2)

        sorted_lat = sorted(latencies_ms)
        p50 = float(np.percentile(sorted_lat, 50))
        p90 = float(np.percentile(sorted_lat, 90))
        p95 = float(np.percentile(sorted_lat, 95))
        p99 = float(np.percentile(sorted_lat, 99))
        avg_lat = float(np.mean(sorted_lat))
        min_lat = float(sorted_lat[0])
        max_lat = float(sorted_lat[-1])

        compliant_count = sum(1 for lat in latencies_ms if lat <= sla_threshold_ms)
        sla_pct = round((compliant_count / num_requests) * 100.0, 2)

        return {
            "status": "COMPLETED",
            "total_requests": num_requests,
            "concurrency_workers": concurrency,
            "total_duration_seconds": round(total_wall_sec, 3),
            "throughput_tps": throughput_tps,
            "sla_threshold_ms": sla_threshold_ms,
            "sla_compliance_pct": sla_pct,
            "latencies_ms": {
                "min": round(min_lat, 3),
                "avg": round(avg_lat, 3),
                "p50": round(p50, 3),
                "p90": round(p90, 3),
                "p95": round(p95, 3),
                "p99": round(p99, 3),
                "max": round(max_lat, 3)
            },
            "decision_distribution": decisions,
            "success_rate_pct": round((success_count / num_requests) * 100.0, 2),
            "error_count": error_count,
            "sla_verdict": "SLA_MET" if p95 <= 5.0 else "SLA_DEGRADED"
        }


# Global singleton instance
stress_runner = HighScaleStressRunner()
