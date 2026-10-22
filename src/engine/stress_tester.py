"""
AegisFlow AI — High-Scale Financial SLA Stress Testing Engine
Author: Om Kamble

Executes concurrent multi-threaded high-throughput load tests to stress-test
the AegisFlow inference pipeline, feature stores, and policy engine under
heavy production traffic (1,000 - 10,000 req bursts).

Supports diverse real-world surge scenarios:
- 'mixed': Normal e-commerce traffic with intermittent financial crime anomalies.
- 'carding_botnet': Rapid botnet micro-auth attack probing FastThreatFilter & Bloom Filter intercept.
- 'black_friday': Massive traffic spike triggering AdaptiveLoadShedder and Two-Phase async queue drain.
"""

import time
import numpy as np
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


class HighScaleStressRunner:
    def __init__(self, target_eval_func=None):
        self.target_eval_func = target_eval_func
        self.latest_result: Optional[Dict[str, Any]] = None

    def generate_scenario_payloads(self, num_requests: int, scenario: str = "mixed") -> List[Dict[str, Any]]:
        """Generates synthetic realistic payloads tailored to the specified scenario."""
        payloads = []
        scenario_lower = scenario.lower()

        if scenario_lower == "carding_botnet":
            # Botnet probing micro-auths from a clustered subnet with rapid card mutations
            bot_ip = "198.51.100.99"
            for i in range(num_requests):
                card_num = f"41110000{i % 20:04d}1234"
                payloads.append({
                    "transaction_id": f"BOTNET_{i:06d}",
                    "user_id": f"bot_agent_{i % 10}",
                    "merchant_id": "merch_digital_probe",
                    "ip_address": bot_ip,
                    "Amount": round(1.25 + (i % 3) * 0.50, 2),
                    "currency": "USD",
                    "card_identifier": card_num,
                    "V14": float(-4.5 if i % 10 == 0 else -0.5),
                    "V12": float(-3.0 if i % 10 == 0 else -0.2),
                    "V4": 1.8
                })

        elif scenario_lower == "black_friday":
            # Extreme holiday shopping surge with mixed ticket sizes
            for i in range(num_requests):
                is_whale = (i % 50 == 0)
                user_idx = i % 200
                payloads.append({
                    "transaction_id": f"BF_{i:06d}",
                    "user_id": f"cust_holiday_{user_idx:04d}",
                    "merchant_id": f"merch_superstore_{i % 30}",
                    "ip_address": f"203.0.113.{1 + (user_idx % 250)}",
                    "Amount": round(float(2500.0 if is_whale else 15.0 + (i % 120)), 2),
                    "currency": "USD",
                    "card_identifier": f"5200{user_idx:04d}9876",
                    "V14": float(-6.8 if is_whale else 0.05),
                    "V12": float(-4.2 if is_whale else 0.12),
                    "V4": float(3.1 if is_whale else -0.10)
                })

        else:
            # Standard mixed production distribution
            for i in range(num_requests):
                is_anomaly = (i % 25 == 0)
                user_idx = i % 50
                payloads.append({
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
                })

        return payloads

    def run_stress_test(
        self,
        num_requests: int = 500,
        concurrency: int = 8,
        sla_threshold_ms: float = 3.5,
        scenario: str = "mixed"
    ) -> Dict[str, Any]:
        """
        Executes concurrent load bursts against the AegisFlow pipeline
        and computes financial SLA compliance metrics.
        """
        if self.target_eval_func is None:
            from src.api.main import evaluate_single_transaction
            self.target_eval_func = evaluate_single_transaction

        from src.engine.fast_filter import fast_threat_filter
        from src.engine.load_shedder import load_shedder
        from src.engine.async_enricher import async_enricher

        latencies_ms: List[float] = []
        decisions: Dict[str, int] = {"APPROVE": 0, "CHALLENGE_2FA": 0, "BLOCK": 0, "MANUAL_REVIEW": 0}
        success_count = 0
        error_count = 0

        # Snapshot async enricher state before test
        initial_enricher_stats = async_enricher.get_stats()
        initial_filter_stats = fast_threat_filter.get_stats()

        # If running carding botnet, preload a known threat IP to test Bloom Filter intercept
        if scenario.lower() == "carding_botnet":
            fast_threat_filter.add_quarantine_ip("198.51.100.99")

        sample_payloads = self.generate_scenario_payloads(num_requests, scenario)

        start_wall = time.perf_counter()

        def _execute_single(payload):
            t0 = time.perf_counter()
            try:
                res = self.target_eval_func(payload, sync_enrich=False)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                return True, elapsed_ms, res.get("decision", "APPROVE"), res
            except Exception as e:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                return False, elapsed_ms, "ERROR", {"error": str(e)}

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(_execute_single, p) for p in sample_payloads]
            for fut in as_completed(futures):
                ok, elapsed, dec, _ = fut.result()
                latencies_ms.append(elapsed)
                if ok:
                    success_count += 1
                    decisions[dec] = decisions.get(dec, 0) + 1
                else:
                    error_count += 1

        total_wall_sec = max(0.001, time.perf_counter() - start_wall)
        throughput_tps = round(num_requests / total_wall_sec, 2)

        # Allow background workers to drain
        drain_start = time.perf_counter()
        async_enricher.wait_for_drain(timeout_sec=3.0)
        drain_sec = round(time.perf_counter() - drain_start, 3)

        final_enricher_stats = async_enricher.get_stats()
        final_filter_stats = fast_threat_filter.get_stats()
        shedder_metrics = load_shedder.get_metrics()

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

        result = {
            "status": "COMPLETED",
            "scenario": scenario,
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
            "sla_verdict": "SLA_MET" if p95 <= 5.0 else "SLA_DEGRADED",
            "load_shedder_tier": shedder_metrics.get("mode", "NOMINAL"),
            "fast_threat_shield": {
                "bloom_filter_quarantined_ips": final_filter_stats.get("bloom_quarantined_ips", 0),
                "l1_cache_hits": final_filter_stats.get("cache_hits", 0) - initial_filter_stats.get("cache_hits", 0),
                "total_threat_quarantines": final_filter_stats.get("total_quarantined_ips", 0)
            },
            "two_phase_async_enricher": {
                "drain_time_seconds": drain_sec,
                "current_queue_depth": final_enricher_stats.get("current_queue_depth", 0),
                "total_processed": final_enricher_stats.get("total_processed", 0) - initial_enricher_stats.get("total_processed", 0),
                "total_dropped": final_enricher_stats.get("total_dropped", 0) - initial_enricher_stats.get("total_dropped", 0),
                "avg_enrich_latency_ms": final_enricher_stats.get("avg_enrich_latency_ms", 0.0)
            }
        }

        self.latest_result = result
        return result

    def get_latest_result(self) -> Optional[Dict[str, Any]]:
        return self.latest_result


# Global singleton instance
stress_runner = HighScaleStressRunner()
