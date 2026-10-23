"""
FinCipher AI — High-Throughput Multi-Domain Stress & Latency Benchmark Suite
Author: Om Kamble

Validates platform SLAs under high concurrent transaction loads:
- Concurrently evaluates Banking, Cybersecurity, and E-Commerce events
- Profiles P50, P90, P95, and P99 evaluation latencies
- Verifies sub-3.5ms SLA compliance across composite risk evaluations
"""

import time
import random
import statistics
import concurrent.futures
from typing import Dict, Any, List
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from libs.models.events import GenericEvent
from services.ingestion.normalizer import UniversalEventNormalizer
from services.risk_engine.router import universal_risk_router


def generate_benchmark_event(i: int) -> GenericEvent:
    domain_idx = i % 3
    is_anomaly = (i % 7 == 0)

    if domain_idx == 0:
        # Banking
        amt = 9850.0 if is_anomaly else (25.0 + (i % 450))
        country = "KP" if is_anomaly else "US"
        raw = {
            "transaction_id": f"TX_BENCH_{i}_{int(time.time()*1000)}",
            "user_id": f"usr_bench_{i % 50}",
            "amount": amt,
            "currency": "USD",
            "country": country,
            "ip_address": "198.51.100.12" if is_anomaly else f"10.0.{(i%250)}.1"
        }
        return UniversalEventNormalizer.normalize_banking_payment(raw)

    elif domain_idx == 1:
        # Cybersecurity
        status = "FAILURE" if is_anomaly else "SUCCESS"
        raw = {
            "username": "root" if is_anomaly else f"sec_user_{i % 30}",
            "source_ip": "192.0.2.77" if is_anomaly else f"10.1.{(i%250)}.15",
            "status": status,
            "target_host": "prod-auth-bastion-01",
            "mfa_used": not is_anomaly
        }
        return UniversalEventNormalizer.normalize_cyber_auth(raw)

    else:
        # E-Commerce
        promo = "PROMO_EXPLOIT_99" if is_anomaly else "WELCOME10"
        raw = {
            "order_id": f"ORD_BENCH_{i}_{int(time.time()*1000)}",
            "customer_id": f"shopper_{i % 25}",
            "ip_address": "198.51.100.99" if is_anomaly else f"10.2.{(i%250)}.8",
            "total_amount": 120.0 if is_anomaly else 45.0,
            "discount_amount": 95.0 if is_anomaly else 4.5,
            "promo_code": promo,
            "discount_applied": True
        }
        return UniversalEventNormalizer.normalize_ecommerce_order(raw)


def run_benchmark(total_events: int = 1500, max_workers: int = 8) -> Dict[str, Any]:
    print(f"\n======================================================================")
    print(f"  FinCipher AI — High-Throughput Multi-Domain Stress Benchmark")
    print(f"======================================================================")
    print(f"  Total Events: {total_events} | Concurrency Workers: {max_workers}")
    print(f"  Domains: Banking, Cybersecurity, E-Commerce")
    print(f"  SLA Target: P95 Latency < 3.5ms\n")

    events = [generate_benchmark_event(i) for i in range(total_events)]

    latencies_ms: List[float] = []

    def evaluate_single(evt: GenericEvent) -> float:
        t0 = time.perf_counter()
        res = universal_risk_router.evaluate_event(evt)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        return dt_ms

    wall_start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(evaluate_single, e) for e in events]
        for f in concurrent.futures.as_completed(futures):
            latencies_ms.append(f.result())
    wall_duration = time.perf_counter() - wall_start

    sorted_lat = sorted(latencies_ms)
    p50 = sorted_lat[int(0.50 * len(sorted_lat))]
    p90 = sorted_lat[int(0.90 * len(sorted_lat))]
    p95 = sorted_lat[int(0.95 * len(sorted_lat))]
    p99 = sorted_lat[int(0.99 * len(sorted_lat))]
    avg = statistics.mean(latencies_ms)
    tps = total_events / max(0.001, wall_duration)

    is_compliant = p95 < 3.5

    print(f"  Execution Results:")
    print(f"  ------------------------------------------------------------------")
    print(f"  Total Duration:     {wall_duration:.3f} s")
    print(f"  Throughput:         {tps:.1f} events/sec")
    print(f"  Mean Latency:       {avg:.3f} ms")
    print(f"  P50 Latency:        {p50:.3f} ms")
    print(f"  P90 Latency:        {p90:.3f} ms")
    print(f"  P95 Latency:        {p95:.3f} ms (Target < 3.5ms) -> {'[PASSED]' if is_compliant else '[FAILED]'}")
    print(f"  P99 Latency:        {p99:.3f} ms")
    print(f"======================================================================\n")

    return {
        "total_events": total_events,
        "duration_seconds": round(wall_duration, 4),
        "throughput_tps": round(tps, 1),
        "p50_ms": round(p50, 3),
        "p90_ms": round(p90, 3),
        "p95_ms": round(p95, 3),
        "p99_ms": round(p99, 3),
        "avg_ms": round(avg, 3),
        "sla_target_ms": 3.5,
        "sla_compliant": is_compliant
    }


if __name__ == "__main__":
    result = run_benchmark(total_events=1200, max_workers=6)
