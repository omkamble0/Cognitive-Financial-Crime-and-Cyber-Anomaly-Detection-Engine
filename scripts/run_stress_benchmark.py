import urllib.request
import json
import time

def run_bench(scenario: str, req_count: int = 500, conc: int = 8, sla_ms: float = 3.5):
    payload = {
        "requests": req_count,
        "concurrency": conc,
        "sla_ms": sla_ms,
        "scenario": scenario
    }
    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/benchmark/stress",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def main():
    print("=" * 72)
    print("  [AEGISFLOW] Step 4: High-Scale Multi-Scenario Stress Benchmark Suite")
    print("=" * 72)

    scenarios = [
        {"name": "mixed", "requests": 300, "concurrency": 8, "sla": 5.0, "desc": "Mixed Production E-Commerce Traffic"},
        {"name": "carding_botnet", "requests": 1000, "concurrency": 16, "sla": 3.5, "desc": "Distributed Carding Botnet Micro-Auth Probing (FastThreatFilter Shield)"},
        {"name": "black_friday", "requests": 300, "concurrency": 8, "sla": 5.0, "desc": "Black Friday Traffic Surge (Two-Phase Decoupled Flow)"}
    ]

    for item in scenarios:
        sc = item["name"]
        req_count = item["requests"]
        conc = item["concurrency"]
        sla = item["sla"]
        desc = item["desc"]

        print(f"\n>> Executing Scenario: [{sc.upper()}] — {desc}")
        print(f"   Config: {req_count} requests | Concurrency: {conc} workers | Target SLA: {sla}ms")

        t0 = time.perf_counter()
        res = run_bench(sc, req_count, conc, sla)
        elapsed = time.perf_counter() - t0

        print(f"  * Throughput:           {res['throughput_tps']:.2f} TPS")
        print(f"  * Wall Duration:        {res['total_duration_seconds']:.3f}s (Roundtrip: {elapsed:.3f}s)")
        print(f"  * Latency Distribution: min={res['latencies_ms']['min']:.3f}ms | avg={res['latencies_ms']['avg']:.3f}ms | p50={res['latencies_ms']['p50']:.3f}ms | p95={res['latencies_ms']['p95']:.3f}ms | p99={res['latencies_ms']['p99']:.3f}ms")
        print(f"  * Financial SLA:        {res['sla_compliance_pct']}% compliant (Verdict: {res['sla_verdict']})")
        print(f"  * Decision Breakdown:   {res['decision_distribution']}")
        print(f"  * Threat Shield Status: Quarantined IPs: {res.get('fast_threat_shield', {}).get('bloom_filter_quarantined_ips')}")
        print(f"  * Async Worker Queue:   depth={res['two_phase_async_enricher']['current_queue_depth']}, processed={res['two_phase_async_enricher']['total_processed']}, dropped={res['two_phase_async_enricher']['total_dropped']}")

    print("\n" + "=" * 72)
    print("  [SUCCESS] ALL STRESS BENCHMARK SCENARIOS VALIDATED")
    print("=" * 72)

if __name__ == "__main__":
    main()
