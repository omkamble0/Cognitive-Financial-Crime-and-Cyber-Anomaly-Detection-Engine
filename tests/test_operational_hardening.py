"""
FinCipher AI — Phase 5 Operational Hardening & Production Reliability Tests
Author: Om Kamble

Validates:
1. Threat intelligence live external feed synchronization & index metrics
2. Worker Redis / Autonomous streaming loop & telemetry
3. High-throughput multi-domain stress benchmark with sub-3.5ms P95 SLA assertion
4. MLOps model governance promotion gates & drift controls
5. REST API operational endpoints (/threat-intel/sync, /threat-intel/metrics, /benchmark/run)
"""

import unittest
from fastapi.testclient import TestClient
from apps.api.main import app
from services.threat_intel.connector import threat_intel_connector
from apps.worker.worker import FinCipherMultiDomainWorker
from scripts.stress_benchmark import run_benchmark
from src.engine.model_registry import ModelRegistry, ModelStage


class TestOperationalHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_threat_intel_sync_and_metrics(self):
        """Validates threat intelligence feed sync, error tolerance, and metrics reporting."""
        # 1. Check initial metrics
        metrics = threat_intel_connector.get_metrics()
        self.assertIn("total_indicators", metrics)
        self.assertGreater(metrics["total_indicators"], 10)
        self.assertIn("breakdown", metrics)

        # 2. Add custom IoC
        threat_intel_connector.add_custom_ioc("45.33.32.156", "IP_ADDRESS")
        match = threat_intel_connector.check_indicator("45.33.32.156")
        self.assertIsNotNone(match)
        self.assertEqual(match.threat_category, "BULLETPROOF_PROXY")

        # 3. Simulate feed sync with mock local source
        sync_res = threat_intel_connector.sync_external_feeds(
            feed_sources=[
                {"name": "Local Test List", "type": "IP_ADDRESS", "category": "TOR_EXIT_NODE", "url": ""}
            ]
        )
        self.assertIn(sync_res["status"], ("COMPLETED", "PARTIAL", "OFFLINE_FALLBACK"))
        self.assertIn("metrics", sync_res)

    def test_worker_streaming_telemetry_and_synthetic_loop(self):
        """Validates worker loop, latency metrics, and automated synthetic streaming."""
        worker = FinCipherMultiDomainWorker(enable_synthetic_fallback=True)
        worker.run_loop(max_events=15, interval_seconds=0.01)

        metrics = worker.get_metrics()
        self.assertEqual(metrics["processed_count"], 15)
        self.assertGreaterEqual(metrics["processed_count"], metrics["anomalies_detected"])
        self.assertIn("p95_evaluation_latency_ms", metrics)
        self.assertLess(metrics["p95_evaluation_latency_ms"], 20.0)

    def test_high_throughput_benchmark_sla(self):
        """Validates that under multi-domain load, P95 latency is strictly under 3.5ms."""
        result = run_benchmark(total_events=600, max_workers=4)
        self.assertEqual(result["total_events"], 600)
        self.assertTrue(result["sla_compliant"], f"P95 latency {result['p95_ms']}ms exceeded 3.5ms SLA target!")
        self.assertLess(result["p95_ms"], 3.5)
        self.assertGreater(result["throughput_tps"], 500.0)

    def test_model_governance_lifecycle(self):
        """Validates MLOps model registry staging and promotion gates."""
        registry = ModelRegistry()
        prod = registry.get_production_model()
        self.assertIsNotNone(prod)
        self.assertEqual(prod["stage"], ModelStage.PRODUCTION.value)

        # Register challenger
        reg_res = registry.register_model(
            version="v2.5.0-rc",
            algorithm="FinCipher Transformer Risk Classifier",
            f1_score=0.942,
            auc_roc=0.989,
            p95_latency_ms=0.85,
            false_positive_rate=0.005,
            training_samples=500000,
            feature_names=["amount", "velocity", "device_entropy"],
            artifact_path="models/v250.pkl"
        )
        self.assertEqual(reg_res["stage"], ModelStage.STAGING.value)

        # Promote to Production
        promoted = registry.promote_model("v2.5.0-rc", ModelStage.PRODUCTION, operator="lead_quant_analyst")
        self.assertEqual(promoted["stage"], ModelStage.PRODUCTION.value)
        self.assertEqual(registry.get_production_model()["version"], "v2.5.0-rc")

    def test_operational_rest_endpoints(self):
        """Validates REST endpoints for threat-intel sync, metrics, and micro-benchmark."""
        # Metrics endpoint
        res_m = self.client.get("/api/v1/events/threat-intel/metrics")
        self.assertEqual(res_m.status_code, 200)
        data_m = res_m.json()
        self.assertIn("total_indicators", data_m)

        # Sync endpoint
        res_s = self.client.post("/api/v1/events/threat-intel/sync", json={"timeout": 1.0})
        self.assertEqual(res_s.status_code, 200)

        # Benchmark endpoint
        res_b = self.client.post("/api/v1/events/benchmark/run?events_count=50")
        self.assertEqual(res_b.status_code, 200)
        data_b = res_b.json()
        self.assertEqual(data_b["status"], "COMPLETED")
        self.assertEqual(data_b["events_evaluated"], 50)
        self.assertTrue(data_b["sla_compliant"])
        self.assertLess(data_b["latency_stats_ms"]["p95"], 3.5)


if __name__ == "__main__":
    unittest.main()
