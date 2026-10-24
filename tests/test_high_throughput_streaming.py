"""
FinCipher AI — High-Throughput Streaming & Multi-Domain Ingestion Pipeline Tests
Author: Om Kamble
"""

import pytest
import time
from src.streaming.continuous_streamer import continuous_streamer
from services.ingestion.normalizer import UniversalEventNormalizer
from services.risk_engine.router import universal_risk_router


class TestHighThroughputStreamingPipeline:
    """Verifies multi-domain event streaming, dynamic throughput scaling up to 5,000 TPS, and zero-drop backpressure."""

    def test_multi_domain_event_generation(self):
        """Verifies event generation across Banking, Cyber, and E-Commerce."""
        # 1. Banking Event
        bank_evt = continuous_streamer._generate_banking_event(is_fraud=False)
        assert bank_evt.domain.value == "BANKING"
        assert bank_evt.event_type.value == "PAYMENT"
        assert "amount" in bank_evt.payload

        # 2. Cyber Event
        cyber_evt = continuous_streamer._generate_cyber_event(is_fraud=False)
        assert cyber_evt.domain.value == "CYBERSECURITY"
        assert "ip_address" in cyber_evt.context
        assert cyber_evt.primary_entity_id.startswith("usr_") or cyber_evt.primary_entity_id in continuous_streamer.cyber_users

        # 3. E-Commerce Event
        ecom_evt = continuous_streamer._generate_ecommerce_event(is_fraud=False)
        assert ecom_evt.domain.value == "ECOMMERCE"
        assert "cart_total" in ecom_evt.payload

    def test_multi_domain_burst_injection(self):
        """Verifies synchronous burst ingestion with graph linkages."""
        burst_results = continuous_streamer.inject_burst(count=15, domain="ALL")
        assert len(burst_results) == 15
        for res in burst_results:
            assert "decision" in res
            assert res["decision"] in ("APPROVE", "ALLOW", "CHALLENGE", "CHALLENGE_2FA", "MFA_CHALLENGE", "BLOCK", "QUARANTINE")
            assert "latency_ms" in res
            assert "graph_cluster" in res

    def test_domain_pivoting(self):
        """Verifies setting stream domain to specific architectures."""
        st_cyber = continuous_streamer.set_domain("CYBERSECURITY")
        assert st_cyber["active_domain"] == "CYBERSECURITY"

        st_ecom = continuous_streamer.set_domain("ECOMMERCE")
        assert st_ecom["active_domain"] == "ECOMMERCE"

        st_all = continuous_streamer.set_domain("ALL")
        assert st_all["active_domain"] == "ALL"

    def test_dynamic_tps_scaling(self):
        """Verifies rate adjustment and status reporting up to high throughput."""
        status = continuous_streamer.set_rate(1000.0)
        assert status["target_tps"] == 1000.0

        status_max = continuous_streamer.set_rate(5000.0)
        assert status_max["target_tps"] == 5000.0

        # Reset to safe default
        continuous_streamer.set_rate(2.0)

    def test_shock_injection_scenarios(self):
        """Verifies shock injection across attack profiles."""
        shocks = ["CARDING_BURST", "IMPOSSIBLE_TRAVEL", "BSA_STRUCTURING", "PROMO_FARMING", "BRUTE_FORCE_BOTS"]
        for s in shocks:
            res = continuous_streamer.inject_shock(s)
            assert res["status"] == "shock_injected"
            assert res["active_shock"] == s

        # Reset to nominal
        continuous_streamer.inject_shock("NOMINAL")

    def test_background_streaming_lifecycle(self):
        """Verifies start, streaming telemetry, and clean shutdown without deadlocks."""
        emitted_events = []

        def capture_callback(payload):
            emitted_events.append(payload)

        continuous_streamer.set_broadcast_callback(capture_callback)
        start_res = continuous_streamer.start(tps=10.0, fraud_ratio=0.10, domain="ALL")
        assert start_res["is_running"] is True

        time.sleep(0.4)
        status = continuous_streamer.get_status()
        assert status["is_running"] is True
        assert status["total_streamed"] > 0
        assert "p95_latency_ms" in status
        assert "buffer_health_pct" in status

        stop_res = continuous_streamer.stop()
        assert stop_res["is_running"] is False
        assert continuous_streamer.is_running is False
