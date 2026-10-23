"""
FinCipher AI — Production Live Monitoring & Platform Hardening Test Suite
Author: Om Kamble

Validates Priorities 5, 6, 7, and 8:
1. Versioned Parameterized Domain Rule Packs with Dynamic Calibration (Priority 5)
2. Threat Intelligence Sync Worker, Dynamic TTL Caching & Offline Fallback (Priority 6)
3. Cryptographic Merkle Audit Proofs & Model Governance Canary Promotion (Priority 7)
4. Prometheus Telemetry (/metrics) & Kubernetes Health Probes (/health/live, /health/ready) (Priority 8)
"""

import time
import unittest
from fastapi.testclient import TestClient
from apps.api.main import app

from services.domains.rule_packs import rule_pack_registry, DomainRulePack, RuleDefinition
from services.threat_intel.connector import (
    threat_intel_connector,
    threat_intel_sync_worker,
    ThreatIntelSyncWorker
)
from src.engine.audit_ledger import audit_ledger
from src.engine.canary_pipeline import CanaryModelEvaluator


class TestProductionMonitoringSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    # =========================================================================
    # PRIORITY 5: PARAMETERIZED DOMAIN RULE PACKS & CALIBRATION
    # =========================================================================
    def test_domain_rule_packs_and_dynamic_calibration(self):
        """Validates rule pack discovery, parameter tuning, calibration, and tenant binding."""
        # 1. Verify default production rule packs exist for Banking, Cyber, E-Commerce
        packs = rule_pack_registry.list_all_packs()
        domains = {p["domain"] for p in packs}
        self.assertIn("BANKING", domains)
        self.assertIn("CYBERSECURITY", domains)
        self.assertIn("ECOMMERCE", domains)

        # 2. Retrieve default Banking pack
        banking_pack = rule_pack_registry.get_pack("BANKING")
        self.assertIsNotNone(banking_pack)
        self.assertIn("AML_CTR_STRUCTURING", banking_pack.rules)
        self.assertEqual(banking_pack.rules["AML_CTR_STRUCTURING"].parameters["ctr_ceiling"], 10000.0)

        # 3. Dynamically calibrate Banking pack with strict thresholds and version bump
        calibrated = rule_pack_registry.calibrate_pack(
            domain="BANKING",
            version=banking_pack.version,
            rule_weights={"AML_CTR_STRUCTURING": 0.95},
            parameters={"AML_CTR_STRUCTURING": {"lower_bound": 7500.0, "ctr_ceiling": 9999.0}},
            decision_thresholds={"block_above": 0.70},
            new_version="2.0.0-strict",
            author="chief_compliance_officer"
        )
        self.assertEqual(calibrated.version, "2.0.0-strict")
        self.assertEqual(calibrated.rules["AML_CTR_STRUCTURING"].weight, 0.95)
        self.assertEqual(calibrated.rules["AML_CTR_STRUCTURING"].parameters["lower_bound"], 7500.0)
        self.assertEqual(calibrated.decision_thresholds["block_above"], 0.70)

        # 4. Bind client tenant to calibrated strict pack
        rule_pack_registry.bind_tenant_pack("tenant_strict_corp", "BANKING", "2.0.0-strict")
        tenant_pack = rule_pack_registry.get_pack_for_tenant("BANKING", "tenant_strict_corp")
        self.assertEqual(tenant_pack.version, "2.0.0-strict")

        # 5. REST Endpoints for Rule Packs
        res_list = self.client.get("/api/v1/events/rules/packs")
        self.assertEqual(res_list.status_code, 200)
        self.assertGreaterEqual(res_list.json()["total_packs"], 3)

        res_pack = self.client.get("/api/v1/events/rules/packs/BANKING?tenant_id=tenant_strict_corp")
        self.assertEqual(res_pack.status_code, 200)
        self.assertEqual(res_pack.json()["version"], "2.0.0-strict")

    # =========================================================================
    # PRIORITY 6: THREAT INTELLIGENCE SYNC & TTL CACHING
    # =========================================================================
    def test_threat_intelligence_sync_and_ttl_cache(self):
        """Validates threat feeds, indicator matching, dynamic TTL expiration, and worker fallback."""
        # 1. Match known indicators
        match_tor = threat_intel_connector.check_indicator("185.220.101.5")
        self.assertIsNotNone(match_tor)
        self.assertEqual(match_tor.threat_category, "TOR_EXIT_NODE")

        match_burner = threat_intel_connector.check_indicator("attacker@mailinator.com")
        self.assertIsNotNone(match_burner)
        self.assertEqual(match_burner.threat_category, "DISPOSABLE_EMAIL")

        # 2. Dynamic TTL Indicator: Register with 2-second TTL
        test_ip = f"198.51.100.{int(time.time() % 200 + 50)}"
        threat_intel_connector.add_indicator_with_ttl(
            indicator=test_ip,
            indicator_type="IP_ADDRESS",
            category="BOTNET_BEACON",
            ttl_seconds=1.0
        )
        # Should match immediately
        immediate_match = threat_intel_connector.check_indicator(test_ip)
        self.assertIsNotNone(immediate_match)
        self.assertEqual(immediate_match.threat_category, "BOTNET_BEACON")

        # After sleep, TTL should expire and indicator should return clean (None)
        time.sleep(1.2)
        expired_match = threat_intel_connector.check_indicator(test_ip)
        self.assertIsNone(expired_match)

        # 3. Scheduled Worker & Graceful Offline Fallback
        worker = ThreatIntelSyncWorker(
            connector=threat_intel_connector,
            custom_feeds=[{"name": "Invalid Unreachable Feed", "url": "http://127.0.0.1:59999/feed", "type": "IP_ADDRESS"}]
        )
        sync_result = worker.trigger_immediate_sync()
        status = worker.get_worker_status()
        self.assertIn("fallback_active", status)
        self.assertTrue(status["fallback_active"])

        # 4. REST Endpoints for Threat Intel
        res_status = self.client.get("/api/v1/events/threat-intel/status")
        self.assertEqual(res_status.status_code, 200)
        self.assertIn("connector_metrics", res_status.json())

        res_check = self.client.get("/api/v1/events/threat-intel/check?value=185.220.101.5")
        self.assertEqual(res_check.status_code, 200)
        self.assertTrue(res_check.json()["matched"])

    # =========================================================================
    # PRIORITY 7: CRYPTOGRAPHIC MERKLE AUDIT & MODEL GOVERNANCE
    # =========================================================================
    def test_cryptographic_audit_and_canary_governance(self):
        """Validates Merkle hash chain verification, tamper detection, and hot model promotion."""
        # 1. Verify healthy audit ledger integrity
        v_res = self.client.get("/api/v1/events/audit/verify")
        self.assertEqual(v_res.status_code, 200)
        self.assertTrue(v_res.json()["is_valid"])
        self.assertEqual(v_res.json()["status"], "VERIFIED_SECURE")
        self.assertIn("root_merkle_digest", v_res.json())

        # 2. Simulate malicious insider tampering
        t_res = self.client.post("/api/v1/events/audit/simulate-tampering")
        self.assertEqual(t_res.status_code, 200)

        # Verification must now instantly flag COMPROMISED / INVALID_SIGNATURE
        v_compromised = self.client.get("/api/v1/events/audit/verify")
        self.assertFalse(v_compromised.json()["is_valid"])

        # 3. Cryptographically re-seal and restore ledger
        r_res = self.client.post("/api/v1/events/audit/restore")
        self.assertEqual(r_res.status_code, 200)
        self.assertEqual(r_res.json()["status"], "VERIFIED_SECURE")

        # Verify healthy once again
        v_restored = self.client.get("/api/v1/events/audit/verify")
        self.assertTrue(v_restored.json()["is_valid"])

        # 4. MLOps Canary Governance: Shadow scoring & hot promotion
        canary = CanaryModelEvaluator()
        # Feed synthetic shadow scores
        for i in range(10):
            canary.score_shadow(champion_score=0.25, amount=100.0)
        telemetry = canary.get_telemetry()
        self.assertIn("champion_model", telemetry)

        # Hot-promote challenger
        p_res = canary.promote_challenger()
        self.assertTrue(p_res["success"])
        self.assertIn("merkle_audit_hash", p_res)

        # Rollback
        rb_res = canary.rollback()
        self.assertTrue(rb_res["success"])

        # Test API endpoints for governance
        res_gov = self.client.get("/api/v1/events/governance/canary")
        self.assertEqual(res_gov.status_code, 200)

    # =========================================================================
    # PRIORITY 8: SCALE, OBSERVABILITY & PROMETHEUS METRICS
    # =========================================================================
    def test_observability_and_prometheus_metrics(self):
        """Validates Kubernetes health probes and standard Prometheus /metrics scraping."""
        # 1. Liveness Probe
        res_live = self.client.get("/health/live")
        self.assertEqual(res_live.status_code, 200)
        self.assertEqual(res_live.json()["status"], "UP")
        self.assertEqual(res_live.json()["brand"], "FinCipher AI")

        # 2. Readiness Probe
        res_ready = self.client.get("/health/ready")
        self.assertIn(res_ready.status_code, (200, 503))  # May be 200 or 503 if offline ML model unloaded
        self.assertIn("checks", res_ready.json())
        self.assertIn("audit_ledger", res_ready.json()["checks"])

        # 3. Prometheus /metrics Scraping
        res_metrics = self.client.get("/metrics")
        self.assertEqual(res_metrics.status_code, 200)
        content = res_metrics.text
        self.assertIn("fincipher_uptime_seconds", content)
        self.assertIn("fincipher_pipeline_queue_depth", content)
        self.assertIn("fincipher_merkle_audit_blocks_total", content)
        self.assertIn("fincipher_threat_intel_indicators_total", content)
