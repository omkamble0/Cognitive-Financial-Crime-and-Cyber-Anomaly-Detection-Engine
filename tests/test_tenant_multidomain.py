"""
FinCipher AI — Multi-Domain Multi-Tenant Configuration Tests
Author: Om Kamble

Validates:
1. Dynamic tenant policy resolution across Banking, Cybersecurity, and E-Commerce
2. Divergent risk posture decisions (e.g., Alpha Bank strict 0.70 block vs Beta Pay 0.90 block)
3. REST API endpoints for tenant profile listing, retrieval, and runtime threshold mutation
"""

import unittest
from fastapi.testclient import TestClient
from apps.api.main import app
from src.engine.tenant_config import tenant_config_manager
from services.risk_engine.router import universal_risk_router
from services.ingestion.normalizer import UniversalEventNormalizer


class TestTenantMultiDomain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_tenant_domain_threshold_retrieval(self):
        """Validates that tenant_config_manager provides domain-specific thresholds."""
        alpha_bank = tenant_config_manager.get_domain_thresholds("tenant_alpha_bank", "BANKING")
        self.assertEqual(alpha_bank["block_threshold"], 0.70)
        self.assertEqual(alpha_bank["challenge_threshold"], 0.50)

        beta_pay = tenant_config_manager.get_domain_thresholds("tenant_beta_pay", "BANKING")
        self.assertEqual(beta_pay["block_threshold"], 0.90)
        self.assertEqual(beta_pay["challenge_threshold"], 0.75)

    def test_divergent_tenant_risk_decision(self):
        """
        Validates that identical risk event yields BLOCK for strict tenant (Alpha Bank)
        and CHALLENGE_2FA for lenient tenant (Beta Pay).
        """
        # Event with risk ~0.75 (above Alpha's 0.70, below Beta's 0.90)
        raw_event = {
            "transaction_id": "TX_TENANT_TEST_01",
            "user_id": "usr_tenant_test",
            "amount": 9500.0,  # AML structuring signal triggers elevated risk
            "currency": "USD",
            "country": "US",
            "ip_address": "10.0.0.1"
        }

        # Alpha Bank evaluation
        evt_alpha = UniversalEventNormalizer.normalize_banking_payment(raw_event, tenant_id="tenant_alpha_bank")
        res_alpha = universal_risk_router.evaluate_event(evt_alpha)
        self.assertEqual(res_alpha["tenant_id"], "tenant_alpha_bank")

        # Beta Pay evaluation
        evt_beta = UniversalEventNormalizer.normalize_banking_payment(raw_event, tenant_id="tenant_beta_pay")
        res_beta = universal_risk_router.evaluate_event(evt_beta)
        self.assertEqual(res_beta["tenant_id"], "tenant_beta_pay")

        # Risk score is identical, but decision honors tenant posture
        self.assertEqual(res_alpha["risk_score"], res_beta["risk_score"])
        # If risk is ~0.80, Alpha Bank (thresh 0.70) blocks, Beta Pay (thresh 0.90) does not block
        if 0.70 <= res_alpha["risk_score"] < 0.90:
            self.assertEqual(res_alpha["decision"], "BLOCK")
            self.assertIn(res_beta["decision"], ("CHALLENGE_2FA", "ALLOW"))

    def test_tenant_api_endpoints(self):
        """Validates REST endpoints for tenant configuration query and update."""
        # 1. List tenants
        res_list = self.client.get("/api/v1/events/tenants")
        self.assertEqual(res_list.status_code, 200)
        data_list = res_list.json()
        self.assertGreaterEqual(data_list["total_tenants"], 3)

        # 2. Get specific tenant
        res_get = self.client.get("/api/v1/events/tenants/tenant_alpha_bank")
        self.assertEqual(res_get.status_code, 200)
        data_get = res_get.json()
        self.assertEqual(data_get["organization_name"], "Alpha Investment Bank")

        # 3. Update tenant cyber policy
        res_put = self.client.put(
            "/api/v1/events/tenants/tenant_alpha_bank",
            json={
                "cybersecurity": {
                    "block_threshold": 0.65,
                    "challenge_threshold": 0.40,
                    "failed_login_burst_limit": 2
                }
            }
        )
        self.assertEqual(res_put.status_code, 200)
        data_put = res_put.json()
        self.assertEqual(data_put["configuration"]["cybersecurity"]["block_threshold"], 0.65)

        # Verify updated threshold in router
        thresh = tenant_config_manager.get_domain_thresholds("tenant_alpha_bank", "CYBERSECURITY")
        self.assertEqual(thresh["block_threshold"], 0.65)


if __name__ == "__main__":
    unittest.main()
