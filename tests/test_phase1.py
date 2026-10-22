"""
AegisFlow — Phase 1 & 2 Test Suite: Foundation, Security, Config, RBAC & Persistence
"""

import unittest
from src.core.config import settings
from src.core.security import (
    UserRole,
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_jwt_token,
    require_roles
)
from src.core.logging import mask_card_number, mask_email, mask_pii_dict
from src.db.database import (
    init_database,
    list_cases,
    get_case_detail,
    create_case,
    update_case_status,
    add_case_note,
    list_alerts,
    persist_transaction_evaluation,
    authenticate_user
)


class TestPhase1And2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_database()

    def test_config_settings_validation(self):
        self.assertIsNotNone(settings.APP_NAME)
        self.assertIn(settings.ENVIRONMENT, ["development", "testing", "staging", "production"])
        self.assertEqual(settings.JWT_ALGORITHM, "HS256")
        self.assertTrue(settings.ACCESS_TOKEN_EXPIRE_MINUTES > 0)

    def test_pbkdf2_password_hashing(self):
        raw_pwd = "P@ssw0rdSecure2026!"
        h, salt = hash_password(raw_pwd)
        self.assertTrue(len(h) > 32)
        self.assertTrue(verify_password(raw_pwd, h, salt))
        self.assertFalse(verify_password("WrongPassword123", h, salt))

    def test_jwt_token_lifecycle(self):
        token = create_access_token(user_id=42, username="analyst_test", role=UserRole.ANALYST.value)
        self.assertIsInstance(token, str)

        payload = decode_jwt_token(token)
        self.assertEqual(payload["sub"], "42")
        self.assertEqual(payload["username"], "analyst_test")
        self.assertEqual(payload["role"], UserRole.ANALYST.value)
        self.assertEqual(payload["type"], "access")

        refresh = create_refresh_token(user_id=42, username="analyst_test", role=UserRole.ANALYST.value)
        ref_payload = decode_jwt_token(refresh)
        self.assertEqual(ref_payload["type"], "refresh")

    def test_pii_masking_engine(self):
        # Card PAN masking
        card = "4111222233334444"
        masked_card = mask_card_number(card)
        self.assertEqual(masked_card, "4111********4444")

        # Email masking
        email = "sarah.chen@risk-platform.ai"
        masked_email = mask_email(email)
        self.assertEqual(masked_email, "s***@risk-platform.ai")

        # Recursive dict masking
        data = {
            "card_identifier": "5200999988881234",
            "user_email": "user@example.com",
            "jwt_secret": "my-secret-key-12345",
            "amount": 250.0
        }
        sanitized = mask_pii_dict(data)
        self.assertEqual(sanitized["card_identifier"], "5200********1234")
        self.assertEqual(sanitized["user_email"], "u***@example.com")
        self.assertEqual(sanitized["jwt_secret"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized["amount"], 250.0)

    def test_rbac_role_hierarchy(self):
        checker = require_roles("fraud_manager", "admin")
        
        # Admin should pass
        admin_user = {"id": 1, "username": "admin", "role": "admin"}
        self.assertEqual(checker(admin_user)["username"], "admin")

        # Fraud Manager should pass
        mgr_user = {"id": 2, "username": "mgr", "role": "fraud_manager"}
        self.assertEqual(checker(mgr_user)["username"], "mgr")

        # Analyst should be denied with 403 Forbidden
        analyst_user = {"id": 3, "username": "analyst", "role": "analyst"}
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            checker(analyst_user)
        self.assertEqual(cm.exception.status_code, 403)

    def test_case_management_and_notes_crud(self):
        new_case = create_case(
            title="Smurfing Ring Cash-Out Investigation",
            priority="P1_CRITICAL",
            entity_id="usr_smurf_99",
            risk_score=0.92,
            assigned_to="analyst_sarah",
            linked_transactions=["TXN_SMURF_001", "TXN_SMURF_002"]
        )
        self.assertIsNotNone(new_case)
        self.assertTrue(new_case["case_number"].startswith("CASE-"))
        self.assertEqual(new_case["status"], "OPEN")

        # Add note
        note = add_case_note(new_case["id"], "analyst_sarah", "Confirmed multi-hop layering pattern across 3 accounts.")
        self.assertEqual(note["author"], "analyst_sarah")

        # Update case status
        updated = update_case_status(
            case_id=new_case["id"],
            new_status="RESOLVED",
            operator="manager_marcus",
            disposition="CONFIRMED_FRAUD",
            reason="Confirmed money mule ring with law enforcement escalation."
        )
        self.assertEqual(updated["status"], "RESOLVED")
        self.assertEqual(updated["disposition"], "CONFIRMED_FRAUD")
        self.assertTrue(len(updated["notes"]) >= 1)

    def test_transaction_evaluation_persistence_and_alert_trigger(self):
        txn = {
            "transaction_id": "TXN_PERSIST_TEST_01",
            "user_id": "usr_test_persist",
            "card_identifier": "4111222233334444",
            "Amount": 1500.0,
            "currency": "USD",
            "merchant_id": "merch_luxury",
            "ip_address": "198.51.100.44"
        }
        ok = persist_transaction_evaluation(
            txn_dict=txn,
            risk_score=0.88,
            decision_str="BLOCK",
            risk_level="HIGH",
            latency_ms=1.15,
            triggered_rules=["RULE_ANOMALOUS_AMOUNT", "RULE_HIGH_VELOCITY"],
            explainability=[{"feature": "Amount", "z_score": 5.4}]
        )
        self.assertTrue(ok)

        # Verify automated alert generation for high-risk / block
        alerts = list_alerts(status="OPEN")
        matching = [a for a in alerts if a["transaction_id"] == "TXN_PERSIST_TEST_01"]
        self.assertTrue(len(matching) >= 1)
        self.assertIn("Automated Risk Alert: BLOCK", matching[0]["title"])

    def test_case_management_rest_api_endpoints(self):
        from fastapi.testclient import TestClient
        from src.api.main import app

        client = TestClient(app)

        # 1. Test Login & JWT issuance
        login_resp = client.post("/api/v1/auth/login", json={
            "username_or_email": "admin",
            "password": "SECurity@uDit66@"
        })
        self.assertEqual(login_resp.status_code, 200)
        auth_data = login_resp.json()
        self.assertIn("access_token", auth_data)
        self.assertIn("refresh_token", auth_data)
        self.assertEqual(auth_data["token_type"], "bearer")

        # 2. Test Cases List
        cases_resp = client.get("/api/v1/cases")
        self.assertEqual(cases_resp.status_code, 200)
        case_list = cases_resp.json()
        self.assertTrue(len(case_list) >= 1)

        # 3. Test Create Case via REST
        create_resp = client.post("/api/v1/cases", json={
            "title": "API Fraud Case: Rapid BIN Probing",
            "priority": "P1_CRITICAL",
            "entity_id": "ip_198.51.100.77",
            "risk_score": 0.95,
            "assigned_to": "analyst_sarah"
        })
        self.assertEqual(create_resp.status_code, 200)
        created = create_resp.json()
        case_id = created["id"]
        self.assertEqual(created["status"], "OPEN")

        # 4. Test Add Note via REST
        note_resp = client.post(f"/api/v1/cases/{case_id}/notes", json={
            "author": "analyst_sarah",
            "note_text": "Investigated IP origin; confirmed Tor exit node."
        })
        self.assertEqual(note_resp.status_code, 200)

        # 5. Test Case Action Override via REST
        action_resp = client.post(f"/api/v1/cases/{case_id}/actions", json={
            "status": "RESOLVED",
            "disposition": "CONFIRMED_FRAUD",
            "reason": "Confirmed carding botnet with law enforcement escalation.",
            "operator": "manager_marcus"
        })
        self.assertEqual(action_resp.status_code, 200)
        self.assertEqual(action_resp.json()["status"], "RESOLVED")

        # 6. Test Alerts List via REST
        alerts_resp = client.get("/api/v1/alerts")
        self.assertEqual(alerts_resp.status_code, 200)
        alerts_list = alerts_resp.json()
        self.assertTrue(len(alerts_list) >= 1)
        first_alert = alerts_list[0]

        # 7. Test Alert Triage via REST
        triage_resp = client.post(f"/api/v1/alerts/{first_alert['id']}/triage", json={
            "status": "TRIAGED",
            "operator": "analyst_sarah",
            "reason": "Correlated with active case"
        })
        self.assertEqual(triage_resp.status_code, 200)
        self.assertTrue(triage_resp.json()["updated"])

    def test_model_registry_governance_and_promotion_gates(self):
        from src.engine.model_registry import model_registry, ModelStage

        models = model_registry.list_models()
        self.assertTrue(len(models) >= 2)

        prod_model = model_registry.get_production_model()
        self.assertEqual(prod_model["version"], "v2.3.0")
        self.assertEqual(prod_model["stage"], ModelStage.PRODUCTION.value)
        self.assertTrue(prod_model["f1_score"] >= 0.90)

        # Register Challenger in Staging
        challenger = model_registry.register_model(
            version="v2.5.0-test",
            algorithm="LightGBM Latent Ensemble",
            f1_score=0.942,
            auc_roc=0.988,
            p95_latency_ms=0.88,
            false_positive_rate=0.004,
            training_samples=350000,
            feature_names=["Amount", "Time", "V14", "V12", "V4"]
        )
        self.assertEqual(challenger["stage"], ModelStage.STAGING.value)

        # Promote to Shadow
        shadow = model_registry.promote_model("v2.5.0-test", ModelStage.SHADOW, operator="lead_architect")
        self.assertEqual(shadow["stage"], ModelStage.SHADOW.value)

        # Test Quality Gate Failure (reject model with low F1 score)
        model_registry.register_model(
            version="v2.5.1-bad",
            algorithm="Degraded Model",
            f1_score=0.72,  # < 0.85 gate threshold
            auc_roc=0.80,
            p95_latency_ms=1.2,
            false_positive_rate=0.05,
            training_samples=10000,
            feature_names=["Amount"]
        )
        with self.assertRaises(ValueError) as cm:
            model_registry.promote_model("v2.5.1-bad", ModelStage.PRODUCTION, operator="lead_architect")
        self.assertIn("Gate Failed", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
