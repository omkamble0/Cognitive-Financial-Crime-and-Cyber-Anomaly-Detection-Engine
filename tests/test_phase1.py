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

    def test_prometheus_fincipher_metrics(self):
        """Verifies Phase 5 Prometheus / OpenMetrics exposition under FinCipher AI schema."""
        from src.api.main import api_prometheus_metrics
        resp = api_prometheus_metrics()
        self.assertEqual(resp.media_type, "text/plain; version=0.0.4; charset=utf-8")
        body = resp.body.decode("utf-8")
        
        # Verify FinCipher AI Prometheus signals
        self.assertIn("fincipher_inference_latency_ms", body)
        self.assertIn("fincipher_transactions_total", body)
        self.assertIn("fincipher_transaction_volume_usd_total", body)
        self.assertIn("fincipher_graph_syndicates_active", body)
        self.assertIn("fincipher_merkle_blocks_total", body)
        self.assertIn("fincipher_merkle_integrity_intact", body)
        self.assertIn("fincipher_drift_psi", body)
        self.assertIn("fincipher_bigan_reconstruction_error", body)
        self.assertIn("fincipher_fast_filter_quarantined_ips", body)
        self.assertIn("fincipher_rl_bandit_exploration_rate", body)
        self.assertIn("fincipher_active_cases_total", body)
        self.assertIn("fincipher_active_alerts_total", body)
        self.assertIn("fincipher_mlops_registered_models_total", body)
        self.assertIn("fincipher_mlops_active_model_f1", body)

        # Legacy Scrape Compatibility signals
        self.assertIn("aegisflow_inference_latency_ms", body)
        self.assertIn("aegisflow_transactions_total", body)

    def test_deep_health_readiness_probe(self):
        """Verifies Phase 5 Kubernetes readiness & liveness probe diagnostics."""
        from src.api.main import api_liveness_probe, api_readiness_probe
        import json

        # Liveness check
        live_res = api_liveness_probe()
        self.assertEqual(live_res["status"], "UP")
        self.assertEqual(live_res["brand"], "FinCipher AI")

        # Readiness check
        ready_resp = api_readiness_probe()
        self.assertEqual(ready_resp.status_code, 200)
        data = json.loads(ready_resp.body.decode("utf-8"))
        self.assertEqual(data["status"], "READY")
        self.assertIn("checks", data)
        checks = data["checks"]
        self.assertIn("ml_model_artifacts", checks)
        self.assertIn("database", checks)
        self.assertIn("feature_store", checks)
        self.assertIn("graph_engine", checks)
        self.assertIn("audit_ledger", checks)
        self.assertIn("fast_threat_shield", checks)
        self.assertIn("model_registry", checks)
        self.assertEqual(checks["model_registry"]["status"], "HEALTHY")

    def test_security_vulnerabilities_remediation(self):
        """Verifies defensive remediation for SQLi, CORS, RBAC, Brute Force, and Upload Path Traversal."""
        from fastapi.testclient import TestClient
        from src.api.main import app, LOGIN_FAILURE_ATTEMPTS
        import io

        client = TestClient(app)

        # 1. SQL Injection Prevention: non-integer / malicious LIMIT clauses fall back safely
        sqli_cases = list_cases(limit="50; DROP TABLE cases;--")
        self.assertIsInstance(sqli_cases, list)

        sqli_alerts = list_alerts(limit="10 UNION SELECT 1,2,3,4")
        self.assertIsInstance(sqli_alerts, list)

        # 2. Information Disclosure / Unrestricted User Enumeration (CWE-200)
        anon_users_resp = client.get("/api/v1/auth/users")
        self.assertIn(anon_users_resp.status_code, [401, 403])

        # Authenticated as Admin must succeed
        admin_token = create_access_token(user_id=1, username="admin", role="admin")
        auth_users_resp = client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(auth_users_resp.status_code, 200)
        self.assertIsInstance(auth_users_resp.json(), list)

        # 3. Brute Force Login Rate Limiter (CWE-307)
        LOGIN_FAILURE_ATTEMPTS.clear()
        for _ in range(5):
            client.post("/api/v1/auth/login", json={
                "username_or_email": "target_user",
                "password": "wrong_password_attempt"
            })
        
        # 6th attempt should be blocked with HTTP 429 Too Many Requests
        rate_limited_resp = client.post("/api/v1/auth/login", json={
            "username_or_email": "target_user",
            "password": "wrong_password_attempt"
        })
        self.assertEqual(rate_limited_resp.status_code, 429)
        self.assertIn("temporarily locked", rate_limited_resp.json()["detail"])
        LOGIN_FAILURE_ATTEMPTS.clear()

        # 4. Path Traversal & Unrestricted File Type Upload (CWE-22 / CWE-434)
        bad_file = io.BytesIO(b"echo 'malicious script'")
        bad_upload = client.post(
            "/api/v1/upload-dataset",
            files={"file": ("../../evil_script.sh", bad_file, "text/x-shellscript")}
        )
        self.assertEqual(bad_upload.status_code, 400)
        self.assertIn("Unsupported file type", bad_upload.json()["detail"])

        # 5. Operator Identity Binding: prevent spoofing in audit log
        analyst_token = create_access_token(user_id=10, username="verified_analyst", role="analyst")
        test_case = create_case(title="Sec Audit Case", priority="P3_MEDIUM", entity_id="usr_audit_sec", risk_score=0.72)
        action_resp = client.post(
            f"/api/v1/cases/{test_case['id']}/actions",
            headers={"Authorization": f"Bearer {analyst_token}"},
            json={
                "status": "IN_REVIEW",
                "operator": "spoofed_admin",
                "reason": "Security audit test"
            }
        )
        self.assertEqual(action_resp.status_code, 200)

        # Test note author binding prevents spoofing
        note_resp = client.post(
            f"/api/v1/cases/{test_case['id']}/notes",
            headers={"Authorization": f"Bearer {analyst_token}"},
            json={
                "author": "spoofed_admin",
                "note_text": "Security test note"
            }
        )
        self.assertEqual(note_resp.status_code, 200)
        self.assertEqual(note_resp.json()["author"], "verified_analyst")

        # Verify analyst_actions audit log recorded verified_analyst
        from src.db.database import get_db_connection, IS_POSTGRES
        conn = get_db_connection()
        c = conn.cursor()
        param = "%s" if IS_POSTGRES else "?"
        c.execute(f"SELECT operator FROM analyst_actions WHERE target_id = {param} ORDER BY id DESC LIMIT 1", (test_case["case_number"],))
        row = c.fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["operator"], "verified_analyst")

    def test_phase7_alert_notifications_and_dispatch(self):
        """Verifies Phase 7 outbound alert notification dispatcher and API status."""
        from fastapi.testclient import TestClient
        from src.api.main import app
        from src.engine.notifier import alert_notifier

        client = TestClient(app)

        # 1. Verify notification status endpoint
        resp = client.get("/api/v1/notifications/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["enabled"])
        self.assertIn("channels", data)
        self.assertIn("webhook", data["channels"])
        self.assertIn("slack", data["channels"])

        # 2. Test synthetic alert dispatch
        test_resp = client.post("/api/v1/notifications/test", json={
            "alert_title": "Test SAR Escalation",
            "severity": "CRITICAL",
            "summary": "Synthetic test alert for SOC webhook validation",
            "risk_score": 0.96,
            "entity_id": "usr_test_phase7"
        })
        self.assertEqual(test_resp.status_code, 200)
        self.assertEqual(test_resp.json()["status"], "dispatched")

        # 3. Verify notification appears in history
        hist_resp = client.get("/api/v1/notifications/history?limit=10")
        self.assertEqual(hist_resp.status_code, 200)
        history = hist_resp.json()
        self.assertTrue(len(history) >= 1)
        self.assertEqual(history[0]["alert_title"], "Test SAR Escalation")

    def test_phase7_multi_tenancy_partitioning(self):
        """Verifies Phase 7 multi-tenant data isolation and active tenant metrics."""
        from fastapi.testclient import TestClient
        from src.api.main import app

        client = TestClient(app)

        # Create case for Tenant A
        case_a = create_case(
            title="Tenant Alpha Structuring Ring",
            priority="P2_HIGH",
            entity_id="usr_alpha_99",
            risk_score=0.82,
            tenant_id="tenant_alpha_bank"
        )
        self.assertIsNotNone(case_a)

        # Create case for Tenant B
        case_b = create_case(
            title="Tenant Beta Fleet Carding Attack",
            priority="P1_CRITICAL",
            entity_id="usr_beta_01",
            risk_score=0.94,
            tenant_id="tenant_beta_pay"
        )
        self.assertIsNotNone(case_b)

        # Query filtered by Tenant Alpha
        cases_alpha = list_cases(tenant_id="tenant_alpha_bank")
        self.assertTrue(any(c["id"] == case_a["id"] for c in cases_alpha))
        self.assertFalse(any(c["id"] == case_b["id"] for c in cases_alpha))

        # Query active tenants API
        tenants_resp = client.get("/api/v1/tenants")
        self.assertEqual(tenants_resp.status_code, 200)
        tenants_list = tenants_resp.json()
        tenant_ids = [t["tenant_id"] for t in tenants_list]
        self.assertIn("tenant_alpha_bank", tenant_ids)
        self.assertIn("tenant_beta_pay", tenant_ids)

    def test_phase7_case_evidence_package_export(self):
        """Verifies Phase 7 cryptographic case evidence export with SHA-256 Merkle chain verification."""
        from fastapi.testclient import TestClient
        from src.api.main import app
        import json
        import hashlib

        client = TestClient(app)

        # Create sample case
        case = create_case(
            title="Evidence Export Verification Case",
            priority="P1_CRITICAL",
            entity_id="usr_evidence_test",
            risk_score=0.91,
            linked_transactions=["TXN_EVD_001", "TXN_EVD_002"]
        )
        add_case_note(case["id"], "lead_investigator", "Attached forensic chain-of-custody documentation.")

        # Request evidence export package
        resp = client.get(f"/api/v1/cases/{case['id']}/export-evidence")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Content-Disposition", resp.headers)
        self.assertIn(f"FinCipher_Evidence_{case['case_number']}.json", resp.headers["Content-Disposition"])
        self.assertIn("X-Evidence-Checksum", resp.headers)

        # Parse package
        pkg = json.loads(resp.text)
        self.assertIn("evidence_package_id", pkg)
        self.assertIn("regulatory_certifications", pkg)
        self.assertIn("cryptographic_merkle_proof", pkg)
        self.assertTrue(pkg["cryptographic_merkle_proof"]["ledger_verified"])
        self.assertEqual(pkg["case_overview"]["case_number"], case["case_number"])
        self.assertTrue(len(pkg["analyst_notes"]) >= 1)
        self.assertIn("package_sha256_checksum", pkg)


    def test_phase6_backup_and_disaster_recovery(self):
        """Verifies Phase 6 automated backup creation, manifest checksum verification, and API endpoints."""
        from fastapi.testclient import TestClient
        from src.api.main import app
        from src.engine.backup_manager import backup_manager

        client = TestClient(app)

        # 1. Trigger backup creation
        res = backup_manager.create_backup("test_suite_snapshot")
        self.assertEqual(res["status"], "VERIFIED")
        self.assertTrue(res["archive_filename"].endswith(".tar.gz"))
        backup_id = res["backup_id"]

        # 2. Verify backup integrity
        v_res = backup_manager.verify_backup(backup_id)
        self.assertTrue(v_res["valid"])
        self.assertEqual(v_res["status"], "INTACT")
        self.assertEqual(v_res["expected_checksum"], v_res["calculated_checksum"])

        # 3. Test API endpoint for listing backups
        api_res = client.get("/api/v1/admin/backups")
        self.assertEqual(api_res.status_code, 200)
        backups = api_res.json()
        self.assertTrue(any(b["backup_id"] == backup_id for b in backups))

    def test_phase6_compliance_data_retention(self):
        """Verifies Phase 6 compliance retention policy, statutory locks, and dry-run execution."""
        from fastapi.testclient import TestClient
        from src.api.main import app
        from src.engine.retention import retention_engine

        client = TestClient(app)

        # 1. Check retention status
        status = retention_engine.get_retention_status()
        self.assertEqual(status["statutory_case_retention_days"], 1825)
        self.assertIn("compliance_frameworks", status)
        self.assertIn("inventory", status)

        # 2. Execute dry-run retention sweep
        dry_res = retention_engine.apply_retention_policy(dry_run=True)
        self.assertEqual(dry_res["mode"], "DRY_RUN")
        self.assertIn("would_purge", dry_res)

        # 3. Test API retention endpoints
        st_resp = client.get("/api/v1/admin/retention/status")
        self.assertEqual(st_resp.status_code, 200)
        self.assertEqual(st_resp.json()["statutory_case_retention_days"], 1825)

        apply_resp = client.post("/api/v1/admin/retention/apply?dry_run=true")
        self.assertEqual(apply_resp.status_code, 200)
        self.assertEqual(apply_resp.json()["mode"], "DRY_RUN")

    def test_phase4_experiment_tracking(self):
        """Verifies Phase 4 MLflow-compatible experiment tracker logging and querying."""
        from fastapi.testclient import TestClient
        from src.api.main import app
        from src.engine.experiment_tracker import experiment_tracker

        client = TestClient(app)

        # 1. Log an experiment run
        run_record = experiment_tracker.log_run(
            experiment_name="IsolationForest_AutoCalibrated",
            model_type="IsolationForest",
            parameters={"n_estimators": 100, "contamination": 0.02},
            metrics={"f1_score": 0.942, "auc_roc": 0.988, "p95_latency_ms": 2.1},
            tags={"env": "test", "release": "v2.0"}
        )
        self.assertIn("run_id", run_record)
        run_id = run_record["run_id"]

        # 2. Retrieve the experiment run
        retrieved = experiment_tracker.get_run(run_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["metrics"]["f1_score"], 0.942)

        # 3. Test API endpoint
        api_resp = client.get("/api/v1/mlops/experiments")
        self.assertEqual(api_resp.status_code, 200)
        runs = api_resp.json()
        self.assertTrue(any(r["run_id"] == run_id for r in runs))

    def test_phase7_per_tenant_configurations(self):
        """Verifies Phase 7 per-tenant dynamic configuration thresholds."""
        from fastapi.testclient import TestClient
        from src.api.main import app
        from src.engine.tenant_config import tenant_config_manager

        client = TestClient(app)

        # 1. Update config for a tenant
        cfg = tenant_config_manager.set_config(
            "tenant_fintech_fast",
            block_threshold=0.88,
            challenge_threshold=0.60,
            velocity_window_hours=48,
            custom_rules={"carding_block": True}
        )
        self.assertEqual(cfg["block_threshold"], 0.88)
        self.assertEqual(cfg["challenge_threshold"], 0.60)

        # 2. Retrieve config
        retrieved = tenant_config_manager.get_config("tenant_fintech_fast")
        self.assertEqual(retrieved["block_threshold"], 0.88)

        # 3. Test API endpoint
        api_resp = client.get("/api/v1/tenants/tenant_fintech_fast/config")
        self.assertEqual(api_resp.status_code, 200)
    def test_mlops_automated_drift_rollback(self):
        """Verifies Phase 4/6 MLOps automated rollback when Population Stability Index breaches critical threshold."""
        from fastapi.testclient import TestClient
        from src.api.main import app
        from src.engine.canary_pipeline import canary_pipeline

        client = TestClient(app)

        # 1. Promote a candidate challenger so a previous champion is recorded
        promote_res = canary_pipeline.promote_challenger()
        self.assertTrue(promote_res["success"])
        prev_champ = canary_pipeline.previous_champion
        current_champ = canary_pipeline.champion_name

        # 2. Test normal drift (PSI < 0.25) -> should NOT trigger rollback
        normal_check = canary_pipeline.check_and_auto_rollback(psi_value=0.08)
        self.assertFalse(normal_check["triggered"])
        self.assertEqual(normal_check["status"], "NORMAL")

        # 3. Test critical drift (PSI >= 0.25) -> MUST trigger automated rollback
        crit_check = canary_pipeline.check_and_auto_rollback(psi_value=0.32)
        self.assertTrue(crit_check["triggered"])
        self.assertEqual(crit_check["status"], "AUTOMATED_ROLLBACK_EXECUTED")
        self.assertEqual(crit_check["restored_champion"], prev_champ)

        # 4. Test API endpoint for drift evaluation
        api_resp = client.post("/api/v1/mlops/governance/evaluate-drift?psi_value=0.12")
        self.assertEqual(api_resp.status_code, 200)
        self.assertFalse(api_resp.json()["triggered"])

    def test_xai_audit_narrative_generation(self):
        """Verifies Explainable AI (XAI) plain-English forensic narrative generation for FinCEN SAR compliance."""
        from src.engine.explainability import ExplainabilityEngine

        engine = ExplainabilityEngine()
        sample_attributions = [
            {"feature": "V14", "title": "Latent Cardholder Pattern Anomaly (V14 Subspace)", "z_score": 4.82, "signal": "Negative Spike", "contribution_percentage": 58.4},
            {"feature": "Amount", "title": "Transaction Ticket Size Deviation", "z_score": 3.10, "signal": "High Value Ticket", "contribution_percentage": 41.6}
        ]

        narrative = engine.generate_narrative(sample_attributions, ml_score=0.88, decision="BLOCK")
        self.assertIn("BLOCK", narrative)
        self.assertIn("0.88", narrative)
        self.assertIn("V14 Subspace", narrative)
        self.assertIn("58.4%", narrative)

    def test_audit_vulnerabilities_and_flaws_remediated(self):
        """Verifies remediations for path traversal, TarSlip, memory leaks, and out-of-order telemetry."""
        from src.engine.backup_manager import backup_manager
        from src.engine.experiment_tracker import experiment_tracker
        from src.engine.carding_sentinel import CardingSentinel
        from src.engine.threat_intelligence import ThreatIntelligenceEngine
        import os
        import time

        # 1. Path Traversal & TarSlip in Backup Manager (CWE-22)
        v_bad = backup_manager.verify_backup("../../../etc/passwd")
        self.assertFalse(v_bad["valid"])
        self.assertIn("alphanumeric characters", v_bad["error"])

        v_bad2 = backup_manager.verify_backup("test/evil/nested")
        self.assertFalse(v_bad2["valid"])

        with self.assertRaises(ValueError):
            backup_manager.restore_backup("../../../evil_snapshot")

        # 2. Path Traversal in Experiment Tracker (CWE-22)
        evil_run = experiment_tracker.log_run(
            experiment_name="../../traversal_attack/exp_test",
            model_type="TestModel",
            parameters={"p": 1},
            metrics={"m": 0.99}
        )
        self.assertIn("run_id", evil_run)
        # Verify run_path is contained within experiment_tracker.runs_dir
        expected_base = os.path.abspath(experiment_tracker.runs_dir)
        run_file = os.path.abspath(evil_run.get("run_path", ""))
        self.assertTrue(run_file.startswith(expected_base), f"{run_file} escapes {expected_base}")

        # 3. CardingSentinel Cache Pruning / Bounded State (CWE-400)
        sentinel = CardingSentinel()
        now = time.time()
        # Seed quarantined IP that expired in the past
        sentinel.quarantined_ips["192.168.1.1"] = now - 100.0
        # Seed an active quarantine
        sentinel.quarantined_ips["192.168.1.2"] = now + 500.0
        sentinel._prune_expired_state()
        self.assertNotIn("192.168.1.1", sentinel.quarantined_ips)
        self.assertIn("192.168.1.2", sentinel.quarantined_ips)

        # 4. ThreatIntelligenceEngine Out-of-Order Geo-Velocity & Cache Capping
        threat_engine = ThreatIntelligenceEngine()
        # First event in London at t = 1000
        threat_engine.evaluate_geo_velocity(
            user_id="user_geo_test",
            current_lat=51.5074,
            current_lon=-0.1278,
            location_name="London, UK",
            timestamp=1000.0
        )
        # Second event arrives out-of-order with an earlier timestamp (t = 500)
        # Should not throw impossible travel alert or corrupt recent location
        res_ooo = threat_engine.evaluate_geo_velocity(
            user_id="user_geo_test",
            current_lat=40.7128,
            current_lon=-74.0060,
            location_name="New York, USA",
            timestamp=500.0
        )
        self.assertFalse(res_ooo.is_impossible_travel)
        # Recent cache should still reflect t = 1000 event
        self.assertEqual(threat_engine.user_geo_cache["user_geo_test"]["timestamp"], 1000.0)


if __name__ == "__main__":
    unittest.main()



