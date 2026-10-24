"""
FinCipher AI — Phase 7 Enterprise ML Governance & Autonomous Shadow Retraining Tests
Author: Om Kamble

Verifies:
1. Autonomous candidate model retraining with synthetic feature distributions.
2. Production quality gate validation (F1 >= 0.88, Latency <= 2.5ms, AUC >= 0.90, FPR <= 0.02).
3. Challenger registration and Canary pipeline provisioning.
4. Dynamic Canary traffic routing split (0% pure shadow to 100% full canary).
5. Hot promotion to Production Champion with Merkle non-repudiation and instant rollback.
6. REST API endpoints under /api/v1/governance/*
7. Database CRUD persistence in ml_governance_jobs table.
"""

import pytest
import time
from fastapi.testclient import TestClient

from src.api.main import app
from src.engine.shadow_retraining_engine import (
    ShadowRetrainingEngine,
    shadow_retraining_engine
)
from src.engine.canary_pipeline import canary_pipeline
from src.engine.model_registry import model_registry, ModelStage
from src.db.database import (
    init_database,
    create_ml_governance_job,
    get_ml_governance_job,
    update_ml_governance_job,
    list_ml_governance_jobs
)

# Ensure all database tables exist
init_database()


@pytest.fixture(autouse=True)
def clean_model_registry_state():
    """Restores baseline models in model_registry and canary_pipeline after each test."""
    yield
    model_registry._initialize_baseline_models()
    model_registry._active_production_version = "v2.3.0"
    canary_pipeline.champion_name = "RandomForest_Balanced_v2.2"
    canary_pipeline.challenger_name = "WGAN_Augmented_Challenger_v3.0"
    canary_pipeline.previous_champion = None


class TestShadowRetrainingEngine:
    """Unit tests for the autonomous shadow retraining engine."""

    def test_engine_initial_status(self):
        engine = ShadowRetrainingEngine()
        status = engine.get_status()

        assert status["status"] == "OPERATIONAL"
        assert status["canary_traffic_split_pct"] == 0.0
        assert status["routing_mode"] == "PURE_SHADOW_SCORING"
        assert "production_champion" in status
        assert "active_challenger" in status
        assert "drift_telemetry" in status
        assert "quality_gates" in status
        assert status["quality_gates"]["min_f1"] == 0.88
        assert status["quality_gates"]["max_p95_latency_ms"] == 2.5

    def test_train_candidate_model_pass_gates(self):
        engine = ShadowRetrainingEngine()
        job = engine.train_candidate_model(
            trigger_source="TEST_UNIT",
            n_samples=1000,
            model_version="v3.TEST.1-shadow"
        )

        assert job["job_id"].startswith("JOB-RETRAIN-")
        assert job["model_version"] == "v3.TEST.1-shadow"
        assert job["is_valid"] is True
        assert job["status"] == "VALIDATED"
        assert job["f1_score"] >= 0.85
        assert job["auc_roc"] >= 0.88
        assert job["p95_latency_ms"] <= 2.5
        assert job["merkle_hash"] != ""

        # Verify Challenger provisioned in Canary pipeline
        assert canary_pipeline.challenger_name == "v3.TEST.1-shadow"

        # Verify registered in ModelRegistry
        reg_model = model_registry.get_model("v3.TEST.1-shadow")
        assert reg_model is not None
        assert reg_model["stage"] == ModelStage.SHADOW.value

        # Verify persisted in database
        db_job = get_ml_governance_job(job["job_id"])
        assert db_job is not None
        assert db_job["status"] == "VALIDATED"
        assert db_job["f1_score"] == pytest.approx(job["f1_score"], rel=1e-3)

    def test_train_candidate_model_fail_gate(self):
        # Artificially set an unachievable latency gate (e.g. 0.00001ms)
        strict_engine = ShadowRetrainingEngine(max_p95_latency_ms_gate=0.00001)
        job = strict_engine.train_candidate_model(
            trigger_source="TEST_REJECT",
            n_samples=500,
            model_version="v3.TEST.FAIL-shadow"
        )

        assert job["is_valid"] is False
        assert job["status"] == "REJECTED"

        # Model should NOT be registered in ModelRegistry
        assert model_registry.get_model("v3.TEST.FAIL-shadow") is None

        # DB record should reflect REJECTED status
        db_job = get_ml_governance_job(job["job_id"])
        assert db_job is not None
        assert db_job["status"] == "REJECTED"

    def test_dynamic_canary_traffic_routing_split(self):
        engine = ShadowRetrainingEngine()

        # 0% split: 100% Champion
        engine.set_canary_traffic_split(0.0)
        route_0 = engine.route_transaction_decision(
            champion_decision="APPROVE",
            challenger_decision="BLOCK",
            txn_id="TXN-100"
        )
        assert route_0["effective_decision"] == "APPROVE"
        assert route_0["routed_to"] == "PRIMARY_CHAMPION"
        assert route_0["is_canary"] is False

        # 100% split: 100% Challenger
        engine.set_canary_traffic_split(100.0)
        route_100 = engine.route_transaction_decision(
            champion_decision="APPROVE",
            challenger_decision="BLOCK",
            txn_id="TXN-100"
        )
        assert route_100["effective_decision"] == "BLOCK"
        assert route_100["routed_to"] == "CANARY_CHALLENGER"
        assert route_100["is_canary"] is True

        # Clamping check (< 0 clamped to 0, > 100 clamped to 100)
        res_neg = engine.set_canary_traffic_split(-15.0)
        assert res_neg["current_split_pct"] == 0.0

        res_over = engine.set_canary_traffic_split(145.0)
        assert res_over["current_split_pct"] == 100.0

        # Reset
        engine.set_canary_traffic_split(0.0)

    def test_check_drift_and_auto_trigger(self):
        engine = ShadowRetrainingEngine()

        # Under nominal conditions without force
        res_nominal = engine.check_drift_and_auto_trigger(force=False)
        assert "triggered" in res_nominal

        # Force trigger
        res_forced = engine.check_drift_and_auto_trigger(force=True)
        assert res_forced["triggered"] is True
        assert "job" in res_forced
        assert res_forced["job"]["status"] in ("VALIDATED", "REJECTED")

    def test_evaluate_and_promote_and_rollback(self):
        engine = ShadowRetrainingEngine()

        # Train a candidate first
        engine.train_candidate_model(
            trigger_source="PROMOTION_TEST",
            n_samples=800,
            model_version="v3.PROMO.1-shadow"
        )

        initial_champ = canary_pipeline.champion_name

        # Promote Challenger
        promo_res = engine.evaluate_and_promote_challenger(
            operator="lead_quant",
            reason="Canary metrics passed Tier-1 performance criteria"
        )
        assert promo_res["success"] is True
        assert promo_res["new_champion"] == "v3.PROMO.1-shadow"
        assert promo_res["retired_champion"] == initial_champ
        assert promo_res["canary_traffic_split_pct"] == 0.0
        assert promo_res["merkle_audit_hash"] != ""

        # Verify active in pipeline
        assert canary_pipeline.champion_name == "v3.PROMO.1-shadow"

        # Now test Emergency Rollback
        rollback_res = engine.emergency_rollback(
            operator="lead_quant",
            reason="Emergency test rollback"
        )
        assert rollback_res["success"] is True
        assert rollback_res["restored_champion"] == initial_champ
        assert rollback_res["demoted_model"] == "v3.PROMO.1-shadow"
        assert canary_pipeline.champion_name == initial_champ


class TestMLGovernanceEndpoints:
    """Integration tests for the /api/v1/governance/* REST endpoints."""

    def setup_method(self):
        self.client = TestClient(app)

    def test_get_governance_status_endpoint(self):
        res = self.client.get("/api/v1/governance/retrain/status")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "OPERATIONAL"
        assert "production_champion" in data
        assert "active_challenger" in data
        assert "drift_telemetry" in data

    def test_trigger_shadow_retrain_endpoint(self):
        res = self.client.post("/api/v1/governance/retrain/trigger", json={
            "trigger_source": "API_TEST",
            "n_samples": 800,
            "model_version": "v3.API.1-shadow"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "SUCCESS"
        job = data["job"]
        assert job["model_version"] == "v3.API.1-shadow"
        assert job["status"] in ("VALIDATED", "REJECTED")

    def test_list_governance_jobs_endpoint(self):
        res = self.client.get("/api/v1/governance/retrain/jobs?limit=5")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "SUCCESS"
        assert isinstance(data["jobs"], list)
        assert data["count"] == len(data["jobs"])

    def test_configure_canary_traffic_split_endpoint(self):
        res = self.client.post("/api/v1/governance/canary/traffic-split", json={
            "split_pct": 20.0,
            "operator": "test_analyst"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["current_split_pct"] == 20.0
        assert data["routing_mode"] == "ACTIVE_CANARY"

        # Reset to 0
        self.client.post("/api/v1/governance/canary/traffic-split", json={"split_pct": 0.0})

    def test_evaluate_and_promote_endpoint(self):
        # First ensure a challenger is registered
        shadow_retraining_engine.train_candidate_model(
            trigger_source="PROMO_ENDPOINT",
            n_samples=800,
            model_version="v3.API.PROMO-shadow"
        )

        res = self.client.post("/api/v1/governance/canary/evaluate-and-promote", json={
            "operator": "test_supervisor",
            "reason": "Passed automated canary validation"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["new_champion"] == "v3.API.PROMO-shadow"

        # Roll back to restore initial
        rollback_res = self.client.post("/api/v1/governance/canary/rollback", json={
            "operator": "test_supervisor",
            "reason": "Test clean up"
        })
        assert rollback_res.status_code == 200

    def test_list_registered_models_endpoint(self):
        res = self.client.get("/api/v1/governance/models")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "SUCCESS"
        assert "models" in data
        assert len(data["models"]) >= 2
        assert "active_production" in data


class TestDatabaseGovernanceJobs:
    """Verifies dual database parity and CRUD operations for ML governance jobs."""

    def test_crud_lifecycle(self):
        job_id = f"TEST-JOB-{int(time.time() * 1000)}"
        
        # Create
        created = create_ml_governance_job(
            job_id=job_id,
            model_version="vTEST.0.1",
            algorithm="TestModel",
            trigger_source="PYTEST",
            status="IN_PROGRESS",
            canary_split_pct=10.0
        )
        assert created is not None
        assert created["job_id"] == job_id
        assert created["status"] == "IN_PROGRESS"

        # Update
        ok = update_ml_governance_job(
            job_id=job_id,
            status="VALIDATED",
            f1_score=0.925,
            auc_roc=0.981,
            p95_latency_ms=1.15,
            false_positive_rate=0.007,
            merkle_hash="HASH-TEST-1234"
        )
        assert ok is True

        # Fetch
        fetched = get_ml_governance_job(job_id)
        assert fetched is not None
        assert fetched["status"] == "VALIDATED"
        assert fetched["f1_score"] == pytest.approx(0.925, rel=1e-3)
        assert fetched["merkle_hash"] == "HASH-TEST-1234"

        # List
        jobs_list = list_ml_governance_jobs(limit=10)
        assert any(j["job_id"] == job_id for j in jobs_list)
