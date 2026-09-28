import unittest
import numpy as np

from src.api.main import (
    app, build_feature_dataframe, evaluate_single_transaction,
    health_check, get_stats, model, scaler, Transaction
)
from src.engine.rules import HybridRuleEngine, ActionDecision
from src.engine.explainability import ExplainabilityEngine
from src.streaming.redis_feature_store import RedisFeatureStore


class TestAegisFlowPipeline(unittest.TestCase):

    def test_model_and_scaler_loaded(self):
        self.assertIsNotNone(model, "Model should be loaded")
        self.assertIsNotNone(scaler, "Scaler should be loaded")

    def test_feature_dataframe_dimension_and_columns(self):
        sample_tx = {f"V{i}": 0.5 for i in range(1, 29)}
        sample_tx["Amount"] = 120.50
        sample_tx["Time"] = 3600.0

        df = build_feature_dataframe(sample_tx)
        self.assertEqual(df.shape, (1, 30))
        self.assertEqual(df.columns[-2], "scaled_amount")
        self.assertEqual(df.columns[-1], "scaled_time")

    def test_hybrid_rule_engine(self):
        engine = HybridRuleEngine()

        # Low risk test
        res_low = engine.evaluate(ml_score=0.05, amount=45.0)
        self.assertEqual(res_low.decision, ActionDecision.APPROVE)
        self.assertEqual(res_low.risk_level, "LOW")

        # Velocity spike test
        res_velocity = engine.evaluate(ml_score=0.1, amount=100.0, user_velocity_1m=6)
        self.assertEqual(res_velocity.decision, ActionDecision.BLOCK)
        self.assertTrue(any("VELOCITY_BURST" in r for r in res_velocity.triggered_rules))

        # High amount spike test
        res_amt = engine.evaluate(ml_score=0.2, amount=3000.0, user_avg_amount=100.0)
        self.assertIn(res_amt.decision, (ActionDecision.CHALLENGE_2FA, ActionDecision.MANUAL_REVIEW, ActionDecision.BLOCK))

    def test_explainability_engine(self):
        xai = ExplainabilityEngine()
        anomalous_tx = {
            "V14": -6.5,
            "V12": -4.2,
            "Amount": 2500.0
        }
        reasons = xai.explain(anomalous_tx, ml_score=0.88)
        self.assertTrue(len(reasons) > 0)
        top_features = [r["feature"] for r in reasons]
        self.assertIn("V14", top_features)
        self.assertTrue(reasons[0]["contribution_percentage"] > 0)

    def test_redis_sliding_window_velocity(self):
        rfs = RedisFeatureStore(host="127.0.0.1", port=59999)
        user_id = "test_user_velocity_99"

        # Record multiple rapid transactions
        p1 = rfs.record_transaction(user_id=user_id, txn_id="tx1", amount=50.0)
        p2 = rfs.record_transaction(user_id=user_id, txn_id="tx2", amount=150.0)

        self.assertEqual(p2["velocity_1m"], 2)
        self.assertEqual(p2["total_txns"], 2)
        self.assertEqual(p2["avg_amount"], 100.0)

    def test_api_evaluation_endpoint(self):
        payload = {
            "transaction_id": "TEST_TX_01",
            "user_id": "test_eval_user",
            "Amount": 149.62,
            "Time": 0.0
        }
        res = evaluate_single_transaction(payload)
        self.assertIn("decision", res)
        self.assertIn("fraud_score", res)
        self.assertIn("explainability", res)
        self.assertIn("latency_ms", res)
        self.assertTrue(res["latency_ms"] >= 0.0)

    def test_universal_detector_generic_and_pca(self):
        from src.engine.universal_detector import UniversalDetector
        import pandas as pd
        detector = UniversalDetector()

        # Generic E-Commerce dataframe test
        df_generic = pd.DataFrame({
            "order_id": ["ORD_1", "ORD_2", "ORD_3"],
            "user_id": ["u1", "u2", "u3"],
            "order_amount_usd": [45.0, 95.0, 4800.0],
            "ip_risk": [0.1, 0.2, 0.95]
        })
        analysis_gen = detector.analyze_dataset(df_generic)
        self.assertEqual(analysis_gen["metadata"]["strategy"], "ADAPTIVE_ISOLATION_FOREST_AND_EVT")
        self.assertEqual(len(analysis_gen["scored_records"]), 3)
        self.assertIn("summary_metrics", analysis_gen)

        # PCA dataframe test
        df_pca = pd.DataFrame({
            **{f"V{i}": [0.1, -5.5] for i in range(1, 29)},
            "Amount": [100.0, 2500.0],
            "Time": [0.0, 400.0]
        })
        analysis_pca = detector.analyze_dataset(df_pca)
        self.assertEqual(analysis_pca["metadata"]["strategy"], "SUPERVISED_RANDOM_FOREST")
        self.assertEqual(len(analysis_pca["scored_records"]), 2)

    def test_telemetry_stats_endpoint(self):
        stats = get_stats()
        self.assertIn("total_scanned", stats)
        self.assertIn("avg_latency_ms", stats)
        self.assertIn("p95_latency_ms", stats)

    def test_cryptographic_audit_ledger_and_tamper_detection(self):
        from src.engine.audit_ledger import CryptographicAuditLedger
        ledger = CryptographicAuditLedger()

        # Add 3 transactions
        b1 = ledger.record_decision("TX101", "usr_1", 120.0, "APPROVE", 0.05, ["NOMINAL"])
        b2 = ledger.record_decision("TX102", "usr_2", 850.0, "CHALLENGE_2FA", 0.45, ["RULE_AMOUNT_ANOMALY"])
        b3 = ledger.record_decision("TX103", "usr_3", 3200.0, "BLOCK", 0.94, ["RULE_VELOCITY_BURST"])

        # Initial check must be 100% valid
        v_clean = ledger.verify_integrity()
        self.assertTrue(v_clean["is_valid"])
        self.assertEqual(v_clean["status"], "VERIFIED_SECURE")
        self.assertEqual(v_clean["blocks_verified"], 4) # Genesis + 3 blocks

        # Simulate malicious tampering
        tamper_res = ledger.simulate_tampering(block_index=2)
        self.assertEqual(tamper_res["tampered_block_index"], 2)

        # Verification must instantly catch the tampered payload
        v_tampered = ledger.verify_integrity()
        self.assertFalse(v_tampered["is_valid"])
        self.assertIn(v_tampered["status"], ("TAMPERED_BLOCK_PAYLOAD", "COMPROMISED_CHAIN_LINK", "INVALID_SIGNATURE"))
        self.assertEqual(v_tampered["error_at_index"], 2)

        # Re-seal and restore
        restore_res = ledger.restore_and_reseal()
        self.assertEqual(restore_res["status"], "VERIFIED_SECURE")
        v_restored = ledger.verify_integrity()
        self.assertTrue(v_restored["is_valid"])

    def test_carding_sentinel_botnet_detection(self):
        from src.engine.carding_sentinel import CardingSentinel
        sentinel = CardingSentinel(max_cards_per_ip_60s=3, max_micro_txns_60s=3)
        bot_ip = "185.220.101.55"

        # 1. Normal benign single card transaction
        res1 = sentinel.evaluate_request(ip_address="192.168.1.1", amount=120.0, card_identifier="card_normal_1")
        self.assertEqual(res1.threat_level, "NORMAL")
        self.assertFalse(res1.is_bot_attack)

        # 2. Carding attack: test distinct cards with spaced timestamps
        sentinel.evaluate_request(ip_address=bot_ip, amount=1.00, card_identifier="card_stolen_1", timestamp=1000.0)
        sentinel.evaluate_request(ip_address=bot_ip, amount=1.20, card_identifier="card_stolen_2", timestamp=1001.0)
        res_trip = sentinel.evaluate_request(ip_address=bot_ip, amount=0.99, card_identifier="card_stolen_3", timestamp=1002.0)
        
        self.assertEqual(res_trip.threat_level, "ATTACK_IN_PROGRESS")
        self.assertTrue(res_trip.is_bot_attack)
        self.assertTrue(any("CYBER_CARDING_BURST" in r for r in res_trip.triggered_rules))
        self.assertTrue(any("CYBER_MICRO_AUTH_PROBING" in r for r in res_trip.triggered_rules))

        # 3. Subsequent request from same IP is auto-quarantined
        res_quarantine = sentinel.evaluate_request(ip_address=bot_ip, amount=1.50, card_identifier="card_stolen_4", timestamp=1003.0)
        self.assertEqual(res_quarantine.threat_level, "ATTACK_IN_PROGRESS")
        self.assertTrue(any("CYBER_QUARANTINED_IP" in r for r in res_quarantine.triggered_rules))


if __name__ == "__main__":
    unittest.main()
