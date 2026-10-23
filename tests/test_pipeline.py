import unittest
import numpy as np
import time

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

    def test_cyber_copilot_incident_dossier(self):
        from src.engine.copilot import CyberCopilotEngine
        copilot = CyberCopilotEngine()
        tx = {"Amount": 3200.0, "V14": -6.5, "user_id": "usr_test_99", "ip_address": "198.51.100.24"}
        dossier = copilot.generate_incident_dossier(
            tx_dict=tx,
            decision="BLOCK",
            risk_score=0.92,
            triggered_rules=["RULE_HIGH_AMOUNT: $3200.00", "RULE_LATENT_PCA_DEVIATION: V14 (6.5σ)"],
            attributions=[{"feature": "V14", "description": "Latent Cardholder Pattern Anomaly", "z_score": 6.5}],
            ledger_block={"index": 4, "block_hash": "0xabc12345"}
        )
        self.assertEqual(dossier.risk_level, "CRITICAL")
        self.assertTrue(dossier.confidence_score >= 0.8)
        self.assertIn("AegisFlow", dossier.executive_summary)
        self.assertTrue(len(dossier.tactical_mitigations) > 0)
        self.assertTrue(dossier.fincen_sar_recommended)

    def test_fincen_sar_generation(self):
        from src.engine.copilot import CyberCopilotEngine
        copilot = CyberCopilotEngine()
        tx = {"Amount": 4500.0, "user_id": "usr_aml_suspect", "ip_address": "203.0.113.10"}
        sar = copilot.generate_sar_report(
            tx_dict=tx,
            decision="BLOCK",
            risk_score=0.95,
            triggered_rules=["RULE_HIGH_AMOUNT: $4500.00", "RULE_VELOCITY_BURST: 5 txns in 60s"],
            attributions=[{"feature": "V14", "description": "Latent Cardholder Pattern Anomaly", "z_score": 7.1}],
            ledger_block={"index": 12, "block_hash": "0xfe38491c0"}
        )
        self.assertTrue(sar.sar_tracking_id.startswith("SAR-"))
        self.assertIn("PART I: SUBJECT", sar.official_fincen_narrative)
        self.assertIn("PART V: CRYPTOGRAPHIC CHAIN", sar.official_fincen_narrative)
        self.assertIn("4,500.00", sar.official_fincen_narrative)

    def test_threat_hunter_and_red_team(self):
        from src.engine.copilot import CyberCopilotEngine
        copilot = CyberCopilotEngine()
        sample_txns = [
            {"transaction_id": "TXN_1", "amount": 2.50, "decision": "BLOCK", "triggered_rules": ["CYBER_CARDING_BURST"]},
            {"transaction_id": "TXN_2", "amount": 45.0, "decision": "APPROVE", "triggered_rules": []},
            {"transaction_id": "TXN_3", "amount": 3500.0, "decision": "BLOCK", "triggered_rules": ["RULE_HIGH_AMOUNT"]}
        ]
        hunt = copilot.execute_threat_hunt("Find blocked micro carding transactions", sample_txns, [])
        self.assertTrue(hunt["match_count"] >= 1)
        self.assertEqual(hunt["matched_records"][0]["transaction_id"], "TXN_1")

        red_team = copilot.generate_adversarial_attack_vector("slow_drip_carding")
        self.assertEqual(red_team["status"], "SYNTHETIC_ATTACK_GENERATED")
        self.assertIn("Slow-Drip", red_team["profile"]["name"])

    def test_threat_intelligence_impossible_travel(self):
        from src.engine.threat_intelligence import ThreatIntelligenceEngine
        tie = ThreatIntelligenceEngine(max_commercial_speed_kmh=850.0)
        user = "usr_travel_test_101"

        # Baseline: New York at t = 1000
        res1 = tie.evaluate_geo_velocity(user, 40.7128, -74.0060, "New York", timestamp=1000.0)
        self.assertFalse(res1.is_impossible_travel)
        self.assertEqual(res1.calculated_speed_kmh, 0.0)

        # 10 minutes later: London (5,570 km away) at t = 1600 (speed ~ 33,400 km/h)
        res2 = tie.evaluate_geo_velocity(user, 51.5074, -0.1278, "London", timestamp=1600.0)
        self.assertTrue(res2.is_impossible_travel)
        self.assertTrue(res2.calculated_speed_kmh > 10000.0)
        self.assertTrue(res2.threat_score >= 0.70)
        self.assertIn("PHYSICS-VIOLATING", res2.reason)

    def test_device_entropy_and_aml_structuring(self):
        from src.engine.threat_intelligence import ThreatIntelligenceEngine
        tie = ThreatIntelligenceEngine()

        # Headless bot detection
        dev_bot = tie.evaluate_device_fingerprint("u_bot", user_agent="Mozilla/5.0 HeadlessChrome/120.0")
        self.assertTrue(dev_bot.is_headless_bot)
        self.assertTrue(dev_bot.threat_score >= 0.50)

        # BSA Structuring detection ($9,950 intentionally below $10,000 threshold)
        struct_res = tie.evaluate_structuring_and_smurfing("u_smurf", 9950.0)
        self.assertTrue(struct_res.is_structuring_detected)
        self.assertEqual(struct_res.structuring_zone, "BSA_10K_REPORTING_THRESHOLD")

    def test_langchain_cognitive_agent(self):
        from src.engine.langchain_agent import LangChainCyberAgent
        agent = LangChainCyberAgent()
        
        # Test suspicious transaction
        tx = {
            "transaction_id": "TXN_LC_99",
            "user_id": "usr_lc_99",
            "amount": 9900.0,
            "user_agent": "Mozilla/5.0 HeadlessChrome/121.0",
            "lat": 51.5074,
            "lon": -0.1278,
            "location_name": "London, UK",
            "V14": -5.8,
            "V12": -4.2
        }
        forensic = agent.run_investigation(tx)
        self.assertTrue(forensic.composite_threat_index >= 0.50)
        self.assertIn("MITRE ATT&CK", forensic.mitre_attack_classification)
        self.assertEqual(len(forensic.tool_execution_trace), 4)
        self.assertIn("Step 1", forensic.chain_of_thought_reasoning)
        self.assertIn("Step 2", forensic.chain_of_thought_reasoning)

    def test_currency_normalizer_and_micro_auth(self):
        from src.engine.currency import currency_normalizer

        # USD Test
        self.assertEqual(currency_normalizer.normalize_to_usd(100.0, "USD"), 100.0)
        self.assertTrue(currency_normalizer.is_micro_auth(1.50, "USD"))
        self.assertFalse(currency_normalizer.is_micro_auth(50.0, "USD"))

        # JPY (Stripe Japan ¥1 probing)
        self.assertTrue(currency_normalizer.is_micro_auth(1.0, "JPY"))
        self.assertTrue(currency_normalizer.is_micro_auth(10.0, "JPY"))
        self.assertFalse(currency_normalizer.is_micro_auth(5000.0, "JPY"))
        self.assertEqual(currency_normalizer.format_amount(15000, "JPY"), "¥15,000")

        # EUR & INR
        self.assertTrue(currency_normalizer.is_micro_auth(1.0, "EUR"))
        self.assertTrue(currency_normalizer.is_micro_auth(5.0, "INR"))
        self.assertEqual(currency_normalizer.format_amount(250.50, "EUR"), "€250.50")

    def test_graph_topology_and_cpp_detection(self):
        from src.engine.graph_engine import GraphTopologyEngine
        gte = GraphTopologyEngine(cpp_card_overlap_threshold=3, ring_card_threshold=3)

        # 1. Simulate carding ring: IP testing 4 distinct cards
        ip_attacker = "198.51.100.88"
        for i in range(4):
            gte.record_transaction(f"card_ring_{i}", f"mcht_{i}", ip_attacker, 2.0, timestamp=time.time())

        risk_res = gte.evaluate_graph_risk("card_ring_0", "mcht_0", ip_attacker)
        self.assertTrue(risk_res.is_carding_ring)
        self.assertTrue(risk_res.graph_risk_score >= 0.80)
        self.assertTrue(any("CARDING_RING" in r for r in risk_res.reason_codes))

        # 2. Simulate Common Point of Purchase (CPP) breach
        # Cards A, B, C all shopped at 'compromised_pos_terminal' before fraud was reported
        compromised_pos = "pos_compromised_hotel_99"
        for card in ["card_alpha", "card_beta", "card_gamma"]:
            gte.record_transaction(card, compromised_pos, "203.0.113.1", 45.0, timestamp=time.time() - 3600)
            gte.flag_card_compromised(card, timestamp=time.time())

        # Now an incoming transaction at this POS should trigger CPP proximity warning
        cpp_eval = gte.evaluate_graph_risk("card_new_shopper", compromised_pos, "192.0.2.1")
        self.assertTrue(cpp_eval.is_compromised_merchant_edge)
        self.assertEqual(cpp_eval.suspected_cpp_merchant, compromised_pos)
        self.assertTrue(any("CPP_EXPOSURE" in r for r in cpp_eval.reason_codes))

    def test_zero_hallucination_guardrail(self):
        from src.engine.copilot import CyberCopilotEngine
        copilot = CyberCopilotEngine()

        ground_truth = {
            "amount": 2500.0,
            "user_id": "usr_7711",
            "incident_id": "INC-7711",
            "ip_addr": "198.51.100.24"
        }

        # Test 1: Grounded, accurate text passes
        accurate_text = (
            "AegisFlow intercepted an anomalous transaction of $2,500.00 associated with entity 'usr_7711'. "
            "Telemetry attributes risk to high-velocity capital exfiltration."
        )
        res_pass = copilot.verify_narrative_grounding(accurate_text, ground_truth)
        self.assertTrue(res_pass.is_grounded)
        self.assertEqual(res_pass.hallucination_score, 0.0)

        # Test 2: Hallucinated amount ($85,000 instead of $2,500) is caught and rejected
        hallucinated_text = (
            "The subject laundered $85,000.00 across unmonitored offshore channels from unknown account."
        )
        res_fail = copilot.verify_narrative_grounding(hallucinated_text, ground_truth)
        self.assertFalse(res_pass.hallucination_score > 0.0)
        self.assertFalse(res_fail.is_grounded)
        self.assertTrue(res_fail.hallucination_score >= 0.5)
        self.assertTrue(any("HALLUCINATED_AMOUNT" in d for d in res_fail.discrepancies))

    def test_multi_currency_evaluation_pipeline(self):
        # Test Japanese Yen transaction evaluation via API
        payload_jpy = {
            "transaction_id": "TXN_JPY_MICRO_01",
            "user_id": "tokyo_cardholder_01",
            "Amount": 1.0,  # ¥1 micro-auth probing
            "currency": "JPY",
            "merchant_id": "mcht_shibuya_ecom",
            "ip_address": "133.242.18.99"
        }
        res = evaluate_single_transaction(payload_jpy)
        self.assertEqual(res["currency"], "JPY")
        self.assertEqual(res["formatted_amount"], "¥1")
        self.assertIn("graph_intelligence", res)
        self.assertIn("gan_intelligence", res)
        self.assertTrue(res["latency_ms"] >= 0.0)

    def test_bigan_anomaly_reconstruction(self):
        from src.engine.gan_detector import BiGANAnomalyDetector
        bigan = BiGANAnomalyDetector(input_dim=30, latent_dim=8)

        # 1. Normal benign transaction vector
        x_normal = np.random.randn(30) * 0.4
        res_normal = bigan.evaluate_transaction(x_normal)
        self.assertTrue(res_normal.latency_ms < 5.0)
        self.assertTrue(0.0 <= res_normal.anomaly_score <= 1.0)
        self.assertEqual(len(res_normal.deviated_subspaces), 4)

        # 2. Perturbed anomalous transaction vector (high magnitude outlier)
        x_anomaly = np.random.randn(30) * 0.3
        x_anomaly[13] = -9.5  # V14 extreme deviation
        x_anomaly[11] = -7.8  # V12 extreme deviation
        res_anomaly = bigan.evaluate_transaction(x_anomaly)
        self.assertTrue(res_anomaly.reconstruction_error > res_normal.reconstruction_error)
        top_deviated = [d["feature"] for d in res_anomaly.deviated_subspaces]
        self.assertIn("V14", top_deviated)

        # 3. Adversarial red-team sample generator
        red_team_samples = bigan.generate_adversarial_evasion_samples(n_samples=2)
        self.assertEqual(len(red_team_samples), 2)
        self.assertIn("Amount", red_team_samples[0])
        self.assertIn("V14", red_team_samples[0])

    def test_wgan_data_augmenter_and_balancing(self):
        from src.training.gan_augmenter import WGANDataAugmenter
        augmenter = WGANDataAugmenter(input_dim=30, latent_dim=8)

        # Create small imbalanced dataset: 100 legit, 5 fraud
        np.random.seed(42)
        X_legit = np.random.randn(100, 30)
        X_fraud = np.random.randn(5, 30) + 3.0
        X = np.vstack([X_legit, X_fraud])
        y = np.concatenate([np.zeros(100, dtype=int), np.ones(5, dtype=int)])

        # Augment with WGAN to reach ~20% fraud ratio
        X_bal, y_bal, metrics = augmenter.augment_dataset(X, y, target_fraud_ratio=0.20)
        self.assertEqual(metrics["original_legit"], 100)
        self.assertEqual(metrics["original_fraud"], 5)
        self.assertTrue(metrics["synthetic_fraud_generated"] > 0)
        self.assertEqual(len(X_bal), len(y_bal))
        self.assertTrue(metrics["final_fraud_ratio"] >= 0.15)

    def test_contextual_bandit_rl_agent_and_online_learning(self):
        from src.engine.rl_policy import ContextualBanditPolicyAgent, ActionDecision
        agent = ContextualBanditPolicyAgent(context_dim=7, alpha=0.2)

        # 1. Clean low-risk transaction context
        ctx_clean = {
            "ml_score": 0.04,
            "amount": 25.0,
            "user_velocity_1m": 0,
            "carding_threat_score": 0.0,
            "device_trust_score": 0.98,
            "graph_risk_score": 0.0
        }
        res_clean = agent.select_action(ctx_clean)
        self.assertTrue(res_clean.latency_ms < 1.0)
        self.assertEqual(res_clean.action, ActionDecision.APPROVE)

        # 2. Suspicious burst context
        ctx_burst = {
            "ml_score": 0.72,
            "amount": 850.0,
            "user_velocity_1m": 4,
            "carding_threat_score": 0.85,
            "device_trust_score": 0.15,
            "graph_risk_score": 0.75
        }
        res_burst = agent.select_action(ctx_burst)
        self.assertIn(res_burst.action, (ActionDecision.BLOCK, ActionDecision.MANUAL_REVIEW, ActionDecision.CHALLENGE_2FA))

        # 3. Online learning update: reward signal
        initial_reward = agent.cumulative_reward
        agent.update_policy(ctx_burst, ActionDecision.BLOCK, reward=10.0)
        self.assertEqual(agent.cumulative_reward, initial_reward + 10.0)

        # 4. Verify telemetry
        telemetry = agent.get_telemetry()
        self.assertEqual(telemetry["algorithm"], "LinUCB Disjoint Contextual Multi-Armed Bandit")
        self.assertTrue(telemetry["total_decisions_served"] >= 2)

    def test_concept_drift_monitor_and_psi(self):
        from src.engine.drift_monitor import ConceptDriftMonitor
        monitor = ConceptDriftMonitor(window_size=200)

        # 1. Baseline nominal metrics
        metrics = monitor.get_comprehensive_metrics()
        self.assertIn(metrics["status"], ("STABLE", "MODERATE_DRIFT"))
        self.assertTrue(0.0 <= metrics["global_psi"] <= 1.0)
        self.assertIn("Amount", metrics["features"])
        self.assertIn("V14", metrics["features"])

        # 2. Simulate holiday surge drift
        drift_metrics = monitor.simulate_drift("holiday_surge")
        self.assertTrue(drift_metrics["global_psi"] > 0.05)
        self.assertEqual(drift_metrics["status"], "CRITICAL_DRIFT")

        # 3. Reset to baseline
        reset_metrics = monitor.reset_to_baseline()
        self.assertIn(reset_metrics["status"], ("STABLE", "MODERATE_DRIFT"))

    def test_throughput_benchmark_runner(self):
        from src.engine.benchmark_runner import ThroughputBenchmarkRunner
        runner = ThroughputBenchmarkRunner()

        # Run benchmark on 150 transactions
        res = runner.run_benchmark(num_transactions=150)
        self.assertEqual(res["transactions_benchmarked"], 150)
        self.assertTrue(res["transactions_per_second"] > 100.0)
        self.assertTrue(res["latency_p95_ms"] < 10.0)
        self.assertTrue(res["sla_compliance_pct"] >= 90.0)
        self.assertIn("stage_breakdown_ms", res)
        self.assertIn("latency_histogram", res)

    def test_bipartite_graph_topology_export_and_simulation(self):
        from src.engine.graph_engine import GraphTopologyEngine
        engine = GraphTopologyEngine()

        # 1. Export topology
        topo = engine.get_full_topology(max_nodes=30)
        self.assertTrue(len(topo["nodes"]) > 0)
        self.assertTrue(len(topo["links"]) > 0)
        self.assertIn("telemetry", topo)

        # 2. Simulate CPP Breach
        cpp_topo = engine.simulate_cpp_breach()
        cpp_nodes = [n for n in cpp_topo["nodes"] if n.get("risk") == "cpp_breach"]
        self.assertTrue(len(cpp_nodes) > 0)

        # 3. Simulate Carding Ring
        ring_topo = engine.simulate_carding_ring()
        ring_nodes = [n for n in ring_topo["nodes"] if n.get("risk") == "ring_botnet"]
        self.assertTrue(len(ring_nodes) > 0)

        # 4. Reset
        reset_topo = engine.reset_graph()
        self.assertTrue(len(reset_topo["nodes"]) > 0)

    def test_universal_instrument_classification_and_profiles(self):
        from src.engine.universal_instrument import universal_instrument_classifier, InstrumentCategory

        # 1. RuPay
        p_rupay = universal_instrument_classifier.classify("6011123456789012")
        self.assertEqual(p_rupay.scheme, "RUPAY")
        self.assertEqual(p_rupay.category, InstrumentCategory.PUBLIC_NETWORK)
        self.assertIn("RuPay", p_rupay.brand_name)

        # 2. American Express
        p_amex = universal_instrument_classifier.classify("378282246310005")
        self.assertEqual(p_amex.scheme, "AMEX")
        self.assertEqual(p_amex.category, InstrumentCategory.PUBLIC_NETWORK)

        # 3. Private Corporate Card (Brex / Ramp / Concur)
        p_corp = universal_instrument_classifier.classify("CORP_EXPENSE_4910")
        self.assertEqual(p_corp.scheme, "PRIVATE_CORP")
        self.assertEqual(p_corp.category, InstrumentCategory.PRIVATE_CORPORATE)
        self.assertTrue(p_corp.is_private_instrument)

        # 4. Commercial Fleet / Fuel Card
        p_fleet = universal_instrument_classifier.classify("FLEET_WEX_CARD_102")
        self.assertEqual(p_fleet.scheme, "PRIVATE_CORP")
        self.assertTrue(p_corp.is_private_instrument)

        # 5. Store Closed-Loop Retail Card
        p_store = universal_instrument_classifier.classify("STORE_TARGET_REDCARD_881")
        self.assertEqual(p_store.scheme, "STORE_CLOSED_LOOP")
        self.assertEqual(p_store.category, InstrumentCategory.STORE_CLOSED_LOOP)

        # 6. Virtual Token / DPAN
        p_virt = universal_instrument_classifier.classify("VTOKEN_APPLEPAY_9912")
        self.assertEqual(p_virt.scheme, "VIRTUAL_TOKEN")
        self.assertEqual(p_virt.category, InstrumentCategory.VIRTUAL_TOKEN)

        # 7. Core Banking / PaySim Account
        p_acc = universal_instrument_classifier.classify("ACC_987654321")
        self.assertEqual(p_acc.scheme, "GENERIC_ACCOUNT")
        self.assertEqual(p_acc.category, InstrumentCategory.GENERIC_ACCOUNT)

        # 8. Explicit scheme override
        p_override = universal_instrument_classifier.classify("CUSTOM_TOKEN_99", explicit_scheme="RUPAY")
        self.assertEqual(p_override.scheme, "RUPAY")

    def test_multi_scheme_graph_topology_enrichment(self):
        from src.engine.graph_engine import GraphTopologyEngine
        engine = GraphTopologyEngine()

        topo = engine.get_full_topology(max_nodes=40)
        card_nodes = [n for n in topo["nodes"] if n.get("type") == "card"]
        self.assertTrue(len(card_nodes) > 0)
        first_card = card_nodes[0]
        self.assertIn("scheme", first_card)
        self.assertIn("brand_name", first_card)
        self.assertIn("category", first_card)
        self.assertIn("color", first_card)

        # Test Universal CPP Breach produces diverse compromised schemes
        cpp_topo = engine.simulate_cpp_breach()
        compromised = [n for n in cpp_topo["nodes"] if n.get("risk") == "compromised"]
        schemes = set(n.get("scheme") for n in compromised)
        self.assertTrue(len(schemes) >= 2, "Universal CPP should compromise cards from multiple schemes")

    def test_private_corporate_dataset_analysis(self):
        import os
        import pandas as pd
        from src.engine.universal_detector import UniversalDetector

        detector = UniversalDetector()
        corp_path = os.path.join(os.path.dirname(__file__), "..", "data", "sample_private_corporate_cards.csv")
        self.assertTrue(os.path.exists(corp_path), "sample_private_corporate_cards.csv must exist")

        df = pd.read_csv(corp_path)
        self.assertTrue(len(df) >= 100)
        analysis = detector.analyze_dataset(df)
        self.assertIn("scored_records", analysis)
        self.assertTrue(len(analysis["scored_records"]) > 0)

    def test_api_evaluation_with_instrument_intelligence(self):
        payload = {
            "transaction_id": "TEST_TX_RUPAY",
            "card_identifier": "6011987654321098",
            "bin_number": "601198",
            "currency": "INR",
            "Amount": 1500.0
        }
        res = evaluate_single_transaction(payload)
        self.assertIn("instrument_intelligence", res)
        self.assertEqual(res["instrument_intelligence"]["scheme"], "RUPAY")
        self.assertEqual(res["currency"], "INR")


    def test_three_ds_rba_and_challenge(self):
        from src.engine.three_ds import three_ds_engine, ThreeDSFlow, ThreeDSStatus

        # Low risk -> Frictionless exemption
        low_res = three_ds_engine.initiate_authentication(
            transaction_id="TX_3DS_LOW",
            amount=25.0,
            currency="EUR",
            card_identifier="6011987654321098",
            ml_score=0.12,
            device_trust_score=0.95
        )
        self.assertEqual(low_res.flow, ThreeDSFlow.FRICTIONLESS)
        self.assertEqual(low_res.status, ThreeDSStatus.EXEMPTED)

        # Elevated risk -> Challenge OTP
        high_res = three_ds_engine.initiate_authentication(
            transaction_id="TX_3DS_HIGH",
            amount=1450.0,
            currency="USD",
            card_identifier="4111222233334444",
            ml_score=0.78,
            device_trust_score=0.40
        )
        self.assertEqual(high_res.flow, ThreeDSFlow.CHALLENGE_OTP)
        self.assertEqual(high_res.status, ThreeDSStatus.CHALLENGE_REQUIRED)
        self.assertIsNotNone(high_res.active_token)

        # Verify challenge with correct test OTP
        verif = three_ds_engine.verify_challenge(high_res.active_token, "123456")
        self.assertTrue(verif["success"])
        self.assertEqual(verif["status"], ThreeDSStatus.AUTHENTICATED.value)

    def test_continuous_streamer_controls(self):
        from src.streaming.continuous_streamer import continuous_streamer

        start_res = continuous_streamer.start(tps=5.0, fraud_ratio=0.1)
        self.assertTrue(continuous_streamer.is_running)
        self.assertEqual(continuous_streamer.target_tps, 5.0)

        rate_res = continuous_streamer.set_rate(10.0)
        self.assertEqual(rate_res["target_tps"], 10.0)

        shock_res = continuous_streamer.inject_shock("carding_burst")
        self.assertEqual(shock_res["status"], "shock_injected")

        stop_res = continuous_streamer.stop()
        self.assertFalse(continuous_streamer.is_running)

    def test_adversarial_arena_skirmish_and_campaign(self):
        from src.engine.adversarial_arena import adversarial_arena_engine, AttackStrategy

        # Reset arena to clean baseline
        adversarial_arena_engine.reset_arena()
        self.assertEqual(adversarial_arena_engine.total_duels, 0)
        self.assertEqual(adversarial_arena_engine.hardening_level, 0.0)

        # 1v1 FGSM Skirmish
        duel_fgsm = adversarial_arena_engine.execute_duel(
            strategy=AttackStrategy.FGSM_EVASION,
            epsilon=0.30
        )
        self.assertIsNotNone(duel_fgsm.duel_id)
        self.assertIn(duel_fgsm.winner, ("BLUE_TEAM", "RED_TEAM"))
        self.assertTrue(len(duel_fgsm.top_perturbed_features) > 0)
        self.assertTrue(duel_fgsm.reconstruction_error > 0.0)

        # Automated War Game Campaign
        camp = adversarial_arena_engine.execute_campaign(rounds=6, epsilon_range=(0.15, 0.40))
        self.assertEqual(camp["rounds_executed"], 6)
        self.assertEqual(len(camp["rounds"]), 6)
        self.assertTrue(camp["final_hardening_level"] >= 0.0)
        self.assertTrue(adversarial_arena_engine.total_duels >= 7)

        # Scoreboard
        sb = adversarial_arena_engine.get_scoreboard()
        self.assertIn("blue_win_rate_pct", sb)
        self.assertIn("effective_threshold", sb)
        self.assertTrue(len(sb["recent_duels"]) > 0)

    def test_dynamic_rule_studio(self):
        from src.engine.rules import rule_engine

        # Reset to known default state
        rule_engine.reset_to_defaults()
        rules = rule_engine.get_rules()
        self.assertEqual(len(rules), 4)

        # Add custom rule
        custom = rule_engine.add_custom_rule(
            name="Crypto Off-Ramp Limit",
            description="Challenge all transactions over $1,000",
            condition_field="amount",
            operator=">=",
            threshold_value=1000.0,
            action="CHALLENGE_2FA",
            risk_boost=0.30
        )
        self.assertTrue(custom["rule_id"].startswith("RULE_CUSTOM_"))
        self.assertTrue(custom["enabled"])

        # Toggle rule
        toggled = rule_engine.toggle_rule(custom["rule_id"], False)
        self.assertFalse(toggled["enabled"])

        # Delete rule
        del_success = rule_engine.delete_rule(custom["rule_id"])
        self.assertTrue(del_success)

        # Reset
        rule_engine.reset_to_defaults()
        self.assertEqual(len(rule_engine.get_rules()), 4)

    def test_3ds_intelligence_in_prediction(self):
        payload = {
            "transaction_id": "TXN_3DS_PIPELINE_TEST",
            "user_id": "usr_9999",
            "Amount": 850.0,
            "currency": "EUR",
            "card_identifier": "5500123456789012"
        }
        res = evaluate_single_transaction(payload)
        self.assertIn("three_ds_intelligence", res)
        self.assertIn("flow", res["three_ds_intelligence"])
        self.assertIn("status", res["three_ds_intelligence"])

    def test_multi_hop_mule_chain_detection(self):
        from src.engine.graph_engine import GraphTopologyEngine
        engine = GraphTopologyEngine()
        res = engine.simulate_mule_chain()
        self.assertTrue(len(res["nodes"]) > 0)
        chains = engine.detect_mule_chains()
        self.assertTrue(len(chains) > 0, "Should detect at least 1 multi-hop mule chain")
        mule_chain = chains[0]
        self.assertTrue(mule_chain["hops"] >= 3, "Mule chain should have at least 3 hops")
        self.assertTrue(mule_chain["risk_score"] >= 0.70)
        self.assertIn("path", mule_chain)

    def test_circular_wash_loop_detection(self):
        from src.engine.graph_engine import GraphTopologyEngine
        engine = GraphTopologyEngine()
        res = engine.simulate_circular_loop()
        self.assertTrue(len(res["nodes"]) > 0)
        loops = engine.detect_circular_loops()
        self.assertTrue(len(loops) > 0, "Should detect at least 1 circular wash loop")
        loop = loops[0]
        self.assertTrue(loop["length"] >= 3)
        self.assertEqual(loop["type"], "CIRCULAR_WASH_LAUNDERING")

    def test_smurfing_swarm_structuring_detection(self):
        from src.engine.graph_engine import GraphTopologyEngine
        engine = GraphTopologyEngine()
        res = engine.simulate_smurfing_swarm()
        self.assertTrue(len(res["nodes"]) > 0)
        swarms = engine.detect_smurfing_swarms()
        self.assertTrue(len(swarms) > 0, "Should detect structured smurfing swarm")
        swarm = swarms[0]
        self.assertTrue(swarm["mule_count"] >= 3)
        self.assertEqual(swarm["type"], "STRUCTURING_SMURFING_SWARM")

    def test_syndicate_quarantine_enforcement_and_audit(self):
        from src.engine.graph_engine import GraphTopologyEngine
        from src.engine.audit_ledger import audit_ledger
        engine = GraphTopologyEngine()
        engine.simulate_mule_chain()
        syndicates = engine.detect_active_syndicates()
        self.assertTrue(len(syndicates) > 0)

        target_syn = syndicates[0]
        syn_id = target_syn["syndicate_id"]
        quarantine_res = engine.quarantine_syndicate(syn_id)
        self.assertTrue(quarantine_res["success"])
        self.assertTrue(quarantine_res["quarantined_entities_count"] > 0)

        # Verify incoming transaction on quarantined node is immediately blocked
        quarantined_node = quarantine_res["entities"][0]
        eval_res = engine.evaluate_graph_risk(
            card_id=quarantined_node,
            merchant_id="merchant_normal",
            ip_address="127.0.0.1"
        )
        self.assertTrue(eval_res.is_quarantined_syndicate)
        self.assertEqual(eval_res.graph_risk_score, 1.0)
        self.assertTrue(any("GRAPH_SYNDICATE_QUARANTINE_BLOCKED" in r for r in eval_res.reason_codes))

    def test_prometheus_metrics_exposition(self):
        from src.api.main import api_prometheus_metrics
        resp = api_prometheus_metrics()
        self.assertEqual(resp.media_type, "text/plain; version=0.0.4; charset=utf-8")
        body = resp.body.decode("utf-8")
        self.assertIn("aegisflow_inference_latency_ms", body)
        self.assertIn("aegisflow_transactions_total", body)
        self.assertIn("aegisflow_graph_syndicates_active", body)
        self.assertIn("aegisflow_merkle_blocks_total", body)
        self.assertIn("aegisflow_merkle_integrity_intact", body)

    def test_pagerank_risk_propagation(self):
        from src.engine.graph_engine import GraphTopologyEngine
        engine = GraphTopologyEngine()
        # Create seed compromised card transacting with a merchant
        engine.record_transaction("seed_compromised_card", "breached_target_mcht", "192.168.1.50", amount=50.0, is_fraud=True)
        # Accomplice card transacts with same merchant
        engine.record_transaction("accomplice_card_neighbor", "breached_target_mcht", "192.168.1.51", amount=120.0, is_fraud=False)

        pr_scores = engine.compute_personalized_pagerank()
        self.assertTrue(len(pr_scores) > 0)
        self.assertIn("accomplice_card_neighbor", pr_scores)
        self.assertTrue(pr_scores["accomplice_card_neighbor"] > 0.0)

        # Evaluate risk of accomplice: should flag collusion proximity
        risk_res = engine.evaluate_graph_risk("accomplice_card_neighbor", "breached_target_mcht", "192.168.1.51")
        self.assertTrue(risk_res.pagerank_score > 0.0)

    def test_canary_champion_challenger_shadow_scoring(self):
        from src.engine.canary_pipeline import CanaryModelEvaluator
        canary = CanaryModelEvaluator()
        eval_res = canary.score_shadow(
            champion_score=0.45,
            features_dict={"V14": -4.5, "V4": 2.2},
            amount=250.0,
            decision_champion="CHALLENGE_2FA"
        )
        self.assertIn("champion_score", eval_res)
        self.assertIn("challenger_score", eval_res)
        self.assertIn("divergence", eval_res)
        self.assertTrue(eval_res["divergence"] >= 0.0)

        status = canary.get_canary_telemetry()
        self.assertIn("decision_concordance_pct", status)
        self.assertIn("avg_divergence", status)
        self.assertTrue(status["samples_evaluated"] >= 1)

    def test_canary_model_promotion_and_audit(self):
        from src.engine.canary_pipeline import CanaryModelEvaluator
        canary = CanaryModelEvaluator()
        orig_champion = canary.champion_name
        orig_challenger = canary.challenger_name

        prom_res = canary.promote_challenger()
        self.assertTrue(prom_res["success"])
        self.assertEqual(canary.champion_name, orig_challenger)
        self.assertEqual(canary.previous_champion, orig_champion)
        self.assertTrue(len(prom_res["merkle_audit_hash"]) > 0)

        # Rollback test
        rb_res = canary.rollback()
        self.assertTrue(rb_res["success"])
        self.assertEqual(canary.champion_name, orig_champion)

    def test_redis_pipeline_velocity_scaling(self):
        from src.streaming.redis_feature_store import RedisFeatureStore
        store = RedisFeatureStore()
        user_id = "test_scale_user_99"

        # Rapid succession burst
        for i in range(10):
            res = store.record_transaction(user_id, f"TX_BURST_{i}", 50.0 + i)
            self.assertEqual(res["total_txns"], i + 1)
        self.assertEqual(res["velocity_1m"], 10)
        self.assertTrue(res["avg_amount"] > 0)

    def test_high_scale_concurrent_stress_runner(self):
        from src.engine.stress_tester import HighScaleStressRunner
        runner = HighScaleStressRunner()
        # Stress test 60 concurrent requests across 4 threads
        report = runner.run_stress_test(num_requests=60, concurrency=4, sla_threshold_ms=10.0)
        self.assertEqual(report["status"], "COMPLETED")
        self.assertEqual(report["total_requests"], 60)
        self.assertEqual(report["error_count"], 0)
        self.assertEqual(report["success_rate_pct"], 100.0)
        self.assertTrue(report["throughput_tps"] > 10.0)
        self.assertIn("latencies_ms", report)
        self.assertTrue(report["latencies_ms"]["p95"] > 0.0)

    def test_cloud_liveness_probe(self):
        from src.api.main import api_liveness_probe, health_check
        res = api_liveness_probe()
        self.assertEqual(res["status"], "UP")
        self.assertEqual(res["service"], "aegisflow-core")
        self.assertEqual(res["version"], "v2.3-core")
        self.assertIn("uptime_seconds", res)
        # Check alias
        res_alias = health_check()
        self.assertEqual(res_alias["status"], "UP")

    def test_cloud_readiness_probe(self):
        from src.api.main import api_readiness_probe
        import json
        resp = api_readiness_probe()
        data = json.loads(resp.body)
        self.assertIn("status", data)
        self.assertIn("checks", data)
        self.assertIn("ml_model_artifacts", data["checks"])
        self.assertIn("feature_store", data["checks"])
        self.assertIn("graph_engine", data["checks"])
        self.assertIn("audit_ledger", data["checks"])

    def test_cloud_security_headers_and_tracing(self):
        from fastapi.testclient import TestClient
        client = TestClient(app)
        response = client.get("/health")
        self.assertEqual(response.status_code, 200)

        # OWASP Top 10 & PCI-DSS 4.0 Compliance Checks
        headers = response.headers
        self.assertIn("Strict-Transport-Security", headers)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-XSS-Protection"], "1; mode=block")
        self.assertEqual(headers["Referrer-Policy"], "strict-origin-when-cross-origin")
        self.assertIn("X-Request-ID", headers)
        self.assertIn("X-Response-Time-Ms", headers)
        self.assertEqual(headers["Server"], "AegisFlow-IndustrialEdge/2.3")

    def test_cloud_dos_payload_limiter(self):
        from fastapi.testclient import TestClient
        client = TestClient(app)
        # Simulate oversized payload header (> 2MB for standard endpoint)
        headers = {"content-length": "3145728", "Content-Type": "application/json"}
        response = client.post("/api/v1/scan", headers=headers, content=b"{}")
        self.assertEqual(response.status_code, 413)
        self.assertIn("Payload Too Large", response.text)

    def test_k8s_and_helm_manifests_integrity(self):
        import os
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        
        # Verify Dockerfile non-root security
        dockerfile_path = os.path.join(project_root, "docker", "Dockerfile")
        self.assertTrue(os.path.exists(dockerfile_path))
        with open(dockerfile_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("10001:10001", content)
            self.assertIn("HEALTHCHECK", content)

        # Verify Kubernetes Deployment security context
        k8s_deploy_path = os.path.join(project_root, "docker", "k8s", "deployment.yaml")
        self.assertTrue(os.path.exists(k8s_deploy_path))
        with open(k8s_deploy_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("readOnlyRootFilesystem: true", content)
            self.assertIn("runAsNonRoot: true", content)
            self.assertIn("drop:", content)

        # Verify Helm Chart
        helm_chart_path = os.path.join(project_root, "docker", "helm", "aegisflow", "Chart.yaml")
        self.assertTrue(os.path.exists(helm_chart_path))
        fincipher_helm_path = os.path.join(project_root, "docker", "helm", "fincipher", "Chart.yaml")
        self.assertTrue(os.path.exists(fincipher_helm_path))

    def test_counting_bloom_filter_add_contains_remove(self):
        from src.engine.fast_filter import CountingBloomFilter
        bf = CountingBloomFilter(expected_elements=1000, false_positive_rate=0.01)
        test_card = "card_test_bloom_998811"

        self.assertFalse(bf.contains(test_card))
        bf.add(test_card)
        self.assertTrue(bf.contains(test_card))
        
        # Test deletion
        removed = bf.remove(test_card)
        self.assertTrue(removed)
        self.assertFalse(bf.contains(test_card))

        stats = bf.get_stats()
        self.assertEqual(stats["active_elements"], 0)
        self.assertTrue(stats["allocated_buckets"] > 0)

    def test_l1_velocity_micro_cache_burst_absorption(self):
        from src.engine.fast_filter import L1VelocityMicroCache
        cache = L1VelocityMicroCache(max_keys=100, ttl_seconds=0.4)
        hot_ip = "192.0.2.45"

        for i in range(4):
            cnt, amt, is_hot = cache.record_or_get(hot_ip, 10.0)
            self.assertFalse(is_hot)
            self.assertEqual(cnt, i + 1)

        # 5th request triggers hot attack
        cnt, amt, is_hot = cache.record_or_get(hot_ip, 10.0)
        self.assertTrue(is_hot)
        self.assertEqual(cnt, 5)

    def test_fast_path_threat_interception_speed(self):
        from src.engine.fast_filter import fast_threat_filter
        from src.api.main import evaluate_single_transaction
        
        compromised_card = "card_compromised_leak_987654"
        fast_threat_filter.blacklist_card(compromised_card)

        tx = {
            "transaction_id": "TX_FAST_TEST_01",
            "card_identifier": compromised_card,
            "ip_address": "10.0.0.1",
            "Amount": 49.99
        }
        res = evaluate_single_transaction(tx)
        self.assertEqual(res["decision"], "BLOCK")
        self.assertEqual(res["risk_score"], 1.0)
        self.assertIn("BLOOM_FILTER_INTERCEPT", res["recommendation"])
        # Extremely fast latency (<1.5ms)
        self.assertTrue(res["latency_ms"] < 2.0)
        self.assertIn("audit_ledger", res)

        # Cleanup
        fast_threat_filter.unblacklist_card(compromised_card)

    def test_fast_filter_api_endpoints(self):
        from fastapi.testclient import TestClient
        client = TestClient(app)

        # Get status
        resp = client.get("/api/v1/threat/fast-filter/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("compromised_cards", data)
        self.assertIn("malicious_ips", data)

        # Blacklist IP
        test_ip = "203.0.113.199"
        post_resp = client.post("/api/v1/threat/blacklist", json={"identifier": test_ip, "entity_type": "ip"})
        self.assertEqual(post_resp.status_code, 200)
        self.assertEqual(post_resp.json()["status"], "BLACKLISTED")

        # Unblacklist IP
        del_resp = client.request("DELETE", "/api/v1/threat/blacklist", json={"identifier": test_ip, "entity_type": "ip"})
        self.assertEqual(del_resp.status_code, 200)
        self.assertEqual(del_resp.json()["status"], "UNBLACKLISTED")

    def test_load_shedder_state_transitions(self):
        from src.engine.load_shedder import AdaptiveLoadShedder
        shedder = AdaptiveLoadShedder(
            target_sla_ms=3.5,
            degraded_threshold_ms=2.5,
            emergency_threshold_ms=4.0,
            cooldown_period_sec=0.1
        )
        self.assertEqual(shedder._current_mode, "NOMINAL")
        self.assertTrue(shedder.should_compute_xai())
        self.assertTrue(shedder.should_score_canary())

        # Degrade trigger (fill window with 2.8ms latencies)
        for _ in range(20):
            shedder.record_latency(2.8)
        self.assertEqual(shedder._current_mode, "DEGRADED")
        self.assertFalse(shedder.should_compute_xai())
        self.assertFalse(shedder.should_score_canary())

        # Emergency trigger (fill window with 4.5ms latencies)
        for _ in range(20):
            shedder.record_latency(4.5)
        self.assertEqual(shedder._current_mode, "EMERGENCY")
        self.assertTrue(shedder.should_fast_pass(amount=25.0, device_trust=0.95))
        self.assertFalse(shedder.should_fast_pass(amount=250.0, device_trust=0.95))

    def test_degraded_mode_xai_and_canary_shedding(self):
        from src.engine.load_shedder import load_shedder
        from src.api.main import evaluate_single_transaction

        load_shedder.set_override("DEGRADED")
        tx = {
            "transaction_id": "TX_SHED_TEST_01",
            "card_identifier": "card_normal_user_888",
            "ip_address": "192.168.1.55",
            "Amount": 150.0
        }
        res = evaluate_single_transaction(tx)
        
        # Verify XAI was shed to preserve SLA
        self.assertEqual(len(res["explainability"]), 1)
        self.assertEqual(res["explainability"][0]["feature"], "SLA_LOAD_SHEDDER")
        
        # Verify canary was shed
        self.assertEqual(res["canary_intelligence"]["routing_status"], "SHED_FOR_SLA_PRESERVATION")

        # Cleanup
        load_shedder.set_override(None)

    def test_emergency_fast_pass_micro_transactions(self):
        from src.engine.load_shedder import load_shedder
        from src.api.main import evaluate_single_transaction

        load_shedder.set_override("EMERGENCY")
        tx = {
            "transaction_id": "TX_EMERGENCY_PASS_01",
            "card_identifier": "card_vip_user_444",
            "ip_address": "192.168.1.66",
            "Amount": 19.99,
            "device_trust_score": 0.95
        }
        res = evaluate_single_transaction(tx)
        self.assertEqual(res["decision"], "APPROVE")
        self.assertEqual(res.get("load_shedder_mode"), "EMERGENCY_FAST_PASS")
        self.assertIn("Emergency Fast-Pass", res["recommendation"])

        # Cleanup
        load_shedder.set_override(None)

    def test_load_shedder_api_endpoints(self):
        from fastapi.testclient import TestClient
        client = TestClient(app)

        # Status check
        status_resp = client.get("/api/v1/load-shedder/status")
        self.assertEqual(status_resp.status_code, 200)
        data = status_resp.json()
        self.assertIn("mode", data)
        self.assertIn("target_sla_ms", data)
        self.assertIn("rolling_p95_ms", data)

        # Override mode
        override_resp = client.post("/api/v1/load-shedder/override", json={"mode": "DEGRADED"})
        self.assertEqual(override_resp.status_code, 200)
        self.assertEqual(override_resp.json()["metrics"]["mode"], "DEGRADED")

        # Reset mode
        reset_resp = client.post("/api/v1/load-shedder/reset")
        self.assertEqual(reset_resp.status_code, 200)
        self.assertEqual(reset_resp.json()["metrics"]["mode"], "NOMINAL")

    def test_async_enrichment_engine_enqueue_and_drain(self):
        from src.engine.async_enricher import AsyncEnrichmentEngine
        engine = AsyncEnrichmentEngine(max_queue_size=1000, num_workers=2)
        results = []

        def sample_handler(p):
            results.append(p["val"] * 2)

        for i in range(5):
            success = engine.enqueue(sample_handler, {"val": i})
            self.assertTrue(success)

        engine.wait_for_drain(timeout_sec=1.5)
        self.assertEqual(len(results), 5)
        self.assertEqual(results, [0, 2, 4, 6, 8])

        stats = engine.get_stats()
        self.assertEqual(stats["total_processed"], 5)
        self.assertEqual(stats["current_queue_depth"], 0)
        self.assertTrue(stats["is_healthy"])

    def test_decoupled_two_phase_transaction_flow(self):
        from src.engine.async_enricher import async_enricher
        from src.engine.graph_engine import graph_engine
        from src.api.main import evaluate_single_transaction

        test_card = "card_async_two_phase_77"
        tx = {
            "transaction_id": "TX_ASYNC_01",
            "card_identifier": test_card,
            "merchant_id": "mcht_async_99",
            "ip_address": "198.51.100.22",
            "Amount": 125.0
        }
        res = evaluate_single_transaction(tx, sync_enrich=False)
        self.assertIn("decision", res)
        self.assertIn("risk_score", res)
        self.assertTrue(res["latency_ms"] >= 0.0)

        # Wait for async background worker to drain
        async_enricher.wait_for_drain(timeout_sec=1.5)
        # Verify graph engine has the entity in memory
        self.assertIn(test_card, graph_engine.card_edges)

    def test_async_enricher_api_endpoint(self):
        from fastapi.testclient import TestClient
        client = TestClient(app)

        resp = client.get("/api/v1/async-enricher/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("active_workers", data)
        self.assertEqual(data["active_workers"], 4)
        self.assertIn("current_queue_depth", data)
        self.assertTrue(data["is_healthy"])

    def test_high_scale_stress_runner_scenarios(self):
        from src.engine.stress_tester import stress_runner
        res = stress_runner.run_stress_test(num_requests=30, concurrency=2, scenario="carding_botnet")
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["total_requests"], 30)
        self.assertEqual(res["concurrency_workers"], 2)
        self.assertEqual(res["success_rate_pct"], 100.0)
        self.assertIn("latencies_ms", res)
        self.assertIn("fast_threat_shield", res)
        self.assertIn("two_phase_async_enricher", res)
        self.assertIsNotNone(stress_runner.get_latest_result())

    def test_benchmark_stress_api_endpoints(self):
        from fastapi.testclient import TestClient
        client = TestClient(app)

        # POST /api/v1/benchmark/stress
        resp = client.post("/api/v1/benchmark/stress", json={"requests": 25, "concurrency": 2, "scenario": "mixed"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "COMPLETED")
        self.assertEqual(data["total_requests"], 25)
        self.assertIn("throughput_tps", data)
        self.assertIn("latencies_ms", data)
        self.assertIn("sla_verdict", data)

        # GET /api/v1/benchmark/stress/latest
        latest_resp = client.get("/api/v1/benchmark/stress/latest")
        self.assertEqual(latest_resp.status_code, 200)
        self.assertEqual(latest_resp.json()["total_requests"], 25)


if __name__ == "__main__":
    unittest.main()






