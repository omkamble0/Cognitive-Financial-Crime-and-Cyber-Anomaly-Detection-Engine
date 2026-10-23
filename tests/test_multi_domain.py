"""
FinCipher AI — Multi-Domain Platform Integration & Regression Tests
Author: Om Kamble
"""

import unittest
import time
from fastapi.testclient import TestClient
from src.api.main import app
from libs.models.events import GenericEvent, DomainType, EventType, EntityLink
from libs.models.alerts import Alert, AlertSeverity, AlertStatus
from libs.models.cases import CaseStatus, CaseDisposition
from services.risk_engine.deduplicator import AlertDeduplicator
from services.risk_engine.router import universal_risk_router
from services.case_management.workflow import case_workflow_service
from services.ingestion.normalizer import UniversalEventNormalizer


from services.risk_engine.baselines import behavior_baseline_engine, EntityBehaviorBaselineEngine
from services.graph_analytics.universal_graph import universal_graph_engine, UniversalGraphEngine
from services.policy_engine.engine import declarative_policy_engine, DeclarativePolicyEngine, PolicyRule
from services.threat_intel.connector import threat_intel_connector, UniversalThreatIntelConnector
from services.case_management.narratives import narrative_engine, DomainForensicNarrativeEngine


class TestFinCipherMultiDomain(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_domains_discovery_api(self):
        """Verifies that the /api/v1/events/domains endpoint advertises all 3 domains."""
        resp = self.client.get("/api/v1/events/domains")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("active_domains", data)
        domains = [d["domain"] for d in data["active_domains"]]
        self.assertIn("BANKING", domains)
        self.assertIn("CYBERSECURITY", domains)
        self.assertIn("ECOMMERCE", domains)

    def test_generic_event_ingestion_api(self):
        """Verifies generic event schema validation and ingestion."""
        evt = {
            "domain": "BANKING",
            "event_type": "PAYMENT",
            "primary_entity_id": "usr_test_generic_01",
            "entities": [
                {"id": "usr_test_generic_01", "type": "USER", "role": "ACTOR"}
            ],
            "payload": {"amount": 500.0, "currency": "USD"},
            "context": {"ip_address": "127.0.0.1"}
        }
        resp = self.client.post("/api/v1/events/ingest", json=evt)
        self.assertEqual(resp.status_code, 200)
        res_data = resp.json()
        self.assertEqual(res_data["status"], "PROCESSED")
        self.assertEqual(res_data["evaluation"]["domain"], "BANKING")

    def test_banking_convenience_ingestion_api(self):
        """Verifies raw banking payment ingestion and AML structuring detection."""
        resp = self.client.post("/api/v1/events/ingest/banking", json={
            "transaction_id": "TX_API_STRUCT_01",
            "user_id": "usr_aml_tester",
            "amount": 9500.00,
            "currency": "USD"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["domain"], "BANKING")
        eval_res = data["evaluation"]
        self.assertIn("AML_SUSPECTED_STRUCTURING_CTR_AVOIDANCE", eval_res["rule_hits"])
        self.assertTrue(eval_res["risk_score"] >= 0.80)

    def test_cyber_convenience_ingestion_api(self):
        """Verifies raw cybersecurity syslog ingestion and brute force detection."""
        ip = "192.0.2.77"
        # 5 failed logins
        for _ in range(5):
            resp = self.client.post("/api/v1/events/ingest/cyber", json={
                "username": "victim_account",
                "source_ip": ip,
                "status": "FAILURE"
            })
            self.assertEqual(resp.status_code, 200)

        data = resp.json()
        eval_res = data["evaluation"]
        self.assertEqual(eval_res["decision"], "BLOCK")
        self.assertTrue(any("SOC_BRUTE_FORCE_DETECTED" in r for r in eval_res["rule_hits"]))

    def test_ecommerce_convenience_ingestion_api(self):
        """Verifies raw e-commerce promo code farming detection."""
        ip = "198.51.100.99"
        promo = "SAVE50_EXPLOIT"
        # 3 distinct buyers on same IP
        for i in range(1, 4):
            resp = self.client.post("/api/v1/events/ingest/ecommerce", json={
                "order_id": f"ORD_TEST_{i}",
                "customer_id": f"guest_shopper_{i}",
                "ip_address": ip,
                "total_amount": 100.00,
                "discount_amount": 80.00,
                "promo_code": promo,
                "discount_applied": True
            })
            self.assertEqual(resp.status_code, 200)

        data = resp.json()
        eval_res = data["evaluation"]
        self.assertEqual(eval_res["decision"], "BLOCK")
        self.assertTrue(any("ECOMM_PROMO_FARMING_BURST" in r for r in eval_res["rule_hits"]))

    def test_alert_deduplication_and_suppression(self):
        """Verifies that repetitive alerts within the suppression window are suppressed."""
        dedup = AlertDeduplicator(suppression_window_seconds=10.0)
        fp = Alert.generate_fingerprint("BANKING", "acc_dedup_01", "CARDING_VELOCITY")

        a1 = Alert(
            domain="BANKING",
            title="Carding Velocity Alert",
            severity=AlertSeverity.P2_HIGH,
            primary_entity_id="acc_dedup_01",
            event_id="EVT_01",
            risk_score=0.88,
            dedup_fingerprint=fp
        )
        is_new1, eff1 = dedup.process_alert(a1)
        self.assertTrue(is_new1)
        self.assertEqual(eff1.suppression_count, 0)

        # Immediate second alert with same fingerprint
        a2 = Alert(
            domain="BANKING",
            title="Carding Velocity Alert",
            severity=AlertSeverity.P2_HIGH,
            primary_entity_id="acc_dedup_01",
            event_id="EVT_02",
            risk_score=0.88,
            dedup_fingerprint=fp
        )
        is_new2, eff2 = dedup.process_alert(a2)
        self.assertFalse(is_new2)
        self.assertEqual(eff2.suppression_count, 1)

    def test_case_workflow_state_machine(self):
        """Verifies state machine transitions and evidence export."""
        case = case_workflow_service.create_case_from_alert(
            domain="CYBERSECURITY",
            title="Lateral Movement Anomaly",
            primary_entity_id="host_db_primary",
            risk_score=0.92,
            priority="P1_CRITICAL"
        )
        self.assertIsNotNone(case)
        case_id = case["id"]

        # Valid transition: OPEN -> IN_REVIEW
        updated = case_workflow_service.transition_case_status(
            case_id=case_id,
            new_status=CaseStatus.IN_REVIEW,
            operator="soc_lead_alex",
            reason="Investigating forensic packet capture."
        )
        self.assertEqual(updated["status"], "IN_REVIEW")

        # Invalid transition: IN_REVIEW -> OPEN (Not permitted by state machine)
        with self.assertRaises(ValueError):
            case_workflow_service.transition_case_status(
                case_id=case_id,
                new_status=CaseStatus.OPEN,
                operator="soc_lead_alex"
            )

        # Add forensic note
        note_res = case_workflow_service.add_forensic_note(
            case_id=case_id,
            author="soc_lead_alex",
            note_text="Confirmed anomalous PowerShell execution."
        )
        self.assertEqual(note_res["author"], "soc_lead_alex")

        # Export Evidence Package
        pkg = case_workflow_service.export_evidence_package(case_id=case_id)
        self.assertEqual(pkg.case_overview["id"], case_id)
        self.assertIsNotNone(pkg.package_sha256_checksum)

    def test_behavioral_baseline_engine(self):
        """Verifies Welford dynamic profiling and Z-score deviation anomaly detection."""
        engine = EntityBehaviorBaselineEngine(z_score_threshold=3.0)
        entity_id = "usr_baseline_test_99"
        metric = "spend_amount"

        # Train baseline with nominal transactions (~$50)
        for val in [50.0, 52.0, 48.0, 51.0, 49.0]:
            engine.evaluate_metric(entity_id, metric, val, update_baseline=True)

        summary = engine.get_profile_summary(entity_id)
        self.assertIn(metric, summary)
        self.assertEqual(summary[metric]["observations"], 5)
        self.assertAlmostEqual(summary[metric]["mean"], 50.0, delta=2.0)

        # Huge deviation spike ($8,500)
        eval_spike = engine.evaluate_metric(entity_id, metric, 8500.0, update_baseline=False)
        self.assertTrue(eval_spike.is_anomalous)
        self.assertGreater(eval_spike.z_score, 3.0)
        self.assertGreater(eval_spike.deviation_ratio, 50.0)

    def test_universal_graph_engine_syndicate_detection(self):
        """Verifies BFS multi-hop discovery and fraud syndicate ring classification."""
        graph = UniversalGraphEngine()
        # Create a shared infrastructure ring: 3 users sharing 1 IP and 1 Device
        shared_ip = "198.51.100.222"
        shared_device = "dev_fingerprint_xyz"

        graph.add_edge("user_syn_1", "USER", shared_ip, "IP_ADDRESS", "CONNECTS_FROM")
        graph.add_edge("user_syn_2", "USER", shared_ip, "IP_ADDRESS", "CONNECTS_FROM")
        graph.add_edge("user_syn_3", "USER", shared_device, "DEVICE", "ACCESSED_ON")
        graph.add_edge("user_syn_1", "USER", shared_device, "DEVICE", "ACCESSED_ON")

        # Multi-hop traversal from user_syn_1 (hops=2)
        connected = graph.find_connected_entities("user_syn_1", max_hops=2)
        self.assertIn("user_syn_2", connected)
        self.assertIn("user_syn_3", connected)
        self.assertIn(shared_ip, connected)
        self.assertIn(shared_device, connected)

        # Extract subgraph cluster
        cluster = graph.extract_neighborhood_subgraph("user_syn_1", max_hops=2)
        self.assertTrue(cluster.is_syndicate)
        self.assertEqual(cluster.syndicate_type, "COLLUDING_IDENTITIES_SHARED_INFRASTRUCTURE")
        self.assertGreaterEqual(cluster.total_nodes, 4)

    def test_declarative_policy_engine(self):
        """Verifies enterprise compliance and risk enforcement policy triggers."""
        engine = DeclarativePolicyEngine()

        # Sanctions hard block evaluation
        actions = engine.evaluate_policies(
            domain="BANKING",
            risk_score=0.95,
            triggered_rules=["AML_SANCTIONED_JURISDICTION_NORTH_KOREA"],
            primary_entity_id="acc_sanction_target_01"
        )
        action_types = [a.action_type for a in actions]
        self.assertIn("BLOCK", action_types)
        self.assertIn("QUARANTINE_ENTITY", action_types)
        self.assertIn("CREATE_P1_CASE", action_types)

        # Custom policy registration
        custom_pol = PolicyRule(
            policy_id="POL_CUSTOM_HIGH_RISK_2FA",
            name="Enforce 2FA Step-up for Elevated Risk",
            domain="ALL",
            min_risk_score=0.70,
            required_rules=[],
            action="CHALLENGE_2FA"
        )
        engine.register_policy(custom_pol)
        actions_custom = engine.evaluate_policies(
            domain="ECOMMERCE",
            risk_score=0.75,
            triggered_rules=["SOME_RISK"],
            primary_entity_id="user_stepup_01"
        )
        self.assertTrue(any(a.action_type == "CHALLENGE_2FA" for a in actions_custom))

    def test_entity_and_graph_apis(self):
        """Verifies /entities, /entities/{id}, /entities/{id}/graph, and /policies endpoints."""
        # 1. Ingest an event to ensure entity is stored
        self.client.post("/api/v1/events/ingest/banking", json={
            "transaction_id": "TX_API_GRAPH_01",
            "user_id": "usr_entity_api_test",
            "amount": 2500.00,
            "currency": "USD"
        })

        # 2. List entities
        resp_list = self.client.get("/api/v1/events/entities?limit=10")
        self.assertEqual(resp_list.status_code, 200)
        entities = resp_list.json()
        self.assertIsInstance(entities, list)
        self.assertTrue(len(entities) > 0)

        # 3. Get entity profile with baselines
        resp_entity = self.client.get("/api/v1/events/entities/usr_entity_api_test")
        self.assertEqual(resp_entity.status_code, 200)
        ent_data = resp_entity.json()
        self.assertEqual(ent_data["id"], "usr_entity_api_test")
        self.assertIn("behavior_baselines", ent_data)

        # 4. Get entity graph cluster
        resp_graph = self.client.get("/api/v1/events/entities/usr_entity_api_test/graph?max_hops=2")
        self.assertEqual(resp_graph.status_code, 200)
        graph_data = resp_graph.json()
        self.assertIn("root_entity_id", graph_data)
        self.assertIn("nodes", graph_data)
        self.assertIn("edges", graph_data)

        # 5. List policies
        resp_policies = self.client.get("/api/v1/events/policies")
        self.assertEqual(resp_policies.status_code, 200)
        pols = resp_policies.json()
        self.assertIsInstance(pols, list)
        self.assertTrue(len(pols) >= 3)

    def test_threat_intel_connector(self):
        """Verifies IoC matching across Tor nodes, disposable emails, and dynamic custom blocklists."""
        connector = UniversalThreatIntelConnector()

        # Tor exit IP lookup
        m_tor = connector.check_indicator("198.51.100.12")
        self.assertIsNotNone(m_tor)
        self.assertTrue(m_tor.is_malicious)
        self.assertEqual(m_tor.threat_category, "TOR_EXIT_NODE")
        self.assertIn("T1090", m_tor.mitre_technique)

        # Disposable email lookup
        m_email = connector.check_indicator("attacker99@tempmail.com")
        self.assertIsNotNone(m_email)
        self.assertEqual(m_email.threat_category, "DISPOSABLE_EMAIL")

        # Benign clean IP lookup
        m_clean = connector.check_indicator("8.8.8.8")
        self.assertIsNone(m_clean)

        # Dynamic custom IoC registration
        connector.add_custom_ioc("192.168.100.50", "IP_ADDRESS")
        m_custom = connector.check_indicator("192.168.100.50")
        self.assertIsNotNone(m_custom)
        self.assertTrue(m_custom.is_malicious)

    def test_router_threat_intel_elevation(self):
        """Verifies that an event bearing a Tor exit node triggers threat intel rules and elevates risk."""
        tor_ip = "185.220.101.5"
        event = GenericEvent(
            domain=DomainType.CYBERSECURITY,
            event_type=EventType.LOGIN,
            primary_entity_id="user_tor_attacker",
            entities=[EntityLink(id="user_tor_attacker", type="USER", role="ACTOR")],
            context={"ip_address": tor_ip},
            payload={"status": "SUCCESS"}
        )
        res = universal_risk_router.evaluate_event(event)
        self.assertGreaterEqual(res["risk_score"], 0.85)
        self.assertEqual(res["decision"], "BLOCK")
        self.assertTrue(any("THREAT_INTEL_TOR_EXIT_NODE" in r for r in res["rule_hits"]))

    def test_forensic_narrative_generation(self):
        """Verifies regulatory-compliant narrative generation for SAR, SOC, and Chargebacks."""
        mock_case = {
            "case_number": "CASE-TEST-8800",
            "entity_id": "usr_financial_crime_subject",
            "risk_score": 0.94,
            "total_amount": 15000.0
        }
        mock_eval = {
            "rule_hits": ["AML_SUSPECTED_STRUCTURING_CTR_AVOIDANCE", "AML_SANCTIONED_JURISDICTION_KP"]
        }

        # 1. FinCEN SAR Narrative
        sar = narrative_engine.generate_banking_sar_narrative(mock_case, mock_eval)
        self.assertIn("FINCEN SUSPICIOUS ACTIVITY REPORT", sar)
        self.assertIn("Currency Transaction Reporting", sar)
        self.assertIn("CASE-TEST-8800", sar)

        # 2. SOC Incident Report
        soc = narrative_engine.generate_cyber_incident_report(mock_case, mock_eval)
        self.assertIn("ENTERPRISE SOC FORENSIC INCIDENT DOSSIER", soc)
        self.assertIn("MITRE ATT&CK", soc)
        self.assertIn("T1110", soc)

        # 3. Chargeback Dispute Dossier
        ecomm = narrative_engine.generate_ecommerce_chargeback_dossier(mock_case, mock_eval)
        self.assertIn("MERCHANT DISPUTE & CHARGEBACK ARBITRATION DOSSIER", ecomm)
        self.assertIn("Visa Compelling Evidence 3.0", ecomm)

    def test_threat_intel_and_narrative_apis(self):
        """Verifies /threat-intel/lookup and /cases/{case_id}/narrative endpoints."""
        # 1. Threat intel lookup: Tor IP
        resp_tor = self.client.get("/api/v1/events/threat-intel/lookup?indicator=198.51.100.12")
        self.assertEqual(resp_tor.status_code, 200)
        tor_data = resp_tor.json()
        self.assertTrue(tor_data["is_malicious"])
        self.assertEqual(tor_data["threat_category"], "TOR_EXIT_NODE")

        # 2. Threat intel lookup: Benign IP
        resp_clean = self.client.get("/api/v1/events/threat-intel/lookup?indicator=8.8.8.8")
        self.assertEqual(resp_clean.status_code, 200)
        clean_data = resp_clean.json()
        self.assertFalse(clean_data["is_malicious"])

        # 3. Create case and query narrative
        case_created = case_workflow_service.create_case_from_alert(
            domain="BANKING",
            title="CTR Avoidance Investigation",
            primary_entity_id="usr_api_narrative_test",
            risk_score=0.91,
            priority="P1_CRITICAL"
        )
        case_id = case_created["id"]

        resp_narrative = self.client.get(f"/api/v1/events/cases/{case_id}/narrative?domain=BANKING")
        self.assertEqual(resp_narrative.status_code, 200)
        narr_data = resp_narrative.json()
        self.assertEqual(narr_data["case_id"], case_id)
        self.assertIn("FINCEN SUSPICIOUS ACTIVITY REPORT", narr_data["narrative"])


if __name__ == "__main__":
    unittest.main()

