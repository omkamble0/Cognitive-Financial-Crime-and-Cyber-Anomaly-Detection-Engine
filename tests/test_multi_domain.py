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


if __name__ == "__main__":
    unittest.main()
