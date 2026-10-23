"""
FinCipher AI — Alert Lifecycle & Analyst Action Workflow Tests
Author: Om Kamble

Validates Priorities 3 & 4:
1. Stateful alert deduplication, suppression windows, and entity case correlation
2. Analyst case assignment, priority escalation, and disposition resolution
3. Automated action execution (quarantine, 2FA challenge, evidence export)
4. REST API operational endpoints for alert queue, case management, and audit logs
"""

import time
import unittest
from fastapi.testclient import TestClient
from apps.api.main import app

from services.case_management.lifecycle import AlertLifecycleManager
from services.case_management.actions import AnalystActionEngine, ActionType
from libs.models.cases import CaseDisposition, CasePriority, CaseStatus
from src.db.database import get_case_detail, get_entity


class TestLifecycleAndActions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_alert_deduplication_and_case_correlation(self):
        """Validates that rapid alerts on same entity are deduplicated and clustered into a single case."""
        manager = AlertLifecycleManager(suppression_window_seconds=10.0)
        entity_id = f"usr_cluster_{int(time.time()*1000)}"

        # 1. First critical alert -> Creates a new P1 Case
        res1 = manager.process_and_cluster_alert(
            domain="BANKING",
            primary_entity_id=entity_id,
            event_id="EVT_TX_001",
            risk_score=0.92,
            rule_hits=["AML_STRUCTURING_BURST", "SANCTIONED_GEO_KP"],
            title="Severe Banking Anomaly"
        )
        self.assertEqual(res1["status"], "ACCEPTED")
        self.assertFalse(res1["is_suppressed"])
        self.assertIsNotNone(res1["case_id"])
        self.assertEqual(res1["action"], "CASE_CREATED")
        initial_case_id = res1["case_id"]

        # 2. Duplicate alert within window -> Suppressed
        res2 = manager.process_and_cluster_alert(
            domain="BANKING",
            primary_entity_id=entity_id,
            event_id="EVT_TX_002",
            risk_score=0.92,
            rule_hits=["AML_STRUCTURING_BURST"],
            title="Severe Banking Anomaly"
        )
        self.assertEqual(res2["status"], "SUPPRESSED")
        self.assertTrue(res2["is_suppressed"])
        self.assertEqual(res2["case_id"], initial_case_id)

        # 3. New distinct rule alert on same entity -> Correlated to existing case
        res3 = manager.process_and_cluster_alert(
            domain="BANKING",
            primary_entity_id=entity_id,
            event_id="EVT_TX_003",
            risk_score=0.88,
            rule_hits=["VELOCITY_BURST_EXCEEDED"],
            title="Velocity Burst Anomaly"
        )
        self.assertEqual(res3["status"], "ACCEPTED")
        self.assertEqual(res3["case_id"], initial_case_id)
        self.assertEqual(res3["action"], "LINKED_TO_EXISTING_CASE")

        # Verify case dossier in database has both transactions linked
        case_data = get_case_detail(initial_case_id)
        self.assertIsNotNone(case_data)
        self.assertIn("EVT_TX_001", case_data["linked_transactions"])
        self.assertIn("EVT_TX_003", case_data["linked_transactions"])

    def test_analyst_case_workflow_lifecycle(self):
        """Validates assignment -> escalation -> resolution workflow with audit trail."""
        engine = AnalystActionEngine()
        manager = AlertLifecycleManager()
        entity_id = f"usr_investigate_{int(time.time()*1000)}"

        # Spawn case
        res = manager.process_and_cluster_alert(
            domain="CYBERSECURITY",
            primary_entity_id=entity_id,
            event_id="EVT_CYBER_01",
            risk_score=0.86,
            rule_hits=["BRUTE_FORCE_BURST", "IMPOSSIBLE_TRAVEL"],
            title="Credential Stuffing Incident"
        )
        case_id = res["case_id"]
        self.assertIsNotNone(case_id)

        # 1. Assign Case
        assigned = engine.assign_case(case_id, analyst_username="sarah_soc_lead", operator="soc_manager")
        self.assertEqual(assigned["status"], "IN_REVIEW")
        self.assertEqual(assigned["assigned_to"], "sarah_soc_lead")

        # 2. Escalate Case
        escalated = engine.escalate_case(
            case_id,
            reason="Lateral movement detected targeting production domain controller",
            operator="sarah_soc_lead",
            target_priority=CasePriority.P1_CRITICAL
        )
        self.assertEqual(escalated["status"], "ESCALATED")
        self.assertEqual(escalated["priority"], "P1_CRITICAL")

        # 3. Resolve Case with Disposition
        resolved = engine.resolve_case(
            case_id,
            disposition=CaseDisposition.CONFIRMED_FRAUD,
            resolution_notes="Attacker IP blocked, bastion credentials rotated, 2FA enforced.",
            operator="sarah_soc_lead"
        )
        self.assertEqual(resolved["status"], "RESOLVED")
        self.assertEqual(resolved["disposition"], "CONFIRMED_FRAUD")

        # Verify case notes captured audit trail
        notes = resolved.get("notes", [])
        self.assertGreaterEqual(len(notes), 3)

    def test_action_dispatcher_execution(self):
        """Validates operational actions: quarantine, 2FA challenge, and evidence export."""
        engine = AnalystActionEngine()
        manager = AlertLifecycleManager()
        entity_id = f"usr_action_{int(time.time()*1000)}"

        res = manager.process_and_cluster_alert(
            domain="ECOMMERCE",
            primary_entity_id=entity_id,
            event_id="EVT_ECOM_01",
            risk_score=0.89,
            rule_hits=["PROMO_CODE_FARMING_BURST"],
            title="Promo Abuse Swarm"
        )
        case_id = res["case_id"]

        # 1. Execute Quarantine Action
        q_act = engine.execute_action(
            ActionType.QUARANTINE_ENTITY,
            entity_id=entity_id,
            case_id=case_id,
            reason="Syndicate promo code bot swarm participant",
            operator="risk_director"
        )
        self.assertEqual(q_act["action_type"], "QUARANTINE_ENTITY")
        ent = get_entity(entity_id)
        self.assertTrue(ent["is_quarantined"])

        # 2. Execute 2FA Challenge Action
        c_act = engine.execute_action(
            ActionType.TRIGGER_CHALLENGE_2FA,
            entity_id=entity_id,
            case_id=case_id,
            operator="policy_engine"
        )
        self.assertEqual(c_act["action_type"], "TRIGGER_CHALLENGE_2FA")
        self.assertEqual(c_act["details"]["status"], "CHALLENGE_ISSUED")

        # 3. Execute Evidence Dossier Export Action
        e_act = engine.execute_action(
            ActionType.EXPORT_EVIDENCE_DOSSIER,
            entity_id=entity_id,
            case_id=case_id,
            operator="compliance_officer"
        )
        self.assertEqual(e_act["action_type"], "EXPORT_EVIDENCE_DOSSIER")
        self.assertIn("checksum_sha256", e_act["details"])

    def test_rest_api_lifecycle_endpoints(self):
        """Validates all REST endpoints for alert processing, queueing, case transitions, and audit logs."""
        entity_id = f"usr_rest_{int(time.time()*1000)}"

        # 1. Process Alert API
        res_al = self.client.post("/api/v1/events/alerts/process", json={
            "domain": "BANKING",
            "primary_entity_id": entity_id,
            "risk_score": 0.91,
            "rule_hits": ["AML_STRUCTURING_BURST"],
            "title": "API Test Alert"
        })
        self.assertEqual(res_al.status_code, 200)
        data_al = res_al.json()
        case_id = data_al["case_id"]
        self.assertIsNotNone(case_id)

        # 2. Alerts Queue API
        res_q = self.client.get("/api/v1/events/alerts/queue")
        self.assertEqual(res_q.status_code, 200)
        self.assertIn("active_alerts", res_q.json())

        # 3. Assign Case API
        res_as = self.client.post(f"/api/v1/events/cases/{case_id}/assign", json={
            "analyst_username": "alex_investigator",
            "operator": "triage_lead"
        })
        self.assertEqual(res_as.status_code, 200)
        self.assertEqual(res_as.json()["status"], "ASSIGNED")

        # 4. Escalate Case API
        res_esc = self.client.post(f"/api/v1/events/cases/{case_id}/escalate", json={
            "reason": "Large wire transfer attempt while account under review",
            "operator": "alex_investigator",
            "priority": "P1_CRITICAL"
        })
        self.assertEqual(res_esc.status_code, 200)
        self.assertEqual(res_esc.json()["status"], "ESCALATED")

        # 5. Resolve Case API
        res_res = self.client.post(f"/api/v1/events/cases/{case_id}/resolve", json={
            "disposition": "CONFIRMED_FRAUD",
            "resolution_notes": "Wire blocked, KYC documentation verified fraudulent.",
            "operator": "alex_investigator"
        })
        self.assertEqual(res_res.status_code, 200)
        self.assertEqual(res_res.json()["status"], "RESOLVED")

        # 6. Action Execution API
        res_act = self.client.post("/api/v1/events/actions/execute", json={
            "action_type": "TRIGGER_CHALLENGE_2FA",
            "entity_id": entity_id,
            "case_id": case_id,
            "reason": "Enforcing 2FA after fraud resolution"
        })
        self.assertEqual(res_act.status_code, 200)
        self.assertEqual(res_act.json()["status"], "SUCCESS")

        # 7. Audit Log API
        res_log = self.client.get("/api/v1/events/actions/audit-log")
        self.assertEqual(res_log.status_code, 200)
        self.assertGreater(res_log.json()["total_actions"], 0)


if __name__ == "__main__":
    unittest.main()
