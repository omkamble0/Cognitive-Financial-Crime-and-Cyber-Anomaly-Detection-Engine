"""
Unit & Integration Tests for Operational Workflows, External Threat Intel & Action Dispatches
Author: Om Kamble
"""

import time
import uuid
import pytest
from fastapi.testclient import TestClient
from src.api.main import app
from src.db.database import init_database

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    init_database()


def test_threat_intel_lookup_and_status():
    # 1. Lookup clean indicator
    clean_res = client.get("/api/v1/threat-intel/lookup?indicator=clean_customer_88")
    assert clean_res.status_code == 200
    clean_data = clean_res.json()
    assert clean_data["is_malicious"] is False
    assert clean_data["category"] == "CLEAN"

    # 2. Lookup known malicious Tor exit node
    tor_res = client.get("/api/v1/threat-intel/lookup?indicator=185.220.101.5")
    assert tor_res.status_code == 200
    tor_data = tor_res.json()
    assert tor_data["is_malicious"] is True
    assert tor_data["category"] == "TOR_EXIT_NODE"

    # 3. Lookup OFAC sanctioned address
    ofac_res = client.get("/api/v1/threat-intel/lookup?indicator=0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a")
    assert ofac_res.status_code == 200
    ofac_data = ofac_res.json()
    assert ofac_data["is_malicious"] is True
    assert ofac_data["category"] == "OFAC_SANCTIONED"

    # 4. Status endpoint
    status_res = client.get("/api/v1/threat-intel/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert "total_indicators" in status_data
    assert status_data["total_indicators"] > 0


def test_threat_intel_sync():
    res = client.post("/api/v1/threat-intel/sync")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert "metrics" in data


def test_action_dispatch_lifecycle():
    event_id = f"evt_{uuid.uuid4().hex[:8]}"
    target = f"usr_{uuid.uuid4().hex[:6]}"

    # Dispatch action
    payload = {
        "event_id": event_id,
        "action_type": "QUARANTINE_IP",
        "target": target,
        "reason": "Impossible travel jump detected",
        "operator": "lead_soc_analyst"
    }
    dispatch_res = client.post("/api/v1/actions/dispatch", json=payload)
    assert dispatch_res.status_code == 200
    data = dispatch_res.json()
    assert data["status"] == "SUCCESS"
    assert data["action_type"] == "QUARANTINE_IP"
    assert data["target"] == target

    # Query recent dispatches
    list_res = client.get("/api/v1/actions/dispatches?limit=20")
    assert list_res.status_code == 200
    dispatches = list_res.json()["dispatches"]
    matched = [d for d in dispatches if d["event_id"] == event_id]
    assert len(matched) == 1
    assert matched[0]["target"] == target


def test_case_lifecycle_api_and_sla():
    # 1. Create Case
    create_payload = {
        "title": "Structuring $9,500 Wire Outflow",
        "priority": "P1_CRITICAL",
        "entity_id": f"entity_{uuid.uuid4().hex[:6]}",
        "risk_score": 0.88,
        "assigned_to": "analyst_bob"
    }
    create_res = client.post("/api/v1/cases", json=create_payload)
    assert create_res.status_code == 200
    case = create_res.json()
    case_id = case["id"]
    assert "sla" in case
    assert case["sla"]["target_minutes"] == 15
    assert case["sla"]["sla_status"] in ("WITHIN_SLA", "NEAR_BREACH")

    # 2. Get Case Detail
    get_res = client.get(f"/api/v1/cases/{case_id}")
    assert get_res.status_code == 200
    detail = get_res.json()
    assert detail["id"] == case_id
    assert "sla" in detail
    assert detail["assigned_to"] == "analyst_bob"

    # 3. Transition to IN_REVIEW
    trans1 = client.post("/api/v1/cases/transition", json={
        "case_id": case_id,
        "target_status": "IN_REVIEW",
        "operator": "analyst_bob",
        "reason": "Inspecting beneficiary network"
    })
    assert trans1.status_code == 200
    assert trans1.json()["case"]["status"] == "IN_REVIEW"

    # 4. Resolve as Fraud
    trans2 = client.post("/api/v1/cases/transition", json={
        "case_id": case_id,
        "target_status": "RESOLVED_FRAUD",
        "operator": "analyst_bob",
        "reason": "Confirmed structuring ring"
    })
    assert trans2.status_code == 200
    assert trans2.json()["case"]["status"] == "RESOLVED_FRAUD"

    # 5. Verify Case List includes SLA
    list_res = client.get("/api/v1/cases?limit=10")
    assert list_res.status_code == 200
    all_cases = list_res.json()
    matched = [c for c in all_cases if c["id"] == case_id]
    assert len(matched) == 1
    assert "sla" in matched[0]
