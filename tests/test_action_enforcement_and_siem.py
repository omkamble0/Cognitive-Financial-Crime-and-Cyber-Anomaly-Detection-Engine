"""
FinCipher AI — Test Suite for Action Enforcement Engine, Revocation Lifecycle & SIEM/SOAR Forwarder
Author: Om Kamble
"""

import time
import uuid
import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.db.database import init_database
from src.engine.action_enforcer import action_enforcer, EnforcementActionType
from src.engine.siem_forwarder import siem_forwarder, SiemFormat
from src.streaming.worker_pool import stream_worker_pool

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_environment():
    init_database()


def test_action_enforcer_block_and_preflight():
    target_acc = f"ACC_BAD_{uuid.uuid4().hex[:6]}"
    event_id = f"EVT_{uuid.uuid4().hex[:6]}"

    # Initially clean
    clean_check = action_enforcer.check_preflight_enforcement(entity_id=target_acc)
    assert clean_check["is_blocked"] is False

    # Enforce BLOCK
    enf_res = action_enforcer.enforce_action(
        action_type=EnforcementActionType.BLOCK,
        target=target_acc,
        event_id=event_id,
        reason="Sanctions watchlist hit",
        operator="SOC_SUPERVISOR",
        metadata={"risk_score": 0.99}
    )
    assert enf_res["status"] == "SUCCESS"
    assert enf_res["target"] == target_acc
    action_id = enf_res["action_id"]

    # Preflight check should now block in < 0.2ms
    t0 = time.perf_counter()
    blocked_check = action_enforcer.check_preflight_enforcement(entity_id=target_acc)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    assert blocked_check["is_blocked"] is True
    assert blocked_check["action_type"] == EnforcementActionType.BLOCK
    assert "Sanctions" in blocked_check["reason"]
    assert elapsed_ms < 5.0  # Well within threshold

    # Active enforcements check
    active = action_enforcer.list_active_enforcements()
    assert any(b["account_id"] == target_acc for b in active["blocked_accounts"])

    # Revoke action
    rev_res = action_enforcer.revoke_action(
        dispatch_id=action_id,
        operator="COMPLIANCE_OFFICER",
        reason="False positive cleared after verification"
    )
    assert rev_res["status"] == "SUCCESS"
    assert rev_res["status_updated"] == "REVOKED"

    # Preflight check should now pass
    post_revoke_check = action_enforcer.check_preflight_enforcement(entity_id=target_acc)
    assert post_revoke_check["is_blocked"] is False


def test_action_enforcer_quarantine_ip():
    target_ip = f"198.51.100.{int(time.time()) % 200 + 10}"
    event_id = f"EVT_CYBER_{uuid.uuid4().hex[:6]}"

    # Enforce QUARANTINE
    action_enforcer.enforce_action(
        action_type=EnforcementActionType.QUARANTINE,
        target=target_ip,
        event_id=event_id,
        reason="Brute force credential stuffing",
        operator="AUTO_DEFENSE",
        duration_seconds=300
    )

    # Preflight IP check
    ip_check = action_enforcer.check_preflight_enforcement(ip_address=target_ip)
    assert ip_check["is_blocked"] is True
    assert ip_check["action_type"] == EnforcementActionType.QUARANTINE
    assert ip_check["remaining_seconds"] > 0


def test_siem_format_serialization():
    sample_event = {
        "event_id": "EVT_TEST_SIEM_999",
        "domain": "BANKING",
        "severity": "CRITICAL",
        "risk_score": 0.94,
        "primary_entity_id": "cust_highrisk_42",
        "decision": "BLOCK",
        "rule_hits": ["STRUCTURING_VELOCITY", "KNOWN_MULE_ACCOUNT"],
        "mitre_technique": "T1589",
        "forensic_narrative": "Coordinated structuring cluster detected"
    }

    # 1. Splunk HEC
    splunk_payload = siem_forwarder.format_event(sample_event, fmt=SiemFormat.SPLUNK_HEC)
    assert "event" in splunk_payload
    assert splunk_payload["sourcetype"] == "fincipher:threat:anomaly"
    assert splunk_payload["event"]["event_id"] == "EVT_TEST_SIEM_999"
    assert splunk_payload["event"]["decision"] == "BLOCK"

    # 2. Elastic ECS
    ecs_payload = siem_forwarder.format_event(sample_event, fmt=SiemFormat.ELASTIC_ECS)
    assert "@timestamp" in ecs_payload
    assert ecs_payload["event"]["id"] == "EVT_TEST_SIEM_999"
    assert ecs_payload["user"]["id"] == "cust_highrisk_42"
    assert ecs_payload["fincipher"]["risk_score"] == 0.94

    # 3. CEF
    cef_str = siem_forwarder.format_event(sample_event, fmt=SiemFormat.CEF)
    assert cef_str.startswith("CEF:0|FinCipher|CognitiveRiskEngine|2.3|BANKING_RISK|BLOCK|10|")
    assert "suser=cust_highrisk_42" in cef_str
    assert "cn1=0.94" in cef_str

    # 4. Syslog
    syslog_str = siem_forwarder.format_event(sample_event, fmt=SiemFormat.SYSLOG)
    assert syslog_str.startswith("<134>1")
    assert "fincipher-node" in syslog_str
    assert "entity=\"cust_highrisk_42\"" in syslog_str


def test_siem_forwarder_lifecycle_and_configuration():
    # Configure endpoints
    siem_forwarder.configure(
        splunk_hec_url="http://localhost:8088/services/collector",
        splunk_hec_token="HEC_TOKEN_SEC_99",
        elastic_url="http://localhost:9200",
        webhook_url="http://localhost:9000/siem-hook"
    )

    status = siem_forwarder.get_status()
    assert status["is_running"] is True
    assert status["endpoints"]["splunk_hec"]["configured"] is True
    assert status["endpoints"]["elastic_ecs"]["configured"] is True
    assert status["endpoints"]["webhook"]["configured"] is True

    # Forward synchronous event into verified internal buffer
    evt = {
        "event_id": "EVT_FWD_101",
        "domain": "CYBERSECURITY",
        "severity": "HIGH",
        "risk_score": 0.89,
        "primary_entity_id": "user_compromised_admin",
        "decision": "QUARANTINE"
    }
    fwd_res = siem_forwarder.forward(evt, format_type=SiemFormat.CEF, sync=True)
    assert fwd_res["status"] == "DELIVERED"
    assert len(siem_forwarder.recent_deliveries) > 0


def test_action_and_siem_rest_api_endpoints():
    target_entity = f"cust_api_{uuid.uuid4().hex[:6]}"
    evt_id = f"evt_api_{uuid.uuid4().hex[:6]}"

    # 1. POST /api/v1/actions/enforce
    enforce_resp = client.post("/api/v1/actions/enforce", json={
        "action_type": "BLOCK_ACCOUNT",
        "target": target_entity,
        "event_id": evt_id,
        "reason": "Rapid layered withdrawals via proxy",
        "operator": "lead_soc_analyst",
        "metadata": {"risk_score": 0.96}
    })
    assert enforce_resp.status_code == 200
    enf_data = enforce_resp.json()
    assert enf_data["status"] == "SUCCESS"
    dispatch_id = enf_data["action_id"]

    # 2. GET /api/v1/actions/check (Pre-flight endpoint)
    check_resp = client.get(f"/api/v1/actions/check?entity_id={target_entity}")
    assert check_resp.status_code == 200
    assert check_resp.json()["is_blocked"] is True

    # 3. GET /api/v1/actions/active
    active_resp = client.get("/api/v1/actions/active")
    assert active_resp.status_code == 200
    act_data = active_resp.json()
    assert act_data["total_active"] >= 1

    # 4. POST /api/v1/actions/{id}/revoke
    revoke_resp = client.post(f"/api/v1/actions/{dispatch_id}/revoke", json={
        "operator": "soc_lead",
        "reason": "ID verification confirmed genuine identity"
    })
    assert revoke_resp.status_code == 200
    rev_data = revoke_resp.json()
    assert rev_data["status_updated"] == "REVOKED"

    # 5. Check again should be clean
    check_clean = client.get(f"/api/v1/actions/check?entity_id={target_entity}")
    assert check_clean.json()["is_blocked"] is False

    # 6. SIEM status endpoint
    siem_st_resp = client.get("/api/v1/siem/status")
    assert siem_st_resp.status_code == 200
    assert "supported_formats" in siem_st_resp.json()

    # 7. SIEM forward endpoint
    siem_fwd_resp = client.post("/api/v1/siem/forward", json={
        "event": {
            "event_id": "EVT_SIEM_API_1",
            "domain": "BANKING",
            "severity": "CRITICAL",
            "risk_score": 0.95,
            "decision": "BLOCK"
        },
        "format_type": "ELASTIC_ECS",
        "sync": True
    })
    assert siem_fwd_resp.status_code == 200
    assert siem_fwd_resp.json()["status"] == "DELIVERED"


def test_worker_pool_preflight_block_bypass():
    blocked_user = f"user_preflight_{uuid.uuid4().hex[:6]}"

    # Apply block to user
    action_enforcer.enforce_action(
        action_type=EnforcementActionType.BLOCK,
        target=blocked_user,
        event_id="EVT_SEED_BLOCK",
        reason="Prior confirmed identity theft syndicate"
    )

    # Submit event for blocked user through worker pool
    event = {
        "event_id": f"evt_bypass_{uuid.uuid4().hex[:6]}",
        "domain": "BANKING",
        "user_id": blocked_user,
        "amount": 25000.0,
        "currency": "USD",
        "source_country": "US",
        "timestamp": time.time()
    }

    result = stream_worker_pool.ingest_sync(event, timeout=2.0)
    assert result["decision"] == "BLOCK"
    assert result["preflight_blocked"] is True
    assert result["severity"] == "CRITICAL"
    assert "Immediate edge block" in result["forensic_narrative"]

    # Cleanup: unblock user
    active = action_enforcer.list_active_enforcements()
    for acc in active["blocked_accounts"]:
        if acc.get("account_id") == blocked_user:
            action_enforcer._active_blocked_accounts.pop(blocked_user, None)
