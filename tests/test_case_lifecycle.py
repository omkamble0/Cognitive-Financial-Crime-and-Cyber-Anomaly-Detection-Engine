"""
Unit & Integration Tests for Case Lifecycle State Machine & SLA Engine
Author: Om Kamble
"""

import uuid
import pytest
from datetime import datetime, timezone, timedelta
from src.engine.case_lifecycle import (
    CaseLifecycleManager,
    CaseStatus,
    CasePriority,
    InvalidStateTransitionError
)
from src.db.database import init_database, get_case_detail, list_action_dispatches


@pytest.fixture(autouse=True)
def setup_db():
    init_database()


def test_case_creation_and_sla():
    entity = f"usr_{uuid.uuid4().hex[:8]}"
    case = CaseLifecycleManager.create_case(
        title="Suspicious Rapid Outflow",
        priority="P1_CRITICAL",
        entity_id=entity,
        risk_score=0.92,
        assigned_to="lead_investigator_1",
        initial_note="Automated ingestion trigger from P1 alert."
    )

    assert case["id"] is not None
    assert case["status"] == CaseStatus.ASSIGNED
    assert case["assigned_to"] == "lead_investigator_1"
    assert case["risk_score"] == 0.92

    sla = case["sla"]
    assert sla["target_minutes"] == 15
    assert sla["sla_status"] in ("WITHIN_SLA", "NEAR_BREACH")
    assert "deadline_iso" in sla


def test_valid_lifecycle_transitions():
    entity = f"usr_{uuid.uuid4().hex[:8]}"
    case = CaseLifecycleManager.create_case(
        title="Unusual Wire Transfer",
        priority="P2_HIGH",
        entity_id=entity,
        risk_score=0.78
    )
    case_id = case["id"]
    assert case["status"] in (CaseStatus.NEW, CaseStatus.OPEN)

    # 1. Assign
    c_assigned = CaseLifecycleManager.assign_case(case_id, "analyst_alice", operator="supervisor")
    assert c_assigned["status"] == CaseStatus.ASSIGNED
    assert c_assigned["assigned_to"] == "analyst_alice"

    # 2. Advance to IN_REVIEW
    c_review = CaseLifecycleManager.transition_case(
        case_id=case_id,
        target_status=CaseStatus.IN_REVIEW,
        operator="analyst_alice",
        reason="Beginning forensic graph and device check."
    )
    assert c_review["status"] == CaseStatus.IN_REVIEW

    # 3. Escalate to Lead
    c_escalated = CaseLifecycleManager.transition_case(
        case_id=case_id,
        target_status=CaseStatus.ESCALATED,
        operator="analyst_alice",
        reason="Identified multi-entity mule syndicate ring."
    )
    assert c_escalated["status"] == CaseStatus.ESCALATED

    # 4. Resolve as Fraud
    c_resolved = CaseLifecycleManager.transition_case(
        case_id=case_id,
        target_status=CaseStatus.RESOLVED_FRAUD,
        operator="lead_bob",
        reason="Confirmed synthetic identity mule fraud."
    )
    assert c_resolved["status"] == CaseStatus.RESOLVED_FRAUD

    # Verify automated action dispatch occurred
    dispatches = list_action_dispatches(limit=10)
    matched = [d for d in dispatches if d["target"] == entity]
    assert len(matched) >= 1
    assert matched[0]["action_type"] == "CONFIRMED_FRAUD_BLOCK"


def test_invalid_lifecycle_transition_raises_error():
    entity = f"usr_{uuid.uuid4().hex[:8]}"
    case = CaseLifecycleManager.create_case(
        title="Potential Promo Abuse",
        priority="P3_MEDIUM",
        entity_id=entity,
        risk_score=0.45
    )
    case_id = case["id"]

    # Directly jumping from NEW to RESOLVED_FRAUD without review is illegal
    with pytest.raises(InvalidStateTransitionError):
        CaseLifecycleManager.transition_case(
            case_id=case_id,
            target_status=CaseStatus.RESOLVED_FRAUD,
            operator="rogue_agent",
            reason="Illegal bypass"
        )


def test_sla_breach_calculation():
    # Artificially created 30 minutes ago with 15 min SLA -> BREACHED
    past_time = datetime.now(timezone.utc) - timedelta(minutes=30)
    fake_case = {
        "priority": "P1_CRITICAL",
        "status": "IN_REVIEW",
        "created_at": past_time.isoformat()
    }
    sla = CaseLifecycleManager.calculate_sla(fake_case)
    assert sla["sla_status"] == "BREACHED"
    assert sla["remaining_minutes"] < 0
