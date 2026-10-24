"""
FinCipher AI — End-to-End Analyst Case Lifecycle State Machine & SLA Engine
Author: Om Kamble

Formal finite state machine managing operational lifecycle for financial crime
and cybersecurity cases:
NEW -> ASSIGNED -> IN_REVIEW -> ESCALATED -> RESOLVED_FRAUD | RESOLVED_LEGIT | CLOSED_FALSE_POSITIVE
"""

import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from src.db.database import (
    create_case as db_create_case,
    get_case_detail,
    update_case_status,
    add_case_note,
    record_action_dispatch,
    get_db_connection,
    IS_POSTGRES
)


class CaseStatus:
    NEW = "NEW"
    OPEN = "OPEN"             # Legacy compatibility alias for NEW
    ASSIGNED = "ASSIGNED"
    IN_REVIEW = "IN_REVIEW"
    ESCALATED = "ESCALATED"
    RESOLVED_FRAUD = "RESOLVED_FRAUD"
    RESOLVED_LEGIT = "RESOLVED_LEGIT"
    CLOSED_FALSE_POSITIVE = "CLOSED_FALSE_POSITIVE"
    REOPENED = "REOPENED"


class CasePriority:
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


# SLA Deadlines in minutes
SLA_TARGET_MINUTES = {
    CasePriority.P1_CRITICAL: 15,
    "CRITICAL": 15,
    CasePriority.P2_HIGH: 60,
    "HIGH": 60,
    CasePriority.P3_MEDIUM: 240,
    "MEDIUM": 240,
    CasePriority.P4_LOW: 1440,
    "LOW": 1440
}


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal case lifecycle transition is attempted."""
    pass


class CaseLifecycleManager:
    """
    Manages deterministic lifecycle transitions, SLA tracking,
    analyst assignment, notes audit trail, and automated action triggering.
    """

    # Deterministic State Transition Matrix
    ALLOWED_TRANSITIONS: Dict[str, List[str]] = {
        CaseStatus.NEW: [CaseStatus.ASSIGNED, CaseStatus.IN_REVIEW, CaseStatus.CLOSED_FALSE_POSITIVE],
        CaseStatus.OPEN: [CaseStatus.ASSIGNED, CaseStatus.IN_REVIEW, CaseStatus.CLOSED_FALSE_POSITIVE],  # alias
        CaseStatus.ASSIGNED: [CaseStatus.IN_REVIEW, CaseStatus.ESCALATED, CaseStatus.CLOSED_FALSE_POSITIVE],
        CaseStatus.IN_REVIEW: [CaseStatus.ESCALATED, CaseStatus.RESOLVED_FRAUD, CaseStatus.RESOLVED_LEGIT, CaseStatus.CLOSED_FALSE_POSITIVE],
        CaseStatus.ESCALATED: [CaseStatus.IN_REVIEW, CaseStatus.RESOLVED_FRAUD, CaseStatus.RESOLVED_LEGIT, CaseStatus.CLOSED_FALSE_POSITIVE],
        CaseStatus.RESOLVED_FRAUD: [CaseStatus.REOPENED],
        CaseStatus.RESOLVED_LEGIT: [CaseStatus.REOPENED],
        CaseStatus.CLOSED_FALSE_POSITIVE: [CaseStatus.REOPENED],
        CaseStatus.REOPENED: [CaseStatus.ASSIGNED, CaseStatus.IN_REVIEW]
    }

    @classmethod
    def validate_transition(cls, current_status: str, target_status: str) -> bool:
        """Verifies if transition is legally allowed under policy."""
        curr = current_status.upper()
        target = target_status.upper()
        allowed = cls.ALLOWED_TRANSITIONS.get(curr, [])
        return target in allowed

    @classmethod
    def create_case(
        cls,
        title: str,
        priority: str,
        entity_id: str,
        risk_score: float,
        assigned_to: Optional[str] = None,
        linked_transactions: Optional[List[str]] = None,
        tenant_id: str = "default",
        initial_note: Optional[str] = None
    ) -> Dict[str, Any]:
        """Creates a case and initializes lifecycle SLA and state tracking."""
        prio = priority.upper()
        if not prio.startswith("P") and prio in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            prio = f"P{1 if prio == 'CRITICAL' else (2 if prio == 'HIGH' else (3 if prio == 'MEDIUM' else 4))}_{prio}"

        case_detail = db_create_case(
            title=title,
            priority=prio,
            entity_id=entity_id,
            risk_score=risk_score,
            assigned_to=assigned_to,
            linked_transactions=linked_transactions,
            tenant_id=tenant_id
        )

        case_id = case_detail["id"]

        if initial_note:
            add_case_note(case_id, author="SYSTEM", note_text=initial_note)

        case_detail["sla"] = cls.calculate_sla(case_detail)
        return case_detail


    @classmethod
    def assign_case(
        cls,
        case_id: int,
        analyst_username: str,
        operator: str = "SYSTEM"
    ) -> Dict[str, Any]:
        """Assigns an active analyst to a case and updates state."""
        conn = get_db_connection()
        cursor = conn.cursor()
        param = "%s" if IS_POSTGRES else "?"
        cursor.execute(f"SELECT status, assigned_to FROM cases WHERE id = {param}", (case_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            raise ValueError(f"Case #{case_id} not found.")

        current_status = row["status"]
        cursor.execute(f"""
            UPDATE cases
            SET assigned_to = {param}, status = CASE WHEN status IN ('NEW', 'OPEN') THEN 'ASSIGNED' ELSE status END, updated_at = CURRENT_TIMESTAMP
            WHERE id = {param}
        """, (analyst_username, case_id))
        conn.commit()
        conn.close()

        add_case_note(
            case_id=case_id,
            author=operator,
            note_text=f"Reassigned case to @{analyst_username}"
        )
        detail = get_case_detail(case_id)
        if detail:
            detail["sla"] = cls.calculate_sla(detail)
        return detail

    @classmethod
    def transition_case(
        cls,
        case_id: int,
        target_status: str,
        operator: str,
        reason: str,
        disposition: Optional[str] = None
    ) -> Dict[str, Any]:
        """Transitions case state through validation and audit logging."""
        detail = get_case_detail(case_id)
        if not detail:
            raise ValueError(f"Case #{case_id} not found.")

        current_status = detail.get("status", CaseStatus.NEW).upper()
        target = target_status.upper()

        if not cls.validate_transition(current_status, target):
            raise InvalidStateTransitionError(
                f"Illegal transition from '{current_status}' to '{target}'. "
                f"Allowed destinations: {cls.ALLOWED_TRANSITIONS.get(current_status, [])}"
            )

        updated = update_case_status(
            case_id=case_id,
            new_status=target,
            operator=operator,
            disposition=disposition or target,
            reason=reason
        )

        add_case_note(
            case_id=case_id,
            author=operator,
            note_text=f"State transitioned to {target}. Reason: {reason}"
        )

        if target == CaseStatus.RESOLVED_FRAUD:
            entity_id = detail.get("entity_id", "unknown")
            case_num = str(detail.get("case_number", "CASE-000"))
            clean_event_id = case_num if case_num.startswith("CASE") else f"CASE_{case_num}"
            record_action_dispatch(
                event_id=clean_event_id,
                action_type="CONFIRMED_FRAUD_BLOCK",
                target=entity_id,
                status="DISPATCHED",
                payload={"case_id": case_id, "resolution": target, "operator": operator},
                response={"action": "QUARANTINE_APPLIED", "timestamp": time.time()}
            )

        if updated:
            updated["sla"] = cls.calculate_sla(updated)
        return updated

    @classmethod
    def calculate_sla(cls, case_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates SLA deadline, elapsed time, and breach status."""
        priority = str(case_dict.get("priority", "P3_MEDIUM")).upper()
        target_mins = SLA_TARGET_MINUTES.get(priority, 240)

        created_str = case_dict.get("created_at")
        created_dt = None
        if isinstance(created_str, datetime):
            created_dt = created_str
        elif isinstance(created_str, str):
            try:
                created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            except Exception:
                created_dt = datetime.now(timezone.utc)
        else:
            created_dt = datetime.now(timezone.utc)

        if created_dt.tzinfo is None:
            created_dt = created_dt.replace(tzinfo=timezone.utc)

        deadline_dt = created_dt + timedelta(minutes=target_mins)
        now_dt = datetime.now(timezone.utc)
        elapsed_mins = max(0, int((now_dt - created_dt).total_seconds() / 60))
        remaining_mins = int((deadline_dt - now_dt).total_seconds() / 60)

        status = case_dict.get("status", "NEW").upper()
        is_closed = status in (CaseStatus.RESOLVED_FRAUD, CaseStatus.RESOLVED_LEGIT, CaseStatus.CLOSED_FALSE_POSITIVE)

        if is_closed:
            sla_status = "FULFILLED"
        elif remaining_mins < 0:
            sla_status = "BREACHED"
        elif remaining_mins <= (target_mins * 0.25):
            sla_status = "NEAR_BREACH"
        else:
            sla_status = "WITHIN_SLA"

        return {
            "target_minutes": target_mins,
            "elapsed_minutes": elapsed_mins,
            "remaining_minutes": remaining_mins,
            "sla_status": sla_status,
            "deadline_iso": deadline_dt.isoformat()
        }


case_lifecycle_manager = CaseLifecycleManager()
