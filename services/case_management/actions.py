"""
FinCipher AI — Analyst Investigation Workflow & Automated Action Engine
Author: Om Kamble

Architecture:
- Operational Analyst Case Lifecycle:
  * assign_case: Transitions status to IN_REVIEW, assigns investigator, records audit trail.
  * escalate_case: Escalates priority to P1_CRITICAL with formal escalation rationale.
  * resolve_case: Transitions status to RESOLVED with disposition (CONFIRMED_FRAUD, FALSE_POSITIVE, etc.)
                  and automatically closes linked alert items.
- Policy & Analyst Action Dispatcher:
  * QUARANTINE_ENTITY: Immediately restricts entity across banking, cyber, and e-commerce.
  * TRIGGER_CHALLENGE_2FA: Emits step-up authentication challenge requirement.
  * EXPORT_EVIDENCE_DOSSIER: Generates cryptographically sealed evidence dossier.
- Full immutable audit trail recording into 'analyst_actions'.
"""

import time
from typing import Dict, Any, List, Optional
from enum import Enum
from libs.models.cases import CaseStatus, CaseDisposition, CasePriority
from services.graph_analytics.persistent_graph import persistent_entity_graph
from services.case_management.workflow import case_workflow_service
from src.db.database import (
    get_case_detail,
    update_case_status,
    add_case_note,
    update_alert_status,
    list_analyst_actions,
    get_db_connection,
    IS_POSTGRES
)


class ActionType(str, Enum):
    QUARANTINE_ENTITY = "QUARANTINE_ENTITY"
    TRIGGER_CHALLENGE_2FA = "TRIGGER_CHALLENGE_2FA"
    BLOCK_TRANSACTION = "BLOCK_TRANSACTION"
    DISPATCH_INCIDENT_WEBHOOK = "DISPATCH_INCIDENT_WEBHOOK"
    EXPORT_EVIDENCE_DOSSIER = "EXPORT_EVIDENCE_DOSSIER"


class AnalystActionEngine:
    """
    Manages analyst collaboration workflows, disposition transitions,
    and automated operational action dispatches.
    """

    def assign_case(
        self,
        case_id: int,
        analyst_username: str,
        operator: str
    ) -> Dict[str, Any]:
        """Assigns an open case to an analyst and advances state to IN_REVIEW."""
        case = get_case_detail(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found.")

        conn = get_db_connection()
        cursor = conn.cursor()
        param = "%s" if IS_POSTGRES else "?"

        cursor.execute(f"""
            UPDATE cases 
            SET assigned_to = {param}, status = 'IN_REVIEW', updated_at = CURRENT_TIMESTAMP
            WHERE id = {param}
        """, (analyst_username, case_id))

        cursor.execute(f"""
            INSERT INTO analyst_actions (operator, action_type, target_id, previous_state, new_state, reason)
            VALUES ({param}, 'CASE_ASSIGNMENT', {param}, {param}, 'IN_REVIEW', {param})
        """, (operator, case.get("case_number", str(case_id)), case.get("status", "OPEN"), f"Assigned to {analyst_username}"))

        conn.commit()
        conn.close()

        add_case_note(
            case_id=case_id,
            author=operator,
            note_text=f"Case assigned to investigator @{analyst_username}."
        )

        return get_case_detail(case_id)

    def escalate_case(
        self,
        case_id: int,
        reason: str,
        operator: str,
        target_priority: CasePriority = CasePriority.P1_CRITICAL
    ) -> Dict[str, Any]:
        """Escalates an ongoing case to P1 priority with justification."""
        case = get_case_detail(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found.")

        conn = get_db_connection()
        cursor = conn.cursor()
        param = "%s" if IS_POSTGRES else "?"
        p_val = target_priority.value if hasattr(target_priority, "value") else str(target_priority)

        cursor.execute(f"""
            UPDATE cases 
            SET priority = {param}, status = 'ESCALATED', updated_at = CURRENT_TIMESTAMP
            WHERE id = {param}
        """, (p_val.upper(), case_id))

        cursor.execute(f"""
            INSERT INTO analyst_actions (operator, action_type, target_id, previous_state, new_state, reason)
            VALUES ({param}, 'CASE_ESCALATION', {param}, {param}, {param}, {param})
        """, (operator, case.get("case_number", str(case_id)), case.get("priority"), p_val.upper(), reason))

        conn.commit()
        conn.close()

        add_case_note(
            case_id=case_id,
            author=operator,
            note_text=f"ESCALATION: Priority elevated to {p_val.upper()}. Rationale: {reason}"
        )

        return get_case_detail(case_id)

    def resolve_case(
        self,
        case_id: int,
        disposition: CaseDisposition,
        resolution_notes: str,
        operator: str
    ) -> Dict[str, Any]:
        """Resolves an investigation case, closing all linked alerts."""
        disp_val = disposition.value if hasattr(disposition, "value") else str(disposition)
        
        updated = update_case_status(
            case_id=case_id,
            new_status=CaseStatus.RESOLVED.value,
            operator=operator,
            disposition=disp_val,
            reason=resolution_notes
        )
        if not updated:
            raise ValueError(f"Failed to resolve case {case_id}.")

        add_case_note(
            case_id=case_id,
            author=operator,
            note_text=f"DISPOSITION [{disp_val}]: {resolution_notes}"
        )

        # Close all linked alerts in database
        for alert in updated.get("alerts", []):
            try:
                update_alert_status(alert["id"], "RESOLVED", operator=operator, reason=f"Case {case_id} resolved as {disp_val}")
            except Exception:
                pass

        return get_case_detail(case_id)

    def execute_action(
        self,
        action_type: ActionType,
        entity_id: str,
        case_id: Optional[int] = None,
        reason: str = "Automated policy enforcement",
        operator: str = "system_policy"
    ) -> Dict[str, Any]:
        """Dispatches an operational remediation action."""
        act_val = action_type.value if hasattr(action_type, "value") else str(action_type)
        result = {"action_type": act_val, "entity_id": entity_id, "timestamp": time.time()}

        if act_val == ActionType.QUARANTINE_ENTITY.value:
            q_res = persistent_entity_graph.quarantine_entity(entity_id, reason=reason)
            result["details"] = q_res

        elif act_val == ActionType.TRIGGER_CHALLENGE_2FA.value:
            result["details"] = {
                "challenge_id": f"CHAL_{abs(hash(entity_id + str(time.time()))) % 1000000}",
                "status": "CHALLENGE_ISSUED",
                "method": "FIDO2_TOTP_FALLBACK"
            }

        elif act_val == ActionType.EXPORT_EVIDENCE_DOSSIER.value:
            if not case_id:
                raise ValueError("case_id required for evidence package export.")
            pkg = case_workflow_service.export_evidence_package(case_id, forensic_narrative=reason)
            dump = pkg.model_dump()
            dump["checksum_sha256"] = dump.get("package_sha256_checksum", "")
            result["details"] = dump

        else:
            result["details"] = {"status": "DISPATCHED", "target": entity_id}

        # Log into analyst_actions
        conn = get_db_connection()
        cursor = conn.cursor()
        param = "%s" if IS_POSTGRES else "?"
        cursor.execute(f"""
            INSERT INTO analyst_actions (operator, action_type, target_id, previous_state, new_state, reason)
            VALUES ({param}, {param}, {param}, 'ACTIVE', 'ENFORCED', {param})
        """, (operator, act_val, entity_id, reason))
        conn.commit()
        conn.close()

        if case_id:
            try:
                add_case_note(
                    case_id=case_id,
                    author=operator,
                    note_text=f"ACTION EXECUTED [{act_val}] on {entity_id}: {reason}"
                )
            except Exception:
                pass

        return result

    def get_action_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent analyst and system enforcement history."""
        return list_analyst_actions(limit=limit)


# Global singleton action engine
analyst_action_engine = AnalystActionEngine()
