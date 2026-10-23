"""
FinCipher AI — Case Management & Investigation Workflow Service
Author: Om Kamble
"""

import time
import json
import hashlib
from typing import Dict, Any, List, Optional
from libs.models.cases import Case, CasePriority, CaseStatus, CaseDisposition, CaseNote, EvidencePackage
from src.db.database import create_case, get_case_detail, list_cases, update_case_status, add_case_note
from services.case_management.narratives import narrative_engine


class CaseWorkflowService:
    """
    Orchestrates the case lifecycle, automated case escalation, analyst collaboration,
    disposition changes, and cryptographic forensic package generation.
    """

    ALLOWED_TRANSITIONS = {
        CaseStatus.OPEN: {CaseStatus.IN_REVIEW, CaseStatus.ESCALATED, CaseStatus.RESOLVED, CaseStatus.CLOSED},
        CaseStatus.IN_REVIEW: {CaseStatus.ESCALATED, CaseStatus.RESOLVED, CaseStatus.CLOSED},
        CaseStatus.ESCALATED: {CaseStatus.IN_REVIEW, CaseStatus.RESOLVED, CaseStatus.CLOSED},
        CaseStatus.RESOLVED: {CaseStatus.IN_REVIEW, CaseStatus.CLOSED},
        CaseStatus.CLOSED: set()
    }

    def create_case_from_alert(
        self,
        domain: str,
        title: str,
        primary_entity_id: str,
        risk_score: float,
        priority: CasePriority = CasePriority.P2_HIGH,
        linked_event_ids: Optional[List[str]] = None,
        tenant_id: str = "default"
    ) -> Dict[str, Any]:
        """Creates a structured investigation case in the persistent database."""
        return create_case(
            title=f"[{domain.upper()}] {title}",
            priority=priority.value if hasattr(priority, "value") else str(priority),
            entity_id=primary_entity_id,
            risk_score=risk_score,
            linked_transactions=linked_event_ids or [],
            tenant_id=tenant_id
        )

    def transition_case_status(
        self,
        case_id: int,
        new_status: CaseStatus,
        operator: str,
        disposition: CaseDisposition = CaseDisposition.PENDING,
        reason: str = ""
    ) -> Dict[str, Any]:
        """Validates state machine transitions and logs the analyst audit trail."""
        current = get_case_detail(case_id)
        if not current:
            raise ValueError(f"Case with ID {case_id} not found.")

        curr_status = CaseStatus(current.get("status", "OPEN"))
        allowed = self.ALLOWED_TRANSITIONS.get(curr_status, set())

        if new_status not in allowed:
            raise ValueError(f"Invalid transition from {curr_status.value} to {new_status.value}.")

        updated = update_case_status(
            case_id=case_id,
            new_status=new_status.value,
            operator=operator,
            disposition=disposition.value,
            reason=reason or f"Case transitioned to {new_status.value}"
        )
        return updated

    def add_forensic_note(self, case_id: int, author: str, note_text: str) -> Dict[str, Any]:
        """Appends an immutable forensic note to the case dossier."""
        return add_case_note(case_id=case_id, author=author, note_text=note_text)

    def export_evidence_package(self, case_id: int, forensic_narrative: str = "") -> EvidencePackage:
        """Assembles a sealed cryptographic case evidence dossier for compliance and law enforcement."""
        case_data = get_case_detail(case_id)
        if not case_data:
            raise ValueError(f"Case with ID {case_id} not found.")

        case_num = case_data.get("case_number", "CASE-UNKNOWN")
        raw_evidence = json.dumps(case_data, sort_keys=True)
        checksum = hashlib.sha256(raw_evidence.encode("utf-8")).hexdigest()

        return EvidencePackage(
            case_number=case_num,
            domain=case_data.get("domain", "GENERIC"),
            export_timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            case_overview={
                "id": case_data.get("id"),
                "case_number": case_num,
                "title": case_data.get("title"),
                "priority": case_data.get("priority"),
                "status": case_data.get("status"),
                "risk_score": case_data.get("risk_score"),
                "entity_id": case_data.get("entity_id")
            },
            linked_entities=[{"entity_id": case_data.get("entity_id")}],
            events_timeline=case_data.get("linked_transactions", []),
            analyst_audit_log=case_data.get("notes", []),
            forensic_narrative=forensic_narrative or narrative_engine.generate_narrative_for_domain(
                case_data.get("domain", "BANKING"),
                case_data
            ),
            cryptographic_merkle_root=case_data.get("merkle_proof", "SHA256_GENESIS_ROOT"),
            package_sha256_checksum=checksum
        )


# Singleton
case_workflow_service = CaseWorkflowService()
