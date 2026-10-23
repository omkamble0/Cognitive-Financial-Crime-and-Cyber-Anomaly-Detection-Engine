"""
AegisNexus — Case Management & Investigation Workflow Models
Author: Om Kamble
"""

from enum import Enum
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import uuid
import secrets
from pydantic import BaseModel, Field


class CasePriority(str, Enum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


class CaseStatus(str, Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class CaseDisposition(str, Enum):
    PENDING = "PENDING"
    CONFIRMED_FRAUD = "CONFIRMED_FRAUD"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    INSIDER_THREAT = "INSIDER_THREAT"
    POLICY_VIOLATION = "POLICY_VIOLATION"


class CaseNote(BaseModel):
    id: str = Field(default_factory=lambda: f"NOTE_{uuid.uuid4().hex[:8]}")
    author: str
    note_text: str
    timestamp: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())


class Case(BaseModel):
    id: Optional[int] = None
    case_number: str = Field(default_factory=lambda: f"CASE-{datetime.now().year}-{secrets.randbelow(900000) + 100000}")
    domain: str = Field(default="GENERIC", description="BANKING, CYBERSECURITY, ECOMMERCE")
    title: str
    priority: CasePriority = Field(default=CasePriority.P3_MEDIUM)
    status: CaseStatus = Field(default=CaseStatus.OPEN)
    disposition: CaseDisposition = Field(default=CaseDisposition.PENDING)
    primary_entity_id: str
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    assigned_to: str = Field(default="unassigned")
    linked_event_ids: List[str] = Field(default_factory=list)
    linked_alert_ids: List[str] = Field(default_factory=list)
    evidence_summary: Dict[str, Any] = Field(default_factory=dict)
    notes: List[CaseNote] = Field(default_factory=list)
    merkle_proof: Optional[str] = None
    tenant_id: str = Field(default="default")
    created_at: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    updated_at: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())


class EvidencePackage(BaseModel):
    case_number: str
    domain: str
    export_timestamp: str
    case_overview: Dict[str, Any]
    linked_entities: List[Dict[str, Any]]
    events_timeline: List[Dict[str, Any]]
    analyst_audit_log: List[Dict[str, Any]]
    forensic_narrative: str
    cryptographic_merkle_root: str
    package_sha256_checksum: str
