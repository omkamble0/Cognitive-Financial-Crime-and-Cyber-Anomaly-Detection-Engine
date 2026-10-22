"""
AegisFlow Platform — Relational Data Models & Persistence Schemas
Author: Om Kamble

Defines structured data entities for transactions, ML decisions, alerts,
case management, collaborative analyst notes, and immutable audit trails.
Compatible with SQLite and PostgreSQL (Supabase / RDS).
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


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
    CONFIRMED_FRAUD = "CONFIRMED_FRAUD"
    BENIGN = "BENIGN"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    MONEY_MULE_RING = "MONEY_MULE_RING"
    CARDING_BOTNET = "CARDING_BOTNET"
    SUSPICIOUS_UNRESOLVED = "SUSPICIOUS_UNRESOLVED"


# =============================================================================
# PYDANTIC SCHEMAS (API & Serialization)
# =============================================================================

class TransactionRecord(BaseModel):
    transaction_id: str
    user_id: str
    card_identifier: str
    amount: float
    currency: str = "USD"
    normalized_usd: float
    merchant_id: str
    ip_address: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DecisionRecord(BaseModel):
    transaction_id: str
    user_id: str
    risk_score: float
    decision: str
    risk_level: str
    latency_ms: float
    model_version: str = "v2.3-rf-pca"
    triggered_rules: List[str] = Field(default_factory=list)
    explainability: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AlertRecord(BaseModel):
    alert_id: Optional[int] = None
    transaction_id: str
    user_id: str
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.OPEN
    title: str
    summary: str
    risk_score: float
    assigned_to: Optional[str] = None
    case_id: Optional[int] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CaseNoteRecord(BaseModel):
    note_id: Optional[int] = None
    case_id: int
    author: str
    note_text: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CaseRecord(BaseModel):
    case_id: Optional[int] = None
    case_number: str
    title: str
    priority: CasePriority
    status: CaseStatus = CaseStatus.OPEN
    entity_id: str
    risk_score: float
    assigned_to: Optional[str] = None
    disposition: Optional[CaseDisposition] = None
    notes_count: int = 0
    linked_transactions: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AnalystActionRecord(BaseModel):
    action_id: Optional[int] = None
    operator: str
    action_type: str
    target_id: str
    previous_state: Optional[str] = None
    new_state: Optional[str] = None
    reason: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RuleAuditRecord(BaseModel):
    audit_id: Optional[int] = None
    rule_name: str
    action: str
    operator: str
    previous_predicate: Optional[str] = None
    new_predicate: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
