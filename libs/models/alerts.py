"""
AegisNexus — Alert, Deduplication & Suppression Data Models
Author: Om Kamble
"""

from enum import Enum
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import uuid
import hashlib
from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


class AlertStatus(str, Enum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    SUPPRESSED = "SUPPRESSED"
    ESCALATED_TO_CASE = "ESCALATED_TO_CASE"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: f"ALT_{uuid.uuid4().hex[:10]}")
    domain: str = Field(..., description="BANKING, CYBERSECURITY, ECOMMERCE")
    title: str = Field(..., description="Concise alert description")
    severity: AlertSeverity = Field(default=AlertSeverity.P3_MEDIUM)
    status: AlertStatus = Field(default=AlertStatus.OPEN)
    primary_entity_id: str
    event_id: str
    risk_score: float = Field(..., ge=0.0, le=1.0)
    rule_hits: List[str] = Field(default_factory=list)
    anomaly_signals: Dict[str, Any] = Field(default_factory=dict)
    dedup_fingerprint: str = Field(..., description="SHA-256 hash for sliding window deduplication")
    suppression_count: int = Field(default=0, description="Times suppressed in rolling window")
    tenant_id: str = Field(default="default")
    created_at: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    updated_at: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())

    @staticmethod
    def generate_fingerprint(domain: str, primary_entity_id: str, rule_name: str) -> str:
        """Generates deterministic fingerprint to suppress noisy alert duplicate bursts."""
        raw = f"{domain.upper()}:{primary_entity_id}:{rule_name.upper()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
