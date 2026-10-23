"""
AegisNexus — Pluggable Domain Module Base Interface
Author: Om Kamble
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from libs.models.events import GenericEvent
from libs.models.alerts import AlertSeverity


class DomainEvaluationResult(BaseModel):
    domain: str
    risk_score: float = Field(..., ge=0.0, le=1.0)
    decision: str = Field(..., description="ALLOW, CHALLENGE, BLOCK, INVESTIGATE")
    severity: AlertSeverity = Field(default=AlertSeverity.P3_MEDIUM)
    rule_hits: List[str] = Field(default_factory=list)
    anomaly_signals: Dict[str, Any] = Field(default_factory=dict)
    forensic_narrative: str = Field(default="")
    suggested_case_title: Optional[str] = None


class BaseDomainModule(ABC):
    """Abstract base class that all pluggable risk domains must implement."""

    @property
    @abstractmethod
    def domain_name(self) -> str:
        """Returns the canonical domain identifier (e.g. BANKING, CYBERSECURITY, ECOMMERCE)."""
        pass

    @abstractmethod
    def evaluate_event(self, event: GenericEvent) -> DomainEvaluationResult:
        """Evaluates domain-specific heuristics, features, and risk scoring."""
        pass

    @abstractmethod
    def generate_narrative(self, event: GenericEvent, result: DomainEvaluationResult) -> str:
        """Generates plain-English regulatory or forensic explanation for analysts."""
        pass
