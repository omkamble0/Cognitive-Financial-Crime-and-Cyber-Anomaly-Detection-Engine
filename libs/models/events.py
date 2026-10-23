"""
AegisNexus — Generic Event Ingestion & Normalization Contracts
Author: Om Kamble
"""

from enum import Enum
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field
from libs.models.entities import EntityType


class DomainType(str, Enum):
    BANKING = "BANKING"
    CYBERSECURITY = "CYBERSECURITY"
    ECOMMERCE = "ECOMMERCE"
    GENERIC = "GENERIC"


class EventType(str, Enum):
    # Banking
    PAYMENT = "PAYMENT"
    TRANSFER = "TRANSFER"
    REFUND = "REFUND"
    WITHDRAWAL = "WITHDRAWAL"
    
    # Cybersecurity / IT
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    ACCESS_REQUEST = "ACCESS_REQUEST"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    FILE_ACCESS = "FILE_ACCESS"
    SYSTEM_LOG = "SYSTEM_LOG"
    API_CALL = "API_CALL"
    SECURITY_INCIDENT = "SECURITY_INCIDENT"
    
    # E-Commerce
    ORDER = "ORDER"
    PROMO_APPLIED = "PROMO_APPLIED"
    CART_UPDATE = "CART_UPDATE"
    CHARGEBACK = "CHARGEBACK"
    ACCOUNT_UPDATE = "ACCOUNT_UPDATE"
    
    # General
    GENERIC_ACTIVITY = "GENERIC_ACTIVITY"


class EntityLink(BaseModel):
    id: str
    type: EntityType
    role: str = Field(default="ASSOCIATED", description="Role in event: ACTOR, ORIGIN, DESTINATION, RESOURCE, TARGET")


class GenericEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: f"EVT_{uuid.uuid4().hex[:12]}")
    domain: DomainType = Field(default=DomainType.GENERIC)
    event_type: EventType = Field(default=EventType.GENERIC_ACTIVITY)
    timestamp: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    source: str = Field(default="api_gateway", description="Originating ingestion stream or service")
    primary_entity_id: str = Field(..., description="Main entity under evaluation (user, ip, account)")
    entities: List[EntityLink] = Field(default_factory=list, description="All connected entities in this event")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Domain-specific metrics and attributes")
    context: Dict[str, Any] = Field(default_factory=dict, description="Environmental telemetry: ip, geo, user_agent, tenant_id")
    tenant_id: str = Field(default="default", description="Multi-tenant boundary")


class EventBatch(BaseModel):
    batch_id: str = Field(default_factory=lambda: f"BATCH_{uuid.uuid4().hex[:8]}")
    events: List[GenericEvent]
