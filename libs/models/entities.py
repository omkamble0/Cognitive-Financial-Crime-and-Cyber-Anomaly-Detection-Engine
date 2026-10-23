"""
AegisNexus — Generic Entity & Relationship Data Models
Author: Om Kamble
"""

from enum import Enum
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class EntityType(str, Enum):
    USER = "USER"
    ACCOUNT = "ACCOUNT"
    DEVICE = "DEVICE"
    IP_ADDRESS = "IP_ADDRESS"
    MERCHANT = "MERCHANT"
    VENDOR = "VENDOR"
    APPLICATION = "APPLICATION"
    ASSET = "ASSET"
    FILE = "FILE"
    SESSION = "SESSION"
    TRANSACTION = "TRANSACTION"
    ORDER = "ORDER"
    CASE = "CASE"
    WATCHLIST_ENTITY = "WATCHLIST_ENTITY"
    THREAT_INDICATOR = "THREAT_INDICATOR"


class RelationshipType(str, Enum):
    USES_DEVICE = "USES_DEVICE"
    LOGS_IN_FROM = "LOGS_IN_FROM"
    TRANSFERS_FUNDS_TO = "TRANSFERS_FUNDS_TO"
    PLACES_ORDER = "PLACES_ORDER"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    ACCESSED_ASSET = "ACCESSED_ASSET"
    EXECUTES_FILE = "EXECUTES_FILE"
    AUTHENTICATED_BY = "AUTHENTICATED_BY"
    BELONGS_TO_CLUSTER = "BELONGS_TO_CLUSTER"


class Entity(BaseModel):
    id: str = Field(..., description="Unique entity identifier (e.g. usr_102, ip_198.51.100.1)")
    type: EntityType = Field(..., description="Generic entity classification")
    domain: str = Field(default="GENERIC", description="Primary domain: BANKING, CYBERSECURITY, ECOMMERCE")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary domain-specific metadata")
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Current composite risk score")
    is_quarantined: bool = Field(default=False, description="Whether entity is restricted/frozen")
    first_seen: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    last_seen: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    event_count: int = Field(default=1, ge=0)


class Relationship(BaseModel):
    source_entity_id: str
    source_entity_type: EntityType
    target_entity_id: str
    target_entity_type: EntityType
    relationship_type: RelationshipType
    weight: float = Field(default=1.0, description="Relationship strength, amount, or frequency")
    attributes: Dict[str, Any] = Field(default_factory=dict)
    first_observed: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    last_observed: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
