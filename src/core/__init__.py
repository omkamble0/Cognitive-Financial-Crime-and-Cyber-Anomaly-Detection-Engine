"""
AegisFlow Platform — Core Configuration, Security & Observability Package
"""

from src.core.config import settings, Settings
from src.core.security import (
    UserRole,
    ROLE_PERMISSIONS,
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_jwt_token,
    get_current_user,
    require_roles
)
from src.core.logging import (
    get_logger,
    configure_structured_logging,
    correlation_id_ctx,
    mask_card_number,
    mask_email,
    mask_pii_dict
)

__all__ = [
    "settings",
    "Settings",
    "UserRole",
    "ROLE_PERMISSIONS",
    "hash_password",
    "verify_password",
    "create_access_token",
    "create_refresh_token",
    "decode_jwt_token",
    "get_current_user",
    "require_roles",
    "get_logger",
    "configure_structured_logging",
    "correlation_id_ctx",
    "mask_card_number",
    "mask_email",
    "mask_pii_dict"
]
