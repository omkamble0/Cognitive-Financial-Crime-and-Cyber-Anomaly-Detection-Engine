"""
AegisFlow Platform — Enterprise Authentication & Role-Based Access Control (RBAC)
Author: Om Kamble

Implements standard JWT token lifecycle, PBKDF2 password hashing,
and granular RBAC dependencies for Analyst, Fraud Manager, Auditor, and Admin roles.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, Any, List, Optional, Set
import jwt
from fastapi import HTTPException, Security, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from src.core.config import settings

# Security bearer scheme
security_bearer = HTTPBearer(auto_error=False)


class UserRole(str, Enum):
    ADMIN = "admin"
    FRAUD_MANAGER = "fraud_manager"
    ANALYST = "analyst"
    AUDITOR = "auditor"


# Role Hierarchy & Operational Permissions
ROLE_PERMISSIONS: Dict[UserRole, Set[str]] = {
    UserRole.ADMIN: {
        "transactions:read", "transactions:write",
        "cases:read", "cases:write", "cases:override",
        "rules:read", "rules:write",
        "models:read", "models:promote",
        "audit:read", "users:manage"
    },
    UserRole.FRAUD_MANAGER: {
        "transactions:read", "transactions:write",
        "cases:read", "cases:write", "cases:override",
        "rules:read", "rules:write",
        "models:read", "models:promote",
        "audit:read"
    },
    UserRole.ANALYST: {
        "transactions:read",
        "cases:read", "cases:write",
        "rules:read",
        "models:read",
        "audit:read"
    },
    UserRole.AUDITOR: {
        "transactions:read",
        "cases:read",
        "rules:read",
        "models:read",
        "audit:read"
    }
}


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    """Hashes password with PBKDF2-HMAC-SHA256 (600,000 iterations)."""
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=600_000
    )
    return key.hex(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verifies a plain password against the stored PBKDF2 hash, with legacy SHA-256 fallback."""
    # 1. Check PBKDF2-HMAC-SHA256 (600,000 iterations)
    new_hash, _ = hash_password(password, salt)
    if secrets.compare_digest(new_hash, stored_hash):
        return True
    # 2. Check legacy SHA-256 hash
    legacy_hash = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()
    if secrets.compare_digest(legacy_hash, stored_hash):
        return True
    return False


def create_access_token(
    user_id: int,
    username: str,
    role: str,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Issues a cryptographically signed JWT access token."""
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "type": "access",
        "exp": expire,
        "iat": datetime.now(timezone.utc)
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(
    user_id: int,
    username: str,
    role: str,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Issues a signed refresh token with extended validity."""
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "type": "refresh",
        "exp": expire,
        "iat": datetime.now(timezone.utc)
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_jwt_token(token: str) -> Dict[str, Any]:
    """Decodes and validates JWT token signature and expiration."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired. Please log in again."
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token."
        )


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)
) -> Dict[str, Any]:
    """
    FastAPI dependency extracting and verifying user credentials from Authorization Bearer header.
    Falls back gracefully to session lookup or returns unauthenticated exception.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Bearer token."
        )

    token = credentials.credentials
    # First attempt JWT decoding
    try:
        payload = decode_jwt_token(token)
        return {
            "id": int(payload["sub"]),
            "username": payload["username"],
            "role": payload.get("role", UserRole.ANALYST.value)
        }
    except HTTPException:
        # Check if it's an existing legacy database session token
        from src.db.database import get_user_by_token
        user = get_user_by_token(token)
        if user:
            return user
        raise


def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)
) -> Optional[Dict[str, Any]]:
    """
    Safely resolves current user if Bearer token is provided.
    Returns None if unauthenticated instead of raising 401.
    """
    if not credentials or not credentials.credentials:
        return None
    try:
        return get_current_user(credentials)
    except Exception:
        return None


def require_roles(*allowed_roles: str):
    """
    RBAC dependency factory that validates whether the authenticated user possesses
    one of the required roles.
    Example: Depends(require_roles("admin", "fraud_manager"))
    """
    def _role_checker(current_user: Dict[str, Any] = Depends(get_current_user)):
        user_role_raw = current_user.get("role", "").lower().replace(" ", "_")

        # Map role aliases (e.g., 'Lead Risk Architect' -> 'admin')
        role_alias_map = {
            "lead_risk_architect": "admin",
            "risk_analyst": "analyst",
            "compliance_officer": "auditor",
            "fraud_ops_lead": "fraud_manager"
        }
        normalized_role = role_alias_map.get(user_role_raw, user_role_raw)

        allowed_normalized = [r.lower().replace(" ", "_") for r in allowed_roles]

        # Admin superuser always bypasses role check
        if normalized_role == UserRole.ADMIN.value or "admin" in allowed_normalized:
            if normalized_role == UserRole.ADMIN.value:
                return current_user

        if normalized_role not in allowed_normalized:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Operation requires one of roles {allowed_roles}. Current role: '{current_user.get('role')}'."
            )
        return current_user

    return _role_checker
