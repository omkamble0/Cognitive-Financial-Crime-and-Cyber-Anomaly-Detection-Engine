"""
FinCipher AI — Role-Based Access Control (RBAC) & Permission Matrix
Author: Om Kamble
"""

from enum import Enum
from typing import Set, Dict, List


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    SENIOR_ANALYST = "SENIOR_ANALYST"
    TRIAGE_OPERATOR = "TRIAGE_OPERATOR"
    COMPLIANCE_AUDITOR = "COMPLIANCE_AUDITOR"
    READONLY = "READONLY"


class Permission(str, Enum):
    READ_EVENTS = "READ_EVENTS"
    INGEST_EVENTS = "INGEST_EVENTS"
    TRIAGE_ALERTS = "TRIAGE_ALERTS"
    UPDATE_CASES = "UPDATE_CASES"
    OVERRIDE_POLICIES = "OVERRIDE_POLICIES"
    EXPORT_EVIDENCE = "EXPORT_EVIDENCE"
    MANAGE_USERS = "MANAGE_USERS"
    MANAGE_POLICIES = "MANAGE_POLICIES"


ROLE_PERMISSIONS: Dict[UserRole, Set[Permission]] = {
    UserRole.ADMIN: set(Permission),
    UserRole.SENIOR_ANALYST: {
        Permission.READ_EVENTS, Permission.INGEST_EVENTS, Permission.TRIAGE_ALERTS,
        Permission.UPDATE_CASES, Permission.EXPORT_EVIDENCE
    },
    UserRole.TRIAGE_OPERATOR: {
        Permission.READ_EVENTS, Permission.INGEST_EVENTS, Permission.TRIAGE_ALERTS
    },
    UserRole.COMPLIANCE_AUDITOR: {
        Permission.READ_EVENTS, Permission.EXPORT_EVIDENCE
    },
    UserRole.READONLY: {
        Permission.READ_EVENTS
    }
}


def user_has_permission(role: UserRole, permission: Permission) -> bool:
    """Evaluates whether a given user role possesses the requested permission."""
    allowed = ROLE_PERMISSIONS.get(role, set())
    return permission in allowed
