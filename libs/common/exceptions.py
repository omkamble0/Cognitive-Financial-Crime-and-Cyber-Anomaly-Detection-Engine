"""
FinCipher AI — Unified Platform Exceptions
Author: Om Kamble
"""


class FinCipherException(Exception):
    """Base exception for all FinCipher AI platform errors."""
    def __init__(self, message: str, code: str = "INTERNAL_ERROR"):
        super().__init__(message)
        self.message = message
        self.code = code


class EntityNotFoundException(FinCipherException):
    def __init__(self, entity_id: str):
        super().__init__(f"Entity '{entity_id}' not found in unified entity store.", "ENTITY_NOT_FOUND")
        self.entity_id = entity_id


class PolicyViolationException(FinCipherException):
    def __init__(self, policy_id: str, reason: str):
        super().__init__(f"Action blocked by policy '{policy_id}': {reason}", "POLICY_VIOLATION")
        self.policy_id = policy_id


class InvalidEventSchemaException(FinCipherException):
    def __init__(self, detail: str):
        super().__init__(f"Incoming event failed canonical validation: {detail}", "INVALID_EVENT_SCHEMA")
