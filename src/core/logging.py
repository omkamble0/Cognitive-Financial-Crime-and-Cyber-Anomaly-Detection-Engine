"""
AegisFlow Platform — Centralized Structured Logging & PII Masking Engine
Author: Om Kamble

Provides JSON-formatted structured logging with correlation IDs (X-Request-ID)
and real-time PII redaction for payment cards, emails, and sensitive identifiers.
"""

import re
import json
import logging
import contextvars
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Context variable for thread-safe distributed request correlation
correlation_id_ctx: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("correlation_id", default=None)

# Regular expressions for sensitive financial data
CARD_PAN_REGEX = re.compile(r"\b(?:\d{4}[ -]?){3}(?=\d{4}\b)")
EMAIL_REGEX = re.compile(r"([a-zA-Z0-9_.+-])[a-zA-Z0-9_.+-]*@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")


def mask_card_number(pan: str) -> str:
    """Masks payment card number, preserving only the first 4 and last 4 digits."""
    clean = re.sub(r"[ -]", "", str(pan))
    if len(clean) >= 12:
        return f"{clean[:4]}{'*' * (len(clean) - 8)}{clean[-4:]}"
    return "****"


def mask_email(email: str) -> str:
    """Masks email address, showing only the first character and domain."""
    match = EMAIL_REGEX.match(str(email))
    if match:
        first_char, domain = match.groups()
        return f"{first_char}***@{domain}"
    return "***@***"


def mask_pii_dict(data: Any) -> Any:
    """Recursively walks dictionaries and lists to mask cardholder and personal data."""
    if isinstance(data, dict):
        masked = {}
        for k, v in data.items():
            k_lower = k.lower()
            if any(term in k_lower for term in ["card", "pan", "card_number", "card_identifier"]):
                masked[k] = mask_card_number(v) if v else v
            elif any(term in k_lower for term in ["password", "secret", "token", "salt", "key"]):
                masked[k] = "[REDACTED_SECRET]"
            elif "email" in k_lower:
                masked[k] = mask_email(v) if v else v
            else:
                masked[k] = mask_pii_dict(v)
        return masked
    elif isinstance(data, list):
        return [mask_pii_dict(item) for item in data]
    return data


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as production-grade JSON strings with trace correlation."""
    def format(self, record: logging.LogRecord) -> str:
        log_payload: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": correlation_id_ctx.get() or "none"
        }

        # Include extra attributes attached to logger calls
        if hasattr(record, "transaction_id"):
            log_payload["transaction_id"] = record.transaction_id
        if hasattr(record, "user_id"):
            log_payload["user_id"] = record.user_id
        if hasattr(record, "risk_score"):
            log_payload["risk_score"] = record.risk_score
        if hasattr(record, "decision"):
            log_payload["decision"] = record.decision
        if hasattr(record, "latency_ms"):
            log_payload["latency_ms"] = record.latency_ms

        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(mask_pii_dict(log_payload))


def configure_structured_logging(level: str = "INFO"):
    """Configures root logger with structured JSON handler."""
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Avoid duplicate handlers if reconfigured
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler()
    handler.setFormatter(StructuredJsonFormatter())
    root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Returns a named logger configured for structured JSON output."""
    return logging.getLogger(name)
