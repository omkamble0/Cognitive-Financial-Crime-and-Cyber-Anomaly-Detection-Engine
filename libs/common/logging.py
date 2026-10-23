"""
FinCipher AI — Structured Audit & Telemetry Logger
Author: Om Kamble
"""

import logging
import json
import time
from typing import Dict, Any


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as structured single-line JSON for SIEM/Splunk ingestion."""
    def format(self, record: logging.LogRecord) -> str:
        log_payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno
        }
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            log_payload.update(record.extra_fields)
        return json.dumps(log_payload)


def get_platform_logger(name: str = "fincipher") -> logging.Logger:
    """Returns a configured structured platform logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(StructuredJsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
