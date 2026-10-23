"""
FinCipher AI — Universal Utilities & Common Helpers
Author: Om Kamble
"""

import time
import uuid
import hashlib
import math
from typing import Any, Dict


def current_iso_timestamp() -> str:
    """Returns current UTC timestamp in ISO-8601 format."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def generate_uuid(prefix: str = "") -> str:
    """Generates a unique UUID4 with an optional domain prefix."""
    uid = str(uuid.uuid4()).replace("-", "")[:16]
    return f"{prefix}_{uid}" if prefix else uid


def sha256_hash(payload: Any) -> str:
    """Calculates canonical SHA-256 digest of a string or dictionary."""
    if isinstance(payload, dict):
        import json
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    elif isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raw = str(payload).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of an identifier or string to detect randomness/dga."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])
