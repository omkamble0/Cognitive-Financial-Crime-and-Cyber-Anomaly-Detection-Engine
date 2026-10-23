"""
FinCipher AI — Zero-Trust Data Masking & Tokenization
Author: Om Kamble
"""

import re
import hashlib
import hmac


class DataMaskingEngine:
    """Masks high-risk PII, credit card PANs, and emails for zero-trust compliance."""

    @staticmethod
    def mask_card_pan(pan: str) -> str:
        """Retains first 6 (BIN) and last 4 digits (PCI-DSS compliant)."""
        clean = re.sub(r"\D", "", pan)
        if len(clean) < 10:
            return "******"
        return f"{clean[:6]}{'*' * (len(clean) - 10)}{clean[-4:]}"

    @staticmethod
    def mask_email(email: str) -> str:
        """Masks username part of email: j***e@domain.com."""
        if not email or "@" not in email:
            return "***"
        user, domain = email.split("@", 1)
        if len(user) <= 2:
            masked_user = user[0] + "*"
        else:
            masked_user = user[0] + ("*" * (len(user) - 2)) + user[-1]
        return f"{masked_user}@{domain}"

    @staticmethod
    def tokenize_identifier(identifier: str, salt: str = "fincipher_entropy_salt") -> str:
        """Produces a deterministic, irreversible HMAC-SHA256 pseudonym."""
        return hmac.new(salt.encode("utf-8"), identifier.encode("utf-8"), hashlib.sha256).hexdigest()
