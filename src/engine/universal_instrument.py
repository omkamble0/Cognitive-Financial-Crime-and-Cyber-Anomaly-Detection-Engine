"""
AegisFlow — Universal Payment Instrument & Multi-Dataset Abstraction Engine
Author: Om Kamble

Provides universal, network-agnostic classification, tokenization, and schema
adaptation for all payment instruments and financial datasets:
1. Public Card Networks: RuPay, American Express, Visa, Mastercard, JCB, UnionPay, Discover, Diners Club, Elo, Mir.
2. Private & Enterprise Corporate Cards: Corporate Purchasing (Brex, Ramp, Concur, SAP), Commercial Fleet/Fuel Cards (WEX, Comdata).
3. Store & Closed-Loop Cards: Retailer-branded cards (Target, Amazon, Walmart, Starbucks, Gas Station Closed Loops).
4. Virtual & Tokenized Instruments: Apple Pay / Google Pay DPAN tokens, Single-use Neobank cards (Privacy.com, Revolut).
5. Public & Private Dataset Ledger Accounts: PaySim accounts (C.../M...), Bank Core Account IDs, Kaggle anonymized entities.
"""

import re
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class InstrumentCategory(str, Enum):
    PUBLIC_NETWORK = "PUBLIC_NETWORK"
    PRIVATE_CORPORATE = "PRIVATE_CORPORATE"
    STORE_CLOSED_LOOP = "STORE_CLOSED_LOOP"
    VIRTUAL_TOKEN = "VIRTUAL_TOKEN"
    GENERIC_ACCOUNT = "GENERIC_ACCOUNT"
    DATASET_SYNTHETIC = "DATASET_SYNTHETIC"


@dataclass
class InstrumentProfile:
    scheme: str                   # Normalized scheme code (e.g. "RUPAY", "AMEX", "PRIVATE_CORP")
    category: InstrumentCategory  # Category enum
    brand_name: str               # Human readable display name
    masked_identifier: str        # Tokenized safe string (PCI-DSS compliant)
    accent_color: str             # UI / Graph node visualizer hex color
    is_private_instrument: bool   # True if internal corporate / closed-loop / custom dataset
    description: str              # Description of the instrument tier


class UniversalInstrumentClassifier:
    """
    Universal classifier for payment cards, corporate instruments, virtual tokens,
    and private company dataset identifiers.
    """

    # Major public scheme IIN / BIN prefixes
    SCHEME_PATTERNS = [
        # RuPay (India / International: 60, 65, 81, 82, 508, 353)
        ("RUPAY", r"^(60|65|81|82|508|353)\d{0,14}$", "RuPay Global", "#f97316"),
        # American Express (34, 37)
        ("AMEX", r"^3[47]\d{0,13}$", "American Express", "#0284c7"),
        # Visa (4)
        ("VISA", r"^4\d{0,18}$", "Visa Network", "#2563eb"),
        # Mastercard (51-55, 2221-2720)
        ("MASTERCARD", r"^(5[1-5]\d{0,14}|2(2[2-9][1-9]|2[3-9]\d{2}|[3-6]\d{3}|7[0-1]\d{2}|720\d)\d{0,12})$", "Mastercard Global", "#f59e0b"),
        # Discover (6011, 622126-622925, 644-649, 65)
        ("DISCOVER", r"^(6011|65|64[4-9])\d{0,15}$", "Discover Network", "#f97316"),
        # JCB (3528-3589)
        ("JCB", r"^35(2[89]|[3-8]\d)\d{0,14}$", "JCB International", "#10b981"),
        # UnionPay (62, 81)
        ("UNIONPAY", r"^(62|81)\d{0,17}$", "UnionPay Global", "#ef4444"),
        # Diners Club (300-305, 36, 38)
        ("DINERS", r"^(30[0-5]|36|38)\d{0,13}$", "Diners Club", "#06b6d4"),
        # Elo (Brazil: 4011, 4312, 4389, 4514, 4576, 5041, 5066, 6277, 6362, 6504)
        ("ELO", r"^(4011|4312|4389|4514|4576|5041|5066|6277|6362|6504)\d{0,15}$", "Elo Domestic/Global", "#fbbf24"),
    ]

    # Enterprise & Closed-Loop Token Identifiers
    CORPORATE_KEYWORDS = ("corp", "brex", "ramp", "fleet", "wex", "comdata", "concur", "ariba", "pcard", "company", "ent")
    STORE_KEYWORDS = ("store", "target", "amazon", "walmart", "gift", "closed_loop", "merchant_card", "loyalty", "fuel")
    VIRTUAL_KEYWORDS = ("virtual", "vtoken", "dpan", "applepay", "googlepay", "privacy", "revolut", "disposable")
    ACCOUNT_KEYWORDS = ("acc_", "account", "paysim", "c_", "m_", "ledger", "iban", "wire")

    def classify(
        self,
        identifier: Optional[str] = None,
        bin_code: Optional[str] = None,
        explicit_scheme: Optional[str] = None
    ) -> InstrumentProfile:
        """
        Dynamically classifies any card, corporate token, or dataset account identifier.
        """
        raw_id = str(identifier or "").strip()
        raw_bin = str(bin_code or "").strip()
        scheme_override = str(explicit_scheme or "").strip().upper()

        # 1. Handle Explicit Scheme Overrides
        if scheme_override in ("RUPAY", "AMEX", "VISA", "MASTERCARD", "DISCOVER", "JCB", "UNIONPAY", "DINERS", "ELO"):
            for code, _, brand, color in self.SCHEME_PATTERNS:
                if code == scheme_override:
                    return InstrumentProfile(
                        scheme=code,
                        category=InstrumentCategory.PUBLIC_NETWORK,
                        brand_name=brand,
                        masked_identifier=self._mask_identifier(code, raw_id),
                        accent_color=color,
                        is_private_instrument=False,
                        description=f"{brand} multi-currency open network payment instrument."
                    )

        if scheme_override in ("PRIVATE_CORP", "CORPORATE", "FLEET"):
            return InstrumentProfile(
                scheme="PRIVATE_CORP",
                category=InstrumentCategory.PRIVATE_CORPORATE,
                brand_name="Enterprise Corporate / Fleet Card",
                masked_identifier=self._mask_identifier("CORP", raw_id),
                accent_color="#6366f1",  # Indigo
                is_private_instrument=True,
                description="Private enterprise corporate purchasing or commercial fleet card."
            )

        if scheme_override in ("STORE_CLOSED_LOOP", "CLOSED_LOOP", "STORE"):
            return InstrumentProfile(
                scheme="STORE_CLOSED_LOOP",
                category=InstrumentCategory.STORE_CLOSED_LOOP,
                brand_name="Retail Store / Closed-Loop Card",
                masked_identifier=self._mask_identifier("STORE", raw_id),
                accent_color="#10b981",  # Emerald
                is_private_instrument=True,
                description="Merchant proprietary closed-loop store purchasing card."
            )

        if scheme_override in ("VIRTUAL_TOKEN", "VIRTUAL", "DPAN"):
            return InstrumentProfile(
                scheme="VIRTUAL_TOKEN",
                category=InstrumentCategory.VIRTUAL_TOKEN,
                brand_name="Virtual Token / Neobank Card",
                masked_identifier=self._mask_identifier("VTOK", raw_id),
                accent_color="#8b5cf6",  # Purple
                is_private_instrument=True,
                description="Device tokenized DPAN or single-use ephemeral virtual card."
            )

        if scheme_override in ("GENERIC_ACCOUNT", "PAYSIM", "LEDGER"):
            return InstrumentProfile(
                scheme="GENERIC_ACCOUNT",
                category=InstrumentCategory.GENERIC_ACCOUNT,
                brand_name="Universal Core Ledger Account",
                masked_identifier=self._mask_identifier("ACC", raw_id),
                accent_color="#ec4899",  # Pink
                is_private_instrument=True,
                description="Direct account-to-account or core banking ledger identifier."
            )

        # 2. Check Semantic Keyword Indicators in Identifier string
        lower_id = raw_id.lower()
        if any(k in lower_id for k in self.CORPORATE_KEYWORDS):
            return InstrumentProfile(
                scheme="PRIVATE_CORP",
                category=InstrumentCategory.PRIVATE_CORPORATE,
                brand_name="Enterprise Corporate Card",
                masked_identifier=self._mask_identifier("CORP", raw_id),
                accent_color="#6366f1",
                is_private_instrument=True,
                description="Enterprise corporate purchasing or employee expense card."
            )

        if any(k in lower_id for k in self.STORE_KEYWORDS):
            return InstrumentProfile(
                scheme="STORE_CLOSED_LOOP",
                category=InstrumentCategory.STORE_CLOSED_LOOP,
                brand_name="Store Closed-Loop Instrument",
                masked_identifier=self._mask_identifier("STORE", raw_id),
                accent_color="#10b981",
                is_private_instrument=True,
                description="Proprietary merchant closed-loop or private store loyalty instrument."
            )

        if any(k in lower_id for k in self.VIRTUAL_KEYWORDS):
            return InstrumentProfile(
                scheme="VIRTUAL_TOKEN",
                category=InstrumentCategory.VIRTUAL_TOKEN,
                brand_name="Virtual Token / Digital Wallet",
                masked_identifier=self._mask_identifier("VTOK", raw_id),
                accent_color="#8b5cf6",
                is_private_instrument=True,
                description="Single-use virtual card token or mobile wallet DPAN."
            )

        if any(k in lower_id for k in self.ACCOUNT_KEYWORDS) or lower_id.startswith(("c", "m")) and any(c.isdigit() for c in lower_id):
            return InstrumentProfile(
                scheme="GENERIC_ACCOUNT",
                category=InstrumentCategory.GENERIC_ACCOUNT,
                brand_name="Banking / Ledger Account",
                masked_identifier=self._mask_identifier("ACC", raw_id),
                accent_color="#ec4899",
                is_private_instrument=True,
                description="Direct core banking account or mobile wallet ledger entity."
            )

        # 3. Numeric Card PAN / BIN Pattern Matching (Public Card Networks)
        digits_only = re.sub(r"\D", "", raw_bin or raw_id)
        if digits_only:
            for scheme_code, pattern, brand, color in self.SCHEME_PATTERNS:
                if re.match(pattern, digits_only):
                    return InstrumentProfile(
                        scheme=scheme_code,
                        category=InstrumentCategory.PUBLIC_NETWORK,
                        brand_name=brand,
                        masked_identifier=self._mask_identifier(scheme_code, raw_id or digits_only),
                        accent_color=color,
                        is_private_instrument=False,
                        description=f"{brand} multi-currency global payment instrument."
                    )

        # 4. Universal Fallback (Universal Payment Instrument)
        suffix = raw_id[-4:] if len(raw_id) >= 4 else "0001"
        return InstrumentProfile(
            scheme="UNIVERSAL_CARD",
            category=InstrumentCategory.PUBLIC_NETWORK,
            brand_name="Universal Payment Instrument",
            masked_identifier=f"UNIV-••••-{suffix}",
            accent_color="#14b8a6",  # Teal
            is_private_instrument=False,
            description="Universal multi-currency payment instrument (public or private dataset entity)."
        )

    def _mask_identifier(self, prefix: str, raw_id: str) -> str:
        """Safe masking format complying with PCI-DSS."""
        clean = re.sub(r"\s+", "", raw_id)
        if len(clean) >= 4:
            return f"{prefix}-••••-{clean[-4:]}"
        return f"{prefix}-••••-{clean or '0001'}"


# Global singleton instance
universal_instrument_classifier = UniversalInstrumentClassifier()
