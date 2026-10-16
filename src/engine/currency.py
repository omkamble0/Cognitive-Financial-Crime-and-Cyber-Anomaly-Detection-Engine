"""
AegisFlow AI — Multi-Currency Normalizer & Micro-Authorization Registry
Author: Om Kamble

Provides enterprise multi-currency support for cross-border fraud detection:
- Normalizes diverse fiat currencies to base USD for statistical ML and XAI models.
- Enforces localized micro-authorization thresholds to catch regional carding/probing attacks
  (e.g., Stripe Japan ¥1-¥10 authorisations, US $0.01-$3.00 probing, Indian ₹1-₹10 penny drops).
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass(frozen=True)
class CurrencyProfile:
    code: str
    symbol: str
    rate_to_usd: float       # Multiply foreign amount by rate_to_usd to get USD equivalent
    micro_auth_threshold: float  # Currency-specific micro-auth probing cutoff
    decimals: int
    name: str


class CurrencyNormalizer:
    # 6 Core Global Currencies + AUD
    PROFILES: Dict[str, CurrencyProfile] = {
        "USD": CurrencyProfile(
            code="USD",
            symbol="$",
            rate_to_usd=1.0000,
            micro_auth_threshold=3.00,
            decimals=2,
            name="US Dollar"
        ),
        "JPY": CurrencyProfile(
            code="JPY",
            symbol="¥",
            rate_to_usd=0.0067,  # ~150 JPY = 1 USD
            micro_auth_threshold=500.0,  # Catches ¥1, ¥10, and ¥100-¥500 test charges
            decimals=0,
            name="Japanese Yen"
        ),
        "EUR": CurrencyProfile(
            code="EUR",
            symbol="€",
            rate_to_usd=1.0800,
            micro_auth_threshold=2.50,
            decimals=2,
            name="Euro"
        ),
        "GBP": CurrencyProfile(
            code="GBP",
            symbol="£",
            rate_to_usd=1.2800,
            micro_auth_threshold=2.00,
            decimals=2,
            name="British Pound"
        ),
        "INR": CurrencyProfile(
            code="INR",
            symbol="₹",
            rate_to_usd=0.0120,  # ~83.5 INR = 1 USD
            micro_auth_threshold=250.0,  # Catches ₹1, ₹10 penny drop verifications
            decimals=2,
            name="Indian Rupee"
        ),
        "CAD": CurrencyProfile(
            code="CAD",
            symbol="CA$",
            rate_to_usd=0.7300,
            micro_auth_threshold=3.50,
            decimals=2,
            name="Canadian Dollar"
        ),
        "AUD": CurrencyProfile(
            code="AUD",
            symbol="A$",
            rate_to_usd=0.6500,
            micro_auth_threshold=3.50,
            decimals=2,
            name="Australian Dollar"
        ),
    }

    def __init__(self, default_currency: str = "USD"):
        self.default_currency = default_currency.upper()

    def get_profile(self, currency: Optional[str] = None) -> CurrencyProfile:
        code = (currency or self.default_currency).strip().upper()
        return self.PROFILES.get(code, self.PROFILES["USD"])

    def normalize_to_usd(self, amount: float, currency: Optional[str] = None) -> float:
        """Converts any supported currency amount to equivalent USD for model scoring."""
        profile = self.get_profile(currency)
        return round(float(amount) * profile.rate_to_usd, 4)

    def is_micro_auth(self, amount: float, currency: Optional[str] = None) -> bool:
        """
        Determines if an authorization is an automated card-probing micro-transaction
        using currency-specific thresholds.
        """
        profile = self.get_profile(currency)
        return 0.0 < float(amount) <= profile.micro_auth_threshold

    def format_amount(self, amount: float, currency: Optional[str] = None) -> str:
        """Formats the transaction amount with its official currency symbol and decimals."""
        profile = self.get_profile(currency)
        if profile.decimals == 0:
            return f"{profile.symbol}{int(round(amount)):,}"
        return f"{profile.symbol}{amount:,.2f}"

    def normalize(self, amount: float, currency: Optional[str] = None) -> Dict[str, Any]:
        """Convenience helper returning USD equivalent, formatted string, and micro-auth detection."""
        usd_amt = self.normalize_to_usd(amount, currency)
        micro = self.is_micro_auth(amount, currency)
        formatted = self.format_amount(amount, currency)
        return {
            "amount_usd": usd_amt,
            "original_amount": amount,
            "currency": (currency or self.default_currency).upper(),
            "formatted": formatted,
            "is_micro_auth": micro
        }

    def get_supported_currencies(self) -> List[str]:
        return list(self.PROFILES.keys())

    def get_registry_metadata(self) -> Dict[str, Any]:
        return {
            code: {
                "name": p.name,
                "symbol": p.symbol,
                "rate_to_usd": p.rate_to_usd,
                "micro_auth_threshold": p.micro_auth_threshold,
                "decimals": p.decimals
            }
            for code, p in self.PROFILES.items()
        }


# Global singleton instance for high-throughput zero-allocation access
currency_normalizer = CurrencyNormalizer()
