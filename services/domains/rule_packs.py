"""
FinCipher AI — Parameterized Domain Rule Packs & Dynamic Calibration Registry
Author: Om Kamble

Provides versioned, parameter-driven rule packs for Banking, Cybersecurity, and E-Commerce.
Enables dynamic threshold calibration, rule weight tuning, and multi-tenant custom rule sets
without requiring code redeployment.
"""

import time
import copy
import threading
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class RuleDefinition(BaseModel):
    rule_id: str
    name: str
    description: str
    category: str  # AML, SANCTIONS, FRAUD, AUTH, NETWORK, EXPLOIT, ABUSE
    weight: float = Field(default=0.5, ge=0.0, le=1.0)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class DomainRulePack(BaseModel):
    pack_id: str
    domain: str  # BANKING, CYBERSECURITY, ECOMMERCE
    version: str = "1.0.0"
    description: str = ""
    rules: Dict[str, RuleDefinition] = Field(default_factory=dict)
    decision_thresholds: Dict[str, float] = Field(
        default_factory=lambda: {
            "allow_below": 0.40,
            "challenge_below": 0.75,
            "block_above": 0.85
        }
    )
    risk_weight_multipliers: Dict[str, float] = Field(default_factory=dict)
    last_calibrated_at: float = Field(default_factory=time.time)
    author: str = "FinCipher Risk Architecture"


class RulePackRegistry:
    """
    Thread-safe registry managing versioned, parameterized rule packs per domain and tenant.
    """

    def __init__(self):
        self._lock = threading.RLock()
        # Key: (domain, version) -> DomainRulePack
        self._packs: Dict[str, DomainRulePack] = {}
        # Key: domain -> active_version
        self._active_versions: Dict[str, str] = {}
        # Key: (tenant_id, domain) -> version
        self._tenant_pack_bindings: Dict[str, str] = {}
        
        self._seed_default_packs()

    def _seed_default_packs(self):
        """Initializes default production rule packs for Banking, Cyber, and E-Commerce."""
        # 1. Banking Production Pack (v1.2.0)
        banking_pack = DomainRulePack(
            pack_id="PACK_BANKING_PROD",
            domain="BANKING",
            version="1.2.0",
            description="Enterprise AML, Sanctions, Structuring, and Wire Fraud Rule Pack",
            decision_thresholds={"allow_below": 0.35, "challenge_below": 0.70, "block_above": 0.85},
            rules={
                "AML_SANCTIONED_JURISDICTION": RuleDefinition(
                    rule_id="AML_SANCTIONED_JURISDICTION",
                    name="OFAC / FATF Sanctioned Jurisdiction Route",
                    description="Transaction routed through or to high-risk sanctioned nation",
                    category="SANCTIONS",
                    weight=0.98,
                    parameters={"sanctioned_countries": ["IR", "KP", "SY", "CU", "RU"]}
                ),
                "AML_CTR_STRUCTURING": RuleDefinition(
                    rule_id="AML_CTR_STRUCTURING",
                    name="Currency Transaction Report Threshold Avoidance",
                    description="Transfers structured just below the $10,000 regulatory reporting line",
                    category="AML",
                    weight=0.85,
                    parameters={"lower_bound": 8500.0, "ctr_ceiling": 10000.0}
                ),
                "HIGH_VELOCITY_RAPID_BURST": RuleDefinition(
                    rule_id="HIGH_VELOCITY_RAPID_BURST",
                    name="High Velocity Transfer Burst",
                    description="Excessive outbound transactions within a sliding 1-hour window",
                    category="FRAUD",
                    weight=0.75,
                    parameters={"burst_limit_count": 5, "window_seconds": 3600}
                ),
                "HIGH_VALUE_WIRE_TRANSFER": RuleDefinition(
                    rule_id="HIGH_VALUE_WIRE_TRANSFER",
                    name="Outsized Value Wire Transfer",
                    description="Single transaction exceeding institutional normal variance threshold",
                    category="FRAUD",
                    weight=0.70,
                    parameters={"wire_threshold": 50000.0}
                ),
                "MULE_RAPID_IN_OUT": RuleDefinition(
                    rule_id="MULE_RAPID_IN_OUT",
                    name="Mule Account Pass-Through Velocity",
                    description="Rapid fund exhaustion within 15 minutes of large inbound credit",
                    category="AML",
                    weight=0.90,
                    parameters={"in_out_window_seconds": 900, "exhaustion_pct": 0.90}
                )
            }
        )
        self.register_pack(banking_pack, set_active=True)

        # 2. Cybersecurity SOC Pack (v1.1.0)
        cyber_pack = DomainRulePack(
            pack_id="PACK_CYBER_SOC_PROD",
            domain="CYBERSECURITY",
            version="1.1.0",
            description="SOC Brute Force, Tor Anonymizer, Impossible Travel, and C2 Beaconing",
            decision_thresholds={"allow_below": 0.30, "challenge_below": 0.65, "block_above": 0.80},
            rules={
                "SOC_BRUTE_FORCE": RuleDefinition(
                    rule_id="SOC_BRUTE_FORCE",
                    name="Credential Stuffing / Authentication Flood",
                    description="Repeated failed authentications exceeding threshold within burst window",
                    category="AUTH",
                    weight=0.88,
                    parameters={"failed_attempt_threshold": 5, "window_seconds": 300}
                ),
                "SOC_TOR_EXIT_ANONYMIZER": RuleDefinition(
                    rule_id="SOC_TOR_EXIT_ANONYMIZER",
                    name="Tor Anonymizing Proxy Ingress",
                    description="Inbound session originates from verified Tor exit node",
                    category="NETWORK",
                    weight=0.82,
                    parameters={"block_unauthenticated": True}
                ),
                "SOC_IMPOSSIBLE_TRAVEL": RuleDefinition(
                    rule_id="SOC_IMPOSSIBLE_TRAVEL",
                    name="Geographic Impossible Travel Velocity",
                    description="Logins from geographically distant points requiring unrealistic physical velocity",
                    category="AUTH",
                    weight=0.92,
                    parameters={"max_velocity_kmh": 900.0}
                ),
                "SOC_PRIVILEGE_ESCALATION": RuleDefinition(
                    rule_id="SOC_PRIVILEGE_ESCALATION",
                    name="Unauthorized SUDO / Domain Admin Escalation",
                    description="Anomalous escalation attempt on critical domain controller or bastion",
                    category="EXPLOIT",
                    weight=0.95,
                    parameters={"target_roles": ["domain_admin", "root", "security_officer"]}
                )
            }
        )
        self.register_pack(cyber_pack, set_active=True)

        # 3. E-Commerce / Retail Pack (v1.0.0)
        ecom_pack = DomainRulePack(
            pack_id="PACK_ECOMM_PROD",
            domain="ECOMMERCE",
            version="1.0.0",
            description="Card Testing, Promo Code Botting, Device Switching, and ATO Detection",
            decision_thresholds={"allow_below": 0.40, "challenge_below": 0.70, "block_above": 0.80},
            rules={
                "ECOMM_CARD_TESTING_VELOCITY": RuleDefinition(
                    rule_id="ECOMM_CARD_TESTING_VELOCITY",
                    name="Card Testing Micro-Charge Velocity",
                    description="Multiple distinct credit cards tested within short sliding window",
                    category="FRAUD",
                    weight=0.92,
                    parameters={"distinct_cards_threshold": 3, "window_seconds": 600}
                ),
                "ECOMM_PROMO_FARMING": RuleDefinition(
                    rule_id="ECOMM_PROMO_FARMING",
                    name="Promo Code Syndicate Farming",
                    description="High volume promotional coupon consumption from shared hardware hash",
                    category="ABUSE",
                    weight=0.88,
                    parameters={"redemption_threshold": 3, "window_seconds": 3600}
                ),
                "ECOMM_DEVICE_SWITCH_BURST": RuleDefinition(
                    rule_id="ECOMM_DEVICE_SWITCH_BURST",
                    name="Rapid Multi-Device Fingerprint Switching",
                    description="Single account cycling through disparate browser/OS fingerprints rapidly",
                    category="FRAUD",
                    weight=0.78,
                    parameters={"device_switch_limit": 4, "window_seconds": 1800}
                ),
                "ECOMM_DISPOSABLE_EMAIL": RuleDefinition(
                    rule_id="ECOMM_DISPOSABLE_EMAIL",
                    name="Burner / Disposable Email Domain",
                    description="Checkout attempted using anonymous disposable email service",
                    category="ABUSE",
                    weight=0.65,
                    parameters={}
                )
            }
        )
        self.register_pack(ecom_pack, set_active=True)

    def register_pack(self, pack: DomainRulePack, set_active: bool = False):
        """Registers a new or versioned rule pack in the registry."""
        with self._lock:
            key = f"{pack.domain.upper()}:{pack.version}"
            self._packs[key] = pack
            if set_active or pack.domain.upper() not in self._active_versions:
                self._active_versions[pack.domain.upper()] = pack.version

    def get_pack(self, domain: str, version: Optional[str] = None) -> Optional[DomainRulePack]:
        """Retrieves a rule pack by domain and optional version (defaults to active version)."""
        domain_norm = domain.upper()
        with self._lock:
            ver = version or self._active_versions.get(domain_norm)
            if not ver:
                return None
            key = f"{domain_norm}:{ver}"
            return self._packs.get(key)

    def get_pack_for_tenant(self, domain: str, tenant_id: str = "default") -> DomainRulePack:
        """Retrieves rule pack configured for tenant, falling back to domain active pack."""
        domain_norm = domain.upper()
        with self._lock:
            binding_key = f"{tenant_id}:{domain_norm}"
            ver = self._tenant_pack_bindings.get(binding_key) or self._active_versions.get(domain_norm)
            pack = self.get_pack(domain_norm, ver)
            if not pack:
                # Fallback to any registered version for domain
                for k, v in self._packs.items():
                    if k.startswith(f"{domain_norm}:"):
                        return v
                raise ValueError(f"No rule pack found for domain: {domain_norm}")
            return pack

    def bind_tenant_pack(self, tenant_id: str, domain: str, version: str):
        """Binds a specific tenant to a rule pack version."""
        with self._lock:
            key = f"{domain.upper()}:{version}"
            if key not in self._packs:
                raise ValueError(f"Rule pack {key} does not exist.")
            self._tenant_pack_bindings[f"{tenant_id}:{domain.upper()}"] = version

    def calibrate_pack(
        self,
        domain: str,
        version: str,
        rule_weights: Optional[Dict[str, float]] = None,
        parameters: Optional[Dict[str, Dict[str, Any]]] = None,
        decision_thresholds: Optional[Dict[str, float]] = None,
        new_version: Optional[str] = None,
        author: str = "risk_lead"
    ) -> DomainRulePack:
        """
        Dynamically calibrates rule weights, parameters, or decision thresholds.
        Optionally produces a new version bump (e.g. 1.2.1) without disrupting existing production flows.
        """
        domain_norm = domain.upper()
        with self._lock:
            base_pack = self.get_pack(domain_norm, version)
            if not base_pack:
                raise ValueError(f"Base pack {domain_norm}:{version} not found.")

            # Create calibrated copy
            calibrated = copy.deepcopy(base_pack)
            if new_version:
                calibrated.version = new_version
                calibrated.pack_id = f"PACK_{domain_norm}_{new_version.replace('.', '_')}"

            calibrated.last_calibrated_at = time.time()
            calibrated.author = author

            if decision_thresholds:
                calibrated.decision_thresholds.update(decision_thresholds)

            if rule_weights:
                for rid, weight in rule_weights.items():
                    if rid in calibrated.rules:
                        calibrated.rules[rid].weight = max(0.0, min(1.0, float(weight)))

            if parameters:
                for rid, params in parameters.items():
                    if rid in calibrated.rules:
                        calibrated.rules[rid].parameters.update(params)

            # Register calibrated pack
            self.register_pack(calibrated, set_active=(new_version is not None))
            return calibrated

    def list_all_packs(self) -> List[Dict[str, Any]]:
        """Returns metadata for all registered rule packs."""
        with self._lock:
            result = []
            for (key, pack) in self._packs.items():
                is_active = (self._active_versions.get(pack.domain.upper()) == pack.version)
                result.append({
                    "domain": pack.domain,
                    "version": pack.version,
                    "pack_id": pack.pack_id,
                    "description": pack.description,
                    "is_active_default": is_active,
                    "rule_count": len(pack.rules),
                    "decision_thresholds": pack.decision_thresholds,
                    "last_calibrated_at": pack.last_calibrated_at,
                    "author": pack.author
                })
            return result


# Global singleton registry
rule_pack_registry = RulePackRegistry()
