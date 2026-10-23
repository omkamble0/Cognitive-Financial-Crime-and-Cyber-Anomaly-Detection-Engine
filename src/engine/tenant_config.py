"""
FinCipher AI Platform — Per-Client / Multi-Tenant Configuration Engine (Phase 7)
Author: Om Kamble

Provides customized operational thresholds and risk tolerances per tenant/client:
- Customized fraud block & 2FA challenge thresholds
- Tailored velocity limits (1-minute, 1-hour bursts)
- High-ticket risk triggers tailored to client risk appetite
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("fincipher.tenants")

CONFIG_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../data/tenant_configs.json"))


class TenantConfigModel(BaseModel):
    tenant_id: str
    organization_name: str
    fraud_block_threshold: float = Field(default=0.85, ge=0.50, le=0.99)
    fraud_challenge_threshold: float = Field(default=0.65, ge=0.10, le=0.80)
    max_velocity_1m: int = Field(default=5, ge=1, le=50)
    max_velocity_1h: int = Field(default=20, ge=5, le=200)
    high_ticket_amount_usd: float = Field(default=1000.0, ge=100.0)
    tier: str = "STANDARD"

    # Multi-Domain Customized Thresholds
    banking: Dict[str, Any] = Field(default_factory=lambda: {
        "block_threshold": 0.85,
        "challenge_threshold": 0.65,
        "high_ticket_amount_usd": 1000.0,
        "aml_structuring_threshold": 9000.0
    })
    cybersecurity: Dict[str, Any] = Field(default_factory=lambda: {
        "block_threshold": 0.80,
        "challenge_threshold": 0.60,
        "failed_login_burst_limit": 5,
        "impossible_travel_kmh": 1100.0
    })
    ecommerce: Dict[str, Any] = Field(default_factory=lambda: {
        "block_threshold": 0.85,
        "challenge_threshold": 0.65,
        "max_promo_uses_per_device": 2,
        "refund_velocity_threshold": 3
    })


class TenantConfigManager:
    """Manages tenant-specific multi-domain behavioral risk thresholds and governance."""

    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or CONFIG_FILE
        self._configs: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self):
        # Default baseline tenants with domain profiles
        defaults = {
            "default": {
                "tenant_id": "default",
                "organization_name": "Default Commercial Gateway",
                "fraud_block_threshold": 0.85,
                "fraud_challenge_threshold": 0.65,
                "max_velocity_1m": 5,
                "max_velocity_1h": 20,
                "high_ticket_amount_usd": 1000.0,
                "tier": "STANDARD",
                "banking": {"block_threshold": 0.85, "challenge_threshold": 0.65, "aml_structuring_threshold": 9000.0},
                "cybersecurity": {"block_threshold": 0.80, "challenge_threshold": 0.60, "failed_login_burst_limit": 5},
                "ecommerce": {"block_threshold": 0.85, "challenge_threshold": 0.65, "max_promo_uses_per_device": 2}
            },
            "tenant_alpha_bank": {
                "tenant_id": "tenant_alpha_bank",
                "organization_name": "Alpha Investment Bank",
                "fraud_block_threshold": 0.70,  # Strict risk posture
                "fraud_challenge_threshold": 0.50,
                "max_velocity_1m": 3,
                "max_velocity_1h": 12,
                "high_ticket_amount_usd": 2500.0,
                "tier": "ENTERPRISE",
                "banking": {"block_threshold": 0.70, "challenge_threshold": 0.50, "aml_structuring_threshold": 8000.0},
                "cybersecurity": {"block_threshold": 0.75, "challenge_threshold": 0.50, "failed_login_burst_limit": 3},
                "ecommerce": {"block_threshold": 0.75, "challenge_threshold": 0.55, "max_promo_uses_per_device": 1}
            },
            "tenant_beta_pay": {
                "tenant_id": "tenant_beta_pay",
                "organization_name": "Beta Micro-Payments Network",
                "fraud_block_threshold": 0.90,  # High tolerance for gaming/micro-tx
                "fraud_challenge_threshold": 0.75,
                "max_velocity_1m": 15,
                "max_velocity_1h": 60,
                "high_ticket_amount_usd": 500.0,
                "tier": "ENTERPRISE",
                "banking": {"block_threshold": 0.90, "challenge_threshold": 0.75, "aml_structuring_threshold": 9500.0},
                "cybersecurity": {"block_threshold": 0.85, "challenge_threshold": 0.70, "failed_login_burst_limit": 8},
                "ecommerce": {"block_threshold": 0.90, "challenge_threshold": 0.75, "max_promo_uses_per_device": 5}
            }
        }
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    disk_configs = json.load(f)
                    for k, v in defaults.items():
                        if k not in disk_configs:
                            disk_configs[k] = v
                        else:
                            for dom in ("banking", "cybersecurity", "ecommerce"):
                                if dom not in disk_configs[k]:
                                    disk_configs[k][dom] = v[dom]
                    self._configs = disk_configs
                    self._save()
            except Exception:
                self._configs = defaults
                self._save()
        else:
            self._configs = defaults
            self._save()

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self._configs, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not persist tenant configs: {e}")

    def get_config(self, tenant_id: str) -> Dict[str, Any]:
        """Returns risk configuration for a specific tenant, falling back to default."""
        return self._configs.get(tenant_id, self._configs.get("default", {}))

    def set_config(self, tenant_id: str, config: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        """Sets or updates risk thresholds for a tenant."""
        base = self.get_config(tenant_id).copy()
        updates = (config or {}).copy()
        updates.update(kwargs)
        if "block_threshold" in updates and "fraud_block_threshold" not in updates:
            updates["fraud_block_threshold"] = updates["block_threshold"]
        if "challenge_threshold" in updates and "fraud_challenge_threshold" not in updates:
            updates["fraud_challenge_threshold"] = updates["challenge_threshold"]
        base.update(updates)
        base["tenant_id"] = tenant_id
        self._configs[tenant_id] = base
        self._save()
        return base

    def get_domain_thresholds(self, tenant_id: str, domain: str) -> Dict[str, Any]:
        """Returns domain-tailored block and challenge thresholds for a tenant."""
        cfg = self.get_config(tenant_id)
        dom_key = domain.lower()
        if dom_key in cfg and isinstance(cfg[dom_key], dict):
            dom_cfg = cfg[dom_key]
            return {
                "block_threshold": dom_cfg.get("block_threshold", cfg.get("fraud_block_threshold", 0.85)),
                "challenge_threshold": dom_cfg.get("challenge_threshold", cfg.get("fraud_challenge_threshold", 0.65)),
                **dom_cfg
            }
        return {
            "block_threshold": cfg.get("fraud_block_threshold", 0.85),
            "challenge_threshold": cfg.get("fraud_challenge_threshold", 0.65)
        }

    def list_configs(self) -> List[Dict[str, Any]]:
        """Returns all configured tenant policies."""
        return list(self._configs.values())


# Global singleton manager
tenant_config_manager = TenantConfigManager()
