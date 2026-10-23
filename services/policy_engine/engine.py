"""
FinCipher AI — Declarative Policy Engine & Automated Enforcement
Author: Om Kamble
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from libs.models.events import GenericEvent


class PolicyAction(BaseModel):
    action_type: str = Field(..., description="ALLOW, CHALLENGE_2FA, BLOCK, QUARANTINE_ENTITY, CREATE_P1_CASE")
    reason: str
    target_entity_id: Optional[str] = None


class PolicyRule(BaseModel):
    policy_id: str
    name: str
    domain: str = "ALL"  # BANKING, CYBERSECURITY, ECOMMERCE, ALL
    min_risk_score: float = 0.0
    required_rules: List[str] = Field(default_factory=list)
    action: str = "BLOCK"
    quarantine_entity: bool = False
    auto_escalate_case: bool = False
    is_active: bool = True


class DeclarativePolicyEngine:
    """
    Evaluates declarative risk policies across domains and dictates automated enforcement.
    """

    def __init__(self):
        self._policies: Dict[str, PolicyRule] = {}
        self._seed_default_policies()

    def _seed_default_policies(self):
        """Seeds standard enterprise compliance & security policies."""
        self.register_policy(PolicyRule(
            policy_id="POL_SANCTIONS_HARD_BLOCK",
            name="Sanctions & Blacklisted Jurisdiction Hard Block",
            domain="BANKING",
            min_risk_score=0.90,
            required_rules=["AML_SANCTIONED_JURISDICTION"],
            action="BLOCK",
            quarantine_entity=True,
            auto_escalate_case=True
        ))
        self.register_policy(PolicyRule(
            policy_id="POL_SOC_BRUTE_FORCE_LOCK",
            name="Credential Stuffing Immediate Host Lock",
            domain="CYBERSECURITY",
            min_risk_score=0.85,
            required_rules=["SOC_BRUTE_FORCE"],
            action="BLOCK",
            quarantine_entity=True,
            auto_escalate_case=True
        ))
        self.register_policy(PolicyRule(
            policy_id="POL_PROMO_FARMING_SUPPRESSION",
            name="Coupon Farming Syndicate Suppression",
            domain="ECOMMERCE",
            min_risk_score=0.80,
            required_rules=["ECOMM_PROMO_FARMING"],
            action="BLOCK",
            quarantine_entity=False,
            auto_escalate_case=True
        ))

    def register_policy(self, policy: PolicyRule):
        self._policies[policy.policy_id] = policy

    def evaluate_policies(
        self,
        domain: str,
        risk_score: float,
        triggered_rules: List[str],
        primary_entity_id: str
    ) -> List[PolicyAction]:
        """Evaluates active policies against event risk evaluation results."""
        actions: List[PolicyAction] = []

        for p in self._policies.values():
            if not p.is_active:
                continue
            if p.domain != "ALL" and p.domain != domain.upper():
                continue
            if risk_score < p.min_risk_score:
                continue

            # Check rule matching
            matches = False
            if not p.required_rules:
                matches = True
            else:
                for req in p.required_rules:
                    if any(req in hit for hit in triggered_rules):
                        matches = True
                        break

            if matches:
                actions.append(PolicyAction(
                    action_type=p.action,
                    reason=f"Triggered by policy '{p.name}' ({p.policy_id})",
                    target_entity_id=primary_entity_id
                ))
                if p.quarantine_entity:
                    actions.append(PolicyAction(
                        action_type="QUARANTINE_ENTITY",
                        reason=f"Entity quarantined by policy '{p.name}'",
                        target_entity_id=primary_entity_id
                    ))
                if p.auto_escalate_case:
                    actions.append(PolicyAction(
                        action_type="CREATE_P1_CASE",
                        reason=f"Mandatory investigation required by policy '{p.name}'",
                        target_entity_id=primary_entity_id
                    ))

        return actions


# Singleton
declarative_policy_engine = DeclarativePolicyEngine()
