"""
AegisFlow Dynamic Rule & Decision Engine
Author: Om Kamble

Combines statistical ML probability with deterministic compliance, velocity rules,
and hot-reloadable custom risk policies.
Supports real-time rule toggling, dynamic threshold adjustments, and contextual bandit RL.
"""

import time
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass, asdict
from enum import Enum

from src.engine.rl_policy import rl_policy_agent, ActionDecision, BanditDecisionResult


@dataclass
class RuleDefinition:
    rule_id: str
    name: str
    description: str
    category: str                  # "VELOCITY", "AMOUNT", "DEVICE", "CYBER", "CUSTOM"
    condition_field: str           # e.g. "user_velocity_1m", "amount", "device_trust_score", "carding_threat_score"
    operator: str                  # ">=", ">", "<=", "<", "==", "!="
    threshold_value: float
    action: ActionDecision
    risk_boost: float              # Added to risk score or overrides
    enabled: bool = True
    is_system_rule: bool = True
    trigger_count: int = 0
    last_triggered_at: Optional[float] = None


@dataclass
class RuleEvaluationResult:
    decision: ActionDecision
    risk_level: str
    risk_score: float
    triggered_rules: List[str]
    recommendation: str
    policy_mode: str = "DETERMINISTIC_RULES"
    active_rules_count: int = 0


class HybridRuleEngine:
    def __init__(
        self,
        block_threshold: float = 0.75,
        review_threshold: float = 0.45,
        challenge_threshold: float = 0.25,
        high_amount_threshold: float = 2500.0,
        max_1m_velocity: int = 4,
        max_1h_velocity: int = 15,
        use_rl: bool = True
    ):
        self.block_threshold = block_threshold
        self.review_threshold = review_threshold
        self.challenge_threshold = challenge_threshold
        self.high_amount_threshold = high_amount_threshold
        self.max_1m_velocity = max_1m_velocity
        self.max_1h_velocity = max_1h_velocity
        self.use_rl = use_rl

        # Dynamic rules registry
        self.rules: Dict[str, RuleDefinition] = {}
        self._init_default_rules()

    def _init_default_rules(self):
        """Initializes default production risk rules."""
        self.rules = {
            "RULE_VELOCITY_BURST": RuleDefinition(
                rule_id="RULE_VELOCITY_BURST",
                name="1-Minute Velocity Burst",
                description="Flags rapid-fire automated carding or credential stuffing bursts.",
                category="VELOCITY",
                condition_field="user_velocity_1m",
                operator=">=",
                threshold_value=float(self.max_1m_velocity),
                action=ActionDecision.BLOCK,
                risk_boost=0.50,
                enabled=True,
                is_system_rule=True
            ),
            "RULE_AMOUNT_SPIKE": RuleDefinition(
                rule_id="RULE_AMOUNT_SPIKE",
                name="Extreme Value Anomaly",
                description="Flags high-ticket authorizations exceeding standard baseline thresholds.",
                category="AMOUNT",
                condition_field="amount",
                operator=">=",
                threshold_value=float(self.high_amount_threshold),
                action=ActionDecision.MANUAL_REVIEW,
                risk_boost=0.20,
                enabled=True,
                is_system_rule=True
            ),
            "RULE_UNTRUSTED_DEVICE": RuleDefinition(
                rule_id="RULE_UNTRUSTED_DEVICE",
                name="Untrusted / Spoofed Device Fingerprint",
                description="Detects anomalous browser fingerprints, headless user-agents, or open proxies.",
                category="DEVICE",
                condition_field="device_trust_score",
                operator="<=",
                threshold_value=0.25,
                action=ActionDecision.CHALLENGE_2FA,
                risk_boost=0.30,
                enabled=True,
                is_system_rule=True
            ),
            "RULE_CARDING_SENTINEL": RuleDefinition(
                rule_id="RULE_CARDING_SENTINEL",
                name="Carding / BIN Probing Threat",
                description="Catches distributed micro-authorization probing across card batches.",
                category="CYBER",
                condition_field="carding_threat_score",
                operator=">=",
                threshold_value=0.75,
                action=ActionDecision.BLOCK,
                risk_boost=0.60,
                enabled=True,
                is_system_rule=True
            )
        }

    def get_rules(self) -> List[Dict[str, Any]]:
        """Returns all registered rules for UI inspection."""
        return [asdict(r) for r in self.rules.values()]

    def toggle_rule(self, rule_id: str, enabled: Optional[bool] = None) -> Optional[Dict[str, Any]]:
        """Toggles a rule on or off dynamically without restarting the server."""
        if rule_id in self.rules:
            rule = self.rules[rule_id]
            rule.enabled = not rule.enabled if enabled is None else bool(enabled)
            return asdict(rule)
        return None

    def add_custom_rule(
        self,
        name: str,
        description: str,
        condition_field: str,
        operator: str,
        threshold_value: float,
        action: str = "CHALLENGE_2FA",
        risk_boost: float = 0.25
    ) -> Dict[str, Any]:
        """Creates a hot-reloadable custom rule."""
        rule_id = f"RULE_CUSTOM_{int(time.time()*1000)%1000000}"
        act = ActionDecision(action) if action in ActionDecision._value2member_map_ else ActionDecision.CHALLENGE_2FA
        rule = RuleDefinition(
            rule_id=rule_id,
            name=name,
            description=description,
            category="CUSTOM",
            condition_field=condition_field,
            operator=operator,
            threshold_value=float(threshold_value),
            action=act,
            risk_boost=float(risk_boost),
            enabled=True,
            is_system_rule=False
        )
        self.rules[rule_id] = rule
        return asdict(rule)

    def delete_rule(self, rule_id: str) -> bool:
        """Deletes a custom rule."""
        if rule_id in self.rules and not self.rules[rule_id].is_system_rule:
            del self.rules[rule_id]
            return True
        return False

    def reset_to_defaults(self):
        """Restores baseline default rules."""
        self._init_default_rules()

    def _eval_condition(self, val: float, op: str, threshold: float) -> bool:
        """Evaluates numerical condition against threshold."""
        if op == ">=":
            return val >= threshold
        elif op == ">":
            return val > threshold
        elif op == "<=":
            return val <= threshold
        elif op == "<":
            return val < threshold
        elif op == "==":
            return abs(val - threshold) < 1e-5
        elif op == "!=":
            return abs(val - threshold) >= 1e-5
        return False

    def evaluate(
        self,
        ml_score: float,
        amount: float,
        user_velocity_1m: int = 0,
        user_velocity_1h: int = 0,
        user_avg_amount: float = 0.0,
        device_trust_score: float = 1.0,
        carding_threat_score: float = 0.0,
        carding_rules: Optional[List[str]] = None,
        context_data: Optional[Dict[str, Any]] = None
    ) -> RuleEvaluationResult:
        triggered_rules: List[str] = []
        combined_score = ml_score
        highest_rule_severity = 0  # 0: APPROVE, 1: 2FA, 2: REVIEW, 3: BLOCK
        now = time.time()

        # Build feature lookup map for dynamic evaluation
        field_values = {
            "amount": float(amount),
            "user_velocity_1m": float(user_velocity_1m),
            "user_velocity_1h": float(user_velocity_1h),
            "user_avg_amount": float(user_avg_amount),
            "device_trust_score": float(device_trust_score),
            "carding_threat_score": float(carding_threat_score),
            "ml_score": float(ml_score)
        }
        if context_data:
            for k, v in context_data.items():
                if isinstance(v, (int, float)):
                    field_values[k] = float(v)

        severity_map = {
            ActionDecision.APPROVE: 0,
            ActionDecision.CHALLENGE_2FA: 1,
            ActionDecision.MANUAL_REVIEW: 2,
            ActionDecision.BLOCK: 3
        }

        # 1. Evaluate all enabled registered rules
        for rule_id, rule in self.rules.items():
            if not rule.enabled:
                continue

            field_val = field_values.get(rule.condition_field)
            if field_val is not None:
                is_hit = self._eval_condition(field_val, rule.operator, rule.threshold_value)
                if is_hit:
                    rule.trigger_count += 1
                    rule.last_triggered_at = now
                    rule_msg = f"{rule.rule_id}: {rule.name} (Val: {field_val:.2f} {rule.operator} {rule.threshold_value:.2f})"
                    triggered_rules.append(rule_msg)
                    
                    combined_score = min(1.0, max(combined_score, combined_score + rule.risk_boost))
                    rule_sev = severity_map.get(rule.action, 1)
                    if rule_sev > highest_rule_severity:
                        highest_rule_severity = rule_sev

        # 2. Rule: Excessive Amount Spike vs User Baseline (Specific relational condition)
        if user_avg_amount > 0 and amount > (user_avg_amount * 5.0) and amount > 500.0:
            triggered_rules.append(f"RULE_AMOUNT_ANOMALY: Amount (${amount:.2f}) is 5x above user baseline (${user_avg_amount:.2f})")
            combined_score = min(1.0, combined_score + 0.20)
            highest_rule_severity = max(highest_rule_severity, 2)

        # 3. Add cyber carding & graph tags
        if carding_rules:
            triggered_rules.extend(carding_rules)
            if carding_threat_score >= 0.80:
                combined_score = max(combined_score, 0.95)
                highest_rule_severity = 3
            elif carding_threat_score >= 0.50:
                combined_score = max(combined_score, 0.65)
                highest_rule_severity = max(highest_rule_severity, 1)

        # 4. Determine baseline policy decision
        is_hard_block = (combined_score >= self.block_threshold) or (user_velocity_1m >= self.max_1m_velocity) or (carding_threat_score >= 0.85) or (highest_rule_severity >= 3)

        if is_hard_block:
            det_decision = ActionDecision.BLOCK
        elif combined_score >= self.review_threshold or highest_rule_severity == 2:
            det_decision = ActionDecision.MANUAL_REVIEW
        elif combined_score >= self.challenge_threshold or highest_rule_severity == 1 or len(triggered_rules) > 0:
            det_decision = ActionDecision.CHALLENGE_2FA
        else:
            det_decision = ActionDecision.APPROVE

        policy_mode = "DETERMINISTIC_RULES"

        if is_hard_block:
            decision = ActionDecision.BLOCK
            risk_level = "CRITICAL" if combined_score >= 0.90 else "HIGH"
            recommendation = "Decline transaction immediately and flag payment instrument for investigation."
        elif self.use_rl:
            # Contextual Multi-Armed Bandit RL Agent optimizes boundary tradeoffs
            context = {
                "ml_score": ml_score,
                "amount": amount,
                "user_velocity_1m": user_velocity_1m,
                "carding_threat_score": carding_threat_score,
                "device_trust_score": device_trust_score,
                "graph_risk_score": max(0.0, combined_score - ml_score)
            }
            bandit_res = rl_policy_agent.select_action(context, override_hard_block=False)
            rl_decision = bandit_res.action
            policy_mode = "CONTEXTUAL_BANDIT_RL"

            # Enforce safety invariant: if deterministic rules were triggered, do not relax below rule severity
            if len(triggered_rules) > 0 and severity_map[rl_decision] < severity_map[det_decision]:
                decision = det_decision
            else:
                decision = rl_decision

            if decision == ActionDecision.BLOCK:
                risk_level = "HIGH"
                recommendation = "Policy allocated Block to minimize expected chargeback loss."
            elif decision == ActionDecision.MANUAL_REVIEW:
                risk_level = "HIGH"
                recommendation = "Route to Tier-2 Fraud Analyst Queue for KYC/identity review."
            elif decision == ActionDecision.CHALLENGE_2FA:
                risk_level = "MEDIUM"
                recommendation = "Prompt cardholder with dynamic 3D-Secure 2.3 / biometric challenge."
            else:
                decision = ActionDecision.APPROVE
                risk_level = "LOW"
                recommendation = "Authorize transaction with zero friction (Frictionless clearing)."
        else:
            decision = det_decision
            if decision == ActionDecision.MANUAL_REVIEW:
                risk_level = "HIGH"
                recommendation = "Route to Tier-2 Fraud Analyst Queue for KYC/identity review."
            elif decision == ActionDecision.CHALLENGE_2FA:
                risk_level = "MEDIUM"
                recommendation = "Prompt cardholder with 3D-Secure 2.3 / SMS OTP challenge."
            else:
                risk_level = "LOW"
                recommendation = "Authorize transaction with zero friction."

        return RuleEvaluationResult(
            decision=decision,
            risk_level=risk_level,
            risk_score=round(combined_score, 4),
            triggered_rules=triggered_rules,
            recommendation=recommendation,
            policy_mode=policy_mode,
            active_rules_count=sum(1 for r in self.rules.values() if r.enabled)
        )


# Global singleton instance
rule_engine = HybridRuleEngine()
