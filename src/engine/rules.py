"""
AegisFlow Dynamic Rule & Decision Engine
Combines statistical ML probability with deterministic compliance and velocity rules.
"""

from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

from src.engine.rl_policy import rl_policy_agent, ActionDecision, BanditDecisionResult


@dataclass
class RuleEvaluationResult:
    decision: ActionDecision
    risk_level: str
    risk_score: float
    triggered_rules: List[str]
    recommendation: str
    policy_mode: str = "DETERMINISTIC_RULES"


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

    def evaluate(
        self,
        ml_score: float,
        amount: float,
        user_velocity_1m: int = 0,
        user_velocity_1h: int = 0,
        user_avg_amount: float = 0.0,
        device_trust_score: float = 1.0,
        carding_threat_score: float = 0.0,
        carding_rules: Optional[List[str]] = None
    ) -> RuleEvaluationResult:
        triggered_rules: List[str] = []
        combined_score = ml_score

        # Rule 1: High Velocity Spike (Rapid fire transactions)
        if user_velocity_1m >= self.max_1m_velocity:
            triggered_rules.append(f"RULE_VELOCITY_BURST: {user_velocity_1m} transactions in 1 minute")
            combined_score = max(combined_score, 0.85)

        # Rule 2: Excessive Amount Spike vs User Baseline
        if user_avg_amount > 0 and amount > (user_avg_amount * 5.0) and amount > 500.0:
            triggered_rules.append(f"RULE_AMOUNT_ANOMALY: Amount (${amount:.2f}) is 5x above user baseline (${user_avg_amount:.2f})")
            combined_score = min(1.0, combined_score + 0.20)

        # Rule 3: Extreme Absolute High Amount without history
        if amount >= self.high_amount_threshold:
            triggered_rules.append(f"RULE_HIGH_VALUE_TRANSACTION: Amount exceeds ${self.high_amount_threshold:.2f}")
            combined_score = min(1.0, combined_score + 0.15)

        # Rule 4: Suspicious Device Trust
        if device_trust_score < 0.3:
            triggered_rules.append("RULE_UNTRUSTED_DEVICE: Unrecognized device fingerprint or proxy detected")
            combined_score = min(1.0, combined_score + 0.25)

        # Rule 5: Cyber Carding & Botnet Attack Rule
        if carding_rules:
            triggered_rules.extend(carding_rules)
        if carding_threat_score >= 0.80:
            combined_score = max(combined_score, 0.95)
        elif carding_threat_score >= 0.50:
            combined_score = max(combined_score, 0.65)

        # Determine baseline policy decision
        is_hard_block = (combined_score >= self.block_threshold) or (user_velocity_1m >= self.max_1m_velocity) or (carding_threat_score >= 0.85)

        if is_hard_block:
            det_decision = ActionDecision.BLOCK
        elif combined_score >= self.review_threshold:
            det_decision = ActionDecision.MANUAL_REVIEW
        elif combined_score >= self.challenge_threshold or len(triggered_rules) > 0:
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

            # Hybrid Safety Invariant: If deterministic rules were triggered, enforce at least det_decision
            decision_severity = {
                ActionDecision.APPROVE: 0,
                ActionDecision.CHALLENGE_2FA: 1,
                ActionDecision.MANUAL_REVIEW: 2,
                ActionDecision.BLOCK: 3
            }
            if len(triggered_rules) > 0 and decision_severity[rl_decision] < decision_severity[det_decision]:
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
                recommendation = "Prompt cardholder with dynamic 3D-Secure 2.0 / biometric challenge."
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
                recommendation = "Prompt cardholder with 3D-Secure 2.0 / SMS OTP challenge."
            else:
                risk_level = "LOW"
                recommendation = "Authorize transaction with zero friction."

        return RuleEvaluationResult(
            decision=decision,
            risk_level=risk_level,
            risk_score=round(combined_score, 4),
            triggered_rules=triggered_rules,
            recommendation=recommendation,
            policy_mode=policy_mode
        )
