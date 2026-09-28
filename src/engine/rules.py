"""
AegisFlow Dynamic Rule & Decision Engine
Combines statistical ML probability with deterministic compliance and velocity rules.
"""

from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class ActionDecision(str, Enum):
    APPROVE = "APPROVE"
    CHALLENGE_2FA = "CHALLENGE_2FA"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    BLOCK = "BLOCK"


@dataclass
class RuleEvaluationResult:
    decision: ActionDecision
    risk_level: str
    risk_score: float
    triggered_rules: List[str]
    recommendation: str


class HybridRuleEngine:
    def __init__(
        self,
        block_threshold: float = 0.75,
        review_threshold: float = 0.45,
        challenge_threshold: float = 0.25,
        high_amount_threshold: float = 2500.0,
        max_1m_velocity: int = 4,
        max_1h_velocity: int = 15
    ):
        self.block_threshold = block_threshold
        self.review_threshold = review_threshold
        self.challenge_threshold = challenge_threshold
        self.high_amount_threshold = high_amount_threshold
        self.max_1m_velocity = max_1m_velocity
        self.max_1h_velocity = max_1h_velocity

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

        # Make final action decision
        if combined_score >= self.block_threshold:
            decision = ActionDecision.BLOCK
            risk_level = "CRITICAL" if combined_score >= 0.90 else "HIGH"
            recommendation = "Decline transaction immediately and flag payment instrument for investigation."
        elif combined_score >= self.review_threshold:
            decision = ActionDecision.MANUAL_REVIEW
            risk_level = "HIGH"
            recommendation = "Route to Tier-2 Fraud Analyst Queue for KYC/identity review."
        elif combined_score >= self.challenge_threshold or len(triggered_rules) > 0:
            decision = ActionDecision.CHALLENGE_2FA
            risk_level = "MEDIUM"
            recommendation = "Prompt cardholder with 3D-Secure 2.0 / SMS OTP challenge."
        else:
            decision = ActionDecision.APPROVE
            risk_level = "LOW"
            recommendation = "Authorize transaction with zero friction."

        return RuleEvaluationResult(
            decision=decision,
            risk_level=risk_level,
            risk_score=round(combined_score, 4),
            triggered_rules=triggered_rules,
            recommendation=recommendation
        )
