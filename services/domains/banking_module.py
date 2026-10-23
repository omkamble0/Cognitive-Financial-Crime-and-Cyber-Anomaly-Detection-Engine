"""
FinCipher AI — Banking & Financial Crime Domain Module
Author: Om Kamble
"""

import time
from typing import Dict, Any, List
from libs.models.events import GenericEvent
from libs.models.alerts import AlertSeverity
from services.domains.base_domain import BaseDomainModule, DomainEvaluationResult


class BankingDomainModule(BaseDomainModule):
    """
    Evaluates financial crime, payment anomalies, AML structuring, and sanctions.
    """

    SANCTIONED_COUNTRIES = {"IR", "KP", "SY", "CU", "RU"}
    CTR_STRUCTURING_LIMIT = 10000.0  # FinCEN Currency Transaction Report threshold

    def __init__(self):
        # Sliding memory for structuring detection: account_id -> list of (timestamp, amount)
        self._velocity_cache: Dict[str, List[Dict[str, float]]] = {}

    @property
    def domain_name(self) -> str:
        return "BANKING"

    def evaluate_event(self, event: GenericEvent) -> DomainEvaluationResult:
        payload = event.payload or {}
        context = event.context or {}
        amount = float(payload.get("amount", 0.0))
        currency = str(payload.get("currency", "USD")).upper()
        country = str(context.get("country") or payload.get("beneficiary_country") or "").upper()
        account_id = event.primary_entity_id

        rule_hits = []
        anomaly_signals = {}
        risk_score = 0.05
        now = event.timestamp or time.time()

        # 1. Sanctions & High-Risk Country Check
        if country in self.SANCTIONED_COUNTRIES:
            rule_hits.append(f"AML_SANCTIONED_JURISDICTION_{country}")
            risk_score = max(risk_score, 0.98)
            anomaly_signals["sanction_match"] = country

        # 2. AML Structuring Detection (Transactions repeatedly between $8,500 and $9,999)
        if 8500.0 <= amount < self.CTR_STRUCTURING_LIMIT:
            rule_hits.append("AML_SUSPECTED_STRUCTURING_CTR_AVOIDANCE")
            risk_score = max(risk_score, 0.82)
            anomaly_signals["structuring_ticket"] = amount

        # 3. Account Velocity Tracking (Rapid succession of transfers)
        history = self._velocity_cache.setdefault(account_id, [])
        history.append({"time": now, "amount": amount})
        # Prune older than 1 hour
        self._velocity_cache[account_id] = [h for h in history if now - h["time"] <= 3600]
        recent_txs = self._velocity_cache[account_id]
        
        if len(recent_txs) >= 5:
            rule_hits.append(f"HIGH_VELOCITY_RAPID_BURST_{len(recent_txs)}_TX_PER_HOUR")
            risk_score = max(risk_score, min(0.95, 0.50 + len(recent_txs) * 0.08))
            anomaly_signals["hourly_count"] = len(recent_txs)

        # 4. High-Ticket Single Transaction
        if amount >= 50000.0:
            rule_hits.append("HIGH_VALUE_WIRE_TRANSFER")
            risk_score = max(risk_score, 0.72)
            anomaly_signals["high_value_ticket"] = amount

        # Calculate Decision & Severity
        if risk_score >= 0.85:
            decision = "BLOCK"
            severity = AlertSeverity.P1_CRITICAL
            case_title = f"Critical AML/Banking Fraud: {account_id} (${amount:,.2f})"
        elif risk_score >= 0.50:
            decision = "CHALLENGE"
            severity = AlertSeverity.P2_HIGH
            case_title = f"High Risk Payment Review: {account_id}"
        else:
            decision = "ALLOW"
            severity = AlertSeverity.P4_LOW
            case_title = None

        result = DomainEvaluationResult(
            domain=self.domain_name,
            risk_score=risk_score,
            decision=decision,
            severity=severity,
            rule_hits=rule_hits,
            anomaly_signals=anomaly_signals,
            suggested_case_title=case_title
        )
        result.forensic_narrative = self.generate_narrative(event, result)
        return result

    def generate_narrative(self, event: GenericEvent, result: DomainEvaluationResult) -> str:
        payload = event.payload or {}
        amount = payload.get("amount", 0.0)
        currency = payload.get("currency", "USD")
        
        narrative_parts = [
            f"Financial Crime Pipeline evaluated payment for entity {event.primary_entity_id} valued at {amount:,.2f} {currency}."
        ]
        if result.rule_hits:
            narrative_parts.append(f"Heuristic triggers activated: {', '.join(result.rule_hits)}.")
        if "sanction_match" in result.anomaly_signals:
            narrative_parts.append(f"CRITICAL: Transaction routes through FATF blacklisted jurisdiction {result.anomaly_signals['sanction_match']}.")
        if "structuring_ticket" in result.anomaly_signals:
            narrative_parts.append("Pattern indicates possible structuring to evade mandatory Bank Secrecy Act (BSA) CTR thresholds.")
            
        narrative_parts.append(f"Final Policy Decision: {result.decision} (Composite Risk Score: {result.risk_score:.2f}).")
        return " ".join(narrative_parts)


# Singleton
banking_domain_module = BankingDomainModule()
