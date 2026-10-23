"""
FinCipher AI — E-Commerce & Retail Abuse Domain Module
Author: Om Kamble
"""

import time
from typing import Dict, Any, List
from libs.models.events import GenericEvent
from libs.models.alerts import AlertSeverity
from services.domains.base_domain import BaseDomainModule, DomainEvaluationResult


class EcommerceDomainModule(BaseDomainModule):
    """
    Evaluates e-commerce abuse: promo/voucher farming, refund fraud, bot checkout blitzes, and chargeback risk.
    """

    def __init__(self):
        # Sliding memory: promo_code -> list of (timestamp, ip_address, user_id)
        self._promo_redemptions: Dict[str, List[Dict[str, Any]]] = {}
        # Sliding memory: user_id -> list of refunds
        self._refund_history: Dict[str, List[float]] = {}

    @property
    def domain_name(self) -> str:
        return "ECOMMERCE"

    def evaluate_event(self, event: GenericEvent) -> DomainEvaluationResult:
        payload = event.payload or {}
        context = event.context or {}
        user_id = event.primary_entity_id
        ip_addr = str(context.get("ip_address") or "127.0.0.1")
        promo_code = str(payload.get("promo_code") or "").strip().upper()
        cart_total = float(payload.get("cart_total", 0.0))
        discount_amount = float(payload.get("discount_amount", 0.0))
        is_guest = bool(payload.get("is_guest", False))
        now = event.timestamp or time.time()

        rule_hits = []
        anomaly_signals = {}
        risk_score = 0.04

        # 1. Promo / Voucher Code Farming Attack
        if promo_code:
            redemptions = self._promo_redemptions.setdefault(promo_code, [])
            redemptions.append({"time": now, "ip": ip_addr, "user_id": user_id})
            # Prune older than 10 minutes
            self._promo_redemptions[promo_code] = [r for r in redemptions if now - r["time"] <= 600]
            recent_redemptions = self._promo_redemptions[promo_code]

            # Check if same IP is redeeming the same promo across multiple user IDs
            unique_users_on_ip = {r["user_id"] for r in recent_redemptions if r["ip"] == ip_addr}
            if len(unique_users_on_ip) >= 3:
                rule_hits.append(f"ECOMM_PROMO_FARMING_BURST_{len(unique_users_on_ip)}_ACCOUNTS_SAME_IP")
                risk_score = max(risk_score, 0.88)
                anomaly_signals["promo_syndicate_accounts"] = len(unique_users_on_ip)

            # Deep discount exploit (discount > 75% of cart)
            if cart_total > 0 and (discount_amount / cart_total) > 0.75:
                rule_hits.append("ECOMM_ABNORMAL_DISCOUNT_RATIO_OVER_75PCT")
                risk_score = max(risk_score, 0.76)
                anomaly_signals["discount_pct"] = (discount_amount / cart_total) * 100.0

        # 2. Refund Fraud Velocity
        if event.event_type.value == "REFUND":
            refunds = self._refund_history.setdefault(user_id, [])
            refunds.append(now)
            # Prune older than 24 hours
            self._refund_history[user_id] = [t for t in refunds if now - t <= 86400]
            refund_count_24h = len(self._refund_history[user_id])
            if refund_count_24h >= 4:
                rule_hits.append(f"ECOMM_REFUND_ABUSE_{refund_count_24h}_REFUNDS_24H")
                risk_score = max(risk_score, 0.84)
                anomaly_signals["refund_count_24h"] = refund_count_24h

        # 3. High-Ticket Guest Checkout
        if is_guest and cart_total >= 3000.0:
            rule_hits.append("ECOMM_HIGH_VALUE_GUEST_CHECKOUT")
            risk_score = max(risk_score, 0.65)
            anomaly_signals["guest_cart_total"] = cart_total

        # Calculate Decision & Severity
        if risk_score >= 0.80:
            decision = "BLOCK"
            severity = AlertSeverity.P1_CRITICAL
            case_title = f"Retail Fraud Syndicate: {user_id} ({promo_code or 'Checkout'})"
        elif risk_score >= 0.50:
            decision = "CHALLENGE"
            severity = AlertSeverity.P2_HIGH
            case_title = f"Suspicious Order Review: {user_id}"
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
        cart_total = payload.get("cart_total", 0.0)
        promo = payload.get("promo_code", "None")

        narrative_parts = [
            f"E-Commerce telemetry evaluated order/action for buyer {event.primary_entity_id} (Cart Total: ${cart_total:,.2f}, Coupon: {promo})."
        ]
        if result.rule_hits:
            narrative_parts.append(f"Policy violations detected: {', '.join(result.rule_hits)}.")
        if "promo_syndicate_accounts" in result.anomaly_signals:
            narrative_parts.append(
                f"Multi-account coupon farming syndicate identified from single IP cluster ({result.anomaly_signals['promo_syndicate_accounts']} distinct identities)."
            )
        if "refund_count_24h" in result.anomaly_signals:
            narrative_parts.append(f"High-frequency refund velocity pattern detected with {result.anomaly_signals['refund_count_24h']} returns in 24 hours.")

        narrative_parts.append(f"Disposition: {result.decision} (Risk: {result.risk_score:.2f}).")
        return " ".join(narrative_parts)


# Singleton
ecommerce_domain_module = EcommerceDomainModule()
