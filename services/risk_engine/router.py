"""
FinCipher AI — Universal Risk Engine & Multi-Domain Pipeline Router
Author: Om Kamble
"""

import time
from typing import Dict, Any, Optional
from libs.models.events import GenericEvent, DomainType
from libs.models.alerts import Alert, AlertSeverity, AlertStatus
from services.domains.base_domain import BaseDomainModule, DomainEvaluationResult
from services.domains.banking_module import banking_domain_module
from services.domains.cybersecurity_module import cybersecurity_domain_module
from services.domains.ecommerce_module import ecommerce_domain_module
from services.risk_engine.deduplicator import alert_deduplicator


class UniversalRiskRouter:
    """
    Central orchestration router that coordinates domain modules,
    composite risk scoring, alert suppression, and automated triage.
    """

    def __init__(self):
        self._modules: Dict[str, BaseDomainModule] = {
            "BANKING": banking_domain_module,
            "CYBERSECURITY": cybersecurity_domain_module,
            "ECOMMERCE": ecommerce_domain_module
        }

    def register_module(self, module: BaseDomainModule):
        """Allows dynamic registration of new risk domains at runtime."""
        self._modules[module.domain_name.upper()] = module

    def evaluate_event(self, event: GenericEvent) -> Dict[str, Any]:
        """
        End-to-end evaluation:
        1. Routes event to domain module
        2. Computes composite risk & decisions
        3. Generates deduplicated alert if risk breaches threshold
        4. Returns normalized evaluation response
        """
        start_time = time.perf_counter()
        domain_key = event.domain.value.upper() if hasattr(event.domain, "value") else str(event.domain).upper()
        module = self._modules.get(domain_key, banking_domain_module)

        # 1. Domain Evaluation
        dom_result: DomainEvaluationResult = module.evaluate_event(event)

        # 2. Alert Generation & Suppression
        alert_created = None
        alert_suppressed = False

        if dom_result.risk_score >= 0.50:
            rule_summary = dom_result.rule_hits[0] if dom_result.rule_hits else "RISK_SCORE_ELEVATED"
            fingerprint = Alert.generate_fingerprint(
                domain=domain_key,
                primary_entity_id=event.primary_entity_id,
                rule_name=rule_summary
            )

            candidate_alert = Alert(
                domain=domain_key,
                title=dom_result.suggested_case_title or f"{domain_key} Risk Anomaly ({event.primary_entity_id})",
                severity=dom_result.severity,
                status=AlertStatus.OPEN,
                primary_entity_id=event.primary_entity_id,
                event_id=event.event_id,
                risk_score=dom_result.risk_score,
                rule_hits=dom_result.rule_hits,
                anomaly_signals=dom_result.anomaly_signals,
                dedup_fingerprint=fingerprint,
                tenant_id=event.tenant_id
            )

            is_new, effective_alert = alert_deduplicator.process_alert(candidate_alert)
            alert_created = effective_alert.model_dump()
            alert_suppressed = not is_new

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        return {
            "event_id": event.event_id,
            "domain": domain_key,
            "primary_entity_id": event.primary_entity_id,
            "decision": dom_result.decision,
            "risk_score": dom_result.risk_score,
            "severity": dom_result.severity.value,
            "rule_hits": dom_result.rule_hits,
            "anomaly_signals": dom_result.anomaly_signals,
            "forensic_narrative": dom_result.forensic_narrative,
            "alert": alert_created,
            "alert_suppressed": alert_suppressed,
            "latency_ms": round(latency_ms, 2)
        }


# Singleton router instance
universal_risk_router = UniversalRiskRouter()
