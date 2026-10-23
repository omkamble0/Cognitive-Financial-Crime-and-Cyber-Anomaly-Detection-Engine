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
from services.risk_engine.baselines import behavior_baseline_engine
from services.graph_analytics.universal_graph import universal_graph_engine
from services.policy_engine.engine import declarative_policy_engine
from src.db.database import upsert_entity, save_relationship_record


class UniversalRiskRouter:
    """
    Central orchestration router that coordinates domain modules,
    entity graph linkage, behavioral baselines, policy rules, and automated triage.
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
        1. Ingests entities & graph links
        2. Evaluates behavioral baseline deviations
        3. Routes event to domain module
        4. Evaluates declarative policies & enforcement
        5. Generates deduplicated alert if risk breaches threshold
        """
        start_time = time.perf_counter()
        domain_key = event.domain.value.upper() if hasattr(event.domain, "value") else str(event.domain).upper()
        module = self._modules.get(domain_key, banking_domain_module)

        # 1. Entity Graph Linkage
        primary_id = event.primary_entity_id
        universal_graph_engine.add_node(primary_id, "USER")
        try:
            upsert_entity(primary_id, "USER", domain=domain_key)
        except Exception:
            pass

        for link in event.entities:
            target_id = link.id
            target_type = link.type.value if hasattr(link.type, "value") else str(link.type)
            if target_id != primary_id:
                universal_graph_engine.add_edge(
                    source_id=primary_id,
                    source_type="USER",
                    target_id=target_id,
                    target_type=target_type,
                    relationship=link.role
                )
                try:
                    upsert_entity(target_id, target_type, domain=domain_key)
                    save_relationship_record(primary_id, "USER", target_id, target_type, link.role)
                except Exception:
                    pass

        # 2. Behavioral Baseline Evaluation
        baseline_alerts = []
        payload = event.payload or {}
        if "amount" in payload:
            base_eval = behavior_baseline_engine.evaluate_metric(
                entity_id=primary_id,
                metric_name="ticket_amount",
                value=float(payload["amount"])
            )
            if base_eval.is_anomalous:
                baseline_alerts.append(f"BEHAVIOR_SPEND_DEVIATION_Z_{base_eval.z_score}")

        # 3. Domain Evaluation
        dom_result: DomainEvaluationResult = module.evaluate_event(event)
        all_rules = list(set(dom_result.rule_hits + baseline_alerts))

        # 4. Declarative Policy Evaluation
        policy_actions = declarative_policy_engine.evaluate_policies(
            domain=domain_key,
            risk_score=dom_result.risk_score,
            triggered_rules=all_rules,
            primary_entity_id=primary_id
        )

        effective_decision = dom_result.decision
        if any(a.action_type == "BLOCK" for a in policy_actions):
            effective_decision = "BLOCK"

        # 5. Alert Generation & Suppression
        alert_created = None
        alert_suppressed = False

        if dom_result.risk_score >= 0.50:
            rule_summary = all_rules[0] if all_rules else "RISK_SCORE_ELEVATED"
            fingerprint = Alert.generate_fingerprint(
                domain=domain_key,
                primary_entity_id=primary_id,
                rule_name=rule_summary
            )

            candidate_alert = Alert(
                domain=domain_key,
                title=dom_result.suggested_case_title or f"{domain_key} Risk Anomaly ({primary_id})",
                severity=dom_result.severity,
                status=AlertStatus.OPEN,
                primary_entity_id=primary_id,
                event_id=event.event_id,
                risk_score=dom_result.risk_score,
                rule_hits=all_rules,
                anomaly_signals=dom_result.anomaly_signals,
                dedup_fingerprint=fingerprint,
                tenant_id=event.tenant_id
            )

            is_new, effective_alert = alert_deduplicator.process_alert(candidate_alert)
            alert_created = effective_alert.model_dump()
            alert_suppressed = not is_new

        # Graph neighborhood cluster summary
        cluster = universal_graph_engine.extract_neighborhood_subgraph(primary_id, max_hops=2)
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        return {
            "event_id": event.event_id,
            "domain": domain_key,
            "primary_entity_id": primary_id,
            "decision": effective_decision,
            "risk_score": dom_result.risk_score,
            "severity": dom_result.severity.value,
            "rule_hits": all_rules,
            "anomaly_signals": dom_result.anomaly_signals,
            "forensic_narrative": dom_result.forensic_narrative,
            "policy_actions": [a.model_dump() for a in policy_actions],
            "graph_cluster": {
                "cluster_id": cluster.cluster_id,
                "connected_nodes": cluster.total_nodes,
                "is_syndicate": cluster.is_syndicate
            },
            "alert": alert_created,
            "alert_suppressed": alert_suppressed,
            "latency_ms": round(latency_ms, 2)
        }


# Singleton router instance
universal_risk_router = UniversalRiskRouter()
