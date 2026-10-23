"""
FinCipher AI — Generic Event Ingestion & Normalization REST Endpoints
Author: Om Kamble
"""

import time
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends
from libs.models.events import GenericEvent, EventBatch
from services.ingestion.normalizer import UniversalEventNormalizer
from services.risk_engine.router import universal_risk_router

router = APIRouter(prefix="/api/v1/events", tags=["Universal Event Ingestion"])


@router.post("/ingest", summary="Ingest any generic domain event")
def api_ingest_generic_event(event: GenericEvent) -> Dict[str, Any]:
    """Ingests a standardized GenericEvent into the risk evaluation pipeline."""
    try:
        result = universal_risk_router.evaluate_event(event)
        return {
            "status": "PROCESSED",
            "evaluation": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Event ingestion failed: {str(e)}")


@router.post("/ingest/banking", summary="Ingest raw Banking / Payment event")
def api_ingest_banking_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience endpoint: Normalizes raw banking payload into GenericEvent and scores risk."""
    event = UniversalEventNormalizer.normalize_banking_payment(payload)
    result = universal_risk_router.evaluate_event(event)
    return {
        "status": "PROCESSED",
        "domain": "BANKING",
        "evaluation": result
    }


@router.post("/ingest/cyber", summary="Ingest raw Cybersecurity / SOC Auth event")
def api_ingest_cyber_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience endpoint: Normalizes raw cybersecurity/syslog payload and scores risk."""
    event = UniversalEventNormalizer.normalize_cyber_auth(payload)
    result = universal_risk_router.evaluate_event(event)
    return {
        "status": "PROCESSED",
        "domain": "CYBERSECURITY",
        "evaluation": result
    }


@router.post("/ingest/ecommerce", summary="Ingest raw E-Commerce Order / Promo event")
def api_ingest_ecommerce_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience endpoint: Normalizes raw e-commerce order/promo payload and scores risk."""
    event = UniversalEventNormalizer.normalize_ecommerce_order(payload)
    result = universal_risk_router.evaluate_event(event)
    return {
        "status": "PROCESSED",
        "domain": "ECOMMERCE",
        "evaluation": result
    }


@router.post("/batch", summary="Batch ingest up to 100 events")
def api_ingest_batch(batch: EventBatch) -> Dict[str, Any]:
    """High-throughput multi-event ingestion endpoint."""
    results = []
    for evt in batch.events[:100]:
        res = universal_risk_router.evaluate_event(evt)
        results.append(res)
    return {
        "batch_id": batch.batch_id,
        "processed_count": len(results),
        "evaluations": results
    }


@router.get("/domains", summary="List registered risk domains")
def api_list_domains() -> Dict[str, Any]:
    """Returns active risk domains and supported heuristics."""
    return {
        "active_domains": [
            {
                "domain": "BANKING",
                "capabilities": ["Payment Anomaly", "AML Structuring Avoidance", "Sanctions Screening", "Account Velocity Burst"]
            },
            {
                "domain": "CYBERSECURITY",
                "capabilities": ["Impossible Travel Velocity", "Brute Force / Credential Stuffing", "Privileged Access Escalation without MFA"]
            },
            {
                "domain": "ECOMMERCE",
                "capabilities": ["Multi-Account Promo Code Farming", "Refund Velocity Abuse", "High-Value Guest Checkout Anomaly"]
            }
        ]
    }


# =============================================================================
# ENTITY STORE & GRAPH QUERY ENDPOINTS
# =============================================================================

from src.db.database import list_entities_records, get_entity_record
from services.risk_engine.baselines import behavior_baseline_engine
from services.graph_analytics.universal_graph import universal_graph_engine
from services.policy_engine.engine import declarative_policy_engine


@router.get("/entities", summary="List entities across all domains")
def api_list_entities(type: Optional[str] = None, domain: Optional[str] = None, limit: int = 50):
    """Retrieves entities from the unified entity store."""
    return list_entities_records(entity_type=type, domain=domain, limit=limit)


@router.get("/entities/{entity_id}", summary="Get entity details and behavioral baseline")
def api_get_entity(entity_id: str):
    """Retrieves entity attributes and behavioral baseline summary."""
    rec = get_entity_record(entity_id)
    if not rec:
        raise HTTPException(status_code=404, detail=f"Entity {entity_id} not found.")
    baselines = behavior_baseline_engine.get_profile_summary(entity_id)
    rec["behavior_baselines"] = baselines
    return rec


@router.get("/entities/{entity_id}/graph", summary="Get multi-hop relationship graph cluster")
def api_get_entity_graph(entity_id: str, max_hops: int = 2):
    """Extracts the entity's multi-hop relationship cluster for visual forensic analysis."""
    cluster = universal_graph_engine.extract_neighborhood_subgraph(entity_id, max_hops=min(3, max(1, max_hops)))
    return cluster.model_dump()


@router.get("/policies", summary="List declarative risk and enforcement policies")
def api_list_policies():
    """Lists all active declarative policies across domains."""
    return [p.model_dump() for p in declarative_policy_engine._policies.values()]


# =============================================================================
# THREAT INTELLIGENCE & FORENSIC NARRATIVE ENDPOINTS
# =============================================================================

from services.threat_intel.connector import threat_intel_connector
from services.case_management.narratives import narrative_engine
from src.db.database import get_case_detail


@router.get("/threat-intel/lookup", summary="Lookup indicator against threat intelligence feeds")
def api_threat_intel_lookup(indicator: str, type: Optional[str] = None):
    """Scans an IP, domain, email, hash, or wallet against real-time threat intelligence."""
    match = threat_intel_connector.check_indicator(indicator, indicator_type=type)
    if not match:
        return {
            "indicator": indicator,
            "is_malicious": False,
            "threat_category": "BENIGN",
            "confidence": 0.0,
            "description": "No active threat actor, Tor relay, or malicious IoC detected."
        }
    return match.model_dump()


@router.get("/cases/{case_id}/narrative", summary="Generate regulatory compliance forensic narrative")
def api_get_case_narrative(case_id: int, domain: Optional[str] = None):
    """Generates FinCEN SAR, SOC Incident, or Chargeback Dispute narrative for a case."""
    case = get_case_detail(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")
    target_domain = domain or case.get("domain", "BANKING")
    narrative_text = narrative_engine.generate_narrative_for_domain(target_domain, case)
    return {
        "case_id": case_id,
        "domain": target_domain,
        "narrative": narrative_text
    }


@router.post("/threat-intel/sync", summary="Synchronize threat intelligence from external feeds")
def api_threat_intel_sync(payload: Optional[Dict[str, Any]] = None):
    """Triggers real-time threat feed ingestion and index updating."""
    sources = payload.get("sources") if payload else None
    timeout = payload.get("timeout", 3.0) if payload else 3.0
    sync_res = threat_intel_connector.sync_external_feeds(feed_sources=sources, timeout=timeout)
    return sync_res


@router.get("/threat-intel/metrics", summary="Get threat intelligence telemetry and index metrics")
def api_threat_intel_metrics():
    """Returns total registered IoCs, breakdown by category, query counts, and hit rate."""
    return threat_intel_connector.get_metrics()


@router.post("/benchmark/run", summary="Execute high-throughput multi-domain latency benchmark")
def api_run_benchmark(events_count: int = 100):
    """Executes a real-time micro-benchmark across Banking, Cyber, and E-Commerce."""
    import time
    from services.ingestion.normalizer import UniversalEventNormalizer
    
    count = min(max(10, events_count), 500)
    latencies = []
    t_start = time.perf_counter()

    for i in range(count):
        # Alternate synthetic events across domains
        if i % 3 == 0:
            raw = {
                "transaction_id": f"TX_BENCH_{i}",
                "user_id": f"usr_bench_{i % 20}",
                "amount": 250.0 + (i * 10),
                "currency": "USD",
                "country": "US",
                "ip_address": "10.0.0.1"
            }
            evt = UniversalEventNormalizer.normalize_banking_payment(raw)
        elif i % 3 == 1:
            raw = {
                "username": f"user_{i % 15}",
                "source_ip": "10.0.4.10",
                "status": "SUCCESS",
                "target_host": "prod-auth-bastion-01",
                "mfa_used": True
            }
            evt = UniversalEventNormalizer.normalize_cyber_auth(raw)
        else:
            raw = {
                "order_id": f"ORD_BENCH_{i}",
                "customer_id": f"shopper_{i % 10}",
                "ip_address": "10.0.0.5",
                "total_amount": 75.0,
                "discount_amount": 7.5,
                "promo_code": "SAVE10",
                "discount_applied": True
            }
            evt = UniversalEventNormalizer.normalize_ecommerce_order(raw)

        t0 = time.perf_counter()
        universal_risk_router.evaluate_event(evt)
        latencies.append((time.perf_counter() - t0) * 1000.0)

    total_time_ms = (time.perf_counter() - t_start) * 1000.0
    sorted_lat = sorted(latencies)
    p50 = round(sorted_lat[int(0.50 * len(sorted_lat))], 3)
    p95 = round(sorted_lat[int(0.95 * len(sorted_lat))], 3)
    p99 = round(sorted_lat[int(0.99 * len(sorted_lat))], 3)
    tps = round(count / (total_time_ms / 1000.0), 1)

    return {
        "status": "COMPLETED",
        "events_evaluated": count,
        "elapsed_time_ms": round(total_time_ms, 2),
        "throughput_tps": tps,
        "latency_stats_ms": {
            "p50": p50,
            "p95": p95,
            "p99": p99,
            "avg": round(sum(latencies) / len(latencies), 3)
        },
        "sla_target_ms": 3.5,
        "sla_compliant": p95 < 3.5
    }


# =============================================================================
# MULTI-TENANT CONFIGURATION ENDPOINTS
# =============================================================================

from src.engine.tenant_config import tenant_config_manager


@router.get("/tenants", summary="List all registered client / tenant risk configurations")
def api_list_tenants() -> Dict[str, Any]:
    """Returns active tenant profiles with domain-specific risk policies."""
    return {
        "total_tenants": len(tenant_config_manager.list_configs()),
        "tenants": tenant_config_manager.list_configs()
    }


@router.get("/tenants/{tenant_id}", summary="Get risk policy configuration for a tenant")
def api_get_tenant(tenant_id: str) -> Dict[str, Any]:
    """Returns tenant-specific multi-domain risk thresholds."""
    config = tenant_config_manager.get_config(tenant_id)
    if not config:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found.")
    return config


@router.put("/tenants/{tenant_id}", summary="Update multi-domain risk thresholds for a tenant")
def api_update_tenant(tenant_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    """Updates custom block thresholds, velocity tolerances, and domain policies for a client."""
    updated = tenant_config_manager.set_config(tenant_id, config=updates)
    return {
        "status": "UPDATED",
        "tenant_id": tenant_id,
        "configuration": updated
    }


# =============================================================================
# REAL-TIME INGESTION PIPELINE & BUFFER ENDPOINTS
# =============================================================================

from services.ingestion.pipeline import ingestion_pipeline
from services.graph_analytics.persistent_graph import persistent_entity_graph


@router.post("/pipeline/enqueue", summary="Enqueue raw event into bounded real-time pipeline buffer")
def api_pipeline_enqueue(payload: Dict[str, Any], domain: Optional[str] = None):
    """Asynchronously buffers an incoming domain event with active backpressure control."""
    accepted = ingestion_pipeline.enqueue(payload, domain=domain)
    if not accepted:
        raise HTTPException(status_code=429, detail="Pipeline queue saturated. Event dropped/rejected by backpressure policy.")
    return {
        "status": "ENQUEUED",
        "pipeline_metrics": ingestion_pipeline.get_metrics()
    }


@router.get("/pipeline/metrics", summary="Get real-time pipeline buffer depth and throughput telemetry")
def api_pipeline_metrics():
    """Returns queue depth, utilization, processed counts, inflow TPS, and P95 latency."""
    return ingestion_pipeline.get_metrics()


@router.get("/pipeline/dlq", summary="Inspect Dead-Letter Queue records")
def api_pipeline_dlq(limit: int = 50):
    """Retrieves malformed or corrupted events routed to the DLQ."""
    return {
        "dlq_size": len(ingestion_pipeline.get_dlq_records(limit=limit)),
        "records": ingestion_pipeline.get_dlq_records(limit=limit)
    }


# =============================================================================
# PERSISTENT ENTITY GRAPH & HISTORICAL LINEAGE ENDPOINTS
# =============================================================================

@router.get("/entities/{entity_id}/persistent-graph", summary="Query multi-hop entity subgraph directly from database")
def api_get_persistent_subgraph(entity_id: str, max_hops: int = 2):
    """Executes a database-backed multi-hop BFS traversal to retrieve the persistent neighborhood."""
    cluster = persistent_entity_graph.extract_neighborhood(entity_id, max_hops=max_hops)
    return cluster.model_dump()


@router.get("/entities/{entity_id}/lineage", summary="Retrieve complete chronological event history for an entity")
def api_get_entity_lineage(entity_id: str, limit: int = 50):
    """Reconstructs the full activity timeline from persistent generic_events and relationship edges."""
    return persistent_entity_graph.get_entity_lineage(entity_id, limit=limit)


@router.post("/entities/{entity_id}/quarantine", summary="Enforce persistent operational quarantine block")
def api_quarantine_entity(entity_id: str, reason: str = "Analyst / Policy Quarantine"):
    """Persistently marks entity as quarantined and locks further transactional permissions."""
    return persistent_entity_graph.quarantine_entity(entity_id, reason=reason)


# =============================================================================
# ALERT LIFECYCLE & ANALYST ACTION ENDPOINTS (Priorities 3 & 4)
# =============================================================================

from services.case_management.lifecycle import alert_lifecycle_manager
from services.case_management.actions import analyst_action_engine, ActionType
from libs.models.cases import CaseDisposition, CasePriority


@router.post("/alerts/process", summary="Process, deduplicate, and cluster an incoming risk alert")
def api_process_alert(payload: Dict[str, Any]):
    """Deduplicates alert against sliding window and correlates with active entity cases."""
    domain = payload.get("domain", "BANKING")
    primary_entity_id = payload.get("primary_entity_id") or payload.get("user_id")
    event_id = payload.get("event_id") or payload.get("transaction_id", f"EVT_{int(time.time()*1000)}")
    risk_score = float(payload.get("risk_score", 0.5))
    rule_hits = payload.get("rule_hits", ["RISK_ELEVATED"])
    title = payload.get("title")
    tenant_id = payload.get("tenant_id", "default")

    if not primary_entity_id:
        raise HTTPException(status_code=400, detail="primary_entity_id is required.")

    res = alert_lifecycle_manager.process_and_cluster_alert(
        domain=domain,
        primary_entity_id=primary_entity_id,
        event_id=event_id,
        risk_score=risk_score,
        rule_hits=rule_hits,
        title=title,
        tenant_id=tenant_id
    )
    return res


@router.get("/alerts/queue", summary="Fetch active triage alert queue")
def api_get_alerts_queue(limit: int = 50, tenant_id: Optional[str] = None):
    """Retrieves pending OPEN alerts from persistent database."""
    return {
        "active_alerts": alert_lifecycle_manager.get_active_alerts(limit=limit, tenant_id=tenant_id)
    }


@router.post("/cases/{case_id}/assign", summary="Assign an investigation case to an analyst")
def api_assign_case(case_id: int, payload: Dict[str, Any]):
    """Assigns case and advances status to IN_REVIEW with audit logging."""
    analyst = payload.get("analyst_username")
    operator = payload.get("operator", "admin")
    if not analyst:
        raise HTTPException(status_code=400, detail="analyst_username is required.")

    try:
        updated = analyst_action_engine.assign_case(case_id, analyst, operator=operator)
        return {"status": "ASSIGNED", "case": updated}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/cases/{case_id}/escalate", summary="Escalate case priority to P1")
def api_escalate_case(case_id: int, payload: Dict[str, Any]):
    """Elevates case priority and records justification."""
    reason = payload.get("reason", "Urgent anomaly escalation")
    operator = payload.get("operator", "lead_analyst")
    priority = payload.get("priority", "P1_CRITICAL")

    try:
        updated = analyst_action_engine.escalate_case(
            case_id=case_id,
            reason=reason,
            operator=operator,
            target_priority=CasePriority(priority)
        )
        return {"status": "ESCALATED", "case": updated}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/cases/{case_id}/resolve", summary="Resolve case with formal disposition and close alerts")
def api_resolve_case(case_id: int, payload: Dict[str, Any]):
    """Resolves case and automatically marks all linked alerts as RESOLVED."""
    disposition = payload.get("disposition", "CONFIRMED_FRAUD")
    notes = payload.get("resolution_notes", "Case investigation completed.")
    operator = payload.get("operator", "senior_analyst")

    try:
        disp_enum = CaseDisposition(disposition.upper())
        updated = analyst_action_engine.resolve_case(
            case_id=case_id,
            disposition=disp_enum,
            resolution_notes=notes,
            operator=operator
        )
        return {"status": "RESOLVED", "case": updated}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/actions/execute", summary="Execute operational policy remediation action")
def api_execute_action(payload: Dict[str, Any]):
    """Executes an action: QUARANTINE_ENTITY, TRIGGER_CHALLENGE_2FA, EXPORT_EVIDENCE_DOSSIER."""
    action_type = payload.get("action_type")
    entity_id = payload.get("entity_id")
    case_id = payload.get("case_id")
    reason = payload.get("reason", "Manual / Policy Enforcement")
    operator = payload.get("operator", "analyst")

    if not action_type or not entity_id:
        raise HTTPException(status_code=400, detail="action_type and entity_id are required.")

    try:
        act_enum = ActionType(action_type.upper())
        receipt = analyst_action_engine.execute_action(
            action_type=act_enum,
            entity_id=entity_id,
            case_id=case_id,
            reason=reason,
            operator=operator
        )
        return {"status": "SUCCESS", "receipt": receipt}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/actions/audit-log", summary="Get analyst action audit log")
def api_get_analyst_actions(limit: int = 50):
    """Retrieves immutable audit trail of analyst and policy actions."""
    return {
        "total_actions": len(analyst_action_engine.get_action_history(limit=limit)),
        "actions": analyst_action_engine.get_action_history(limit=limit)
    }


# =============================================================================
# PARAMETERIZED DOMAIN RULE PACKS & CALIBRATION (PRIORITY 5)
# =============================================================================
from services.domains.rule_packs import rule_pack_registry


@router.get("/rules/packs", summary="List all domain rule packs and versions")
def api_list_rule_packs():
    """Lists available versioned rule packs across Banking, Cyber, and E-Commerce."""
    packs = rule_pack_registry.list_all_packs()
    return {
        "total_packs": len(packs),
        "rule_packs": packs
    }


@router.get("/rules/packs/{domain}", summary="Get active rule pack for domain")
def api_get_rule_pack(domain: str, tenant_id: str = "default", version: Optional[str] = None):
    """Retrieves rule pack configuration, thresholds, and weights for a domain and tenant."""
    if version:
        pack = rule_pack_registry.get_pack(domain, version)
    else:
        pack = rule_pack_registry.get_pack_for_tenant(domain, tenant_id)
    if not pack:
        raise HTTPException(status_code=404, detail=f"Rule pack not found for domain: {domain}")
    return pack.model_dump()


@router.post("/rules/packs/{domain}/calibrate", summary="Dynamically calibrate rule pack weights and thresholds")
def api_calibrate_rule_pack(domain: str, payload: Dict[str, Any]):
    """Calibrates rule weights, parameters, or decision thresholds dynamically without code redeployment."""
    version = payload.get("version", "1.0.0")
    weights = payload.get("rule_weights")
    parameters = payload.get("parameters")
    thresholds = payload.get("decision_thresholds")
    new_version = payload.get("new_version")
    author = payload.get("author", "risk_operator")
    try:
        calibrated = rule_pack_registry.calibrate_pack(
            domain=domain,
            version=version,
            rule_weights=weights,
            parameters=parameters,
            decision_thresholds=thresholds,
            new_version=new_version,
            author=author
        )
        return {
            "status": "CALIBRATED",
            "pack": calibrated.model_dump()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/rules/packs/bind-tenant", summary="Bind a tenant to a specific rule pack version")
def api_bind_tenant_pack(payload: Dict[str, Any]):
    """Assigns a custom rule pack version to a tenant organization."""
    tenant_id = payload.get("tenant_id")
    domain = payload.get("domain")
    version = payload.get("version")
    if not tenant_id or not domain or not version:
        raise HTTPException(status_code=400, detail="tenant_id, domain, and version are required.")
    try:
        rule_pack_registry.bind_tenant_pack(tenant_id, domain, version)
        return {
            "status": "BOUND",
            "tenant_id": tenant_id,
            "domain": domain.upper(),
            "version": version
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# =============================================================================
# THREAT INTELLIGENCE SYNC & INDICATOR REGISTRY (PRIORITY 6)
# =============================================================================
from services.threat_intel.connector import threat_intel_connector, threat_intel_sync_worker


@router.get("/threat-intel/status", summary="Get threat intelligence sync status and telemetry")
def api_get_threat_intel_status():
    """Returns background sync worker status, offline fallback state, and IoC counts."""
    return threat_intel_sync_worker.get_worker_status()


@router.post("/threat-intel/sync", summary="Trigger manual threat intelligence feed sync")
def api_trigger_threat_intel_sync():
    """Forces an immediate synchronization cycle with external feeds with offline fallback."""
    res = threat_intel_sync_worker.trigger_immediate_sync()
    return res


@router.post("/threat-intel/indicators", summary="Register custom or dynamic TTL indicator")
def api_register_threat_indicator(payload: Dict[str, Any]):
    """Registers newly identified IoCs with optional automatic TTL expiration."""
    indicator = payload.get("indicator")
    ind_type = payload.get("indicator_type", "IP_ADDRESS")
    category = payload.get("category", "CUSTOM_BLOCKLIST")
    severity = payload.get("severity", "HIGH")
    ttl = payload.get("ttl_seconds")
    description = payload.get("description", "")
    
    if not indicator:
        raise HTTPException(status_code=400, detail="indicator is required.")
        
    if ttl:
        threat_intel_connector.add_indicator_with_ttl(
            indicator=indicator,
            indicator_type=ind_type,
            category=category,
            severity=severity,
            description=description,
            ttl_seconds=float(ttl)
        )
        return {"status": "REGISTERED_WITH_TTL", "indicator": indicator, "ttl_seconds": ttl}
    else:
        threat_intel_connector.add_custom_ioc(indicator, ind_type, category=category)
        return {"status": "REGISTERED_PERMANENT", "indicator": indicator}


@router.get("/threat-intel/check", summary="Check an indicator against threat intelligence feeds")
def api_check_indicator(value: str):
    """Scans an IP, domain, email, hash, or crypto wallet for threat attribution."""
    match = threat_intel_connector.check_indicator(value)
    if not match:
        return {"matched": False, "indicator": value}
    return {"matched": True, "details": match.model_dump()}


# =============================================================================
# CRYPTOGRAPHIC AUDIT & MODEL GOVERNANCE AUTOMATION (PRIORITY 7)
# =============================================================================
import numpy as np
from src.engine.audit_ledger import audit_ledger
from src.engine.canary_pipeline import CanaryModelEvaluator

canary_evaluator = CanaryModelEvaluator()


@router.get("/audit/verify", summary="Verify cryptographic SHA-256 Merkle chain integrity")
def api_verify_audit_ledger():
    """Validates entire cryptographic hash chain for tamper evidence."""
    return audit_ledger.verify_integrity()


@router.post("/audit/simulate-tampering", summary="Simulate ledger tampering for audit resilience demonstration")
def api_simulate_audit_tampering(payload: Optional[Dict[str, Any]] = None):
    """Simulates malicious database alteration to demonstrate instant tamper detection."""
    idx = payload.get("block_index") if payload else None
    return audit_ledger.simulate_tampering(block_index=idx)


@router.post("/audit/restore", summary="Cryptographically re-seal and restore audit ledger integrity")
def api_restore_audit_ledger():
    """Restores compromised ledger integrity and re-seals cryptographic hashes."""
    return audit_ledger.restore_and_reseal()


@router.get("/governance/canary", summary="Get champion/challenger canary shadow scoring telemetry")
def api_get_canary_telemetry():
    """Returns dual-inference shadow evaluation metrics and calibration divergence."""
    return canary_evaluator.get_telemetry()


@router.post("/governance/promote", summary="Zero-downtime hot promote Challenger to Champion")
def api_promote_challenger(payload: Optional[Dict[str, Any]] = None):
    """Promotes shadow model to active champion with cryptographic signing in Merkle audit ledger."""
    res = canary_evaluator.promote_challenger()
    return res


@router.post("/governance/rollback", summary="Rollback Champion model to previous version")
def api_rollback_champion():
    """Rolls back to previously active model version."""
    return canary_evaluator.rollback()






