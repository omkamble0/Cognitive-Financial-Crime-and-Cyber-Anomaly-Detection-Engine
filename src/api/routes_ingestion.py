"""
FinCipher AI — Generic Event Ingestion & Normalization REST Endpoints
Author: Om Kamble
"""

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




