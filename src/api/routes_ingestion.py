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


