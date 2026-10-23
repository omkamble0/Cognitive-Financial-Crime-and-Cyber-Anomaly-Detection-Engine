"""
AegisNexus — Generic Event Ingestion & Normalization REST Endpoints
Author: Om Kamble
"""

from typing import Dict, Any, List
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
