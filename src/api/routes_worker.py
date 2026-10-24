"""
FinCipher AI — Streaming Worker Pool, DLQ & Case Lifecycle REST Endpoints
Author: Om Kamble
"""

import time
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Header, Request
from pydantic import BaseModel, Field

from src.streaming.worker_pool import stream_worker_pool
from src.engine.case_lifecycle import case_lifecycle_manager, InvalidStateTransitionError
from src.db.database import (
    list_dead_letter_events,
    list_action_dispatches,
    get_case_detail
)

router = APIRouter(prefix="/api/v1", tags=["Streaming Workers & Case Lifecycle"])


class IngestEventPayload(BaseModel):
    event_id: Optional[str] = None
    domain: Optional[str] = "BANKING"
    amount: Optional[float] = 0.0
    user_id: Optional[str] = "usr_default"
    currency: Optional[str] = "USD"
    ip_address: Optional[str] = "127.0.0.1"
    device_id: Optional[str] = None
    source: Optional[str] = "rest_api"
    tenant_id: Optional[str] = "default"
    raw_payload: Optional[Dict[str, Any]] = None


class CaseTransitionPayload(BaseModel):
    case_id: int
    target_status: str
    reason: str = "Transitioned via Analyst Investigation Console"
    disposition: Optional[str] = None
    operator: Optional[str] = "analyst_1"


class CaseAssignPayload(BaseModel):
    analyst_username: str
    operator: Optional[str] = "supervisor"


@router.get("/workers/status", summary="Worker pool operational telemetry")
def get_worker_status() -> Dict[str, Any]:
    """Returns worker health, concurrency, circuit state, and queue lag metrics."""
    return {
        "status": "HEALTHY",
        "timestamp": time.time(),
        "metrics": stream_worker_pool.get_metrics()
    }


@router.post("/workers/start", summary="Start streaming worker pool")
def start_workers() -> Dict[str, Any]:
    """Spawns concurrent worker threads if not running."""
    stream_worker_pool.start()
    return {"status": "RUNNING", "metrics": stream_worker_pool.get_metrics()}


@router.post("/workers/stop", summary="Stop streaming worker pool")
def stop_workers() -> Dict[str, Any]:
    """Stops worker threads gracefully."""
    stream_worker_pool.stop()
    return {"status": "STOPPED", "metrics": stream_worker_pool.get_metrics()}


@router.post("/workers/ingest", summary="Ingest event via worker pool with idempotency")
def ingest_event_stream(
    payload: Dict[str, Any],
    request: Request,
    x_idempotency_key: Optional[str] = Header(None, alias="X-Idempotency-Key")
) -> Dict[str, Any]:
    """
    Ingests event through the resilient worker pool:
    - Enforces idempotency via header or payload key
    - Dispatches to thread worker queue
    - Executes risk routing and automated action dispatch
    """
    idem_key = x_idempotency_key or payload.get("idempotency_key")
    try:
        result = stream_worker_pool.ingest_sync(payload, idempotency_key=idem_key, timeout=3.5)
        is_dedup = result.get("idempotent_replay", False)
        return {
            "status": "DEDUPLICATED" if is_dedup else "PROCESSED",
            "idempotency_key": idem_key,
            "evaluation": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Streaming ingestion error: {str(e)}")


@router.get("/dlq", summary="List Dead Letter Queue entries")
def get_dlq_entries(status: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:
    """Returns unparseable or repeatedly failing events in the DLQ."""
    events = list_dead_letter_events(status=status, limit=limit)
    return {
        "count": len(events),
        "events": events
    }


@router.post("/dlq/{dlq_id}/replay", summary="Replay a Dead Letter Queue entry")
def replay_dlq_entry(dlq_id: int) -> Dict[str, Any]:
    """Replays an event from the Dead Letter Queue back into the live worker pool."""
    replayed = stream_worker_pool.replay_dlq(dlq_id)
    if not replayed:
        raise HTTPException(status_code=404, detail=f"DLQ entry #{dlq_id} could not be found or replayed.")
    return {
        "status": "REPLAYED",
        "dlq_id": dlq_id,
        "message": f"Event #{dlq_id} successfully resubmitted to stream worker pool."
    }


@router.get("/actions/dispatches", summary="List automated action dispatches")
def get_action_dispatches(limit: int = 50) -> Dict[str, Any]:
    """Returns recent automated action dispatches (hold, quarantine, block)."""
    dispatches = list_action_dispatches(limit=limit)
    return {
        "count": len(dispatches),
        "dispatches": dispatches
    }


@router.post("/cases/transition", summary="Transition case lifecycle status")
def transition_case_state(payload: CaseTransitionPayload) -> Dict[str, Any]:
    """Validates state machine transitions, records SLA, and updates audit history."""
    try:
        updated = case_lifecycle_manager.transition_case(
            case_id=payload.case_id,
            target_status=payload.target_status,
            operator=payload.operator or "analyst",
            reason=payload.reason,
            disposition=payload.disposition
        )
        return {
            "status": "SUCCESS",
            "case": updated
        }
    except InvalidStateTransitionError as ste:
        raise HTTPException(status_code=400, detail=str(ste))
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Case transition error: {str(e)}")


@router.post("/cases/{case_id}/assign", summary="Assign case to analyst")
def assign_case_to_analyst(case_id: int, payload: CaseAssignPayload) -> Dict[str, Any]:
    """Assigns analyst and advances state to ASSIGNED."""
    try:
        updated = case_lifecycle_manager.assign_case(
            case_id=case_id,
            analyst_username=payload.analyst_username,
            operator=payload.operator or "supervisor"
        )
        return {
            "status": "SUCCESS",
            "case": updated
        }
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Assignment error: {str(e)}")


# =====================================================================
# Threat Intelligence Feeds & Production Action Execution
# =====================================================================

class ActionDispatchPayload(BaseModel):
    event_id: str
    action_type: str  # BLOCK_ACCOUNT, QUARANTINE_IP, HOLD_TRANSACTION, STEP_UP_2FA, NOTIFY_ANALYST
    target: str
    reason: Optional[str] = "Manual operational action executed by analyst"
    operator: Optional[str] = "analyst"
    metadata: Optional[Dict[str, Any]] = None


@router.post("/actions/dispatch", summary="Execute and record an operational action")
def dispatch_action(payload: ActionDispatchPayload) -> Dict[str, Any]:
    """Dispatches a production enforcement action (block, quarantine, hold, step-up)."""
    from src.db.database import record_action_dispatch
    rec_id = record_action_dispatch(
        event_id=payload.event_id,
        action_type=payload.action_type.upper(),
        target=payload.target,
        status="DISPATCHED",
        payload={"reason": payload.reason, "operator": payload.operator, "metadata": payload.metadata or {}},
        response={"dispatched_at": time.time(), "status": "APPLIED"}
    )
    return {
        "status": "SUCCESS",
        "action_id": rec_id,
        "action_type": payload.action_type.upper(),
        "target": payload.target,
        "message": f"Action '{payload.action_type}' successfully dispatched against target {payload.target}."
    }


@router.get("/threat-intel/lookup", summary="Lookup indicator in real-time threat intelligence index")
def lookup_threat_indicator(indicator: str) -> Dict[str, Any]:
    """Scans IP, domain, email, hash, or crypto wallet against live threat feeds & sanctions."""
    from services.threat_intel.connector import threat_intel_connector
    match = threat_intel_connector.check_indicator(indicator)
    if match:
        return {
            "indicator": indicator,
            "is_malicious": True,
            "category": match.threat_category,
            "severity": match.severity,
            "confidence": match.confidence,
            "description": match.description,
            "mitre_technique": match.mitre_technique,
            "attribution": match.attribution
        }
    return {
        "indicator": indicator,
        "is_malicious": False,
        "category": "CLEAN",
        "severity": "NONE",
        "confidence": 0.0,
        "description": "No active threat intelligence or sanction flags found."
    }


@router.get("/threat-intel/status", summary="Threat intelligence feed status & metrics")
def get_threat_intel_status() -> Dict[str, Any]:
    """Returns indicators count, category breakdown, query hit rates, and feed sync status."""
    from services.threat_intel.connector import threat_intel_connector
    return threat_intel_connector.get_metrics()


@router.post("/threat-intel/sync", summary="Synchronize threat feeds with external sources")
def sync_threat_feeds() -> Dict[str, Any]:
    """Pulls updated Tor exit lists, IP reputation blacklists, and sanctions feeds."""
    from services.threat_intel.connector import threat_intel_connector
    return threat_intel_connector.sync_external_feeds()

