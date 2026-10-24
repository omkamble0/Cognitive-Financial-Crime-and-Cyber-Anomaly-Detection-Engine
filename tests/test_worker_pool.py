"""
Unit & Integration Tests for StreamWorkerPool, Idempotency, DLQ & Circuit Breaker
Author: Om Kamble
"""

import time
import uuid
import pytest
from src.streaming.worker_pool import StreamWorkerPool, CircuitBreaker, CircuitState
from src.db.database import (
    init_database,
    check_idempotency_key,
    record_idempotency_key,
    store_dead_letter_event,
    list_dead_letter_events,
    mark_dead_letter_replayed
)


@pytest.fixture(autouse=True)
def setup_db():
    init_database()


def test_circuit_breaker_logic():
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=0.2)
    assert cb.state == CircuitState.CLOSED
    assert cb.allow_request() is True

    # 2 failures - still closed
    cb.record_failure()
    cb.record_failure()
    assert cb.state == CircuitState.CLOSED

    # 3rd failure - trips to OPEN
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert cb.allow_request() is False

    # Wait for recovery timeout -> probe in HALF_OPEN
    time.sleep(0.25)
    assert cb.allow_request() is True
    assert cb.state == CircuitState.HALF_OPEN

    # Success restores to CLOSED
    cb.record_success()
    assert cb.state == CircuitState.CLOSED


def test_idempotency_persistence():
    key = f"test_key_{uuid.uuid4().hex[:10]}"
    assert check_idempotency_key(key) is None

    recorded = record_idempotency_key(
        idempotency_key=key,
        resource_type="PAYMENT",
        resource_id="tx_12345",
        status="COMPLETED",
        response_payload={"decision": "APPROVED", "score": 0.05}
    )
    assert recorded is True

    found = check_idempotency_key(key)
    assert found is not None
    assert found["idempotency_key"] == key
    assert found["payload"]["decision"] == "APPROVED"
    assert found["payload"]["score"] == 0.05


def test_dlq_storage_and_replay():
    evt_id = f"evt_{uuid.uuid4().hex[:8]}"
    raw = '{"amount": "corrupt_data", "currency": "XYZ"}'
    dlq_id = store_dead_letter_event(
        event_id=evt_id,
        domain="BANKING",
        raw_payload=raw,
        error_message="ValueError: invalid literal for float()",
        retry_count=3
    )
    assert dlq_id > 0

    pending = list_dead_letter_events(status="PENDING", limit=10)
    matched = [e for e in pending if e["event_id"] == evt_id]
    assert len(matched) == 1
    assert matched[0]["error_message"] == "ValueError: invalid literal for float()"

    # Mark replayed
    marked = mark_dead_letter_replayed(dlq_id, status="REPLAYED")
    assert marked is True

    updated_dlq = list_dead_letter_events(limit=50)
    replayed_entry = [e for e in updated_dlq if e["id"] == dlq_id]
    assert len(replayed_entry) == 1
    assert replayed_entry[0]["status"] == "REPLAYED"


def test_stream_worker_pool_lifecycle_and_deduplication():
    pool = StreamWorkerPool(num_workers=2)
    pool.start()
    assert pool.is_running is True

    idem_key = f"idem_{uuid.uuid4().hex[:12]}"
    sample_event = {
        "event_id": f"tx_{uuid.uuid4().hex[:8]}",
        "domain": "BANKING",
        "amount": 250.0,
        "currency": "USD",
        "user_id": "usr_test_worker_1",
        "ip_address": "192.168.1.50"
    }

    # 1. First Ingestion: processed normally
    res1 = pool.ingest_sync(sample_event, idempotency_key=idem_key, timeout=3.0)
    assert "decision" in res1
    assert res1.get("idempotent_replay") is not True

    # 2. Second Ingestion with same key: deduplicated from persistent store
    res2 = pool.ingest_sync(sample_event, idempotency_key=idem_key, timeout=3.0)
    assert res2.get("idempotent_replay") is True
    assert res2["decision"] == res1["decision"]

    metrics = pool.get_metrics()
    assert metrics["total_processed"] >= 1
    assert metrics["total_deduplicated"] >= 1
    assert metrics["active_workers"] == 2

    pool.stop()
    assert pool.is_running is False
