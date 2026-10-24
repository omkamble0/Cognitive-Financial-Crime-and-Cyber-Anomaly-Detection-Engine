"""
FinCipher AI — Test Suite for Production Observability, OpenTelemetry Tracing & Kubernetes Health Probes
Author: Om Kamble
"""

import time
import uuid
import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.db.database import init_database
from src.engine.tracer import tracer, OpenTelemetryTracer
from src.streaming.worker_pool import stream_worker_pool

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_environment():
    init_database()


def test_kubernetes_liveness_and_readiness_probes():
    # 1. Liveness probes (/health, /livez, /health/live)
    for path in ["/health", "/livez", "/health/live"]:
        res = client.get(path)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "UP"
        assert "uptime_seconds" in data
        assert data["brand"] == "FinCipher AI"

    # 2. Readiness probes (/ready, /readyz, /health/ready)
    for path in ["/ready", "/readyz", "/health/ready"]:
        res = client.get(path)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "READY"
        checks = data["checks"]
        assert "ml_model_artifacts" in checks
        assert "streaming_worker_pool" in checks
        assert "siem_forwarder" in checks
        assert "action_enforcer" in checks
        assert "database" in checks
        assert "audit_ledger" in checks


def test_prometheus_exposition_format_and_metrics():
    res = client.get("/metrics")
    assert res.status_code == 200
    assert "text/plain" in res.headers.get("content-type", "")

    body = res.text
    # Core system uptime
    assert "fincipher_uptime_seconds" in body

    # Streaming worker pool
    assert "fincipher_worker_pool_active_workers" in body
    assert "fincipher_worker_pool_queue_depth" in body
    assert "fincipher_worker_pool_processed_total" in body
    assert "fincipher_worker_pool_deduplicated_total" in body
    assert "fincipher_worker_pool_dlq_total" in body
    assert "fincipher_worker_pool_circuit_intact" in body

    # Production action enforcement
    assert "fincipher_active_enforcements_total" in body
    assert "fincipher_active_blocked_accounts" in body
    assert "fincipher_active_quarantined_ips" in body

    # SIEM forwarder
    assert "fincipher_siem_forwarded_total" in body
    assert "fincipher_siem_queue_depth" in body

    # OpenTelemetry Traces
    assert "fincipher_traces_spans_total" in body

    # Threat Intel
    assert "fincipher_threat_intel_indicators_total" in body

    # Inference quantiles & transactions
    assert "fincipher_inference_latency_ms" in body
    assert "fincipher_transactions_total" in body
    assert "aegisflow_transactions_total" in body


def test_opentelemetry_tracer_unit():
    custom_tracer = OpenTelemetryTracer(service_name="test-service")

    # 1. Basic span creation
    with custom_tracer.start_span("test.operation", attributes={"env": "test"}) as span:
        assert len(span.trace_id) == 32
        assert len(span.span_id) == 16
        assert span.attributes["env"] == "test"
        span.add_event("checkpoint_1", {"items": 5})

    assert span.end_time is not None
    assert span.duration_ms >= 0.0
    assert span.status == "OK"
    assert len(span.events) == 1

    # 2. W3C traceparent inheritance
    incoming_parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    with custom_tracer.start_span("child.operation", parent_header=incoming_parent) as child:
        assert child.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
        assert child.parent_id == "00f067aa0ba902b7"

    # 3. Formatter
    formatted = custom_tracer.format_w3c_traceparent(child.trace_id, child.span_id)
    assert formatted.startswith("00-4bf92f3577b34da6a3ce929d0e0e4736-")
    assert formatted.endswith("-01")


def test_distributed_tracing_http_middleware_propagation():
    # 1. Request without traceparent generates new traceparent header
    res1 = client.get("/health/live")
    assert res1.status_code == 200
    assert "traceparent" in res1.headers
    assert "X-Trace-ID" in res1.headers
    traceparent_val = res1.headers["traceparent"]
    assert traceparent_val.startswith("00-")

    # 2. Request with explicit W3C traceparent propagates trace ID
    custom_trace_id = "e4a2c91837f64295b9a8421c00001234"
    custom_parent_span = "1122334455667788"
    incoming_header = f"00-{custom_trace_id}-{custom_parent_span}-01"

    res2 = client.get("/health/live", headers={"traceparent": incoming_header})
    assert res2.status_code == 200
    assert res2.headers["X-Trace-ID"] == custom_trace_id
    assert res2.headers["traceparent"].startswith(f"00-{custom_trace_id}-")


def test_tracing_rest_api_endpoints():
    # Execute a request to generate a trace
    gen_res = client.get("/health/live")
    trace_id = gen_res.headers.get("X-Trace-ID")
    assert trace_id is not None

    # 1. GET /api/v1/traces/recent
    recent_res = client.get("/api/v1/traces/recent?limit=20")
    assert recent_res.status_code == 200
    data = recent_res.json()
    assert data["status"] == "SUCCESS"
    assert data["count"] > 0
    assert any(s["trace_id"] == trace_id for s in data["spans"])

    # 2. GET /api/v1/traces/{trace_id}
    tree_res = client.get(f"/api/v1/traces/{trace_id}")
    assert tree_res.status_code == 200
    tree_data = tree_res.json()
    assert tree_data["found"] is True
    assert tree_data["trace_id"] == trace_id
    assert len(tree_data["spans"]) >= 1

    # 3. GET /api/v1/traces/stats/overview
    stats_res = client.get("/api/v1/traces/stats/overview")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert "total_spans_created" in stats
    assert stats["total_spans_created"] > 0


def test_worker_pool_pipeline_distributed_tracing():
    # Submit transaction through worker pool and verify trace_id and span_id attached
    event = {
        "event_id": f"evt_trace_{uuid.uuid4().hex[:6]}",
        "domain": "BANKING",
        "user_id": f"usr_trace_{uuid.uuid4().hex[:6]}",
        "amount": 420.0,
        "currency": "USD",
        "source_country": "US",
        "timestamp": time.time()
    }

    result = stream_worker_pool.ingest_sync(event, timeout=2.0)
    assert "trace_id" in result
    assert "span_id" in result
    assert len(result["trace_id"]) == 32
    assert len(result["span_id"]) == 16

    # Verify trace is queryable in tracer
    timeline = tracer.get_trace_timeline(result["trace_id"])
    assert timeline["found"] is True
    assert any("fincipher.worker.pipeline" in s["name"] for s in timeline["spans"])
