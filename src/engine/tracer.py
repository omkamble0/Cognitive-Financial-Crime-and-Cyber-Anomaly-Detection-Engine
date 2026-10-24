"""
FinCipher AI — Distributed OpenTelemetry & W3C TraceContext Engine
Author: Om Kamble

Provides enterprise distributed tracing, W3C TraceContext propagation,
sub-millisecond span instrumentation, and in-memory trace collection compatible
with OpenTelemetry, Jaeger, and Grafana Tempo.
"""

import os
import time
import uuid
import contextvars
from contextlib import contextmanager
from typing import Dict, Any, List, Optional, Tuple
import threading
from dataclasses import dataclass, field, asdict

# Active span context variable for async/thread propagation
current_span_var: contextvars.ContextVar[Optional["Span"]] = contextvars.ContextVar("current_span", default=None)


def generate_trace_id() -> str:
    """Generates standard 32-character hex trace ID (16 bytes)."""
    return uuid.uuid4().hex


def generate_span_id() -> str:
    """Generates standard 16-character hex span ID (8 bytes)."""
    return uuid.uuid4().hex[:16]


@dataclass
class Span:
    name: str
    trace_id: str
    span_id: str
    parent_id: Optional[str] = None
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    duration_ms: Optional[float] = None
    status: str = "OK"  # OK, ERROR
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)

    def finish(self, status: Optional[str] = None):
        """Marks the span as complete and calculates elapsed duration."""
        if self.end_time is None:
            self.end_time = time.time()
            self.duration_ms = round((self.end_time - self.start_time) * 1000.0, 3)
        if status:
            self.status = status

    def set_attribute(self, key: str, value: Any):
        self.attributes[key] = value

    def add_event(self, name: str, attributes: Optional[Dict[str, Any]] = None):
        self.events.append({
            "name": name,
            "timestamp": time.time(),
            "attributes": attributes or {}
        })

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


class OpenTelemetryTracer:
    """
    Central distributed tracing coordinator.
    Complies with W3C TraceContext specification (RFC Level 1).
    """

    def __init__(self, service_name: str = "fincipher-core"):
        self.service_name = service_name
        self._spans_buffer: List[Span] = []
        self._max_buffer_size = 2000
        self._lock = threading.Lock()
        self.total_spans_created = 0
        self.total_errors = 0

    def parse_w3c_traceparent(self, header: Optional[str]) -> Tuple[str, Optional[str]]:
        """
        Parses W3C traceparent header:
        Format: {version}-{trace_id}-{parent_id}-{trace_flags}
        Example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
        """
        if not header:
            return generate_trace_id(), None

        parts = header.strip().split("-")
        if len(parts) == 4 and parts[0] == "00" and len(parts[1]) == 32 and len(parts[2]) == 16:
            return parts[1], parts[2]
        return generate_trace_id(), None

    def format_w3c_traceparent(self, trace_id: str, span_id: str, sampled: bool = True) -> str:
        """Formats W3C traceparent header."""
        flags = "01" if sampled else "00"
        return f"00-{trace_id}-{span_id}-{flags}"

    @contextmanager
    def start_span(
        self,
        name: str,
        parent_header: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None
    ):
        """Context manager creating a traced block with automatic finish and context propagation."""
        parent_span = current_span_var.get()

        if parent_span:
            trace_id = parent_span.trace_id
            parent_id = parent_span.span_id
        elif parent_header:
            trace_id, parent_id = self.parse_w3c_traceparent(parent_header)
        else:
            trace_id = generate_trace_id()
            parent_id = None

        span = Span(
            name=name,
            trace_id=trace_id,
            span_id=generate_span_id(),
            parent_id=parent_id,
            attributes=attributes or {}
        )
        span.set_attribute("service.name", self.service_name)

        token = current_span_var.set(span)
        with self._lock:
            self.total_spans_created += 1

        try:
            yield span
            span.finish(status="OK")
        except Exception as exc:
            span.finish(status="ERROR")
            span.set_attribute("error.message", str(exc))
            span.set_attribute("error.type", exc.__class__.__name__)
            with self._lock:
                self.total_errors += 1
            raise
        finally:
            current_span_var.reset(token)
            self._record_span(span)

    def _record_span(self, span: Span):
        """Records finished span into in-memory ring buffer."""
        with self._lock:
            self._spans_buffer.append(span)
            if len(self._spans_buffer) > self._max_buffer_size:
                self._spans_buffer.pop(0)

    def get_recent_spans(self, limit: int = 50, trace_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns recent captured spans, optionally filtered by trace_id."""
        with self._lock:
            if trace_id:
                matched = [s.to_dict() for s in self._spans_buffer if s.trace_id == trace_id]
            else:
                matched = [s.to_dict() for s in self._spans_buffer[-limit:]]
            return list(reversed(matched))

    def get_trace_timeline(self, trace_id: str) -> Dict[str, Any]:
        """Reconstructs the hierarchical trace tree for a specific trace_id."""
        with self._lock:
            spans = [s for s in self._spans_buffer if s.trace_id == trace_id]

        if not spans:
            return {"trace_id": trace_id, "found": False, "spans": []}

        min_start = min(s.start_time for s in spans)
        max_end = max((s.end_time or s.start_time) for s in spans)
        total_duration_ms = round((max_end - min_start) * 1000.0, 3)

        spans_dict = [
            {
                **s.to_dict(),
                "relative_start_ms": round((s.start_time - min_start) * 1000.0, 3)
            }
            for s in sorted(spans, key=lambda x: x.start_time)
        ]

        return {
            "trace_id": trace_id,
            "found": True,
            "span_count": len(spans),
            "total_duration_ms": total_duration_ms,
            "spans": spans_dict
        }

    def get_stats(self) -> Dict[str, Any]:
        """Provides telemetry for OpenTelemetry collector health."""
        with self._lock:
            return {
                "service_name": self.service_name,
                "total_spans_created": self.total_spans_created,
                "buffered_spans_count": len(self._spans_buffer),
                "total_errors": self.total_errors,
                "error_rate_pct": round((self.total_errors / max(1, self.total_spans_created)) * 100.0, 2)
            }


# Singleton Tracer instance
tracer = OpenTelemetryTracer(service_name="fincipher-core")
