"""
AegisFlow — Asynchronous Two-Phase Enrichment Engine
Author: Om Kamble

Decouples the critical payment authorization path (<1.2ms SLA) from heavy secondary enrichment:
- Phase 1 (Synchronous In-Line): Fast ML + Rule authorization returned immediately to client.
- Phase 2 (Asynchronous Worker Pool): Non-blocking execution of Graph updates,
  Concept Drift tracking, Merkle Audit block hashing, and WebSocket broadcast.
"""

import time
import queue
import threading
from typing import Dict, Any, Optional, Callable, List
from concurrent.futures import ThreadPoolExecutor


class AsyncEnrichmentEngine:
    """
    High-Throughput Asynchronous Two-Phase Event Dispatcher.
    Buffers and processes secondary financial telemetry without blocking the payment gateway.
    """
    def __init__(self, max_queue_size: int = 50_000, num_workers: int = 4):
        self.max_queue_size = max_queue_size
        self.num_workers = num_workers
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._is_running = True
        self._processed_count = 0
        self._dropped_count = 0
        self._lock = threading.Lock()
        self._enrich_latencies: List[float] = []

        # Start worker daemon threads
        self._threads: List[threading.Thread] = []
        for i in range(num_workers):
            t = threading.Thread(target=self._worker_loop, name=f"AegisAsyncWorker-{i}", daemon=True)
            t.start()
            self._threads.append(t)

    def _worker_loop(self):
        """Continuous consumer loop processing background enrichment tasks."""
        while self._is_running:
            try:
                task = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                t0 = time.perf_counter()
                handler = task.get("handler")
                payload = task.get("payload")
                if callable(handler) and payload is not None:
                    handler(payload)

                elapsed_ms = (time.perf_counter() - t0) * 1000
                with self._lock:
                    self._processed_count += 1
                    self._enrich_latencies.append(elapsed_ms)
                    if len(self._enrich_latencies) > 200:
                        self._enrich_latencies.pop(0)
            except Exception as e:
                # Catch worker errors so threads never die
                pass
            finally:
                self._queue.task_done()

    def enqueue(self, handler: Callable[[Dict[str, Any]], None], payload: Dict[str, Any]) -> bool:
        """
        Non-blocking enqueue for background enrichment.
        Returns True if enqueued, False if backpressure buffer is full.
        """
        try:
            self._queue.put_nowait({"handler": handler, "payload": payload})
            return True
        except queue.Full:
            with self._lock:
                self._dropped_count += 1
            return False

    def wait_for_drain(self, timeout_sec: float = 2.0):
        """Synchronously waits for all enqueued tasks to complete (useful for tests)."""
        deadline = time.time() + timeout_sec
        while not self._queue.empty() and time.time() < deadline:
            time.sleep(0.01)

    def get_stats(self) -> Dict[str, Any]:
        """Returns worker pool metrics and queue depth."""
        with self._lock:
            avg_lat = round(sum(self._enrich_latencies) / (len(self._enrich_latencies) or 1), 3)
            return {
                "active_workers": self.num_workers,
                "current_queue_depth": self._queue.qsize(),
                "max_queue_capacity": self.max_queue_size,
                "total_processed": self._processed_count,
                "total_dropped": self._dropped_count,
                "avg_enrich_latency_ms": avg_lat,
                "is_healthy": (self._queue.qsize() < (self.max_queue_size * 0.90))
            }


# Global singleton instance
async_enricher = AsyncEnrichmentEngine()
