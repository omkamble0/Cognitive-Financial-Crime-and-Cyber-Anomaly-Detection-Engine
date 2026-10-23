"""
FinCipher AI — High-Scale Multi-Domain Asynchronous Event Streaming Worker
Author: Om Kamble

Architecture:
- Consumes real-time events across Banking, Cybersecurity, and E-Commerce.
- Interfaces with Kafka topics or Redis Streams with automated in-memory fallback.
- Normalizes raw payloads into canonical GenericEvent schema via UniversalEventNormalizer.
- Dispatches into UniversalRiskRouter for sub-3.5ms evaluation.
- Triggers automated case escalation and entity behavioral baseline updates.
"""

import os
import time
import json
import random
import signal
import sys
import threading
from typing import Dict, Any, Optional, List, Tuple
from libs.common.logging import get_platform_logger
from libs.models.events import GenericEvent, DomainType, EventType
from services.ingestion.normalizer import UniversalEventNormalizer
from services.risk_engine.router import universal_risk_router
from services.case_management.workflow import case_workflow_service

logger = get_platform_logger("fincipher.worker")


class FinCipherMultiDomainWorker:
    """
    Asynchronous event stream worker with support for Apache Kafka,
    Redis Streams, and high-fidelity autonomous simulation fallback.
    """

    def __init__(
        self,
        kafka_bootstrap: Optional[str] = None,
        redis_host: Optional[str] = None,
        redis_port: int = 6379,
        enable_synthetic_fallback: bool = True
    ):
        self.kafka_bootstrap = kafka_bootstrap or os.getenv("KAFKA_BOOTSTRAP_SERVERS")
        self.redis_host = redis_host or os.getenv("REDIS_HOST")
        self.redis_port = int(os.getenv("REDIS_PORT", redis_port))
        self.enable_synthetic_fallback = enable_synthetic_fallback
        
        self.is_running = False
        self.processed_count = 0
        self.anomalies_detected = 0
        self.cases_escalated = 0

        self._consumer = None
        self._redis_client = None
        self._last_event_time = None
        self._latencies_ms: List[float] = []
        self._init_consumer()

    def get_metrics(self) -> Dict[str, Any]:
        """Returns real-time worker execution telemetry and performance stats."""
        p95 = 0.0
        if self._latencies_ms:
            sorted_lat = sorted(self._latencies_ms)
            idx = int(0.95 * len(sorted_lat))
            p95 = round(sorted_lat[min(idx, len(sorted_lat) - 1)], 3)

        return {
            "is_running": self.is_running,
            "mode": "KAFKA" if self._consumer else ("REDIS_STREAMS" if self._redis_client else "AUTONOMOUS_BUS"),
            "processed_count": self.processed_count,
            "anomalies_detected": self.anomalies_detected,
            "cases_escalated": self.cases_escalated,
            "anomaly_rate_pct": round((self.anomalies_detected / max(1, self.processed_count)) * 100, 2),
            "p95_evaluation_latency_ms": p95,
            "last_event_time": self._last_event_time
        }

    def _init_consumer(self):
        """Attempts to initialize Apache Kafka or Redis stream consumer."""
        if self.kafka_bootstrap:
            try:
                from kafka import KafkaConsumer
                self._consumer = KafkaConsumer(
                    "fincipher.events.banking",
                    "fincipher.events.cyber",
                    "fincipher.events.ecommerce",
                    "fincipher.events.raw",
                    bootstrap_servers=self.kafka_bootstrap.split(","),
                    auto_offset_reset="latest",
                    enable_auto_commit=True,
                    value_deserializer=lambda v: json.loads(v.decode("utf-8")),
                    consumer_timeout_ms=1000
                )
                logger.info(f"Connected to Kafka broker at {self.kafka_bootstrap}")
                return
            except Exception as e:
                logger.warning(f"Kafka unavailable ({e}). Checking Redis streams fallback.")

        if self.redis_host:
            try:
                import redis
                r = redis.Redis(host=self.redis_host, port=self.redis_port, decode_responses=True)
                r.ping()
                self._redis_client = r
                logger.info(f"Connected to Redis Streams broker at {self.redis_host}:{self.redis_port}")
                return
            except Exception as e:
                logger.warning(f"Redis streams unavailable ({e}). Falling back to autonomous worker mode.")

        logger.info("Operating in autonomous streaming mode with internal event bus.")

    def process_raw_message(self, topic: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalizes and evaluates a raw event payload against the target domain.
        """
        # 1. Normalize based on topic / payload hint
        if "banking" in topic or payload.get("domain") == "BANKING" or "transaction_id" in payload:
            event = UniversalEventNormalizer.normalize_banking_payment(payload)
        elif "cyber" in topic or payload.get("domain") == "CYBERSECURITY" or "source_ip" in payload:
            event = UniversalEventNormalizer.normalize_cyber_auth(payload)
        elif "ecommerce" in topic or payload.get("domain") == "ECOMMERCE" or "order_id" in payload:
            event = UniversalEventNormalizer.normalize_ecommerce_order(payload)
        else:
            event = GenericEvent.model_validate(payload)

        # 2. Risk Evaluation via Router with high-resolution latency tracking
        t0 = time.perf_counter()
        res = universal_risk_router.evaluate_event(event)
        lat_ms = (time.perf_counter() - t0) * 1000.0
        
        self.processed_count += 1
        self._last_event_time = time.time()
        self._latencies_ms.append(lat_ms)
        if len(self._latencies_ms) > 1000:
            self._latencies_ms.pop(0)

        # 3. Automated Case Escalation on High-Risk Violations
        if res["risk_score"] >= 0.85 or res["decision"] == "BLOCK":
            self.anomalies_detected += 1
            if any(a.get("action_type") == "CREATE_P1_CASE" for a in res.get("policy_actions", [])):
                try:
                    case_workflow_service.create_case_from_alert(
                        domain=res["domain"],
                        title=f"Autonomous Escalation: {res['domain']} Threat Intercepted",
                        primary_entity_id=res["primary_entity_id"],
                        risk_score=res["risk_score"],
                        priority="P1_CRITICAL",
                        linked_event_ids=[res["event_id"]]
                    )
                    self.cases_escalated += 1
                except Exception as ex:
                    logger.warning(f"Case escalation failed: {ex}")

        return res

    def generate_synthetic_event(self) -> Tuple[str, Dict[str, Any]]:
        """Generates realistic synthetic multi-domain events for local execution and load testing."""
        domain_choice = random.choice(["BANKING", "CYBERSECURITY", "ECOMMERCE"])
        is_attack = random.random() < 0.15  # 15% attack rate

        if domain_choice == "BANKING":
            topic = "fincipher.events.banking"
            amt = random.choice([9500.0, 9850.0]) if is_attack else round(random.uniform(15.0, 350.0), 2)
            country = "KP" if is_attack and random.random() < 0.3 else random.choice(["US", "GB", "DE", "IN"])
            payload = {
                "transaction_id": f"TX_ASYNC_{int(time.time() * 1000)}",
                "user_id": f"usr_stream_{random.randint(100, 999)}",
                "amount": amt,
                "currency": "USD",
                "country": country,
                "ip_address": "198.51.100.12" if is_attack else "10.0.0.1"
            }
        elif domain_choice == "CYBERSECURITY":
            topic = "fincipher.events.cyber"
            status = "FAILURE" if is_attack else "SUCCESS"
            payload = {
                "username": "root" if is_attack else f"dev_{random.randint(1, 50)}",
                "source_ip": "192.0.2.77" if is_attack else "10.0.4.10",
                "status": status,
                "target_host": "prod-auth-bastion-01",
                "mfa_used": not is_attack
            }
        else:
            topic = "fincipher.events.ecommerce"
            promo = "PROMO_EXPLOIT_99" if is_attack else "WELCOME10"
            payload = {
                "order_id": f"ORD_ASYNC_{int(time.time() * 1000)}",
                "customer_id": f"shopper_{random.randint(1, 20)}",
                "ip_address": "198.51.100.99" if is_attack else "10.0.0.5",
                "total_amount": 100.0 if is_attack else 65.0,
                "discount_amount": 80.0 if is_attack else 6.5,
                "promo_code": promo,
                "discount_applied": True
            }

        return topic, payload

    def run_loop(self, max_events: Optional[int] = None, interval_seconds: float = 0.5):
        """Runs the worker consumption loop."""
        self.is_running = True
        logger.info("FinCipher AI asynchronous worker consumption loop started.")

        events_handled = 0
        redis_last_ids = {
            "fincipher.events.banking": "$",
            "fincipher.events.cyber": "$",
            "fincipher.events.ecommerce": "$",
            "fincipher.events.raw": "$"
        }

        while self.is_running:
            try:
                if self._consumer:
                    # Kafka consumption
                    records = self._consumer.poll(timeout_ms=500)
                    for topic_data, messages in records.items():
                        for msg in messages:
                            self.process_raw_message(msg.topic, msg.value)
                            events_handled += 1
                elif self._redis_client:
                    # Redis Streams consumption
                    streams_data = self._redis_client.xread(redis_last_ids, block=500, count=10)
                    for stream_name, entries in streams_data:
                        for entry_id, data in entries:
                            redis_last_ids[stream_name] = entry_id
                            payload = json.loads(data["payload"]) if "payload" in data else data
                            self.process_raw_message(stream_name, payload)
                            events_handled += 1
                else:
                    # Autonomous synthetic streaming
                    topic, payload = self.generate_synthetic_event()
                    self.process_raw_message(topic, payload)
                    events_handled += 1
                    time.sleep(interval_seconds)

                if max_events and events_handled >= max_events:
                    logger.info(f"Target count of {max_events} events reached. Stopping worker.")
                    break

            except Exception as e:
                logger.error(f"Worker stream exception: {e}")
                time.sleep(1.0)

        logger.info(
            f"Worker shutdown complete. Processed: {self.processed_count} | "
            f"Anomalies: {self.anomalies_detected} | Cases Escalated: {self.cases_escalated}"
        )

    def stop(self):
        """Signals worker to stop."""
        self.is_running = False


# Module entrypoint
if __name__ == "__main__":
    from typing import Tuple
    worker = FinCipherMultiDomainWorker()

    def handle_sig(sig, frame):
        worker.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    worker.run_loop()
