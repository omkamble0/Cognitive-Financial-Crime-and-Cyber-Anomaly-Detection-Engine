"""
FinCipher AI — Production Event Pipeline & Persistent Entity Graph Tests
Author: Om Kamble

Validates Priority 1 & 2 Operational Systems:
1. RealTimeIngestionPipeline bounded buffer, backpressure strategies, and DLQ handling
2. PersistentEntityGraph database-backed multi-hop BFS and historical timeline reconstruction
3. Live REST API endpoints for pipeline queue telemetry and entity forensic lineage
"""

import time
import unittest
from fastapi.testclient import TestClient
from apps.api.main import app

from services.ingestion.pipeline import RealTimeIngestionPipeline, BackpressureStrategy
from services.graph_analytics.persistent_graph import persistent_entity_graph
from src.db.database import get_entity, get_entity_events_db, get_entity_relationships_db


class TestPipelineAndPersistentGraph(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_pipeline_bounded_buffer_and_draining(self):
        """Validates real-time buffer enqueuing, async draining, and database persistence."""
        pipe = RealTimeIngestionPipeline(capacity=200, batch_size=20, batch_timeout_ms=20)
        pipe.start()

        # Enqueue 25 multi-domain events
        for i in range(25):
            accepted = pipe.enqueue({
                "transaction_id": f"TX_PIPE_{i}_{int(time.time()*1000)}",
                "user_id": f"usr_pipeline_{i % 5}",
                "amount": 150.0 + (i * 10),
                "currency": "USD",
                "country": "US"
            }, domain="BANKING")
            self.assertTrue(accepted)

        # Allow worker micro-batch draining
        time.sleep(0.3)
        metrics = pipe.get_metrics()
        pipe.stop()

        self.assertGreaterEqual(metrics["total_enqueued"], 25)
        self.assertGreaterEqual(metrics["total_processed"], 20)
        self.assertEqual(metrics["total_dropped"], 0)
        self.assertEqual(metrics["dlq_size"], 0)

    def test_pipeline_backpressure_reject_new(self):
        """Validates REJECT_NEW strategy when queue is saturated."""
        # Create pipeline without starting worker so queue stays full
        small_pipe = RealTimeIngestionPipeline(capacity=5, backpressure=BackpressureStrategy.REJECT_NEW)
        
        # Fill queue
        for i in range(5):
            res = small_pipe.enqueue({"tx": i}, domain="BANKING")
            self.assertTrue(res)

        # 6th element must be rejected
        rejected = small_pipe.enqueue({"tx": 999}, domain="BANKING")
        self.assertFalse(rejected)
        metrics = small_pipe.get_metrics()
        self.assertEqual(metrics["total_dropped"], 1)

    def test_pipeline_dead_letter_queue(self):
        """Validates that corrupted payloads are routed to Dead-Letter Queue without crashing worker."""
        pipe = RealTimeIngestionPipeline(capacity=50, batch_size=10, batch_timeout_ms=10)
        pipe.start()

        # Enqueue corrupted payload that causes normalization failure
        pipe.enqueue({"invalid_raw": True, "domain": "UNKNOWN_DOMAIN_123"}, domain=None)

        time.sleep(0.15)
        pipe.stop()

        dlq_records = pipe.get_dlq_records()
        self.assertGreaterEqual(len(dlq_records), 1)
        self.assertIn("error", dlq_records[0])

    def test_persistent_entity_graph_and_multihop_bfs(self):
        """Validates persistent database-backed entity storage, multi-hop BFS, and syndicate detection."""
        # Record colluding identities sharing a common device infrastructure
        shared_dev = f"dev_shared_{int(time.time()*1000)}"
        user_a = f"usr_ring_a_{int(time.time()*1000)}"
        user_b = f"usr_ring_b_{int(time.time()*1000)}"
        user_c = f"usr_ring_c_{int(time.time()*1000)}"

        # Persist edges to database
        persistent_entity_graph.record_edge(user_a, "USER", shared_dev, "DEVICE", "SHARED_HARDWARE")
        persistent_entity_graph.record_edge(user_b, "USER", shared_dev, "DEVICE", "SHARED_HARDWARE")
        persistent_entity_graph.record_edge(user_c, "USER", shared_dev, "DEVICE", "SHARED_HARDWARE")

        # Multi-hop BFS from user_a should reach user_b and user_c via shared_dev
        connected = persistent_entity_graph.find_connected_entities(user_a, max_hops=2)
        self.assertIn(shared_dev, connected)
        self.assertIn(user_b, connected)
        self.assertIn(user_c, connected)

        # Extract complete cluster and verify syndicate ring detection
        cluster = persistent_entity_graph.extract_neighborhood(user_a, max_hops=2)
        self.assertGreaterEqual(cluster.total_nodes, 4)
        self.assertTrue(cluster.is_syndicate)
        self.assertEqual(cluster.syndicate_type, "COLLUDING_IDENTITIES_SHARED_INFRASTRUCTURE")

    def test_entity_lineage_and_quarantine(self):
        """Validates historical event timeline reconstruction and operational quarantine."""
        test_user = f"usr_lineage_{int(time.time()*1000)}"
        persistent_entity_graph.record_node(test_user, "USER", domain="BANKING", risk_score=0.45)

        # Verify initial profile
        ent = get_entity(test_user)
        self.assertIsNotNone(ent)
        self.assertFalse(ent["is_quarantined"])

        # Quarantine entity
        q_res = persistent_entity_graph.quarantine_entity(test_user, reason="Confirmed Synthetic Identity Ring")
        self.assertEqual(q_res["status"], "QUARANTINED")

        # Verify profile updated persistently in database
        updated_ent = get_entity(test_user)
        self.assertTrue(updated_ent["is_quarantined"])
        self.assertEqual(updated_ent["risk_score"], 0.99)

        # Fetch lineage
        lineage = persistent_entity_graph.get_entity_lineage(test_user)
        self.assertEqual(lineage["entity_id"], test_user)
        self.assertTrue(lineage["entity_profile"]["is_quarantined"])

    def test_pipeline_and_graph_rest_endpoints(self):
        """Validates live API endpoints for pipeline queueing and persistent graph queries."""
        # 1. Enqueue via API
        res_eq = self.client.post(
            "/api/v1/events/pipeline/enqueue?domain=BANKING",
            json={
                "transaction_id": f"TX_API_PIPE_{int(time.time()*1000)}",
                "user_id": "usr_api_stream",
                "amount": 250.0,
                "currency": "USD"
            }
        )
        self.assertEqual(res_eq.status_code, 200)
        self.assertEqual(res_eq.json()["status"], "ENQUEUED")

        # 2. Pipeline metrics API
        res_m = self.client.get("/api/v1/events/pipeline/metrics")
        self.assertEqual(res_m.status_code, 200)
        data_m = res_m.json()
        self.assertIn("queue_depth", data_m)
        self.assertIn("total_enqueued", data_m)

        # 3. DLQ API
        res_dlq = self.client.get("/api/v1/events/pipeline/dlq")
        self.assertEqual(res_dlq.status_code, 200)
        self.assertIn("records", res_dlq.json())

        # 4. Quarantine API
        res_q = self.client.post("/api/v1/events/entities/usr_api_stream/quarantine?reason=Test+Quarantine")
        self.assertEqual(res_q.status_code, 200)
        self.assertEqual(res_q.json()["status"], "QUARANTINED")

        # 5. Persistent graph API
        res_pg = self.client.get("/api/v1/events/entities/usr_api_stream/persistent-graph?max_hops=2")
        self.assertEqual(res_pg.status_code, 200)
        self.assertIn("nodes", res_pg.json())

        # 6. Entity lineage API
        res_lin = self.client.get("/api/v1/events/entities/usr_api_stream/lineage")
        self.assertEqual(res_lin.status_code, 200)
        self.assertEqual(res_lin.json()["entity_id"], "usr_api_stream")


if __name__ == "__main__":
    unittest.main()
