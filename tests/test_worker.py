"""
FinCipher AI — Multi-Domain Asynchronous Worker Unit Tests
Author: Om Kamble
"""

import unittest
from apps.worker.worker import FinCipherMultiDomainWorker


class TestWorkerStreaming(unittest.TestCase):
    def test_worker_processing_banking_event(self):
        worker = FinCipherMultiDomainWorker(enable_synthetic_fallback=True)
        res = worker.process_raw_message("fincipher.events.banking", {
            "transaction_id": "TX_WORKER_UNIT_01",
            "user_id": "usr_worker_test",
            "amount": 9500.0,
            "currency": "USD"
        })
        self.assertEqual(res["domain"], "BANKING")
        self.assertGreaterEqual(res["risk_score"], 0.80)
        self.assertIn("AML_SUSPECTED_STRUCTURING_CTR_AVOIDANCE", res["rule_hits"])
        self.assertGreaterEqual(worker.processed_count, 1)

    def test_worker_synthetic_event_generation_and_loop(self):
        worker = FinCipherMultiDomainWorker(enable_synthetic_fallback=True)
        topic, payload = worker.generate_synthetic_event()
        self.assertIn("fincipher.events", topic)
        self.assertIsInstance(payload, dict)

        # Run 3 events
        worker.run_loop(max_events=3, interval_seconds=0.01)
        self.assertEqual(worker.processed_count, 3)


if __name__ == "__main__":
    unittest.main()
