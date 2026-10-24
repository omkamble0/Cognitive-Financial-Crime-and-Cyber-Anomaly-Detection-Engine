"""
FinCipher AI — Comprehensive Tests for Enterprise Streaming Connectors & Threat Watchlist Sync
Author: Om Kamble
"""

import time
import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.engine.threat_watchlist_sync import threat_watchlist_sync, ThreatWatchlistSyncEngine
from src.streaming.connectors import (
    streaming_connector_manager,
    KafkaStreamingConnector,
    RabbitMQStreamingConnector,
    AWSSQSStreamingConnector
)
from src.streaming.worker_pool import streaming_worker_pool
from src.engine.action_enforcer import action_enforcer


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


class TestThreatWatchlistSync:
    """Tests for ThreatWatchlistSyncEngine and Bloom Filter indexing."""

    def test_baseline_watchlists_populated(self):
        totals = threat_watchlist_sync.get_totals()
        assert totals["ofac_entities"] >= 8
        assert totals["tor_exit_nodes"] >= 16
        assert totals["malicious_c2_ips"] >= 6
        assert totals["darknet_wallets"] >= 5
        assert totals["total_indicators"] >= 35

    def test_ofac_entity_match(self):
        match = threat_watchlist_sync.check_entity("VLADIMIR ROSTOV")
        assert match is not None
        assert match.is_match is True
        assert match.category == "OFAC_SDN"
        assert match.severity == "CRITICAL"
        assert match.risk_boost >= 0.95

        # Substring / Alias match
        match_alias = threat_watchlist_sync.check_entity("ROSTOV INVESTMENTS")
        assert match_alias is not None
        assert match_alias.category == "OFAC_SDN"

    def test_tor_exit_node_match(self):
        match = threat_watchlist_sync.check_ip("185.220.101.5")
        assert match is not None
        assert match.is_match is True
        assert match.category == "TOR_EXIT_NODE"
        assert match.severity == "HIGH"
        assert match.risk_boost == 0.65

    def test_malicious_c2_ip_match(self):
        match = threat_watchlist_sync.check_ip("45.154.255.89")
        assert match is not None
        assert match.is_match is True
        assert match.category == "MALICIOUS_C2"
        assert match.severity == "CRITICAL"
        assert "Cobalt Strike" in match.details

    def test_clean_indicator_negative(self):
        assert threat_watchlist_sync.check_ip("8.8.8.8") is None
        assert threat_watchlist_sync.check_entity("John Safe Doe") is None
        assert threat_watchlist_sync.check_crypto_wallet("0x0000000000000000000000000000000000000000") is None

    def test_darknet_wallet_match(self):
        match = threat_watchlist_sync.check_crypto_wallet("0xd90e2f925da726b50c4ed8d0fb90ad053324f31b")
        assert match is not None
        assert match.category == "DARKNET_CRYPTO"
        assert "Tornado.Cash" in match.details

    def test_sync_cycle_updates(self):
        initial_cycle = threat_watchlist_sync.sync_counter
        res = threat_watchlist_sync.sync_all()
        assert res["status"] == "SUCCESS"
        assert res["sync_cycle"] > initial_cycle
        assert res["totals"]["total_indicators"] >= threat_watchlist_sync.get_totals()["total_indicators"]

    def test_inspect_event_multi_dimensional(self):
        event = {
            "user_id": "VLADIMIR ROSTOV",
            "ip_address": "185.220.101.5",
            "wallet_address": "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
            "amount": 50000.0
        }
        matches = threat_watchlist_sync.inspect_event(event)
        assert len(matches) >= 3
        categories = {m.category for m in matches}
        assert "OFAC_SDN" in categories
        assert "TOR_EXIT_NODE" in categories
        assert "DARKNET_CRYPTO" in categories


class TestStreamingConnectors:
    """Tests for multi-protocol enterprise streaming broker connectors."""

    def test_connectors_registered(self):
        all_status = streaming_connector_manager.get_all_status()
        assert len(all_status) >= 3
        types = {c["connector_type"] for c in all_status}
        assert "KAFKA" in types
        assert "RABBITMQ" in types
        assert "AWS_SQS" in types

    def test_connector_pause_and_resume(self):
        kafka = streaming_connector_manager.get_connector("conn-kafka-prod")
        assert kafka is not None

        streaming_connector_manager.control_connector("conn-kafka-prod", "pause")
        assert kafka.status == "PAUSED"

        streaming_connector_manager.control_connector("conn-kafka-prod", "resume")
        assert kafka.status == "RUNNING"

    def test_test_burst_injection(self):
        kafka = streaming_connector_manager.get_connector("conn-kafka-prod")
        initial_ingested = kafka.messages_ingested

        res = streaming_connector_manager.control_connector("conn-kafka-prod", "test_burst")
        assert res["success"] is True
        assert res["injected_count"] == 10
        assert kafka.messages_ingested == initial_ingested + 10


class TestWorkerPipelineWatchlistIntegration:
    """Tests that inbound events matching watchlists trigger immediate enforcement and SIEM forwarding."""

    def test_ofac_event_triggers_immediate_sanctions_freeze(self):
        target_name = "DARK_MATRIX_SYNDICATE"
        # Ensure target is clean from previous runs
        action_enforcer._active_blocked_accounts.pop(target_name, None)

        event = {
            "user_id": target_name,
            "amount": 250000.0,
            "currency": "USD",
            "domain": "BANKING",
            "ip_address": "104.244.72.115",
            "idempotency_key": f"test_ofac_{int(time.time()*1000)}"
        }
        result = streaming_worker_pool.ingest_sync(event, idempotency_key=event["idempotency_key"])
        assert result["decision"] == "BLOCK"
        assert result["risk_score"] == 1.0
        assert result["severity"] == "CRITICAL"
        assert result.get("watchlist_match") is True or result.get("preflight_blocked") is True
        assert "OFAC" in str(result.get("rule_hits", [])) or "ENFORCEMENT" in str(result.get("rule_hits", []))

        # Verify Action Enforcer recorded the enforcement
        enforcements = action_enforcer.list_active_enforcements()
        ofac_enforcements = [e for e in enforcements.get("blocked_accounts", []) if e.get("account_id") == target_name]
        assert len(ofac_enforcements) >= 1

    def test_tor_ip_event_boosts_risk_and_flags_watchlist(self):
        event = {
            "user_id": "regular_user_99",
            "amount": 450.0,
            "currency": "USD",
            "domain": "BANKING",
            "ip_address": "185.220.101.6",  # Tor exit node
            "idempotency_key": f"test_tor_{int(time.time()*1000)}"
        }
        result = streaming_worker_pool.ingest_sync(event, idempotency_key=event["idempotency_key"])
        assert "watchlist_matches" in result
        assert result["risk_score"] >= 0.65
        assert any("TOR_EXIT_NODE" in hit for hit in result.get("rule_hits", []))


class TestConnectorAndWatchlistEndpoints:
    """Tests FastAPI REST endpoints for connectors and threat watchlists."""

    def test_get_connectors_status_endpoint(self, client):
        resp = client.get("/api/v1/connectors/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "SUCCESS"
        assert len(data["connectors"]) >= 3

    def test_control_connector_endpoint(self, client):
        resp = client.post("/api/v1/connectors/conn-rabbitmq-events/control", json={"action": "test_burst"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["injected_count"] == 10

    def test_watchlists_overview_endpoint(self, client):
        resp = client.get("/api/v1/threat-intel/watchlists/overview")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "SUCCESS"
        assert data["totals"]["total_indicators"] >= 35

    def test_watchlists_sync_endpoint(self, client):
        resp = client.post("/api/v1/threat-intel/watchlists/sync")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "SUCCESS"
        assert "sync_cycle" in data

    def test_watchlists_search_endpoint(self, client):
        resp = client.get("/api/v1/threat-intel/watchlists/search?q=185.220.101.5")
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_hit"] is True
        assert len(data["matches"]) >= 1
        assert data["matches"][0]["category"] == "TOR_EXIT_NODE"

    def test_watchlists_check_endpoint(self, client):
        payload = {
            "entity_name": "PHOENIX CYPHER VENTURES",
            "ip_address": "45.154.255.89"
        }
        resp = client.post("/api/v1/threat-intel/watchlists/check", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_match"] is True
        assert data["matches_count"] >= 2
