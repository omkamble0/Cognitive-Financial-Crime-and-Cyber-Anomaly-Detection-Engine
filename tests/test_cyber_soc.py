"""
Unit and Integration Tests for CyberSOCEngine and MITRE ATT&CK Telemetry (Phase 8)
Author: Om Kamble
"""

import pytest
from src.engine.cyber_soc import CyberSOCEngine, haversine_distance, KNOWN_GEO_HUBS


def test_haversine_distance():
    # NYC to London is ~5,570 km
    nyc = KNOWN_GEO_HUBS["NYC"]
    lon = KNOWN_GEO_HUBS["LON"]
    dist = haversine_distance(nyc["lat"], nyc["lon"], lon["lat"], lon["lon"])
    assert 5500.0 < dist < 5650.0


def test_cyber_soc_initialization_and_telemetry():
    engine = CyberSOCEngine()
    telemetry = engine.get_soc_telemetry()
    assert telemetry["status"] == "online"
    assert telemetry["active_quarantines_count"] >= 4
    assert len(telemetry["corridors"]) >= 4
    assert "T1078.004" in telemetry["mitre_matrix"]
    assert "T1110.003" in telemetry["mitre_matrix"]


def test_quarantine_ip_and_release():
    engine = CyberSOCEngine()
    test_ip = "198.51.100.99"
    
    # Quarantine
    host = engine.quarantine_ip(
        ip=test_ip,
        reason="Test Brute Force Probe",
        technique_id="T1110.001",
        duration_seconds=300,
        threat_score=0.92
    )
    assert host.ip == test_ip
    assert host.is_active is True
    assert host.remaining_seconds > 0

    # Verify present in telemetry
    telemetry = engine.get_soc_telemetry()
    quarantined_ips = [h["ip"] for h in telemetry["quarantined_hosts"]]
    assert test_ip in quarantined_ips

    # Release
    released = engine.release_ip(test_ip)
    assert released is True
    assert engine.quarantined_hosts[test_ip].is_active is False


def test_simulate_impossible_travel():
    engine = CyberSOCEngine()
    inc = engine.simulate_impossible_travel("NYC", "TYO")
    assert inc.technique_id == "T1078.004"
    assert inc.calculated_speed_kmh > 850.0  # Must violate commercial airliner limit
    assert inc.distance_km > 10000.0
    assert inc.status == "QUARANTINED"
    assert inc.threat_score >= 0.70


def test_simulate_credential_stuffing():
    engine = CyberSOCEngine()
    inc = engine.simulate_credential_stuffing(bot_size=20)
    assert inc.technique_id == "T1110.003"
    assert inc.severity == "HIGH"
    assert inc.threat_score > 0.90
    assert inc.status == "QUARANTINED"


def test_simulate_headless_bot():
    engine = CyberSOCEngine()
    inc = engine.simulate_headless_bot()
    assert inc.technique_id == "T1059.006"
    assert "HEADLESS BROWSER" in inc.details
    assert inc.status == "INTERCEPTED"
