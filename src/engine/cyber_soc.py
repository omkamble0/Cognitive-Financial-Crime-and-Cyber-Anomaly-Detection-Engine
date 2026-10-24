"""
FinCipher AI — Enterprise Cybersecurity Threat Intelligence & SOC Stream Engine (Phase 8)
Author: Om Kamble

Provides real-time MITRE ATT&CK telemetry, impossible travel corridors,
brute-force rate limiting, and automated edge IP quarantine.
"""

import time
import math
import random
import threading
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculates great-circle distance between two GPS coordinates in kilometers."""
    R = 6371.0  # Earth radius in km
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


KNOWN_GEO_HUBS = {
    "NYC": {"city": "New York", "country": "US", "lat": 40.7128, "lon": -74.0060},
    "LON": {"city": "London", "country": "GB", "lat": 51.5074, "lon": -0.1278},
    "FRA": {"city": "Frankfurt", "country": "DE", "lat": 50.1109, "lon": 8.6821},
    "TYO": {"city": "Tokyo", "country": "JP", "lat": 35.6762, "lon": 139.6503},
    "SGP": {"city": "Singapore", "country": "SG", "lat": 1.3521, "lon": 103.8198},
    "DXB": {"city": "Dubai", "country": "AE", "lat": 25.2048, "lon": 55.2708},
    "BOM": {"city": "Mumbai", "country": "IN", "lat": 19.0760, "lon": 72.8777},
    "SYD": {"city": "Sydney", "country": "AU", "lat": -33.8688, "lon": 151.2093},
    "SFO": {"city": "San Francisco", "country": "US", "lat": 37.7749, "lon": -122.4194},
    "AMS": {"city": "Amsterdam", "country": "NL", "lat": 52.3676, "lon": 4.9041}
}


@dataclass
class CyberIncident:
    incident_id: str
    timestamp: float
    technique_id: str
    technique_name: str
    tactic: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    entity_id: str
    source_ip: str
    source_location: Dict[str, Any]
    target_location: Dict[str, Any]
    calculated_speed_kmh: float
    distance_km: float
    time_elapsed_minutes: float
    status: str  # QUARANTINED, INTERCEPTED, CHALLENGED, BLOCKED, MONITORING
    threat_score: float
    details: str


@dataclass
class QuarantinedHost:
    ip: str
    reason: str
    technique_id: str
    quarantined_at: float
    expires_at: float
    threat_score: float
    country: str
    asn: str
    is_active: bool = True

    @property
    def remaining_seconds(self) -> int:
        return max(0, int(self.expires_at - time.time()))


class CyberSOCEngine:
    """Enterprise Cybersecurity Security Operations Center (SOC) Engine."""

    def __init__(self):
        self._lock = threading.Lock()
        self.incidents: List[CyberIncident] = []
        self.quarantined_hosts: Dict[str, QuarantinedHost] = {}
        self.mitre_stats: Dict[str, Dict[str, Any]] = {
            "T1078.004": {"name": "Impossible Travel (Cloud Accounts)", "tactic": "Initial Access", "count": 0, "status": "ACTIVE_INTERCEPT"},
            "T1110.003": {"name": "Credential Stuffing / BIN Testing", "tactic": "Credential Access", "count": 0, "status": "ELEVATED_THREAT"},
            "T1110.001": {"name": "Password Spray & Login Bursts", "tactic": "Credential Access", "count": 0, "status": "ACTIVE_INTERCEPT"},
            "T1059.006": {"name": "Headless Botnet & Scripting", "tactic": "Execution", "count": 0, "status": "MONITORING"},
            "T1090.003": {"name": "Tor & Multi-Hop Anonymizers", "tactic": "Defense Evasion", "count": 0, "status": "ACTIVE_INTERCEPT"},
            "T1657": {"name": "Mule Liquidity Siphoning", "tactic": "Impact", "count": 0, "status": "MONITORING"}
        }
        self._seed_baseline_incidents()

    def _seed_baseline_incidents(self):
        """Seeds realistic baseline cyber incidents and quarantined malicious IPs."""
        now = time.time()

        # Seed initial quarantined IPs
        initial_quarantines = [
            ("185.220.101.42", "MITRE T1110.003: Distributed Credential Stuffing (42 failed auths/min)", "T1110.003", 0.94, "NL", "AS208323 TOR-EXIT", 600),
            ("194.26.29.112", "MITRE T1078.004: Impossible Travel Relay (JFK -> HND in 6 mins)", "T1078.004", 0.98, "RU", "AS49505 OOO Network", 1200),
            ("45.154.255.89", "MITRE T1059.006: Headless Puppeteer Script Scraping & BIN Testing", "T1059.006", 0.88, "RO", "AS200019 Datacenter Proxy", 900),
            ("103.145.13.204", "MITRE T1110.001: Password Spraying on Corporate SSO Endpoint", "T1110.001", 0.91, "SG", "AS13335 Cloudflare Gateway", 1800),
        ]
        for ip, reason, tech, score, country, asn, ttl in initial_quarantines:
            self.quarantined_hosts[ip] = QuarantinedHost(
                ip=ip,
                reason=reason,
                technique_id=tech,
                quarantined_at=now - 120,
                expires_at=now + ttl,
                threat_score=score,
                country=country,
                asn=asn,
                is_active=True
            )
            if tech in self.mitre_stats:
                self.mitre_stats[tech]["count"] += 1

        # Seed initial impossible travel corridors
        corridor_pairs = [
            ("NYC", "TYO", "usr_sec_corp_09", "185.220.101.42", 10850.0, 8.5),
            ("LON", "SGP", "usr_fin_wealth_41", "194.26.29.112", 10880.0, 14.0),
            ("FRA", "SFO", "usr_devops_cloud_12", "45.154.255.89", 9150.0, 11.2),
            ("DXB", "SYD", "usr_exec_vip_77", "103.145.13.204", 12050.0, 9.0)
        ]
        for i, (src_code, dst_code, uid, ip, dist, mins) in enumerate(corridor_pairs):
            src = KNOWN_GEO_HUBS[src_code]
            dst = KNOWN_GEO_HUBS[dst_code]
            speed = dist / (mins / 60.0)
            inc = CyberIncident(
                incident_id=f"CYBER-INC-{1000 + i}",
                timestamp=now - (i * 180),
                technique_id="T1078.004",
                technique_name="Impossible Travel & Geo-Velocity Relay",
                tactic="Initial Access",
                severity="CRITICAL",
                entity_id=uid,
                source_ip=ip,
                source_location=src,
                target_location=dst,
                calculated_speed_kmh=round(speed, 1),
                distance_km=dist,
                time_elapsed_minutes=mins,
                status="QUARANTINED",
                threat_score=0.97,
                details=f"Physics violation: Entity traversed {dist:,.0f} km in {mins:.1f} mins ({speed:,.0f} km/h > 850 km/h commercial limit)."
            )
            self.incidents.append(inc)

    def prune_expired(self):
        """Removes expired quarantines and maintains incident ring buffer."""
        now = time.time()
        with self._lock:
            # Mark inactive or remove expired
            for ip, host in list(self.quarantined_hosts.items()):
                if now >= host.expires_at:
                    host.is_active = False

            # Keep last 150 incidents
            if len(self.incidents) > 150:
                self.incidents = self.incidents[-150:]

    def quarantine_ip(
        self,
        ip: str,
        reason: str,
        technique_id: str = "T1110.003",
        duration_seconds: int = 900,
        threat_score: float = 0.95,
        country: str = "GLOBAL",
        asn: str = "AS-UNKNOWN"
    ) -> QuarantinedHost:
        """Manually or programmatically quarantines an IP address at edge."""
        now = time.time()
        host = QuarantinedHost(
            ip=ip,
            reason=reason,
            technique_id=technique_id,
            quarantined_at=now,
            expires_at=now + duration_seconds,
            threat_score=threat_score,
            country=country,
            asn=asn,
            is_active=True
        )
        with self._lock:
            self.quarantined_hosts[ip] = host
            if technique_id in self.mitre_stats:
                self.mitre_stats[technique_id]["count"] += 1
        return host

    def release_ip(self, ip: str) -> bool:
        """Removes an IP from quarantine."""
        with self._lock:
            if ip in self.quarantined_hosts:
                self.quarantined_hosts[ip].is_active = False
                return True
            return False

    def record_incident(self, incident: CyberIncident):
        """Records a new cyber incident into the SOC live stream."""
        with self._lock:
            self.incidents.insert(0, incident)
            if incident.technique_id in self.mitre_stats:
                self.mitre_stats[incident.technique_id]["count"] += 1
            if len(self.incidents) > 150:
                self.incidents.pop()

    def simulate_impossible_travel(self, src_hub: str = "NYC", dst_hub: str = "TYO") -> CyberIncident:
        """Simulates a physics-violating impossible travel cyber event."""
        now = time.time()
        src = KNOWN_GEO_HUBS.get(src_hub, KNOWN_GEO_HUBS["NYC"])
        dst = KNOWN_GEO_HUBS.get(dst_hub, KNOWN_GEO_HUBS["TYO"])

        dist = haversine_distance(src["lat"], src["lon"], dst["lat"], dst["lon"])
        transit_minutes = round(random.uniform(4.0, 12.0), 1)
        speed = dist / (transit_minutes / 60.0)

        attacker_ip = f"185.220.{random.randint(100, 105)}.{random.randint(10, 250)}"
        uid = f"usr_corp_analyst_{random.randint(101, 999)}"

        inc = CyberIncident(
            incident_id=f"CYBER-INC-{int(now) % 100000}",
            timestamp=now,
            technique_id="T1078.004",
            technique_name="Impossible Travel & Geo-Velocity Relay",
            tactic="Initial Access",
            severity="CRITICAL",
            entity_id=uid,
            source_ip=attacker_ip,
            source_location=src,
            target_location=dst,
            calculated_speed_kmh=round(speed, 1),
            distance_km=round(dist, 1),
            time_elapsed_minutes=transit_minutes,
            status="QUARANTINED",
            threat_score=round(min(0.99, 0.75 + (speed / 15000.0) * 0.24), 3),
            details=(
                f"PHYSICS-VIOLATING VELOCITY: Entity hopped {dist:,.1f} km from {src['city']}, {src['country']} "
                f"to {dst['city']}, {dst['country']} in {transit_minutes} mins ({speed:,.0f} km/h vs. 850 km/h airline ceiling). "
                f"Instant Edge Quarantine deployed to prevent corporate SSO token hijacking."
            )
        )
        self.record_incident(inc)
        self.quarantine_ip(
            ip=attacker_ip,
            reason=f"MITRE T1078.004: Impossible Travel Relay from {src['city']} to {dst['city']}",
            technique_id="T1078.004",
            duration_seconds=1200,
            threat_score=inc.threat_score,
            country=src["country"],
            asn="AS9009 TOR-ANON-RELAY"
        )
        return inc

    def simulate_credential_stuffing(self, bot_size: int = 15) -> CyberIncident:
        """Simulates a distributed credential stuffing / brute force blitz."""
        now = time.time()
        attacker_ip = f"45.141.{random.randint(50, 99)}.{random.randint(10, 250)}"
        target_uid = f"usr_auth_target_{random.randint(200, 500)}"
        hub = KNOWN_GEO_HUBS["FRA"]

        inc = CyberIncident(
            incident_id=f"CYBER-INC-{int(now) % 100000}",
            timestamp=now,
            technique_id="T1110.003",
            technique_name="Distributed Credential Stuffing & BIN Testing",
            tactic="Credential Access",
            severity="HIGH",
            entity_id=target_uid,
            source_ip=attacker_ip,
            source_location=hub,
            target_location=hub,
            calculated_speed_kmh=0.0,
            distance_km=0.0,
            time_elapsed_minutes=0.5,
            status="QUARANTINED",
            threat_score=0.965,
            details=(
                f"HIGH-ENTROPY BRUTE FORCE: {bot_size} consecutive failed auth probes detected within 30 seconds "
                f"from host {attacker_ip}. Token bucket rate limiter engaged with immediate null-route quarantine."
            )
        )
        self.record_incident(inc)
        self.quarantine_ip(
            ip=attacker_ip,
            reason=f"MITRE T1110.003: High-Entropy Credential Stuffing Blitz ({bot_size} probes/30s)",
            technique_id="T1110.003",
            duration_seconds=900,
            threat_score=0.965,
            country="DE",
            asn="AS200019 PROXY-CLUSTER"
        )
        return inc

    def simulate_headless_bot(self) -> CyberIncident:
        """Simulates a Puppeteer / HeadlessChrome scraping and account takeover bot."""
        now = time.time()
        attacker_ip = f"194.26.{random.randint(20, 40)}.{random.randint(10, 250)}"
        target_uid = f"usr_customer_{random.randint(1000, 9999)}"
        hub = KNOWN_GEO_HUBS["LON"]

        inc = CyberIncident(
            incident_id=f"CYBER-INC-{int(now) % 100000}",
            timestamp=now,
            technique_id="T1059.006",
            technique_name="Headless Botnet & Scripting Automation",
            tactic="Execution",
            severity="HIGH",
            entity_id=target_uid,
            source_ip=attacker_ip,
            source_location=hub,
            target_location=hub,
            calculated_speed_kmh=0.0,
            distance_km=0.0,
            time_elapsed_minutes=1.0,
            status="INTERCEPTED",
            threat_score=0.890,
            details=(
                f"HEADLESS BROWSER SIGNATURE: Missing WebGL canvas entropy, navigator.webdriver flag positive, "
                f"and automated DOM interaction speed (<40ms per input field). Bot quarantined."
            )
        )
        self.record_incident(inc)
        self.quarantine_ip(
            ip=attacker_ip,
            reason="MITRE T1059.006: Headless Puppeteer / Selenium Botnet Signature",
            technique_id="T1059.006",
            duration_seconds=600,
            threat_score=0.89,
            country="GB",
            asn="AS49505 AUTOMATION-HOST"
        )
        return inc

    def get_soc_telemetry(self) -> Dict[str, Any]:
        """Returns comprehensive SOC telemetry for dashboard visualizers."""
        self.prune_expired()
        with self._lock:
            active_quarantines = [
                {
                    "ip": h.ip,
                    "reason": h.reason,
                    "technique_id": h.technique_id,
                    "threat_score": h.threat_score,
                    "country": h.country,
                    "asn": h.asn,
                    "remaining_seconds": h.remaining_seconds,
                    "quarantined_at": h.quarantined_at,
                    "is_active": h.is_active
                }
                for h in self.quarantined_hosts.values()
                if h.is_active
            ]

            incident_dicts = [asdict(inc) for inc in self.incidents[:25]]

            # Geo Corridor summary
            corridors = []
            for inc in self.incidents:
                if inc.technique_id == "T1078.004" and inc.calculated_speed_kmh > 0:
                    corridors.append({
                        "incident_id": inc.incident_id,
                        "source": inc.source_location,
                        "target": inc.target_location,
                        "speed_kmh": inc.calculated_speed_kmh,
                        "distance_km": inc.distance_km,
                        "transit_minutes": inc.time_elapsed_minutes,
                        "severity": inc.severity,
                        "threat_score": inc.threat_score,
                        "ip": inc.source_ip,
                        "entity_id": inc.entity_id
                    })
                if len(corridors) >= 6:
                    break

            return {
                "status": "online",
                "total_incidents": len(self.incidents),
                "active_quarantines_count": len(active_quarantines),
                "quarantined_hosts": active_quarantines,
                "recent_incidents": incident_dicts,
                "corridors": corridors,
                "mitre_matrix": self.mitre_stats,
                "geo_hubs": KNOWN_GEO_HUBS,
                "timestamp": time.time()
            }


# Global singleton instance
cyber_soc_engine = CyberSOCEngine()
cyber_soc_stream = cyber_soc_engine
