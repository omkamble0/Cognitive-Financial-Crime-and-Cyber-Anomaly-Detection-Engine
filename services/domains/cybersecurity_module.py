"""
AegisNexus — Cybersecurity & SOC Incident Domain Module
Author: Om Kamble
"""

import time
import math
from typing import Dict, Any, List
from libs.models.events import GenericEvent
from libs.models.alerts import AlertSeverity
from services.domains.base_domain import BaseDomainModule, DomainEvaluationResult


class CybersecurityDomainModule(BaseDomainModule):
    """
    Evaluates cybersecurity authentication telemetry, impossible travel, brute force, and privilege abuse.
    """

    MAX_COMMERCIAL_SPEED_KMH = 1100.0

    def __init__(self):
        # Sliding memory for failed logins: user_id/ip -> list of failure timestamps
        self._auth_failures: Dict[str, List[float]] = {}
        # Sliding memory for user location: user_id -> {"timestamp": float, "lat": float, "lon": float, "city": str}
        self._geo_cache: Dict[str, Dict[str, Any]] = {}

    @property
    def domain_name(self) -> str:
        return "CYBERSECURITY"

    def evaluate_event(self, event: GenericEvent) -> DomainEvaluationResult:
        payload = event.payload or {}
        context = event.context or {}
        user_id = event.primary_entity_id
        ip_addr = str(context.get("ip_address") or "127.0.0.1")
        status = str(payload.get("status", "SUCCESS")).upper()
        now = event.timestamp or time.time()

        rule_hits = []
        anomaly_signals = {}
        risk_score = 0.05

        # 1. Brute-Force / Credential Stuffing Detection
        if status in ("FAILURE", "FAILED"):
            fails = self._auth_failures.setdefault(ip_addr, [])
            fails.append(now)
            # Prune older than 5 minutes
            self._auth_failures[ip_addr] = [t for t in fails if now - t <= 300]
            fail_count = len(self._auth_failures[ip_addr])
            if fail_count >= 5:
                rule_hits.append(f"SOC_BRUTE_FORCE_DETECTED_{fail_count}_FAILS_5M")
                risk_score = max(risk_score, min(0.96, 0.60 + fail_count * 0.07))
                anomaly_signals["failed_login_burst"] = fail_count

        # 2. Impossible Travel / Geo-Velocity Anomaly
        lat = context.get("geo_lat")
        lon = context.get("geo_lon")
        city = context.get("city") or "Unknown"

        if lat is not None and lon is not None:
            prev = self._geo_cache.get(user_id)
            if prev and now > prev["timestamp"]:
                time_elapsed_hours = (now - prev["timestamp"]) / 3600.0
                if time_elapsed_hours > 0:
                    distance_km = self._haversine(prev["lat"], prev["lon"], float(lat), float(lon))
                    speed_kmh = distance_km / time_elapsed_hours
                    if speed_kmh > self.MAX_COMMERCIAL_SPEED_KMH and distance_km > 100.0:
                        rule_hits.append(f"SOC_IMPOSSIBLE_TRAVEL_{int(speed_kmh)}_KMH")
                        risk_score = max(risk_score, 0.92)
                        anomaly_signals["speed_kmh"] = speed_kmh
                        anomaly_signals["distance_km"] = distance_km
                        anomaly_signals["prev_city"] = prev.get("city")
                        anomaly_signals["curr_city"] = city

            # Update cache if current is contemporary
            if not prev or now >= prev.get("timestamp", 0.0):
                self._geo_cache[user_id] = {
                    "timestamp": now,
                    "lat": float(lat),
                    "lon": float(lon),
                    "city": city
                }

        # 3. Privileged Access Escalation Without MFA
        if event.event_type.value == "PRIVILEGE_ESCALATION" or payload.get("privilege_level") in ("ADMIN", "ROOT"):
            if not payload.get("is_mfa"):
                rule_hits.append("SOC_PRIVILEGE_ESCALATION_WITHOUT_MFA")
                risk_score = max(risk_score, 0.88)
                anomaly_signals["unauthenticated_priv_elevation"] = True

        # Calculate Decision & Severity
        if risk_score >= 0.85:
            decision = "BLOCK"
            severity = AlertSeverity.P1_CRITICAL
            case_title = f"Critical SOC Threat: {user_id} ({ip_addr})"
        elif risk_score >= 0.50:
            decision = "CHALLENGE"
            severity = AlertSeverity.P2_HIGH
            case_title = f"Suspicious IT Security Access: {user_id}"
        else:
            decision = "ALLOW"
            severity = AlertSeverity.P4_LOW
            case_title = None

        result = DomainEvaluationResult(
            domain=self.domain_name,
            risk_score=risk_score,
            decision=decision,
            severity=severity,
            rule_hits=rule_hits,
            anomaly_signals=anomaly_signals,
            suggested_case_title=case_title
        )
        result.forensic_narrative = self.generate_narrative(event, result)
        return result

    def generate_narrative(self, event: GenericEvent, result: DomainEvaluationResult) -> str:
        narrative_parts = [
            f"Cybersecurity SIEM/SOC engine ingested access telemetry for account {event.primary_entity_id}."
        ]
        if result.rule_hits:
            narrative_parts.append(f"Active threat alerts: {', '.join(result.rule_hits)}.")
        if "speed_kmh" in result.anomaly_signals:
            narrative_parts.append(
                f"Impossible travel identified between {result.anomaly_signals.get('prev_city')} and {result.anomaly_signals.get('curr_city')} "
                f"requiring an impossible velocity of {result.anomaly_signals['speed_kmh']:.1f} km/h."
            )
        if "unauthenticated_priv_elevation" in result.anomaly_signals:
            narrative_parts.append("Unauthorized privilege escalation attempt detected without required multi-factor token.")

        narrative_parts.append(f"Enforcement Action: {result.decision} (Risk: {result.risk_score:.2f}).")
        return " ".join(narrative_parts)

    @staticmethod
    def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Great-circle distance between two GPS coordinates in kilometers."""
        r = 6371.0
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)

        a = math.sin(delta_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        return r * c


# Singleton
cybersecurity_domain_module = CybersecurityDomainModule()
