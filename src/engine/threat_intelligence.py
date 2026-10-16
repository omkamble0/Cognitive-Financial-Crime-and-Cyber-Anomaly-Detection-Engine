"""
AegisFlow AI — Enterprise Cybersecurity Threat Intelligence & Anomaly Engine
Author: Om Kamble

Implements advanced cyber-defense and financial fraud detection concepts:
1. Impossible Travel & Geo-Velocity Anomaly (Haversine Distance vs. Physical Velocity)
2. Device Fingerprint Drift & Session Hijacking Sentinel
3. AML Anti-Structuring / Smurfing Detection (BSA Threshold Evasion)
4. Mule Account Rapid Liquidity Drainage & Funneling Ratios
"""

import math
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field


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


@dataclass
class GeoVelocityResult:
    is_impossible_travel: bool
    calculated_speed_kmh: float
    distance_km: float
    time_elapsed_seconds: float
    previous_location: Dict[str, Any]
    current_location: Dict[str, Any]
    threat_score: float
    reason: str


@dataclass
class DeviceFingerprintResult:
    is_session_hijacked: bool
    device_entropy_score: float
    is_headless_bot: bool
    browser_anomaly_detected: bool
    threat_score: float
    reasons: List[str]


@dataclass
class StructuringResult:
    is_structuring_detected: bool
    structuring_zone: Optional[str]
    threshold_evasion_amount: float
    cumulative_window_volume: float
    transaction_count_in_window: int
    threat_score: float
    reasons: List[str]


class ThreatIntelligenceEngine:
    def __init__(self, max_commercial_speed_kmh: float = 850.0):
        self.max_commercial_speed_kmh = max_commercial_speed_kmh
        # In-memory stores: user_id -> (timestamp, lat, lon, city, ip)
        self.user_geo_cache: Dict[str, Dict[str, Any]] = {}
        # user_id -> list of (timestamp, amount, currency)
        self.user_smurf_cache: Dict[str, List[Tuple[float, float]]] = {}
        # user_id -> known device profiles
        self.user_device_cache: Dict[str, Dict[str, Any]] = {}

        # Standard known test IP coordinate approximations
        self.KNOWN_CITY_COORDS = {
            "new_york": (40.7128, -74.0060, "New York, USA"),
            "london": (51.5074, -0.1278, "London, UK"),
            "frankfurt": (50.1109, 8.6821, "Frankfurt, Germany"),
            "tokyo": (35.6762, 139.6503, "Tokyo, Japan"),
            "mumbai": (19.0760, 72.8777, "Mumbai, India"),
            "singapore": (1.3521, 103.8198, "Singapore"),
            "san_francisco": (37.7749, -122.4194, "San Francisco, USA")
        }

    # =========================================================================
    # 1. IMPOSSIBLE TRAVEL & GEO-VELOCITY ANOMALY DETECTION
    # =========================================================================
    def evaluate_geo_velocity(
        self,
        user_id: str,
        current_lat: float,
        current_lon: float,
        location_name: str = "Unknown Location",
        ip_address: str = "127.0.0.1",
        timestamp: Optional[float] = None
    ) -> GeoVelocityResult:
        now = timestamp or time.time()
        prev = self.user_geo_cache.get(user_id)

        # Update cache for future checks
        self.user_geo_cache[user_id] = {
            "timestamp": now,
            "lat": current_lat,
            "lon": current_lon,
            "location_name": location_name,
            "ip_address": ip_address
        }

        if not prev:
            return GeoVelocityResult(
                is_impossible_travel=False,
                calculated_speed_kmh=0.0,
                distance_km=0.0,
                time_elapsed_seconds=0.0,
                previous_location={"location_name": "Initial Baseline", "ip": ip_address},
                current_location={"location_name": location_name, "lat": current_lat, "lon": current_lon, "ip": ip_address},
                threat_score=0.0,
                reason="First recorded geographic coordinate for entity."
            )

        time_elapsed = max(1.0, now - prev["timestamp"])
        distance = haversine_distance(prev["lat"], prev["lon"], current_lat, current_lon)
        hours = time_elapsed / 3600.0
        calculated_speed = distance / hours

        is_impossible = calculated_speed > self.max_commercial_speed_kmh and distance > 100.0
        threat_score = 0.0

        if is_impossible:
            # Scale threat score based on excess velocity
            threat_score = min(0.99, 0.70 + min(0.29, (calculated_speed / 2000.0) * 0.2))
            reason = (
                f"PHYSICS-VIOLATING GEO-VELOCITY: Entity traversed {distance:.1f} km from "
                f"'{prev['location_name']}' to '{location_name}' in {time_elapsed/60:.1f} minutes "
                f"(Velocity: {calculated_speed:,.1f} km/h, surpassing physical airline limits of {self.max_commercial_speed_kmh} km/h). "
                f"Indicates active credential relay, session hijacking, or automated proxy hopping."
            )
        elif distance > 500.0:
            threat_score = 0.25
            reason = f"Cross-region physical relocation ({distance:.1f} km) within plausible transit timeframe."
        else:
            threat_score = 0.02
            reason = f"Geographic velocity ({calculated_speed:.1f} km/h) consistent with nominal cardholder behavior."

        return GeoVelocityResult(
            is_impossible_travel=is_impossible,
            calculated_speed_kmh=round(calculated_speed, 2),
            distance_km=round(distance, 2),
            time_elapsed_seconds=round(time_elapsed, 1),
            previous_location=prev,
            current_location={"location_name": location_name, "lat": current_lat, "lon": current_lon, "ip": ip_address},
            threat_score=round(threat_score, 4),
            reason=reason
        )

    # =========================================================================
    # 2. DEVICE FINGERPRINT & SESSION HIJACKING SENTINEL
    # =========================================================================
    def evaluate_device_fingerprint(
        self,
        user_id: str,
        user_agent: Optional[str] = None,
        canvas_hash: Optional[str] = None,
        device_trust_score: float = 1.0,
        ip_address: str = "127.0.0.1"
    ) -> DeviceFingerprintResult:
        ua = (user_agent or "").lower()
        reasons = []
        threat = 0.0

        # Check for headless browser / automated script signatures
        is_headless = any(sig in ua for sig in (
            "headlesschrome", "phantomjs", "selenium", "puppeteer",
            "python-requests", "curl/", "postmanruntime", "aiohttp", "wget"
        ))
        if is_headless:
            threat += 0.55
            reasons.append(f"HEADLESS_AUTOMATION_SIGNATURE: User-Agent matches automated scraper/bot library ({ua[:30]}...)")

        # Missing user-agent or suspiciously short string
        if len(ua) < 15:
            threat += 0.30
            reasons.append("ABNORMAL_USER_AGENT: Missing or truncated client identification string")

        # Check for device fingerprint drift across active session
        prev_dev = self.user_device_cache.get(user_id)
        current_canvas = canvas_hash or f"canvas_{hash(ua) % 100000}"

        is_hijacked = False
        if prev_dev:
            # If user-agent or canvas hash completely changes while device trust is low
            if prev_dev.get("canvas_hash") != current_canvas:
                threat += 0.40
                is_hijacked = True
                reasons.append("CANVAS_FINGERPRINT_MUTATION: Browser rendering signature shifted abruptly within active session.")
            if prev_dev.get("user_agent") != ua and "mobile" not in ua:
                threat += 0.35
                is_hijacked = True
                reasons.append("USER_AGENT_DISCORDANCE: Operating system / browser architecture switched mid-flow.")
        else:
            self.user_device_cache[user_id] = {
                "user_agent": ua,
                "canvas_hash": current_canvas,
                "ip": ip_address
            }

        # Device trust weighting
        if device_trust_score < 0.3:
            threat += 0.25
            reasons.append(f"LOW_DEVICE_REPUTATION: Device trust coefficient at {device_trust_score:.2f}")

        threat_score = min(0.99, threat)
        if not reasons:
            reasons.append("Device fingerprint and browser rendering entropy conform to established hardware profile.")

        return DeviceFingerprintResult(
            is_session_hijacked=is_hijacked,
            device_entropy_score=round(threat_score, 4),
            is_headless_bot=is_headless,
            browser_anomaly_detected=is_hijacked or is_headless,
            threat_score=round(threat_score, 4),
            reasons=reasons
        )

    # =========================================================================
    # 3. AML ANTI-STRUCTURING & SMURFING DETECTION (BSA THRESHOLD EVASION)
    # =========================================================================
    def evaluate_structuring_and_smurfing(
        self,
        user_id: str,
        amount: float,
        timestamp: Optional[float] = None,
        sliding_window_hours: float = 24.0
    ) -> StructuringResult:
        now = timestamp or time.time()
        window_sec = sliding_window_hours * 3600.0

        # Maintain user history
        user_txns = self.user_smurf_cache.setdefault(user_id, [])
        user_txns.append((now, amount))

        # Prune older transactions
        user_txns = [t for t in user_txns if now - t[0] <= window_sec]
        self.user_smurf_cache[user_id] = user_txns

        reasons = []
        threat = 0.0
        structuring_zone = None

        # Check BSA $10,000 threshold evasion zone ($9,000 to $9,999)
        if 9000.0 <= amount < 10000.0:
            structuring_zone = "BSA_10K_REPORTING_THRESHOLD"
            threat += 0.65
            reasons.append(f"BSA_STRUCTURING_ZONE: Ticket amount (${amount:,.2f}) intentionally hovers just below the statutory $10,000 FinCEN reporting threshold.")

        # Check Travel Rule $3,000 threshold evasion zone ($2,700 to $2,999)
        elif 2700.0 <= amount < 3000.0:
            structuring_zone = "BSA_TRAVEL_RULE_3K"
            threat += 0.45
            reasons.append(f"TRAVEL_RULE_EVASION: Ticket amount (${amount:,.2f}) hovers just under the $3,000 Funds Travel Rule.")

        # Smurfing detection: Multiple cumulative transactions in 24h that together exceed $10,000
        cum_volume = sum(t[1] for t in user_txns)
        tx_count = len(user_txns)

        if tx_count >= 3 and cum_volume >= 9500.0:
            threat += 0.40
            reasons.append(f"CUMULATIVE_SMURFING_CLUSTER: {tx_count} transactions totaling ${cum_volume:,.2f} USD within {sliding_window_hours}h structured across sub-threshold tranches.")

        threat_score = min(0.99, threat)
        is_structuring = threat_score >= 0.45

        if not reasons:
            reasons.append("Transaction amount outside statutory structuring / smurfing evasion bands.")

        return StructuringResult(
            is_structuring_detected=is_structuring,
            structuring_zone=structuring_zone,
            threshold_evasion_amount=amount,
            cumulative_window_volume=round(cum_volume, 2),
            transaction_count_in_window=tx_count,
            threat_score=round(threat_score, 4),
            reasons=reasons
        )

    # =========================================================================
    # 4. MULE ACCOUNT RAPID LIQUIDITY DRAIN RATIO
    # =========================================================================
    def evaluate_mule_drain_ratio(
        self,
        inflow_amount: float,
        outflow_amount: float,
        retention_time_seconds: float
    ) -> Dict[str, Any]:
        """Identifies rapid pass-through money mule funnels (e.g. 95% drained in < 180s)."""
        if inflow_amount <= 0.0:
            drain_ratio = 1.0
        else:
            drain_ratio = min(1.0, outflow_amount / inflow_amount)

        is_mule = (drain_ratio >= 0.88 and retention_time_seconds <= 300.0 and inflow_amount >= 500.0)
        threat_score = 0.85 if is_mule else (0.45 if drain_ratio >= 0.85 else 0.05)

        return {
            "is_mule_behavior": is_mule,
            "drain_ratio_pct": round(drain_ratio * 100, 1),
            "retention_seconds": round(retention_time_seconds, 1),
            "threat_score": threat_score,
            "diagnosis": "MULE_LIQUIDITY_FUNNEL_SUSPECTED" if is_mule else "STANDARD_ACCOUNT_HOLDING"
        }
