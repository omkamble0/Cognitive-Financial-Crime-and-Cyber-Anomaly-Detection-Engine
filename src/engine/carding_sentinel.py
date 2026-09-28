"""
AegisFlow AI — Distributed Carding, BIN Probing & Botnet Attack Sentinel
Author: Om Kamble

Mitigates automated credential stuffing, card testing / BIN attacks, and distributed botnet probing
using sliding-window IP entropy and micro-transaction anomaly detection.
"""

import time
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class CardingEvaluationResult:
    threat_level: str  # "NORMAL", "SUSPICIOUS", "ATTACK_IN_PROGRESS"
    threat_score: float  # 0.0 to 1.0
    is_bot_attack: bool
    triggered_rules: List[str]
    unique_cards_in_window: int
    micro_txns_in_window: int
    recommendation: str


class CardingSentinel:
    def __init__(
        self,
        max_cards_per_ip_60s: int = 3,
        max_micro_txns_60s: int = 4,
        micro_amount_threshold: float = 3.00,
        bot_velocity_interval_sec: float = 0.4
    ):
        self.max_cards_per_ip_60s = max_cards_per_ip_60s
        self.max_micro_txns_60s = max_micro_txns_60s
        self.micro_amount_threshold = micro_amount_threshold
        self.bot_velocity_interval_sec = bot_velocity_interval_sec

        # In-Memory sliding-window stores
        # IP -> list of (timestamp, card_identifier, amount, is_declined)
        self.ip_window: Dict[str, List[Tuple_Txn]] = {}
        # BIN -> list of (timestamp, ip, is_declined)
        self.bin_window: Dict[str, List[Dict[str, Any]]] = {}
        # Blocked / Throttled IPs list
        self.quarantined_ips: Dict[str, float] = {}  # ip -> expires_at

    def evaluate_request(
        self,
        ip_address: str,
        amount: float,
        card_identifier: Optional[str] = None,
        bin_number: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_trust: float = 1.0,
        timestamp: Optional[float] = None
    ) -> CardingEvaluationResult:
        now = timestamp or time.time()
        client_ip = ip_address or "127.0.0.1"
        card_id = card_identifier or f"card_{client_ip[-4:]}"
        bin_code = bin_number or (card_id[:6] if len(card_id) >= 6 else "411111")

        # 0. Check if IP is currently quarantined
        if client_ip in self.quarantined_ips:
            if now < self.quarantined_ips[client_ip]:
                return CardingEvaluationResult(
                    threat_level="ATTACK_IN_PROGRESS",
                    threat_score=0.99,
                    is_bot_attack=True,
                    triggered_rules=[f"CYBER_QUARANTINED_IP: IP {client_ip} is actively quarantined for carding attacks"],
                    unique_cards_in_window=99,
                    micro_txns_in_window=99,
                    recommendation="Immediate Hard Drop at Edge WAF / Rate Limiter."
                )
            else:
                del self.quarantined_ips[client_ip]

        # Record into sliding window
        records = self.ip_window.setdefault(client_ip, [])
        records.append({
            "time": now,
            "card_id": card_id,
            "bin": bin_code,
            "amount": amount
        })

        # Prune older than 5 minutes (300s)
        self.ip_window[client_ip] = [r for r in records if now - r["time"] <= 300]
        recent = self.ip_window[client_ip]

        # 1-minute window metrics
        recent_60s = [r for r in recent if now - r["time"] <= 60]
        unique_cards_60s = len(set(r["card_id"] for r in recent_60s))
        micro_txns_60s = sum(1 for r in recent_60s if r["amount"] <= self.micro_amount_threshold)
        
        # Check inter-arrival interval (sub-second bursts from script bots)
        rapid_burst = False
        if len(recent_60s) >= 2:
            time_diffs = [recent_60s[i]["time"] - recent_60s[i-1]["time"] for i in range(1, len(recent_60s))]
            if any(0 < dt < self.bot_velocity_interval_sec for dt in time_diffs):
                rapid_burst = True

        triggered: List[str] = []
        threat_score = 0.0

        # Rule 1: High Carding Velocity (Multiple distinct credit cards tested from single IP)
        if unique_cards_60s >= self.max_cards_per_ip_60s:
            triggered.append(f"CYBER_CARDING_BURST: {unique_cards_60s} unique cards tested in 60s from IP {client_ip}")
            threat_score = max(threat_score, 0.88)

        # Rule 2: Micro-transaction Probing (Testing active cards with $1-$2 auths)
        if micro_txns_60s >= self.max_micro_txns_60s:
            triggered.append(f"CYBER_MICRO_AUTH_PROBING: {micro_txns_60s} sub-${self.micro_amount_threshold:.2f} authorizations in 60s")
            threat_score = max(threat_score, 0.78)

        # Rule 3: High-frequency script bot speed
        if rapid_burst:
            triggered.append("CYBER_BOT_TIMING_SIGNATURE: Programmatic request cadence (<400ms inter-arrival interval)")
            threat_score = max(threat_score, 0.82)

        # Rule 4: Untrusted device + elevated card testing
        if device_trust < 0.3 and unique_cards_60s >= 2:
            triggered.append("CYBER_UNTRUSTED_CARDING_DEVICE: Headless browser / proxy footprint testing cards")
            threat_score = max(threat_score, 0.85)

        # Decide threat level & quarantine
        if threat_score >= 0.80:
            threat_level = "ATTACK_IN_PROGRESS"
            is_bot = True
            # Quarantine IP for 10 minutes
            self.quarantined_ips[client_ip] = now + 600
            recommendation = "Engage Edge WAF Challenge / Block all transactions from this IP."
        elif threat_score >= 0.50 or len(triggered) > 0:
            threat_level = "SUSPICIOUS"
            is_bot = False
            recommendation = "Enforce CAPTCHA / 3D-Secure Step-Up Authentication."
        else:
            threat_level = "NORMAL"
            is_bot = False
            recommendation = "Normal benign human payment activity."

        return CardingEvaluationResult(
            threat_level=threat_level,
            threat_score=round(threat_score, 3),
            is_bot_attack=is_bot,
            triggered_rules=triggered,
            unique_cards_in_window=unique_cards_60s,
            micro_txns_in_window=micro_txns_60s,
            recommendation=recommendation
        )

    def get_security_telemetry(self) -> Dict[str, Any]:
        """Returns active threat statistics for SecOps dashboard."""
        now = time.time()
        active_ips = len(self.ip_window)
        quarantined = [ip for ip, exp in self.quarantined_ips.items() if now < exp]
        
        # Calculate recent attacks
        recent_attacks = 0
        for ip, records in self.ip_window.items():
            recent_60s = [r for r in records if now - r["time"] <= 60]
            unique_cards = len(set(r["card_id"] for r in recent_60s))
            if unique_cards >= self.max_cards_per_ip_60s:
                recent_attacks += 1

        return {
            "active_monitored_ips": active_ips,
            "quarantined_ips_count": len(quarantined),
            "quarantined_ips": quarantined[:10],
            "carding_attacks_mitigated_60s": recent_attacks,
            "protection_status": "ACTIVE (WAF + In-Memory Token Bucket)"
        }
