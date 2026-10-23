"""
FinCipher AI — Production Alert Deduplication & Case Creation Lifecycle Engine
Author: Om Kamble

Architecture:
- High-efficiency deduplication sliding window preventing analyst alert fatigue.
- Entity-Centric Case Correlation:
  * When an alert breaches threshold, searches for an active OPEN / IN_REVIEW case for that entity.
  * Links related alerts to the existing investigation dossier instead of spawning duplicate cases.
  * Automatically creates P1/P2 cases when severe anomalies or burst thresholds are reached.
- Direct persistence into 'alerts' and 'cases' database tables.
"""

import time
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from libs.models.alerts import AlertSeverity, AlertStatus
from libs.models.cases import CasePriority
from src.db.database import (
    create_alert_record,
    find_open_case_for_entity,
    link_alert_to_case,
    create_case,
    list_alerts
)


class AlertLifecycleManager:
    """
    Coordinates stateful alert deduplication, suppression windows,
    and automatic case clustering across Banking, Cyber, and E-Commerce domains.
    """

    def __init__(self, suppression_window_seconds: float = 300.0):
        self.suppression_window = suppression_window_seconds
        # Fingerprint -> {"first_seen": float, "last_seen": float, "count": int, "alert_id": int, "case_id": Optional[int]}
        self._memory_cache: Dict[str, Dict[str, Any]] = {}

    def _generate_fingerprint(self, domain: str, entity_id: str, rule_name: str) -> str:
        raw = f"{domain.upper()}:{entity_id.strip()}:{rule_name.strip()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def process_and_cluster_alert(
        self,
        domain: str,
        primary_entity_id: str,
        event_id: str,
        risk_score: float,
        rule_hits: List[str],
        title: Optional[str] = None,
        tenant_id: str = "default"
    ) -> Dict[str, Any]:
        """
        Deduplicates alert, persists record into database, and correlates with active cases.
        """
        now = time.time()
        primary_rule = rule_hits[0] if rule_hits else "RISK_ELEVATED"
        fp = self._generate_fingerprint(domain, primary_entity_id, primary_rule)

        severity = (
            "CRITICAL" if risk_score >= 0.85 else
            "HIGH" if risk_score >= 0.70 else
            "MEDIUM" if risk_score >= 0.50 else "LOW"
        )
        alert_title = title or f"[{domain.upper()}] Anomaly Detected on {primary_entity_id}"
        summary = f"Rules Triggered: {', '.join(rule_hits[:4])}"

        # 1. Deduplication Check
        cached = self._memory_cache.get(fp)
        if cached and (now - cached["first_seen"]) < self.suppression_window:
            cached["count"] += 1
            cached["last_seen"] = now
            return {
                "status": "SUPPRESSED",
                "is_suppressed": True,
                "suppression_count": cached["count"],
                "alert_id": cached.get("alert_id"),
                "case_id": cached.get("case_id"),
                "fingerprint": fp
            }

        # 2. Persist new alert in database
        alert_id = create_alert_record(
            transaction_id=event_id,
            user_id=primary_entity_id,
            severity=severity,
            title=alert_title,
            summary=summary,
            risk_score=risk_score,
            status="OPEN",
            tenant_id=tenant_id
        )

        # 3. Case Correlation
        existing_case = find_open_case_for_entity(primary_entity_id, tenant_id=tenant_id)
        action_taken = "ALERT_QUEUED"
        case_id = None

        if existing_case:
            case_id = existing_case["id"]
            link_alert_to_case(alert_id, case_id, event_id=event_id)
            action_taken = "LINKED_TO_EXISTING_CASE"
        elif risk_score >= 0.80 or severity in ("CRITICAL", "HIGH"):
            # Automatically spawn an investigation case
            priority = (
                CasePriority.P1_CRITICAL if risk_score >= 0.85 or severity == "CRITICAL"
                else CasePriority.P2_HIGH
            )
            created_case = create_case(
                title=f"Autonomous Investigation: {alert_title}",
                priority=priority.value,
                entity_id=primary_entity_id,
                risk_score=risk_score,
                linked_transactions=[event_id],
                tenant_id=tenant_id
            )
            if created_case:
                case_id = created_case["id"]
                link_alert_to_case(alert_id, case_id, event_id=event_id)
                action_taken = "CASE_CREATED"

        # Update Cache
        self._memory_cache[fp] = {
            "first_seen": now,
            "last_seen": now,
            "count": 0,
            "alert_id": alert_id,
            "case_id": case_id
        }

        return {
            "status": "ACCEPTED",
            "is_suppressed": False,
            "alert_id": alert_id,
            "case_id": case_id,
            "action": action_taken,
            "severity": severity,
            "risk_score": risk_score,
            "fingerprint": fp
        }

    def get_active_alerts(self, limit: int = 50, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves active alerts from the database."""
        return list_alerts(status="OPEN", limit=limit, tenant_id=tenant_id)


# Global singleton alert lifecycle manager
alert_lifecycle_manager = AlertLifecycleManager()
