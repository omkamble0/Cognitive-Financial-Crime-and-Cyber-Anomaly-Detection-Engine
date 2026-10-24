"""
FinCipher AI — Production Action Enforcement Engine & Revocation Lifecycle
Author: Om Kamble

Manages real-time production enforcement policies, automated edge actions,
hold/quarantine lifecycles, and supervisory revocation workflows:
- ALLOW: Clean throughput
- HOLD: Transaction escrow / manual verification hold
- BLOCK: Entity account lock & syndicate blacklisting
- QUARANTINE: Edge IP isolation with duration & physics tracking
- STEP_UP_2FA: Out-of-band biometric / 3DS challenge trigger
- NOTIFY: SIEM/SOAR and analyst chat dispatch
"""

import time
import json
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple

from src.db.database import (
    record_action_dispatch,
    list_action_dispatches,
    get_db_connection,
    IS_POSTGRES
)
from src.engine.notifier import alert_notifier
from src.engine.cyber_soc import cyber_soc_engine

logger = logging.getLogger("FinCipher.ActionEnforcer")


class EnforcementActionType:
    ALLOW = "ALLOW"
    HOLD = "HOLD_TRANSACTION"
    BLOCK = "BLOCK_ACCOUNT"
    QUARANTINE = "QUARANTINE_IP"
    STEP_UP_2FA = "STEP_UP_2FA"
    NOTIFY = "NOTIFY_ANALYST"


class ActionEnforcer:
    """
    Central operational execution engine for fraud & cyber enforcement.
    Maintains fast in-memory active blocklists and persistent audit logs.
    """

    def __init__(self):
        # In-memory fast filters for <0.2ms edge evaluation
        self._active_blocked_accounts: Dict[str, Dict[str, Any]] = {}
        self._active_holds: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def check_preflight_enforcement(
        self,
        entity_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Sub-millisecond edge inspection before executing inference pipeline.
        Returns whether the entity or IP is pre-emptively blocked or quarantined.
        """
        now = time.time()
        with self._lock:
            # 1. Check account block
            if entity_id and entity_id in self._active_blocked_accounts:
                block_info = self._active_blocked_accounts[entity_id]
                return {
                    "is_blocked": True,
                    "action_type": EnforcementActionType.BLOCK,
                    "target": entity_id,
                    "reason": block_info.get("reason", "Account administratively blocked"),
                    "dispatched_at": block_info.get("timestamp")
                }

            # 2. Check IP quarantine
            if ip_address:
                cyber_soc_engine.prune_expired()
                if ip_address in cyber_soc_engine.quarantined_hosts:
                    host = cyber_soc_engine.quarantined_hosts[ip_address]
                    if host.is_active and now < host.expires_at:
                        return {
                            "is_blocked": True,
                            "action_type": EnforcementActionType.QUARANTINE,
                            "target": ip_address,
                            "reason": f"IP quarantined: {host.reason}",
                            "expires_at": host.expires_at,
                            "remaining_seconds": int(host.expires_at - now)
                        }

        return {"is_blocked": False}

    def enforce_action(
        self,
        action_type: str,
        target: str,
        event_id: str,
        reason: str = "Automated risk policy enforcement",
        operator: str = "SYSTEM",
        duration_seconds: int = 3600,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Executes a production enforcement action and records persistent audit."""
        act_upper = action_type.upper()
        now = time.time()
        meta = metadata or {}

        with self._lock:
            if "BLOCK" in act_upper:
                self._active_blocked_accounts[target] = {
                    "reason": reason,
                    "operator": operator,
                    "timestamp": now,
                    "event_id": event_id
                }
            elif "QUARANTINE" in act_upper:
                cyber_soc_engine.quarantine_ip(
                    ip=target,
                    reason=reason,
                    duration_seconds=duration_seconds,
                    threat_score=float(meta.get("risk_score", 0.95))
                )
            elif "HOLD" in act_upper:
                self._active_holds[event_id] = {
                    "target": target,
                    "reason": reason,
                    "operator": operator,
                    "timestamp": now,
                    "status": "HOLD",
                    "expires_at": now + duration_seconds
                }

        # Outbound notification if critical or blocked
        if act_upper in (EnforcementActionType.BLOCK, EnforcementActionType.QUARANTINE, EnforcementActionType.NOTIFY):
            try:
                alert_notifier.dispatch(
                    alert_title=f"Enforcement Action: {act_upper}",
                    severity="CRITICAL" if "BLOCK" in act_upper else "HIGH",
                    summary=f"Action {act_upper} executed against target {target}. Reason: {reason}",
                    risk_score=float(meta.get("risk_score", 0.90)),
                    entity_id=target,
                    transaction_id=event_id,
                    sync=False
                )
            except Exception as e:
                logger.warning(f"Notification dispatch failed: {e}")

        # Persist in DB
        action_id = record_action_dispatch(
            event_id=event_id,
            action_type=act_upper,
            target=target,
            status="DISPATCHED",
            payload={"reason": reason, "operator": operator, "duration": duration_seconds, "metadata": meta},
            response={"status": "ACTIVE", "executed_at": now}
        )

        logger.info(f"[ActionEnforcer] {act_upper} applied to {target} (Action ID: {action_id})")

        return {
            "status": "SUCCESS",
            "action_id": action_id,
            "action_type": act_upper,
            "target": target,
            "reason": reason,
            "operator": operator,
            "timestamp": now
        }

    def revoke_action(
        self,
        dispatch_id: int,
        operator: str,
        reason: str
    ) -> Dict[str, Any]:
        """Revokes a previously dispatched enforcement action with supervisory audit trail."""
        conn = get_db_connection()
        cursor = conn.cursor()
        param = "%s" if IS_POSTGRES else "?"

        cursor.execute(f"SELECT * FROM action_dispatches WHERE id = {param}", (dispatch_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            raise ValueError(f"Action dispatch #{dispatch_id} not found.")

        record = dict(row)
        action_type = record.get("action_type", "").upper()
        target = record.get("target", "")

        # Revoke in-memory state
        with self._lock:
            if "BLOCK" in action_type:
                self._active_blocked_accounts.pop(target, None)
            elif "QUARANTINE" in action_type:
                if target in cyber_soc_engine.quarantined_hosts:
                    cyber_soc_engine.quarantined_hosts[target].is_active = False
            elif "HOLD" in action_type:
                self._active_holds.pop(record.get("event_id"), None)

        # Update DB record
        cursor.execute(f"""
            UPDATE action_dispatches
            SET status = 'REVOKED',
                response_json = {param}
            WHERE id = {param}
        """, (json.dumps({"revoked_at": time.time(), "revoked_by": operator, "revocation_reason": reason}), dispatch_id))
        conn.commit()
        conn.close()

        logger.info(f"[ActionEnforcer] Action #{dispatch_id} ({action_type} on {target}) revoked by {operator}")

        return {
            "status": "SUCCESS",
            "action_id": dispatch_id,
            "action_type": action_type,
            "target": target,
            "status_updated": "REVOKED",
            "revoked_by": operator,
            "reason": reason
        }

    def list_active_enforcements(self) -> Dict[str, Any]:
        """Returns all currently active blocks, quarantines, and holds."""
        now = time.time()
        cyber_soc_engine.prune_expired()

        with self._lock:
            active_quarantines = [
                {
                    "ip": ip,
                    "reason": host.reason,
                    "threat_score": host.threat_score,
                    "remaining_seconds": max(0, int(host.expires_at - now))
                }
                for ip, host in cyber_soc_engine.quarantined_hosts.items()
                if host.is_active and now < host.expires_at
            ]
            active_blocks = [
                {"account_id": acc, **details}
                for acc, details in self._active_blocked_accounts.items()
            ]
            active_holds = [
                {"event_id": eid, **details}
                for eid, details in self._active_holds.items()
                if details["status"] == "HOLD" and now < details["expires_at"]
            ]

        return {
            "total_active": len(active_quarantines) + len(active_blocks) + len(active_holds),
            "blocked_accounts": active_blocks,
            "quarantined_ips": active_quarantines,
            "held_transactions": active_holds
        }


# Global Action Enforcer singleton
action_enforcer = ActionEnforcer()
