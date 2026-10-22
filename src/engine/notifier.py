"""
FinCipher AI Platform — Enterprise Alert Notification Dispatcher (Phase 7)
Author: Om Kamble

Dispatches real-time outbound alert notifications across multiple enterprise channels:
- Generic Webhooks (REST / JSON)
- Slack Incoming Webhooks (Block Kit / Alert Attachment format)
- Microsoft Teams & Discord Webhook compatibility
- In-memory event audit log for notification tracking & SOC visibility
"""

import time
import json
import logging
import threading
from enum import Enum
from typing import Dict, Any, List, Optional
import urllib.request
import urllib.error

logger = logging.getLogger("fincipher.notifier")


class NotificationChannel(str, Enum):
    WEBHOOK = "webhook"
    SLACK = "slack"
    TEAMS = "teams"
    CONSOLE = "console"


class AlertNotifier:
    """Enterprise multi-channel notification engine for financial cyber alerts."""

    def __init__(self):
        self.enabled: bool = True
        self.webhook_url: Optional[str] = None
        self.slack_webhook_url: Optional[str] = None
        self.min_severity: str = "HIGH"
        self._history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def configure(
        self,
        enabled: bool = True,
        webhook_url: Optional[str] = None,
        slack_webhook_url: Optional[str] = None,
        min_severity: str = "HIGH"
    ):
        """Updates dispatcher configuration dynamically."""
        self.enabled = enabled
        if webhook_url is not None:
            self.webhook_url = webhook_url.strip() if webhook_url else None
        if slack_webhook_url is not None:
            self.slack_webhook_url = slack_webhook_url.strip() if slack_webhook_url else None
        self.min_severity = min_severity.upper()

    def get_status(self) -> Dict[str, Any]:
        """Returns notification subsystem health and channel readiness."""
        return {
            "enabled": self.enabled,
            "min_severity": self.min_severity,
            "channels": {
                "webhook": {"configured": bool(self.webhook_url), "url": self.webhook_url},
                "slack": {"configured": bool(self.slack_webhook_url), "url": self._mask_url(self.slack_webhook_url)},
                "console": {"configured": True, "active": True}
            },
            "dispatched_count": len(self._history)
        }

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent dispatched notification event logs."""
        with self._lock:
            return list(reversed(self._history[-limit:]))

    def dispatch(
        self,
        alert_title: str,
        severity: str,
        summary: str,
        risk_score: float,
        entity_id: Optional[str] = None,
        transaction_id: Optional[str] = None,
        tenant_id: str = "default",
        sync: bool = False
    ) -> Dict[str, Any]:
        """
        Dispatches outbound notification for a high-risk security alert.
        Executes asynchronously by default to protect API inference SLA.
        """
        if not self.enabled:
            return {"status": "skipped", "reason": "notifications_disabled"}

        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        alert_rank = severity_rank.get(severity.upper(), 2)
        min_rank = severity_rank.get(self.min_severity, 3)

        if alert_rank < min_rank:
            return {"status": "skipped", "reason": f"severity_{severity}_below_{self.min_severity}"}

        event = {
            "event_id": f"notif_{int(time.time() * 1000)}",
            "timestamp": time.time(),
            "alert_title": alert_title,
            "severity": severity.upper(),
            "risk_score": float(risk_score),
            "summary": summary,
            "entity_id": entity_id or "unknown",
            "transaction_id": transaction_id or "N/A",
            "tenant_id": tenant_id,
            "dispatched_channels": []
        }

        if sync:
            return self._execute_dispatch(event)
        else:
            t = threading.Thread(target=self._execute_dispatch, args=(event,), daemon=True)
            t.start()
            return {"status": "queued", "event_id": event["event_id"]}

    def _execute_dispatch(self, event: Dict[str, Any]) -> Dict[str, Any]:
        # Always record to console / local history
        event["dispatched_channels"].append(NotificationChannel.CONSOLE.value)
        logger.info(
            f"[FinCipher Notification] [{event['severity']}] {event['alert_title']} | "
            f"Score: {event['risk_score']:.2f} | Entity: {event['entity_id']}"
        )

        # 1. Generic Webhook delivery
        if self.webhook_url:
            ok = self._send_http_json(self.webhook_url, event)
            if ok:
                event["dispatched_channels"].append(NotificationChannel.WEBHOOK.value)

        # 2. Slack Incoming Webhook delivery
        if self.slack_webhook_url:
            slack_payload = self._build_slack_payload(event)
            ok = self._send_http_json(self.slack_webhook_url, slack_payload)
            if ok:
                event["dispatched_channels"].append(NotificationChannel.SLACK.value)

        with self._lock:
            self._history.append(event)
            if len(self._history) > 200:
                self._history = self._history[-200:]

        return {"status": "dispatched", "channels": event["dispatched_channels"], "event": event}

    def _build_slack_payload(self, event: Dict[str, Any]) -> Dict[str, Any]:
        color = "#ff0055" if event["severity"] == "CRITICAL" else "#ff9900" if event["severity"] == "HIGH" else "#00f2fe"
        return {
            "text": f"🚨 *FinCipher AI Security Alert: {event['alert_title']}*",
            "attachments": [
                {
                    "color": color,
                    "fields": [
                        {"title": "Severity", "value": event["severity"], "short": True},
                        {"title": "Risk Score", "value": f"{event['risk_score']:.2f}", "short": True},
                        {"title": "Entity / User", "value": event["entity_id"], "short": True},
                        {"title": "Transaction ID", "value": event["transaction_id"], "short": True},
                        {"title": "Tenant", "value": event["tenant_id"], "short": True},
                        {"title": "Summary", "value": event["summary"], "short": False}
                    ],
                    "footer": "FinCipher AI Cognitive Security Operations Engine",
                    "ts": int(event["timestamp"])
                }
            ]
        }

    def _send_http_json(self, url: str, payload: Dict[str, Any]) -> bool:
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "FinCipher-AI-Alert-Notifier/2.3"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return resp.status < 400
        except Exception as e:
            logger.warning(f"Failed to deliver notification to {url}: {e}")
            return False

    @staticmethod
    def _mask_url(url: Optional[str]) -> Optional[str]:
        if not url or len(url) < 15:
            return url
        return url[:12] + "..." + url[-6:]


# Global singleton instance
alert_notifier = AlertNotifier()
