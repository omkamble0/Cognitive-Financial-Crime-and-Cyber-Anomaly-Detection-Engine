"""
AegisNexus — Alert Deduplication & Suppression Engine
Author: Om Kamble
"""

import time
from typing import Dict, Any, Optional, Tuple
from libs.models.alerts import Alert, AlertSeverity, AlertStatus


class AlertDeduplicator:
    """
    Prevents alert fatigue by suppressing duplicate alerts within a sliding time window.
    Consolidates rapid alert bursts into a single high-context alert.
    """

    def __init__(self, suppression_window_seconds: float = 300.0, max_cache_size: int = 5000):
        self.suppression_window = suppression_window_seconds
        self.max_cache_size = max_cache_size
        # Map: fingerprint -> {"alert": Alert, "first_seen": float, "last_seen": float, "count": int}
        self._cache: Dict[str, Dict[str, Any]] = {}

    def process_alert(self, alert: Alert) -> Tuple[bool, Alert]:
        """
        Processes an incoming alert.
        Returns:
            (is_new, effective_alert)
            - is_new = True: This alert should be published / escalated to case management.
            - is_new = False: This alert is a duplicate and was suppressed in the sliding window.
        """
        now = time.time()
        self._prune(now)

        fp = alert.dedup_fingerprint
        record = self._cache.get(fp)

        if record and (now - record["first_seen"]) < self.suppression_window:
            # Duplicate within suppression window
            record["count"] += 1
            record["last_seen"] = now
            cached_alert: Alert = record["alert"]
            cached_alert.suppression_count = record["count"]
            cached_alert.updated_at = now
            # Elevate severity if burst is aggressive
            if record["count"] >= 10 and cached_alert.severity != AlertSeverity.P1_CRITICAL:
                cached_alert.severity = AlertSeverity.P1_CRITICAL
                cached_alert.title = f"[AGGRESSIVE BURST x{record['count']}] {alert.title}"
            return False, cached_alert

        # First occurrence in window
        self._cache[fp] = {
            "alert": alert,
            "first_seen": now,
            "last_seen": now,
            "count": 0
        }
        return True, alert

    def _prune(self, now: float):
        """Cleans up expired suppression keys to bound memory growth."""
        if len(self._cache) > 200:
            expired = [fp for fp, rec in self._cache.items() if (now - rec["last_seen"]) > self.suppression_window]
            for fp in expired:
                self._cache.pop(fp, None)

        if len(self._cache) > self.max_cache_size:
            # LRU eviction
            for fp in list(self._cache.keys())[:500]:
                self._cache.pop(fp, None)


# Singleton instance
alert_deduplicator = AlertDeduplicator()
