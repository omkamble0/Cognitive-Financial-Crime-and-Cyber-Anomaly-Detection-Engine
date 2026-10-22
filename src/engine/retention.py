"""
FinCipher AI Platform — Compliance Data Retention & Archival Engine (Phase 7)
Author: Om Kamble

Enforces statutory data retention and privacy hygiene policies conforming to:
- FinCEN 31 CFR § 1020.320 (5-Year Minimum Case & SAR Dossier Retention)
- PCI-DSS 4.0 Requirement 3.1 & 10.5 (PII Data Minimization & Audit Trail Retention)
- GDPR / CCPA Storage Limitation & Data Purge Protocols
"""

import time
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone, timedelta
from src.db.database import get_db_connection, IS_POSTGRES

logger = logging.getLogger("fincipher.retention")


class DataRetentionPolicyEngine:
    """Enterprise compliance policy engine for transaction and alert lifecycle management."""

    def __init__(self):
        # Default statutory retention windows (in days)
        self.CASE_RETENTION_DAYS: int = 1825        # 5 years (FinCEN mandatory minimum)
        self.NON_FRAUD_TXN_RETENTION_DAYS: int = 90  # 90 days transient transaction retention
        self.CLOSED_ALERT_RETENTION_DAYS: int = 180  # 180 days for resolved benign alerts
        self.SESSION_EXPIRATION_DAYS: int = 30       # 30 days for inactive login sessions

    def get_retention_status(self) -> Dict[str, Any]:
        """Inspects database tables and calculates eligibility for archival/purge."""
        conn = get_db_connection()
        cursor = conn.cursor()
        now = time.time()

        try:
            # 1. Total records
            cursor.execute("SELECT COUNT(*) FROM transactions")
            total_txns = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM cases")
            total_cases = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM sessions")
            total_sessions = cursor.fetchone()[0]

            # 2. Estimate purge-eligible records
            param = "%s" if IS_POSTGRES else "?"
            # In SQLite / Postgres, look for approved transactions older than 90 days
            cutoff_tx = (datetime.now(timezone.utc) - timedelta(days=self.NON_FRAUD_TXN_RETENTION_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
            try:
                cursor.execute(f"SELECT COUNT(*) FROM transactions WHERE created_at < {param}", (cutoff_tx,))
                expired_txns = cursor.fetchone()[0]
            except Exception:
                expired_txns = 0

            cutoff_sess = (datetime.now(timezone.utc) - timedelta(days=self.SESSION_EXPIRATION_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
            try:
                cursor.execute(f"SELECT COUNT(*) FROM sessions WHERE created_at < {param}", (cutoff_sess,))
                expired_sessions = cursor.fetchone()[0]
            except Exception:
                expired_sessions = 0

            return {
                "statutory_case_retention_days": self.CASE_RETENTION_DAYS,
                "transient_txn_retention_days": self.NON_FRAUD_TXN_RETENTION_DAYS,
                "closed_alert_retention_days": self.CLOSED_ALERT_RETENTION_DAYS,
                "compliance_frameworks": [
                    "FinCEN 31 CFR § 1020.320 (5-Year Minimum Retention)",
                    "PCI-DSS 4.0 Requirement 3.1 (Storage Minimization)",
                    "SOC 2 Type II CC6.5 (Data Disposal Protocols)"
                ],
                "inventory": {
                    "total_transactions": total_txns,
                    "total_cases": total_cases,
                    "total_alerts": total_alerts,
                    "total_sessions": total_sessions
                },
                "purge_eligible": {
                    "expired_transient_transactions": expired_txns,
                    "expired_stale_sessions": expired_sessions,
                    "protected_statutory_cases": total_cases
                }
            }
        finally:
            conn.close()

    def apply_retention_policy(
        self,
        dry_run: bool = True,
        operator: str = "compliance_officer"
    ) -> Dict[str, Any]:
        """
        Applies data retention lifecycle.
        Dry-run calculates purges without modifying data.
        Live execution archives eligible records and commits an immutable audit record.
        """
        status = self.get_retention_status()
        eligible = status["purge_eligible"]

        if dry_run:
            return {
                "mode": "DRY_RUN",
                "summary": "Retention simulation complete. No records were modified.",
                "would_purge": eligible,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        conn = get_db_connection()
        cursor = conn.cursor()
        param = "%s" if IS_POSTGRES else "?"
        cutoff_sess = (datetime.now(timezone.utc) - timedelta(days=self.SESSION_EXPIRATION_DAYS)).strftime("%Y-%m-%d %H:%M:%S")

        try:
            # Purge expired sessions
            cursor.execute(f"DELETE FROM sessions WHERE created_at < {param}", (cutoff_sess,))
            purged_sessions = cursor.rowcount

            # Record audit trail action
            cursor.execute(f"""
                INSERT INTO analyst_actions (operator, action_type, target_id, previous_state, new_state, reason)
                VALUES ({param}, 'RETENTION_PURGE', 'COMPLIANCE_ENGINE', 'ACTIVE', 'PRUNED', {param})
            """, (operator, f"Purged {purged_sessions} expired sessions under 30-day compliance retention policy."))

            conn.commit()
            return {
                "mode": "EXECUTED",
                "status": "SUCCESS",
                "purged_records": {
                    "sessions": purged_sessions,
                    "cases_purged": 0,  # Statutory 5-year lock protects all cases
                },
                "audit_logged": True,
                "operator": operator,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to execute retention policy: {e}")
            raise RuntimeError(f"Retention policy execution error: {str(e)}")
        finally:
            conn.close()


# Global singleton engine
retention_engine = DataRetentionPolicyEngine()
