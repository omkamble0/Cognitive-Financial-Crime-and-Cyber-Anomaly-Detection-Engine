"""
AegisFlow Platform — Enterprise Database & Persistence Engine (PostgreSQL / SQLite)
Author: Om Kamble

Provides persistent storage and ACID transactions for:
- Payment transactions & ML model decisions
- Real-time Alert Queue & Case Management
- Collaborative Analyst Investigation Notes & Overrides
- Cryptographic Rule Audit Trails
"""

import os
import json
import secrets
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from src.core.security import hash_password, verify_password, UserRole

DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("SUPABASE_DB_URL")
IS_POSTGRES = bool(DATABASE_URL and (DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://")))

if IS_POSTGRES:
    import psycopg2
    from psycopg2.extras import RealDictCursor
else:
    import sqlite3

DB_FALLBACK_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "aegisflow_cloud.db")


def get_db_connection():
    if IS_POSTGRES:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        return conn
    else:
        os.makedirs(os.path.dirname(DB_FALLBACK_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_FALLBACK_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn


def get_database_status() -> Dict[str, Any]:
    """Return whether connected to Supabase/Postgres Cloud or local fallback."""
    if IS_POSTGRES:
        db_host = DATABASE_URL.split("@")[-1].split("/")[0] if "@" in DATABASE_URL else "Cloud PostgreSQL"
        return {
            "type": "Supabase / Cloud PostgreSQL",
            "host": db_host,
            "connected": True,
            "is_cloud": True
        }
    return {
        "type": "Cloud Ready (SQLite Fallback)",
        "host": "local (Set DATABASE_URL in .env to connect to Cloud PostgreSQL)",
        "connected": True,
        "is_cloud": False
    }


def init_database():
    """Initialize cloud PostgreSQL or SQLite schema with full audit & case management tables."""
    conn = get_db_connection()
    cursor = conn.cursor()

    if IS_POSTGRES:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                full_name VARCHAR(255) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                salt VARCHAR(100) NOT NULL,
                role VARCHAR(100) NOT NULL DEFAULT 'analyst',
                avatar_initials VARCHAR(10) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP WITH TIME ZONE
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                action VARCHAR(255) NOT NULL,
                details TEXT,
                timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token VARCHAR(255) PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS transactions (
                id SERIAL PRIMARY KEY,
                transaction_id VARCHAR(100) UNIQUE NOT NULL,
                user_id VARCHAR(100) NOT NULL,
                card_identifier VARCHAR(100),
                amount DOUBLE PRECISION NOT NULL,
                currency VARCHAR(10) NOT NULL,
                normalized_usd DOUBLE PRECISION NOT NULL,
                merchant_id VARCHAR(100),
                ip_address VARCHAR(100),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS decisions (
                id SERIAL PRIMARY KEY,
                transaction_id VARCHAR(100) NOT NULL REFERENCES transactions(transaction_id) ON DELETE CASCADE,
                user_id VARCHAR(100) NOT NULL,
                risk_score DOUBLE PRECISION NOT NULL,
                decision VARCHAR(50) NOT NULL,
                risk_level VARCHAR(50) NOT NULL,
                latency_ms DOUBLE PRECISION NOT NULL,
                model_version VARCHAR(50) NOT NULL,
                triggered_rules TEXT,
                explainability TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS cases (
                id SERIAL PRIMARY KEY,
                case_number VARCHAR(100) UNIQUE NOT NULL,
                title VARCHAR(255) NOT NULL,
                priority VARCHAR(50) NOT NULL,
                status VARCHAR(50) NOT NULL DEFAULT 'OPEN',
                entity_id VARCHAR(100) NOT NULL,
                risk_score DOUBLE PRECISION NOT NULL,
                assigned_to VARCHAR(100),
                disposition VARCHAR(100),
                linked_transactions TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                transaction_id VARCHAR(100) NOT NULL,
                user_id VARCHAR(100) NOT NULL,
                severity VARCHAR(50) NOT NULL,
                status VARCHAR(50) NOT NULL DEFAULT 'OPEN',
                title VARCHAR(255) NOT NULL,
                summary TEXT NOT NULL,
                risk_score DOUBLE PRECISION NOT NULL,
                assigned_to VARCHAR(100),
                case_id INTEGER REFERENCES cases(id) ON DELETE SET NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS case_notes (
                id SERIAL PRIMARY KEY,
                case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                author VARCHAR(100) NOT NULL,
                note_text TEXT NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS analyst_actions (
                id SERIAL PRIMARY KEY,
                operator VARCHAR(100) NOT NULL,
                action_type VARCHAR(100) NOT NULL,
                target_id VARCHAR(100) NOT NULL,
                previous_state VARCHAR(100),
                new_state VARCHAR(100),
                reason TEXT NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS rule_audits (
                id SERIAL PRIMARY KEY,
                rule_name VARCHAR(100) NOT NULL,
                action VARCHAR(50) NOT NULL,
                operator VARCHAR(100) NOT NULL,
                previous_predicate TEXT,
                new_predicate TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)
    else:
        # SQLite Schema
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'analyst',
                avatar_initials TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL,
                card_identifier TEXT,
                amount REAL NOT NULL,
                currency TEXT NOT NULL,
                normalized_usd REAL NOT NULL,
                merchant_id TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                risk_score REAL NOT NULL,
                decision TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                latency_ms REAL NOT NULL,
                model_version TEXT NOT NULL,
                triggered_rules TEXT,
                explainability TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (transaction_id) REFERENCES transactions (transaction_id)
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_number TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                priority TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN',
                entity_id TEXT NOT NULL,
                risk_score REAL NOT NULL,
                assigned_to TEXT,
                disposition TEXT,
                linked_transactions TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN',
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                risk_score REAL NOT NULL,
                assigned_to TEXT,
                case_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES cases (id)
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS case_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                author TEXT NOT NULL,
                note_text TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES cases (id)
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analyst_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operator TEXT NOT NULL,
                action_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                previous_state TEXT,
                new_state TEXT,
                reason TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rule_audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                action TEXT NOT NULL,
                operator TEXT NOT NULL,
                previous_predicate TEXT,
                new_predicate TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

    # Phase 7: Multi-Tenant schema migration (ensure tenant_id exists across key tables)
    for tbl in ["cases", "alerts", "transactions", "decisions"]:
        try:
            if IS_POSTGRES:
                cursor.execute(f"ALTER TABLE {tbl} ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) DEFAULT 'default'")
            else:
                cursor.execute(f"ALTER TABLE {tbl} ADD COLUMN tenant_id TEXT DEFAULT 'default'")
        except Exception:
            pass

    # Ensure admin, analyst, and auditor accounts are seeded
    param = "%s" if IS_POSTGRES else "?"
    default_accounts = [
        ("admin", "admin@risk-platform.ai", "Om Kamble", "SECurity@uDit66@", "admin", "OK"),
        ("analyst_sarah", "sarah.chen@risk-platform.ai", "Sarah Chen", "Analyst2026!Secure", "analyst", "SC"),
        ("manager_marcus", "marcus.vance@risk-platform.ai", "Marcus Vance", "Manager2026!Secure", "fraud_manager", "MV"),
        ("auditor_elena", "elena.rostova@compliance.ai", "Elena Rostova", "Auditor2026!Secure", "auditor", "ER")
    ]
    for uname, email, fname, pwd, role, initials in default_accounts:
        cursor.execute(f"SELECT id FROM users WHERE LOWER(username) = LOWER({param})", (uname,))
        if not cursor.fetchone():
            h, s = hash_password(pwd)
            cursor.execute(f"""
                INSERT INTO users (username, email, full_name, password_hash, salt, role, avatar_initials)
                VALUES ({param}, {param}, {param}, {param}, {param}, {param}, {param})
            """, (uname, email, fname, h, s, role, initials))

    # Seed baseline demonstration case if none exist
    cursor.execute("SELECT COUNT(*) as cnt FROM cases")
    row = cursor.fetchone()
    case_cnt = row["cnt"] if isinstance(row, dict) or hasattr(row, "__getitem__") else row[0]
    if case_cnt == 0:
        cursor.execute(f"""
            INSERT INTO cases (case_number, title, priority, status, entity_id, risk_score, assigned_to, linked_transactions)
            VALUES ({param}, {param}, {param}, {param}, {param}, {param}, {param}, {param})
        """, (
            "CASE-2026-0891",
            "Coordinated Multi-Card Probing via Tor Exit Node (198.51.100.99)",
            "P1_CRITICAL",
            "OPEN",
            "ip_198.51.100.99",
            0.98,
            "analyst_sarah",
            json.dumps(["TXN_881920", "TXN_881921", "TXN_881922"])
        ))
        cursor.execute(f"""
            INSERT INTO cases (case_number, title, priority, status, entity_id, risk_score, assigned_to, linked_transactions)
            VALUES ({param}, {param}, {param}, {param}, {param}, {param}, {param}, {param})
        """, (
            "CASE-2026-0892",
            "High-Ticket Velocity Surge on Dormant Corporate Fleet Card",
            "P2_HIGH",
            "IN_REVIEW",
            "card_fleet_wex_881",
            0.84,
            "manager_marcus",
            json.dumps(["TXN_991044", "TXN_991045"])
        ))

    conn.commit()
    conn.close()


def persist_transaction_evaluation(
    txn_dict: Dict[str, Any],
    risk_score: float,
    decision_str: str,
    risk_level: str,
    latency_ms: float,
    triggered_rules: List[str],
    explainability: List[Dict[str, Any]],
    model_version: str = "v2.3-rf-pca",
    tenant_id: str = "default"
) -> bool:
    """Thread-safe persistence of transaction payload and authorization decision with multi-tenant partitioning."""
    conn = get_db_connection()
    cursor = conn.cursor()
    param = "%s" if IS_POSTGRES else "?"

    txn_id = txn_dict.get("transaction_id") or f"TXN_{secrets.token_hex(6)}"
    user_id = txn_dict.get("user_id", "user_unknown")
    card_id = txn_dict.get("card_identifier") or txn_dict.get("card_id")
    amount = float(txn_dict.get("Amount", txn_dict.get("amount", 0.0)))
    currency = str(txn_dict.get("currency", "USD")).upper()
    norm_usd = float(txn_dict.get("normalized_usd", amount))
    merchant_id = str(txn_dict.get("merchant_id", "mcht_unknown"))
    ip_addr = str(txn_dict.get("ip_address", "127.0.0.1"))
    tid = txn_dict.get("tenant_id") or tenant_id or "default"

    try:
        # Insert transaction (idempotent)
        if IS_POSTGRES:
            cursor.execute(f"""
                INSERT INTO transactions (transaction_id, user_id, card_identifier, amount, currency, normalized_usd, merchant_id, ip_address, tenant_id)
                VALUES ({param}, {param}, {param}, {param}, {param}, {param}, {param}, {param}, {param})
                ON CONFLICT (transaction_id) DO NOTHING
            """, (txn_id, user_id, card_id, amount, currency, norm_usd, merchant_id, ip_addr, tid))

            cursor.execute(f"""
                INSERT INTO decisions (transaction_id, user_id, risk_score, decision, risk_level, latency_ms, model_version, triggered_rules, explainability, tenant_id)
                VALUES ({param}, {param}, {param}, {param}, {param}, {param}, {param}, {param}, {param}, {param})
                ON CONFLICT (transaction_id) DO NOTHING
            """, (
                txn_id, user_id, risk_score, decision_str, risk_level, latency_ms, model_version,
                json.dumps(triggered_rules), json.dumps(explainability), tid
            ))
        else:
            cursor.execute(f"""
                INSERT OR IGNORE INTO transactions (transaction_id, user_id, card_identifier, amount, currency, normalized_usd, merchant_id, ip_address, tenant_id)
                VALUES ({param}, {param}, {param}, {param}, {param}, {param}, {param}, {param}, {param})
            """, (txn_id, user_id, card_id, amount, currency, norm_usd, merchant_id, ip_addr, tid))

            cursor.execute(f"""
                INSERT OR IGNORE INTO decisions (transaction_id, user_id, risk_score, decision, risk_level, latency_ms, model_version, triggered_rules, explainability, tenant_id)
                VALUES ({param}, {param}, {param}, {param}, {param}, {param}, {param}, {param}, {param}, {param})
            """, (
                txn_id, user_id, risk_score, decision_str, risk_level, latency_ms, model_version,
                json.dumps(triggered_rules), json.dumps(explainability), tid
            ))

        # If high-risk or blocked, automatically generate an Alert record & dispatch notification
        if risk_score >= 0.75 or decision_str in ("BLOCK", "CHALLENGE_2FA"):
            severity = "CRITICAL" if risk_score >= 0.90 else "HIGH" if risk_score >= 0.75 else "MEDIUM"
            alert_title = f"Automated Risk Alert: {decision_str} on {currency} {amount:,.2f}"
            alert_summary = f"Triggered by rules: {', '.join(triggered_rules[:3])}"
            cursor.execute(f"""
                INSERT INTO alerts (transaction_id, user_id, severity, status, title, summary, risk_score, tenant_id)
                VALUES ({param}, {param}, {param}, 'OPEN', {param}, {param}, {param}, {param})
            """, (
                txn_id, user_id, severity,
                alert_title,
                alert_summary,
                risk_score,
                tid
            ))

            # Outbound alert notification (Phase 7)
            try:
                from src.engine.notifier import alert_notifier
                alert_notifier.dispatch(
                    alert_title=alert_title,
                    severity=severity,
                    summary=alert_summary,
                    risk_score=risk_score,
                    entity_id=user_id,
                    transaction_id=txn_id,
                    tenant_id=tid
                )
            except Exception:
                pass

        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        return False
    finally:
        conn.close()


# =============================================================================
# CASE MANAGEMENT & INVESTIGATION CRUD
# =============================================================================

def list_cases(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    limit: int = 50,
    tenant_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    param = "%s" if IS_POSTGRES else "?"

    query = "SELECT * FROM cases WHERE 1=1"
    params = []
    if status:
        query += f" AND status = {param}"
        params.append(status.upper())
    if priority:
        query += f" AND priority = {param}"
        params.append(priority.upper())
    if tenant_id:
        query += f" AND tenant_id = {param}"
        params.append(tenant_id)
    try:
        safe_limit = max(1, min(1000, int(limit)))
    except (ValueError, TypeError):
        safe_limit = 50
    query += f" ORDER BY id DESC LIMIT {param}"
    params.append(safe_limit)

    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()

    result = []
    for r in rows:
        d = dict(r)
        if isinstance(d.get("linked_transactions"), str):
            try:
                d["linked_transactions"] = json.loads(d["linked_transactions"])
            except Exception:
                d["linked_transactions"] = []
        result.append(d)
    return result


def get_case_detail(case_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    param = "%s" if IS_POSTGRES else "?"

    cursor.execute(f"SELECT * FROM cases WHERE id = {param}", (case_id,))
    case_row = cursor.fetchone()
    if not case_row:
        conn.close()
        return None

    case_dict = dict(case_row)
    if isinstance(case_dict.get("linked_transactions"), str):
        try:
            case_dict["linked_transactions"] = json.loads(case_dict["linked_transactions"])
        except Exception:
            case_dict["linked_transactions"] = []

    # Fetch notes
    cursor.execute(f"SELECT * FROM case_notes WHERE case_id = {param} ORDER BY id ASC", (case_id,))
    notes = [dict(n) for n in cursor.fetchall()]
    case_dict["notes"] = notes

    # Fetch linked alerts
    cursor.execute(f"SELECT * FROM alerts WHERE case_id = {param} ORDER BY id DESC", (case_id,))
    alerts = [dict(a) for a in cursor.fetchall()]
    case_dict["alerts"] = alerts

    conn.close()
    return case_dict


def create_case(
    title: str,
    priority: str,
    entity_id: str,
    risk_score: float,
    assigned_to: Optional[str] = None,
    linked_transactions: Optional[List[str]] = None,
    tenant_id: str = "default"
) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    param = "%s" if IS_POSTGRES else "?"

    case_num = f"CASE-{datetime.now().year}-{secrets.randbelow(9000) + 1000}"
    tx_json = json.dumps(linked_transactions or [])

    if IS_POSTGRES:
        cursor.execute(f"""
            INSERT INTO cases (case_number, title, priority, status, entity_id, risk_score, assigned_to, linked_transactions, tenant_id)
            VALUES ({param}, {param}, {param}, 'OPEN', {param}, {param}, {param}, {param}, {param})
            RETURNING id;
        """, (case_num, title, priority.upper(), entity_id, risk_score, assigned_to, tx_json, tenant_id))
        case_id = cursor.fetchone()["id"]
    else:
        cursor.execute(f"""
            INSERT INTO cases (case_number, title, priority, status, entity_id, risk_score, assigned_to, linked_transactions, tenant_id)
            VALUES ({param}, {param}, {param}, 'OPEN', {param}, {param}, {param}, {param}, {param})
        """, (case_num, title, priority.upper(), entity_id, risk_score, assigned_to, tx_json, tenant_id))
        case_id = cursor.lastrowid

    conn.commit()
    conn.close()

    # Outbound alert notification on critical case creation (Phase 7)
    if str(priority).upper() in ("P1_CRITICAL", "CRITICAL"):
        try:
            from src.engine.notifier import alert_notifier
            alert_notifier.dispatch(
                alert_title=f"Critical Case Created: {case_num}",
                severity="CRITICAL",
                summary=title,
                risk_score=risk_score,
                entity_id=entity_id,
                tenant_id=tenant_id
            )
        except Exception:
            pass

    return get_case_detail(case_id)


def update_case_status(
    case_id: int,
    new_status: str,
    operator: str,
    disposition: Optional[str] = None,
    reason: str = "Status updated via Case Management"
) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    param = "%s" if IS_POSTGRES else "?"

    cursor.execute(f"SELECT status, case_number FROM cases WHERE id = {param}", (case_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    prev_status = row["status"]
    case_num = row["case_number"]

    cursor.execute(f"""
        UPDATE cases 
        SET status = {param}, disposition = {param}, updated_at = CURRENT_TIMESTAMP
        WHERE id = {param}
    """, (new_status.upper(), disposition, case_id))

    # Record analyst action audit trail
    cursor.execute(f"""
        INSERT INTO analyst_actions (operator, action_type, target_id, previous_state, new_state, reason)
        VALUES ({param}, 'CASE_STATUS_CHANGE', {param}, {param}, {param}, {param})
    """, (operator, case_num, prev_status, new_status.upper(), reason))

    conn.commit()
    conn.close()
    return get_case_detail(case_id)


def add_case_note(case_id: int, author: str, note_text: str) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    param = "%s" if IS_POSTGRES else "?"

    cursor.execute(f"""
        INSERT INTO case_notes (case_id, author, note_text)
        VALUES ({param}, {param}, {param})
    """, (case_id, author, note_text))
    conn.commit()
    conn.close()
    return {"case_id": case_id, "author": author, "note_text": note_text, "timestamp": datetime.now(timezone.utc).isoformat()}


# =============================================================================
# ALERT QUEUE CRUD
# =============================================================================

def list_alerts(
    status: Optional[str] = None,
    limit: int = 50,
    tenant_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    param = "%s" if IS_POSTGRES else "?"

    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if status:
        query += f" AND status = {param}"
        params.append(status.upper())
    if tenant_id:
        query += f" AND tenant_id = {param}"
        params.append(tenant_id)
    try:
        safe_limit = max(1, min(1000, int(limit)))
    except (ValueError, TypeError):
        safe_limit = 50
    query += f" ORDER BY id DESC LIMIT {param}"
    params.append(safe_limit)

    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_alert_status(alert_id: int, new_status: str, operator: str, reason: str = "") -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    param = "%s" if IS_POSTGRES else "?"

    cursor.execute(f"UPDATE alerts SET status = {param}, updated_at = CURRENT_TIMESTAMP WHERE id = {param}", (new_status.upper(), alert_id))
    cursor.execute(f"""
        INSERT INTO analyst_actions (operator, action_type, target_id, previous_state, new_state, reason)
        VALUES ({param}, 'ALERT_TRIAGE', {param}, 'OPEN', {param}, {param})
    """, (operator, str(alert_id), new_status.upper(), reason or f"Alert marked as {new_status}"))
    conn.commit()
    conn.close()
    return True


# =============================================================================
# USER AUTHENTICATION & SESSION MANAGEMENT
# =============================================================================

def register_user(username: str, email: str, full_name: str, password: str, role: str = "analyst") -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    param = "%s" if IS_POSTGRES else "?"

    query_check = f"SELECT id FROM users WHERE LOWER(username) = LOWER({param}) OR LOWER(email) = LOWER({param})"
    cursor.execute(query_check, (username.strip(), email.strip()))
    if cursor.fetchone():
        conn.close()
        raise ValueError("Username or Email is already registered.")

    parts = full_name.strip().split()
    initials = "".join([p[0].upper() for p in parts[:2]]) if parts else "U"
    pwd_hash, salt = hash_password(password)

    if IS_POSTGRES:
        cursor.execute(f"""
            INSERT INTO users (username, email, full_name, password_hash, salt, role, avatar_initials)
            VALUES ({param}, {param}, {param}, {param}, {param}, {param}, {param})
            RETURNING id;
        """, (username.strip().lower(), email.strip().lower(), full_name.strip(), pwd_hash, salt, role, initials))
        user_id = cursor.fetchone()["id"]
    else:
        cursor.execute(f"""
            INSERT INTO users (username, email, full_name, password_hash, salt, role, avatar_initials)
            VALUES ({param}, {param}, {param}, {param}, {param}, {param}, {param})
        """, (username.strip().lower(), email.strip().lower(), full_name.strip(), pwd_hash, salt, role, initials))
        user_id = cursor.lastrowid

    token = secrets.token_urlsafe(32)
    cursor.execute(f"INSERT INTO sessions (token, user_id) VALUES ({param}, {param})", (token, user_id))
    conn.commit()
    conn.close()

    return {
        "id": user_id,
        "username": username.strip().lower(),
        "email": email.strip().lower(),
        "full_name": full_name.strip(),
        "role": role,
        "avatar_initials": initials,
        "token": token
    }


def authenticate_user(identifier: str, password: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    param = "%s" if IS_POSTGRES else "?"

    query = f"""
        SELECT id, username, email, full_name, password_hash, salt, role, avatar_initials 
        FROM users 
        WHERE LOWER(username) = LOWER({param}) OR LOWER(email) = LOWER({param})
    """
    cursor.execute(query, (identifier.strip(), identifier.strip()))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return None

    if not verify_password(password, row["password_hash"], row["salt"]):
        conn.close()
        return None

    cursor.execute(f"UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = {param}", (row["id"],))
    token = secrets.token_urlsafe(32)
    cursor.execute(f"INSERT INTO sessions (token, user_id) VALUES ({param}, {param})", (token, row["id"]))
    conn.commit()
    conn.close()

    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "full_name": row["full_name"],
        "role": row["role"],
        "avatar_initials": row["avatar_initials"],
        "token": token
    }


def get_user_by_token(token: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    param = "%s" if IS_POSTGRES else "?"

    query = f"""
        SELECT u.id, u.username, u.email, u.full_name, u.role, u.avatar_initials, u.created_at, u.last_login
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = {param}
    """
    cursor.execute(query, (token,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None

    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "full_name": row["full_name"],
        "role": row["role"],
        "avatar_initials": row["avatar_initials"],
        "created_at": str(row["created_at"]),
        "last_login": str(row["last_login"])
    }


def list_registered_users() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, full_name, role, avatar_initials, created_at FROM users ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def logout_session(token: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    param = "%s" if IS_POSTGRES else "?"
    cursor.execute(f"DELETE FROM sessions WHERE token = {param}", (token,))
    conn.commit()
    conn.close()


def get_entity_intelligence(entity_id: str) -> Dict[str, Any]:
    """Retrieves 360-degree entity intelligence (linked cards, IPs, spend volume, cases, alerts)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    param = "%s" if IS_POSTGRES else "?"

    query_tx = f"""
        SELECT t.transaction_id, t.user_id, t.card_identifier, t.amount, t.currency, t.normalized_usd, t.merchant_id, t.ip_address, t.created_at,
               d.risk_score, d.decision, d.risk_level, d.model_version
        FROM transactions t
        LEFT JOIN decisions d ON t.transaction_id = d.transaction_id
        WHERE t.user_id = {param} OR t.card_identifier = {param} OR t.ip_address = {param}
        ORDER BY t.id DESC LIMIT 50
    """
    cursor.execute(query_tx, (entity_id, entity_id, entity_id))
    tx_rows = [dict(r) for r in cursor.fetchall()]

    linked_cards = list({r["card_identifier"] for r in tx_rows if r.get("card_identifier")})
    linked_ips = list({r["ip_address"] for r in tx_rows if r.get("ip_address")})
    merchants = list({r["merchant_id"] for r in tx_rows if r.get("merchant_id")})
    total_volume = sum(r.get("normalized_usd", 0.0) for r in tx_rows)

    cursor.execute(f"SELECT * FROM cases WHERE entity_id = {param} OR entity_id LIKE {param} ORDER BY id DESC LIMIT 10", (entity_id, f"%{entity_id}%"))
    case_rows = [dict(c) for c in cursor.fetchall()]

    cursor.execute(f"SELECT * FROM alerts WHERE user_id = {param} ORDER BY id DESC LIMIT 15", (entity_id,))
    alert_rows = [dict(a) for a in cursor.fetchall()]

    conn.close()

    max_risk = max([r.get("risk_score", 0.0) for r in tx_rows] or [0.0])

    return {
        "entity_id": entity_id,
        "overall_risk_score": max_risk,
        "total_transactions": len(tx_rows),
        "total_volume_usd": round(total_volume, 2),
        "linked_cards": linked_cards,
        "linked_ips": linked_ips,
        "associated_merchants": merchants,
        "cases": case_rows,
        "alerts": alert_rows,
        "recent_timeline": tx_rows[:20]
    }


def list_active_tenants() -> List[Dict[str, Any]]:
    """Lists distinct organization tenants with case, alert, and transaction volume statistics (Phase 7)."""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT DISTINCT tenant_id FROM cases WHERE tenant_id IS NOT NULL")
        case_tenants = {r[0] if isinstance(r, tuple) else r["tenant_id"] for r in cursor.fetchall()}
    except Exception:
        case_tenants = set()

    try:
        cursor.execute("SELECT DISTINCT tenant_id FROM transactions WHERE tenant_id IS NOT NULL")
        tx_tenants = {r[0] if isinstance(r, tuple) else r["tenant_id"] for r in cursor.fetchall()}
    except Exception:
        tx_tenants = set()

    all_tenants = sorted(list(case_tenants | tx_tenants | {"default", "tenant_enterprise_01"}))

    param = "%s" if IS_POSTGRES else "?"
    results = []
    for tid in all_tenants:
        try:
            cursor.execute(f"SELECT COUNT(*) as c FROM cases WHERE tenant_id = {param}", (tid,))
            row = cursor.fetchone()
            c_cnt = row["c"] if isinstance(row, dict) else row[0]
        except Exception:
            c_cnt = 0

        try:
            cursor.execute(f"SELECT COUNT(*) as a FROM alerts WHERE tenant_id = {param}", (tid,))
            row = cursor.fetchone()
            a_cnt = row["a"] if isinstance(row, dict) else row[0]
        except Exception:
            a_cnt = 0

        try:
            cursor.execute(f"SELECT COUNT(*) as t FROM transactions WHERE tenant_id = {param}", (tid,))
            row = cursor.fetchone()
            t_cnt = row["t"] if isinstance(row, dict) else row[0]
        except Exception:
            t_cnt = 0

        results.append({
            "tenant_id": tid,
            "status": "ACTIVE",
            "total_cases": c_cnt,
            "total_alerts": a_cnt,
            "total_transactions": t_cnt,
            "tier": "ENTERPRISE" if "enterprise" in tid else "STANDARD"
        })

    conn.close()
    return results

