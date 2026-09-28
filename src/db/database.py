"""
AegisFlow AI — Cloud Database & Authentication Engine (Supabase / PostgreSQL Cloud)
Author: Om Kamble
"""

import os
import hashlib
import secrets
from datetime import datetime
from typing import Optional, Dict, Any, List

# Check environment for cloud database URL (e.g. Supabase, Neon, AWS RDS, etc.)
DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("SUPABASE_DB_URL")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY") or os.getenv("SUPABASE_ANON_KEY")

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


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    return hashed, salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    hashed, _ = hash_password(password, salt)
    return hashed == stored_hash


def get_database_status() -> Dict[str, Any]:
    """Return whether connected to Supabase/Postgres Cloud or local fallback."""
    if IS_POSTGRES:
        # Mask credentials in URL for safety
        db_host = DATABASE_URL.split("@")[-1].split("/")[0] if "@" in DATABASE_URL else "Cloud PostgreSQL"
        return {
            "type": "Supabase / Cloud PostgreSQL",
            "host": db_host,
            "connected": True,
            "is_cloud": True
        }
    return {
        "type": "Cloud Ready (SQLite Fallback)",
        "host": "local (Set DATABASE_URL in .env to connect to Supabase Cloud)",
        "connected": True,
        "is_cloud": False
    }


def init_database():
    """Initialize cloud PostgreSQL or SQLite schema. Does NOT seed fake users."""
    conn = get_db_connection()
    cursor = conn.cursor()

    if IS_POSTGRES:
        # Cloud PostgreSQL Schema (Supabase)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                full_name VARCHAR(255) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                salt VARCHAR(100) NOT NULL,
                role VARCHAR(100) NOT NULL DEFAULT 'Risk Analyst',
                avatar_initials VARCHAR(10) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP WITH TIME ZONE
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                action VARCHAR(255) NOT NULL,
                details TEXT,
                timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token VARCHAR(255) PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
                role TEXT NOT NULL DEFAULT 'Risk Analyst',
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
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)

    # Ensure master admin account is initialized
    param_placeholder = "%s" if IS_POSTGRES else "?"
    cursor.execute(f"SELECT id FROM users WHERE LOWER(username) = LOWER({param_placeholder})", ("admin",))
    if not cursor.fetchone():
        h, s = hash_password("SECurity@uDit66@")
        if IS_POSTGRES:
            cursor.execute("""
                INSERT INTO users (username, email, full_name, password_hash, salt, role, avatar_initials)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, ("admin", "admin@risk-platform.ai", "Om Kamble", h, s, "Lead Risk Architect", "OK"))
        else:
            cursor.execute("""
                INSERT INTO users (username, email, full_name, password_hash, salt, role, avatar_initials)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, ("admin", "admin@risk-platform.ai", "Om Kamble", h, s, "Lead Risk Architect", "OK"))

    conn.commit()
    conn.close()
    print(f"[OK] Database Schema Initialized ({'Supabase / Postgres Cloud' if IS_POSTGRES else 'Zero-Setup Database'}). Master account configured.")


def register_user(username: str, email: str, full_name: str, password: str, role: str = "Risk Analyst") -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()

    param_placeholder = "%s" if IS_POSTGRES else "?"

    # Check if username or email exists
    query_check = f"SELECT id FROM users WHERE LOWER(username) = LOWER({param_placeholder}) OR LOWER(email) = LOWER({param_placeholder})"
    cursor.execute(query_check, (username.strip(), email.strip()))
    if cursor.fetchone():
        conn.close()
        raise ValueError("Username or Email is already registered.")

    parts = full_name.strip().split()
    initials = "".join([p[0].upper() for p in parts[:2]]) if parts else "U"
    pwd_hash, salt = hash_password(password)

    if IS_POSTGRES:
        cursor.execute("""
            INSERT INTO users (username, email, full_name, password_hash, salt, role, avatar_initials)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
        """, (username.strip().lower(), email.strip().lower(), full_name.strip(), pwd_hash, salt, role, initials))
        user_id = cursor.fetchone()["id"]
    else:
        cursor.execute("""
            INSERT INTO users (username, email, full_name, password_hash, salt, role, avatar_initials)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username.strip().lower(), email.strip().lower(), full_name.strip(), pwd_hash, salt, role, initials))
        user_id = cursor.lastrowid

    conn.commit()

    token = secrets.token_urlsafe(32)
    cursor.execute(f"INSERT INTO sessions (token, user_id) VALUES ({param_placeholder}, {param_placeholder})", (token, user_id))
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
    param_placeholder = "%s" if IS_POSTGRES else "?"

    query = f"""
        SELECT id, username, email, full_name, password_hash, salt, role, avatar_initials 
        FROM users 
        WHERE LOWER(username) = LOWER({param_placeholder}) OR LOWER(email) = LOWER({param_placeholder})
    """
    cursor.execute(query, (identifier.strip(), identifier.strip()))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return None

    if not verify_password(password, row["password_hash"], row["salt"]):
        conn.close()
        return None

    # Update last login
    cursor.execute(f"UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = {param_placeholder}", (row["id"],))

    token = secrets.token_urlsafe(32)
    cursor.execute(f"INSERT INTO sessions (token, user_id) VALUES ({param_placeholder}, {param_placeholder})", (token, row["id"]))
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
    param_placeholder = "%s" if IS_POSTGRES else "?"

    query = f"""
        SELECT u.id, u.username, u.email, u.full_name, u.role, u.avatar_initials, u.created_at, u.last_login
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = {param_placeholder}
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

    return [
        {
            "id": r["id"],
            "username": r["username"],
            "email": r["email"],
            "full_name": r["full_name"],
            "role": r["role"],
            "avatar_initials": r["avatar_initials"]
        }
        for r in rows
    ]


def logout_session(token: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    param_placeholder = "%s" if IS_POSTGRES else "?"
    cursor.execute(f"DELETE FROM sessions WHERE token = {param_placeholder}", (token,))
    conn.commit()
    conn.close()
