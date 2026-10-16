"""Database-backed user store with PBKDF2 password hashing and audit logging.

Provides secure credential verification, role-based metadata, and security event auditing
persisted into a local SQLite database (data/users.db) or DuckDB storage.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

# Default password hashing configuration
PBKDF2_ITERATIONS = 100_000
HASH_ALGORITHM = "sha256"

DEFAULT_SQLITE_PATH = Path("data/users.db")


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    """Hash a plaintext password with a cryptographically secure salt using PBKDF2."""
    if not salt:
        salt = secrets.token_hex(16)
    hash_bytes = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    )
    return hash_bytes.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """Verify a plaintext password against a stored hash and salt."""
    test_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(test_hash, password_hash)


class UsersDatabase:
    """Manages user persistence, authentication, and security audit logs in SQLite."""

    def __init__(self, storage: Optional[Any] = None, db_path: Optional[str] = None):
        self._custom_storage = storage
        if self._custom_storage is not None:
            self._is_sqlite = False
        else:
            self._is_sqlite = True
            resolved_path = Path(db_path or os.getenv("SQLITE_USERS_DB", str(DEFAULT_SQLITE_PATH)))
            resolved_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(resolved_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        self._init_tables()

    def _execute(self, sql: str, params: tuple = ()):
        if self._is_sqlite:
            cursor = self._conn.cursor()
            cursor.execute(sql, params)
            self._conn.commit()
            return cursor
        else:
            return self._custom_storage.execute(sql, params)

    def _query(self, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
        if self._is_sqlite:
            cursor = self._conn.cursor()
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        else:
            df = self._custom_storage.query(sql, params)
            if hasattr(df, "to_dict"):
                return df.to_dict(orient="records")
            return df

    def _init_tables(self):
        """Initialize users and audit_logs tables if they do not exist."""
        if self._is_sqlite:
            self._execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    full_name TEXT,
                    email TEXT,
                    role TEXT DEFAULT 'analyst',
                    disabled INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                );
            """)
            self._execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    username TEXT NOT NULL,
                    status TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT
                );
            """)
        else:
            self._execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id VARCHAR PRIMARY KEY,
                    username VARCHAR UNIQUE,
                    password_hash VARCHAR,
                    salt VARCHAR,
                    full_name VARCHAR,
                    role VARCHAR,
                    disabled BOOLEAN,
                    created_at TIMESTAMP
                );
            """)
            self._execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id VARCHAR PRIMARY KEY,
                    timestamp TIMESTAMP,
                    event_type VARCHAR,
                    username VARCHAR,
                    status VARCHAR,
                    details VARCHAR,
                    ip_address VARCHAR
                );
            """)

        # Seed default admin and analyst users if users table is empty
        users = self._query("SELECT COUNT(*) as count FROM users")
        count = users[0]["count"] if users else 0
        if count == 0:
            self.create_user(
                username="admin",
                password=os.getenv("ADMIN_PASSWORD", "admin123"),
                full_name="System Administrator",
                role="admin",
                email="admin@ciphersentinel.soc",
            )
            self.create_user(
                username="analyst",
                password=os.getenv("ANALYST_PASSWORD", "analyst123"),
                full_name="Janhvi S.",
                role="analyst",
                email="janhvi.s@ciphersentinel.soc",
            )
            self.log_audit_event("SYSTEM_INIT", "system", "SUCCESS", "Seeded default admin and analyst users into SQLite")

    def create_user(
        self, username: str, password: str, full_name: str = "", role: str = "analyst", email: str = ""
    ) -> Dict[str, Any]:
        """Create a new user with hashed password in SQLite."""
        existing = self.get_user(username)
        if existing:
            raise ValueError(f"User '{username}' already exists")

        pw_hash, salt = hash_password(password)
        user_id = f"usr_{secrets.token_hex(6)}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if self._is_sqlite:
            self._execute(
                """
                INSERT INTO users (id, username, password_hash, salt, full_name, email, role, disabled, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, username.lower().strip(), pw_hash, salt, full_name, email, role, 0, now),
            )
        else:
            self._execute(
                """
                INSERT INTO users (id, username, password_hash, salt, full_name, role, disabled, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, username.lower().strip(), pw_hash, salt, full_name, role, False, now),
            )

        return {
            "id": user_id,
            "username": username.lower().strip(),
            "full_name": full_name,
            "email": email,
            "role": role,
            "disabled": False,
            "created_at": now,
        }

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieve user record by username."""
        rows = self._query(
            "SELECT * FROM users WHERE username = ?",
            (username.lower().strip(),),
        )
        if not rows:
            return None
        row = rows[0]
        return {
            "id": str(row["id"]),
            "username": str(row["username"]),
            "password_hash": str(row["password_hash"]),
            "salt": str(row["salt"]),
            "full_name": str(row.get("full_name") or ""),
            "email": str(row.get("email") or ""),
            "role": str(row.get("role") or "analyst"),
            "disabled": bool(row.get("disabled", 0)),
            "created_at": str(row["created_at"]),
        }

    def list_users(self) -> List[Dict[str, Any]]:
        """List all users without sensitive hash/salt."""
        rows = self._query("SELECT id, username, full_name, email, role, disabled, created_at FROM users ORDER BY created_at")
        return rows

    def authenticate(self, username: str, password: str, ip_address: str = "local") -> Optional[Dict[str, Any]]:
        """Authenticate username and password, recording an audit log event."""
        user = self.get_user(username)
        if not user or user["disabled"]:
            self.log_audit_event("AUTH_LOGIN", username, "FAILURE", "User not found or disabled", ip_address)
            return None

        if not verify_password(password, user["password_hash"], user["salt"]):
            self.log_audit_event("AUTH_LOGIN", username, "FAILURE", "Invalid password", ip_address)
            return None

        self.log_audit_event("AUTH_LOGIN", username, "SUCCESS", "Authentication successful", ip_address)
        return {
            "id": user["id"],
            "username": user["username"],
            "full_name": user["full_name"],
            "email": user.get("email", ""),
            "role": user["role"],
        }

    def log_audit_event(
        self,
        event_type: str,
        username: str,
        status: str,
        details: str = "",
        ip_address: str = "127.0.0.1",
    ):
        """Append an entry to the security audit trail in SQLite."""
        event_id = f"aud_{secrets.token_hex(8)}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._execute(
            """
            INSERT INTO audit_logs (id, timestamp, event_type, username, status, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, now, event_type, username, status, details, ip_address),
        )

    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent audit events."""
        rows = self._query(
            f"SELECT id, timestamp, event_type, username, status, details, ip_address FROM audit_logs ORDER BY timestamp DESC LIMIT {int(limit)}"
        )
        return rows

    def close(self):
        """Close database connection."""
        if self._is_sqlite and hasattr(self, "_conn"):
            self._conn.close()
        elif hasattr(self, "_custom_storage") and hasattr(self._custom_storage, "close"):
            self._custom_storage.close()
