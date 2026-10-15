"""Database-backed user store with PBKDF2 password hashing and audit logging.

Provides secure credential verification, role-based metadata, and security event auditing
persisted directly in DuckDB.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import datetime
from typing import Optional, Dict, Any, List
from ..storage.storage import DuckDBStorage

# Default password hashing configuration
PBKDF2_ITERATIONS = 100_000
HASH_ALGORITHM = "sha256"


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
    """Manages user persistence, authentication, and security audit logs in DuckDB."""

    def __init__(self, storage: Optional[DuckDBStorage] = None):
        self._storage = storage or DuckDBStorage()
        self._init_tables()

    def _init_tables(self):
        """Initialize users and audit_logs tables if they do not exist."""
        self._storage.execute("""
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
        self._storage.execute("""
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
        # Seed default admin user if users table is empty
        res = self._storage.query("SELECT COUNT(*) as count FROM users")
        if res["count"][0] == 0:
            self.create_user(
                username="admin",
                password=os.getenv("ADMIN_PASSWORD", "admin123"),
                full_name="System Administrator",
                role="admin",
            )
            self.log_audit_event("SYSTEM_INIT", "system", "SUCCESS", "Seeded default admin user")

    def create_user(
        self, username: str, password: str, full_name: str = "", role: str = "analyst"
    ) -> Dict[str, Any]:
        """Create a new user with hashed password."""
        existing = self.get_user(username)
        if existing:
            raise ValueError(f"User '{username}' already exists")

        pw_hash, salt = hash_password(password)
        user_id = f"usr_{secrets.token_hex(6)}"
        now = datetime.datetime.now(datetime.timezone.utc)

        self._storage.execute(
            """
            INSERT INTO users (id, username, password_hash, salt, full_name, role, disabled, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, username.lower(), pw_hash, salt, full_name, role, False, now),
        )
        return {
            "id": user_id,
            "username": username.lower(),
            "full_name": full_name,
            "role": role,
            "disabled": False,
            "created_at": now.isoformat(),
        }

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieve user record by username."""
        df = self._storage.query(
            "SELECT id, username, password_hash, salt, full_name, role, disabled, created_at FROM users WHERE username = ?",
            (username.lower(),),
        )
        if df.empty:
            return None
        row = df.iloc[0]
        return {
            "id": str(row["id"]),
            "username": str(row["username"]),
            "password_hash": str(row["password_hash"]),
            "salt": str(row["salt"]),
            "full_name": str(row["full_name"]),
            "role": str(row["role"]),
            "disabled": bool(row["disabled"]),
            "created_at": str(row["created_at"]),
        }

    def list_users(self) -> List[Dict[str, Any]]:
        """List all users without sensitive hash/salt."""
        df = self._storage.query(
            "SELECT id, username, full_name, role, disabled, created_at FROM users ORDER BY created_at"
        )
        return df.to_dict(orient="records")

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
        """Append an entry to the security audit trail."""
        event_id = f"aud_{secrets.token_hex(8)}"
        now = datetime.datetime.now(datetime.timezone.utc)
        self._storage.execute(
            """
            INSERT INTO audit_logs (id, timestamp, event_type, username, status, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, now, event_type, username, status, details, ip_address),
        )

    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent audit events."""
        df = self._storage.query(
            f"SELECT id, timestamp, event_type, username, status, details, ip_address FROM audit_logs ORDER BY timestamp DESC LIMIT {int(limit)}"
        )
        return df.to_dict(orient="records")

    def close(self):
        """Close database connection."""
        self._storage.close()
