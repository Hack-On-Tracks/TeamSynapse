"""SQLite application store (cases, queue, feedback, reveal requests, audit). Analytical data
lives in DuckDB/Parquet; the identity map is NEVER stored here (see identity_vault)."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from common.settings import path_for

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases(
  case_id TEXT PRIMARY KEY, user_id TEXT, dst_id TEXT, peer_group TEXT, opened_day INTEGER, last_day INTEGER,
  status TEXT, tier TEXT, peak_tier TEXT, case_score REAL, peak_score REAL, confidence REAL, confidence_level TEXT,
  disposition TEXT DEFAULT 'new', bundle_json TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS queue(day INTEGER, rank INTEGER, case_id TEXT, case_score REAL, priority INTEGER);
CREATE INDEX IF NOT EXISTS idx_queue_day ON queue(day);
CREATE TABLE IF NOT EXISTS feedback(id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, analyst TEXT,
  disposition TEXT, note TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS reveal_requests(id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, pseudonym TEXT,
  requester TEXT, reason TEXT, status TEXT, approver TEXT, decision_note TEXT, requested_at TEXT, decided_at TEXT);
CREATE TABLE IF NOT EXISTS policy_entries(id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, value TEXT,
  added_by TEXT, ts TEXT, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, role TEXT,
  action TEXT, resource TEXT, detail TEXT, prev_hash TEXT, hash TEXT);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
  BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
  BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
"""

_SECRET_PATTERNS = [
    (re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), "[REDACTED_JWT]"),
    (re.compile(r"gAAAA[A-Za-z0-9_\-=]{20,}"), "[REDACTED_FERNET]"),
    (re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token|authorization)\s*[:=]\s*\S+"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"), "Bearer [REDACTED]"),
    (re.compile(r"\b[0-9a-fA-F]{64}\b"), "[REDACTED_HEX64]"),
]


def redact(text: str, limit: int = 2000) -> str:
    s = str(text)
    for pat, rep in _SECRET_PATTERNS:
        s = pat.sub(rep, s)
    return s[:limit]


def db_path() -> Path:
    return path_for("cases") / "ciphersentinel.db"


def connect(path: Path | None = None) -> sqlite3.Connection:
    con = sqlite3.connect(str(path or db_path()), check_same_thread=False, timeout=30)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def append_audit(con: sqlite3.Connection, actor: str, role: str, action: str, resource: str = "", detail: dict | str | None = None) -> int:
    """Append a hash-chained audit event (secrets redacted). Tamper-EVIDENT, not tamper-proof."""
    det = redact(json.dumps(detail, default=str) if not isinstance(detail, str) else detail) if detail is not None else ""
    prev = con.execute("SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = prev["hash"] if prev else "GENESIS"
    ts = now_iso()
    h = hashlib.sha256("|".join([prev_hash, ts, actor, role, action, resource, det]).encode()).hexdigest()
    cur = con.execute("INSERT INTO audit_events(ts,actor,role,action,resource,detail,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?)",
                      (ts, actor, role, action, resource, det, prev_hash, h))
    con.commit()
    return cur.lastrowid


def verify_audit_chain(con: sqlite3.Connection) -> dict:
    prev = "GENESIS"; n = 0
    for r in con.execute("SELECT * FROM audit_events ORDER BY id"):
        h = hashlib.sha256("|".join([prev, r["ts"], r["actor"], r["role"], r["action"], r["resource"], r["detail"]]).encode()).hexdigest()
        if r["prev_hash"] != prev or r["hash"] != h:
            return {"valid": False, "broken_at_id": r["id"], "events": n}
        prev = r["hash"]; n += 1
    return {"valid": True, "events": n}
