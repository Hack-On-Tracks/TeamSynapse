"""Thread-safe DuckDB storage manager for Windows and multi-worker environments.

Maintains a singleton connection per database path with re-entrant locking and retry logic
to prevent file contention errors ('The process cannot access the file because it is being used
by another process').
"""
from __future__ import annotations

import os
import time
import threading
import logging
from pathlib import Path
from typing import Optional, Any
import duckdb
import pandas as pd

logger = logging.getLogger("ciphersentinel.storage")


class DuckDBStorage:
    _connections: dict[str, duckdb.DuckDBPyConnection] = {}
    _fallback_connections: dict[str, duckdb.DuckDBPyConnection] = {}
    _lock = threading.RLock()

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = str(Path(db_path or os.getenv('DUCKDB_PATH', './data/duckdb.db')).resolve())
        # Ensure directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = self._get_connection(self.db_path)
        self.cursor = self.conn.cursor()

    @classmethod
    def _get_connection(cls, db_path: str) -> duckdb.DuckDBPyConnection:
        with cls._lock:
            # If already cached and valid, reuse
            if db_path in cls._connections:
                return cls._connections[db_path]

            # Try opening standard read-write connection with backoff
            for attempt in range(8):
                try:
                    conn = duckdb.connect(db_path, read_only=False)
                    try:
                        conn.execute('INSTALL json; LOAD json;')
                    except Exception:
                        pass
                    cls._connections[db_path] = conn
                    return conn
                except Exception as e:
                    err_str = str(e).lower()
                    if "used by another process" in err_str or "cannot open file" in err_str:
                        # Attempt read-only mode if write lock is held
                        try:
                            ro_conn = duckdb.connect(db_path, read_only=True)
                            cls._connections[db_path] = ro_conn
                            return ro_conn
                        except Exception:
                            pass
                        time.sleep(0.2 * (attempt + 1))
                        continue
                    if attempt == 7:
                        logger.warning(f"[DuckDBStorage] Could not acquire lock for {db_path} ({e}). Using in-memory fallback.")
                        break
                    time.sleep(0.15 * (attempt + 1))

            # Resilient fallback: Return in-memory database to prevent 500 ASGI failure
            if db_path not in cls._fallback_connections:
                fb = duckdb.connect(":memory:")
                # Initialize minimal tables for safety
                try:
                    fb.execute("""
                        CREATE TABLE IF NOT EXISTS audit_logs (
                            id VARCHAR, user_id VARCHAR, username VARCHAR, action VARCHAR,
                            details VARCHAR, ip_address VARCHAR, timestamp TIMESTAMP
                        );
                        CREATE TABLE IF NOT EXISTS threat_cases (
                            case_id VARCHAR, entity_id VARCHAR, entity_type VARCHAR,
                            risk_score DOUBLE, severity VARCHAR, status VARCHAR,
                            created_at TIMESTAMP, updated_at TIMESTAMP
                        );
                        CREATE TABLE IF NOT EXISTS threat_scores (
                            entity_id VARCHAR, entity_type VARCHAR, composite_score DOUBLE,
                            risk_level VARCHAR, primary_detector VARCHAR, score_timestamp TIMESTAMP
                        );
                    """)
                except Exception:
                    pass
                cls._fallback_connections[db_path] = fb

            return cls._fallback_connections[db_path]

    def execute(self, sql: str, params: Optional[tuple] = None) -> Any:
        with self._lock:
            for attempt in range(5):
                try:
                    if params:
                        return self.cursor.execute(sql, params)
                    return self.cursor.execute(sql)
                except Exception as e:
                    err_str = str(e).lower()
                    if "used by another process" in err_str and attempt < 4:
                        time.sleep(0.2 * (attempt + 1))
                        continue
                    raise e

    def insert_dataframe(self, df: pd.DataFrame, table_name: str):
        with self._lock:
            self.cursor.register('temp_df', df)
            self.cursor.execute(f'CREATE OR REPLACE TABLE {table_name} AS SELECT * FROM temp_df')
            self.cursor.unregister('temp_df')

    def append_dataframe(self, df: pd.DataFrame, table_name: str):
        with self._lock:
            self.cursor.register('temp_append_df', df)
            # Create table if not exists with same schema
            self.cursor.execute(f'CREATE TABLE IF NOT EXISTS {table_name} AS SELECT * FROM temp_append_df WHERE 1=0')
            self.cursor.execute(f'INSERT INTO {table_name} SELECT * FROM temp_append_df')
            self.cursor.unregister('temp_append_df')

    def query(self, sql: str, params: Optional[tuple] = None) -> pd.DataFrame:
        with self._lock:
            try:
                res = self.execute(sql, params)
                return res.fetchdf()
            except Exception as e:
                err_str = str(e).lower()
                # Graceful degradation on missing tables
                if "does not exist" in err_str or "not found" in err_str:
                    return pd.DataFrame()
                raise e

    def close(self):
        """Close the cursor for this request, keeping the singleton connection alive."""
        try:
            self.cursor.close()
        except Exception:
            pass
