"""Thread-safe DuckDB storage manager for Windows and multi-worker environments.

Maintains a singleton connection per database path with re-entrant locking and retry logic
to prevent file contention errors ('The process cannot access the file because it is being used
by another process').
"""
from __future__ import annotations

import os
import time
import threading
from pathlib import Path
from typing import Optional, Any
import duckdb
import pandas as pd


class DuckDBStorage:
    _connections: dict[str, duckdb.DuckDBPyConnection] = {}
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
            if db_path not in cls._connections:
                # Open with retry in case file was recently closed by another process
                for attempt in range(5):
                    try:
                        conn = duckdb.connect(db_path)
                        try:
                            conn.execute('INSTALL json; LOAD json;')
                        except Exception:
                            pass
                        cls._connections[db_path] = conn
                        break
                    except Exception as e:
                        if attempt == 4:
                            raise e
                        time.sleep(0.1 * (attempt + 1))
            return cls._connections[db_path]

    def execute(self, sql: str, params: Optional[tuple] = None) -> Any:
        with self._lock:
            for attempt in range(5):
                try:
                    if params:
                        return self.cursor.execute(sql, params)
                    return self.cursor.execute(sql)
                except Exception as e:
                    if "used by another process" in str(e) and attempt < 4:
                        time.sleep(0.1 * (attempt + 1))
                        continue
                    raise e

    def insert_dataframe(self, df: pd.DataFrame, table_name: str):
        with self._lock:
            self.cursor.register('temp_df', df)
            self.cursor.execute(f'CREATE OR REPLACE TABLE {table_name} AS SELECT * FROM temp_df')
            self.cursor.unregister('temp_df')

    def query(self, sql: str, params: Optional[tuple] = None) -> pd.DataFrame:
        with self._lock:
            res = self.execute(sql, params)
            return res.fetchdf()

    def close(self):
        """Close the cursor for this request, keeping the singleton connection alive."""
        try:
            self.cursor.close()
        except Exception:
            pass
