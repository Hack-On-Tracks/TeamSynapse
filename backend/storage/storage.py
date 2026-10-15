import os
import duckdb
from pathlib import Path

class DuckDBStorage:
    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.getenv('DUCKDB_PATH', './data/duckdb.db')
        # Ensure directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(self.db_path)
        # Enable extensions if needed
        self.conn.execute('INSTALL json; LOAD json;')

    def execute(self, sql: str, params: tuple = None):
        if params:
            return self.conn.execute(sql, params)
        return self.conn.execute(sql)

    def insert_dataframe(self, df, table_name: str):
        self.conn.register('temp_df', df)
        self.conn.execute(f'CREATE OR REPLACE TABLE {table_name} AS SELECT * FROM temp_df')
        self.conn.unregister('temp_df')

    def query(self, sql: str, params: tuple = None):
        return self.execute(sql, params).fetchdf()

    def close(self):
        self.conn.close()
