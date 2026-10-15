"""Parse generic CSV/JSON flow exports into the canonical (payload-free) schema."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

# Well-known aliases from common flow exporters -> canonical names.
ALIASES = {
    "timestamp": "ts", "start_time": "ts", "time": "ts",
    "src_user": "user", "username_hash": "user",
    "src": "src_ip", "source_ip": "src_ip", "dst": "dst_ip", "dest_ip": "dst_ip",
    "bytes_out": "orig_bytes", "bytes_in": "resp_bytes", "src_bytes": "orig_bytes", "dst_bytes": "resp_bytes",
    "pkts_out": "orig_pkts", "pkts_in": "resp_pkts",
    "server_name": "sni", "dst_port_number": "dst_port", "protocol": "proto", "ja3_hash": "ja3",
}


def read_flow_file(path: str | Path) -> pd.DataFrame:
    p = Path(path)
    if p.suffix.lower() == ".csv":
        return pd.read_csv(p)
    if p.suffix.lower() in {".json", ".jsonl", ".ndjson"}:
        text = p.read_text(encoding="utf-8").strip()
        if text.startswith("["):
            return pd.DataFrame(json.loads(text))
        return pd.DataFrame([json.loads(line) for line in text.splitlines() if line.strip()])
    if p.suffix.lower() == ".parquet":
        return pd.read_parquet(p)
    raise ValueError(f"Unsupported flow file type: {p.suffix}")


def normalize_flows(df: pd.DataFrame) -> pd.DataFrame:
    """Rename well-known aliases. Unknown columns are kept so the strict validator can reject them."""
    ren = {c: ALIASES[c] for c in df.columns if c in ALIASES and ALIASES[c] not in df.columns}
    return df.rename(columns=ren)


def parse_flows(path: str | Path) -> pd.DataFrame:
    return normalize_flows(read_flow_file(path))
