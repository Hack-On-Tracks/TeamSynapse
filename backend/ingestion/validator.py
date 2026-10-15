"""Strict payload-free validation of flow, user and DNS records.

Unexpected columns are REJECTED (not silently stored). Malformed rows are dropped and counted.
"""
from __future__ import annotations

import pandas as pd

from common.settings import DNS_COLUMNS, FLOW_COLUMNS, FORBIDDEN_FIELDS, USER_COLUMNS


class SchemaViolation(ValueError):
    """Raised when input contains non-whitelisted or forbidden (payload-like) fields."""


def check_columns(columns, allowed, kind: str) -> None:
    cols = list(columns)
    forbidden = sorted(c for c in cols if c.lower() in FORBIDDEN_FIELDS)
    if forbidden:
        raise SchemaViolation(f"{kind}: forbidden/payload-like fields rejected: {forbidden}")
    extra = sorted(set(cols) - set(allowed))
    if extra:
        raise SchemaViolation(f"{kind}: unexpected fields rejected (strict whitelist): {extra}")


def validate_flows(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Validate and coerce raw flows to the canonical dtypes.

    Returns (clean_df, report). Timestamps are normalised to naive UTC.
    """
    check_columns(df.columns, FLOW_COLUMNS.keys(), "flows")
    missing = [c for c, m in FLOW_COLUMNS.items() if m["required"] and c not in df.columns]
    if missing:
        raise SchemaViolation(f"flows: missing required fields: {missing}")
    n0 = len(df)
    d = df.copy()
    for c, m in FLOW_COLUMNS.items():
        if c not in d.columns:
            d[c] = pd.NA if m["dtype"] != "float" else float("nan")
    ts = pd.to_datetime(d["ts"], errors="coerce", utc=True)
    d["ts"] = ts.dt.tz_convert("UTC").dt.tz_localize(None)
    for c in ["orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "duration", "capture_quality", "identity_confidence"]:
        d[c] = pd.to_numeric(d[c], errors="coerce")
    d["dst_port"] = pd.to_numeric(d["dst_port"], errors="coerce")
    d["proto"] = d["proto"].astype("string").str.lower()
    report = {"rows_in": n0, "dropped": {}}

    def drop(mask, reason):
        nonlocal d
        k = int(mask.sum())
        if k:
            report["dropped"][reason] = k
            d = d[~mask]

    drop(d["ts"].isna(), "bad_timestamp")
    drop(d["user"].isna() | (d["user"].astype("string").str.len() == 0), "missing_user")
    drop(d["dst_id"].isna(), "missing_destination")
    drop(d["orig_bytes"].isna() | d["resp_bytes"].isna(), "missing_byte_counts")
    drop((d["orig_bytes"] < 0) | (d["resp_bytes"] < 0), "negative_bytes")
    drop(~d["proto"].isin(["tcp", "udp", "icmp"]), "invalid_protocol")
    drop(d["dst_port"].isna() | (d["dst_port"] < 0) | (d["dst_port"] > 65535), "invalid_port")
    dup_cols = ["ts", "user", "dst_id", "dst_port", "proto", "orig_bytes", "resp_bytes"]
    drop(d.duplicated(subset=dup_cols, keep="first"), "duplicate_flow")
    d["dst_port"] = d["dst_port"].astype(int)
    d["is_quic"] = d["is_quic"].map(lambda x: bool(x) if pd.notna(x) else False)
    for c in ["user", "device", "dst_id", "dst_ip", "dst_category", "tls_version", "sni", "ja3", "src_ip"]:
        d[c] = d[c].astype(object).where(d[c].notna(), None)
    d["dst_category"] = d["dst_category"].fillna("unknown")
    report["rows_out"] = len(d)
    report["rows_dropped"] = n0 - len(d)
    return d.reset_index(drop=True), report


def validate_users(df: pd.DataFrame) -> pd.DataFrame:
    check_columns(df.columns, set(USER_COLUMNS) | {"src_ip"}, "users")
    miss = [c for c in USER_COLUMNS if c not in df.columns]
    if miss:
        raise SchemaViolation(f"users: missing required fields: {miss}")
    return df.drop_duplicates("user").reset_index(drop=True)


def validate_dns(df: pd.DataFrame) -> pd.DataFrame:
    check_columns(df.columns, DNS_COLUMNS, "dns")
    miss = [c for c in DNS_COLUMNS if c not in df.columns]
    if miss:
        raise SchemaViolation(f"dns: missing required fields: {miss}")
    d = df.copy()
    d["ts_hour"] = pd.to_datetime(d["ts_hour"], utc=True).dt.tz_localize(None)
    return d.dropna().reset_index(drop=True)
