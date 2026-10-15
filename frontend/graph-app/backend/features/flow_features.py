"""Flow -> same-day aggregates using DuckDB. No history is used here (history features
are computed in the user_day / user_destination_day modules from TRAILING data only)."""
from __future__ import annotations

import duckdb
import numpy as np
import pandas as pd


def time_origin(flows: pd.DataFrame, cfg: dict) -> pd.Timestamp:
    t0 = pd.Timestamp(cfg["settings"]["simulation"]["start_date"])
    mn = flows["ts"].min().normalize()
    return min(t0, mn)


def prepare_flows(flows: pd.DataFrame, users: pd.DataFrame, cfg: dict, t0: pd.Timestamp | None = None) -> pd.DataFrame:
    """Add day/hour and per-flow context flags (offhours, scheduled-window, TLS-FP novelty)."""
    pol, fcfg = cfg["policies"], cfg["settings"]["features"]
    f = flows.copy()
    t0 = t0 or time_origin(f, cfg)
    f["day"] = (f["ts"] - t0).dt.days.astype(int)
    f["hour"] = f["ts"].dt.hour
    f["peer_group"] = f["user_id"].map(users.set_index("user_id")["peer_group"])
    wh = pol["work_hours"]
    start = f["peer_group"].map(lambda g: wh.get(g, [8, 18])[0]).values
    end = f["peer_group"].map(lambda g: wh.get(g, [8, 18])[1]).values
    f["is_offhours"] = (f["hour"].values < start) | (f["hour"].values >= end)
    f["in_sched"] = False
    for w in pol["scheduled_windows"]:
        f.loc[f["dst_id"].isin(w["destinations"]) & f["hour"].isin(w["hours"]), "in_sched"] = True
    f["sni_hidden"] = f["sni"].isna()
    f["ja3_missing"] = f["ja3"].isna()
    first_ja3 = f.groupby(["user_id", "ja3"])["day"].transform("min")
    f["ja3_novel"] = (f["ja3"].notna() & (first_ja3 >= fcfg["established_before_day"]) & ((f["day"] - first_ja3) <= 14))
    f["ja3_novel"] = f["ja3_novel"] & ~f["is_quic"]
    for c in ["orig_pkts", "resp_pkts", "capture_quality", "identity_confidence"]:
        f[c] = f[c].astype(float)
    f.attrs["t0"] = t0
    return f


_MEASURES = """
    sum(orig_bytes) AS out_bytes,
    sum(resp_bytes) AS in_bytes,
    count(*) AS n_conn,
    sum(CASE WHEN orig_bytes >= {uh_min} AND orig_bytes >= {uh_ratio} * resp_bytes THEN 1 ELSE 0 END) AS upload_heavy_flows,
    sum(CASE WHEN orig_bytes >= 100000 AND orig_bytes >= 4 * resp_bytes THEN 1 ELSE 0 END) AS upload_like_starts,
    sum(orig_bytes) / nullif(sum(orig_pkts), 0) AS mean_out_pkt,
    sum(resp_bytes) / nullif(sum(resp_pkts), 0) AS mean_in_pkt,
    sum(CASE WHEN is_offhours THEN orig_bytes ELSE 0 END) / nullif(sum(orig_bytes), 0) AS offhours_share,
    avg(CASE WHEN sni_hidden THEN 1.0 ELSE 0.0 END) AS hidden_sni_share,
    avg(CASE WHEN ja3_missing THEN 1.0 ELSE 0.0 END) AS ja3_missing_share,
    avg(CASE WHEN ja3_novel THEN 1.0 ELSE 0.0 END) AS ja3_novel_share,
    sum(CASE WHEN in_sched THEN orig_bytes ELSE 0 END) / nullif(sum(orig_bytes), 0) AS sched_share,
    avg(identity_confidence) AS identity_confidence,
    avg(capture_quality) AS capture_quality,
    stddev_samp(iat) / nullif(avg(iat), 0) AS iat_cv,
    (stddev_samp(iat) - avg(iat)) / nullif(stddev_samp(iat) + avg(iat), 0) AS burstiness
"""


def aggregate(flows: pd.DataFrame, level: str, cfg: dict) -> pd.DataFrame:
    """level: 'user_day' or 'pair_day' (user x destination x day)."""
    fcfg = cfg["settings"]["features"]
    keys = ["user_id", "day"] if level == "user_day" else ["user_id", "dst_id", "day"]
    part = ", ".join(keys)
    extra = "" if level == "user_day" else "any_value(dst_category) AS dst_category,"
    sql = f"""
        WITH t AS (
            SELECT *, epoch(ts) - lag(epoch(ts)) OVER (PARTITION BY {part} ORDER BY ts) AS iat
            FROM flows
        )
        SELECT {part}, {extra}
        {_MEASURES.format(uh_min=fcfg['upload_heavy_min_bytes'], uh_ratio=fcfg['upload_heavy_ratio'])}
        FROM t GROUP BY {part} ORDER BY {part}
    """
    con = duckdb.connect()
    try:
        con.register("flows", flows[[c for c in flows.columns if c not in ("peer_group",)]])
        out = con.execute(sql).df()
    finally:
        con.close()
    return out
