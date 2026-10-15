"""User x destination x day feature table (the unit of investigation is the user-destination pair)."""
from __future__ import annotations

import numpy as np
import pandas as pd


def volume_gate(out_bytes, cfg) -> np.ndarray:
    """Gate in [0, 1]: 0 at <= low bytes, 1 at >= high bytes (log-linear). Prevents tiny
    incidental transfers from becoming high-risk cases."""
    f = cfg["settings"]["features"]
    lo, hi = np.log10(f["volume_gate_low_bytes"]), np.log10(f["volume_gate_high_bytes"])
    return np.clip((np.log10(np.maximum(np.asarray(out_bytes, dtype=float), 1.0)) - lo) / (hi - lo), 0, 1)


def add_destination_context(pair: pd.DataFrame, users: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    pol, fcfg = cfg["policies"], cfg["settings"]["features"]
    p = pair.merge(users[["user_id", "peer_group", "asset_tier"]], on="user_id", how="left")
    p["first_seen_day"] = p.groupby(["user_id", "dst_id"])["day"].transform("min")
    p["dest_age_days"] = p["day"] - p["first_seen_day"]
    p["is_new"] = (p["first_seen_day"] >= fcfg["established_before_day"]) & (p["dest_age_days"] <= fcfg["new_destination_window_days"])
    p["cat_prior"] = p["dst_category"].map(pol["category_prior"]).fillna(pol["category_prior"]["unknown"])
    al = pol["allowlist"]
    p["allowlisted"] = p["dst_id"].isin(al["destinations"]) | p["dst_category"].isin(al["categories"])
    sched_dst = {d for w in pol["scheduled_windows"] for d in w["destinations"]}
    p["scheduled"] = p["dst_id"].isin(sched_dst) & (p["sched_share"].fillna(0) >= pol["scheduled_min_share"])
    return p


def finalize_pair(pair: pd.DataFrame, ud: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    cols = ["user_id", "day", "z_self", "z_peer", "n_clean_days", "jaccard_peer", "dest_drift",
            "dns_max_hourly_queries", "dns_mean_entropy", "dns_available", "hourly_divergence", "m_baseline"]
    p = pair.merge(ud[cols].rename(columns={"z_self": "z_user_self", "z_peer": "z_user_peer"}),
                   on=["user_id", "day"], how="left")
    p["log_bytes_out"] = np.log1p(p["out_bytes"])
    p["log_bytes_in"] = np.log1p(p["in_bytes"])
    p["log_out_in_ratio"] = p["log_bytes_out"] - p["log_bytes_in"]
    p["out_in_ratio"] = p["out_bytes"] / (p["in_bytes"] + 1.0)
    p["log_bytes_7d"] = np.log1p(p["bytes_7d"])
    p["volume_gate"] = volume_gate(p["out_bytes"], cfg)
    p["m_sni"] = p["hidden_sni_share"] > 0.5
    p["m_ja3"] = p["ja3_missing_share"] > 0.5
    return p
