"""User-day feature table: same-day aggregates + trailing-history features."""
from __future__ import annotations

import warnings

import numpy as np
import pandas as pd
from scipy.spatial.distance import jensenshannon

from features.baselines import Grid


def dns_user_day(dns: pd.DataFrame | None, t0: pd.Timestamp) -> pd.DataFrame:
    if dns is None or len(dns) == 0:
        return pd.DataFrame(columns=["user_id", "day", "dns_max_hourly_queries", "dns_mean_entropy"])
    d = dns.copy()
    d["day"] = (d["ts_hour"] - t0).dt.days.astype(int)
    d["wq"] = d["query_count"] * d["mean_label_entropy"]
    g = d.groupby(["user_id", "day"]).agg(dns_max_hourly_queries=("query_count", "max"),
                                          wq=("wq", "sum"), q=("query_count", "sum")).reset_index()
    g["dns_mean_entropy"] = g["wq"] / g["q"].clip(lower=1)
    return g[["user_id", "day", "dns_max_hourly_queries", "dns_mean_entropy"]]


def hourly_divergence(flows: pd.DataFrame, grid: Grid, ud: pd.DataFrame, min_days: int = 7, window: int = 28) -> np.ndarray:
    """F21: Jensen-Shannon divergence between today's hourly flow distribution and the user's
    trailing 28-day profile (clean days only, >= 7 active days)."""
    H = np.zeros((grid.U, grid.D, 24))
    ui = flows["user_id"].map(grid.uidx).values
    np.add.at(H, (ui, flows["day"].values, flows["hour"].values), 1)
    out = np.full(len(ud), np.nan)
    uidx = ud["user_id"].map(grid.uidx).values
    days = ud["day"].values
    for i in range(len(ud)):
        u, t = uidx[i], days[i]
        lo = max(0, t - window)
        sel = np.arange(lo, t)
        sel = sel[grid.EX[u, sel] > t]
        prof = H[u, sel]
        if (prof.sum(1) > 0).sum() < min_days:
            continue
        p = prof.sum(0); q = H[u, t]
        if p.sum() == 0 or q.sum() == 0:
            continue
        out[i] = jensenshannon(q / q.sum(), p / p.sum(), base=2) ** 2
    return out


def build_user_day(ud: pd.DataFrame, pair: pd.DataFrame, flows: pd.DataFrame, dns: pd.DataFrame | None,
                   grid: Grid, graph_user: pd.DataFrame, users: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    b = cfg["settings"]["baseline"]
    t0 = flows.attrs.get("t0")
    ud = ud.merge(users[["user_id", "peer_group", "asset_tier"]], on="user_id", how="left")
    # new-destination aggregates (from pair table)
    fcfg = cfg["settings"]["features"]
    new_rows = pair[pair["is_new"]]
    g_new = new_rows.groupby(["user_id", "day"]).agg(bytes_new_dests=("out_bytes", "sum")).reset_index()
    first_today = pair[(pair["dest_age_days"] == 0) & (pair["first_seen_day"] >= fcfg["established_before_day"])]
    g_ft = first_today.groupby(["user_id", "day"]).agg(n_new_dests=("dst_id", "nunique"),
                                                      bytes_first_today=("out_bytes", "sum")).reset_index()
    ud = ud.merge(g_new, on=["user_id", "day"], how="left").merge(g_ft, on=["user_id", "day"], how="left")
    for c in ["bytes_new_dests", "n_new_dests", "bytes_first_today"]:
        ud[c] = ud[c].fillna(0.0)
    # robust baselines (self & peer)
    z1 = grid.user_day_z(ud, "out_bytes", b["window_days"], b["min_days"], b["epsilon"], b["z_clip"])
    z2 = grid.user_day_z(ud, "bytes_new_dests", b["window_days"], b["min_days"], b["epsilon"], b["z_clip"])
    ud = ud.merge(z1, on=["user_id", "day"], how="left").merge(z2, on=["user_id", "day"], how="left")
    ud = ud.rename(columns={"z_self_out_bytes": "z_self", "z_peer_out_bytes": "z_peer",
                            "z_self_bytes_new_dests": "z_new_self", "z_peer_bytes_new_dests": "z_new_peer"})
    ud["log_out_in_ratio"] = np.log1p(ud["out_bytes"]) - np.log1p(ud["in_bytes"])
    ud["out_in_ratio"] = ud["out_bytes"] / (ud["in_bytes"] + 1.0)
    M0 = grid.matrix(ud, "out_bytes", fill=0.0)
    C = np.cumsum(M0, axis=1)
    ui = ud["user_id"].map(grid.uidx).values; d = ud["day"].values
    ud["cum7_out_bytes"] = C[ui, d] - np.where(d >= 7, C[ui, np.maximum(d - 7, 0)], 0.0)
    ud["hourly_divergence"] = hourly_divergence(flows, grid, ud)
    ud = ud.merge(graph_user, on=["user_id", "day"], how="left") if len(graph_user) else ud.assign(jaccard_peer=np.nan, dest_drift=np.nan)
    dnsd = dns_user_day(dns, t0)
    ud = ud.merge(dnsd, on=["user_id", "day"], how="left")
    ud["m_dns"] = dns is None
    if dns is not None:
        ud["dns_max_hourly_queries"] = ud["dns_max_hourly_queries"].fillna(0.0)  # visible DNS table, no queries that day
        ud["dns_mean_entropy"] = ud["dns_mean_entropy"].fillna(np.nan)
    ud["dns_available"] = dns is not None
    ud["m_baseline"] = ud["z_self"].isna()
    ud["m_sni"] = ud["hidden_sni_share"] > 0.5
    ud["m_ja3"] = ud["ja3_missing_share"] > 0.5
    return ud
