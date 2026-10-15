"""DNS statistics sub-score and timing sub-score.

M7 (optional Random Forest on CIC-Bell-DNS-EXF-2021) is DEFERRED: a transparent rule on
query rate x label entropy is used instead, with synthetic DNS statistics only.
"""
from __future__ import annotations

import numpy as np
import pandas as pd


def dns_subscore(max_hourly_queries, mean_entropy, cfg: dict) -> np.ndarray:
    sc = cfg["weights"]["subscores"]
    q = np.asarray(max_hourly_queries, dtype=float)
    e = np.asarray(mean_entropy, dtype=float)
    rate = np.clip((np.log10(np.maximum(q, 1.0)) - sc["dns_log10_offset"]) / sc["dns_log10_range"], 0, 1)
    ent = np.clip((np.nan_to_num(e, nan=0.0) - sc["dns_entropy_offset"]) / sc["dns_entropy_range"], 0, 1)
    return rate * ent


def timing_subscore(df: pd.DataFrame, cfg: dict) -> np.ndarray:
    """Off-hours concentration or divergence from the user's hourly profile, gated by volume;
    periodicity adds a small bonus only for off-hours repetition."""
    sc = cfg["weights"]["subscores"]
    off = np.clip((df["offhours_share"].fillna(0).values - sc["offhours_offset"]) / sc["offhours_range"], 0, 1)
    div = np.clip((df["hourly_divergence"].fillna(0).values - 0.5) / 0.4, 0, 1)
    per = np.clip((df["periodicity"].fillna(0).values - sc["periodicity_offset"]) / sc["periodicity_range"], 0, 1)
    base = np.fmax(off, div)
    return np.clip((base + 0.3 * per * off) * df["volume_gate"].values, 0, 1)
