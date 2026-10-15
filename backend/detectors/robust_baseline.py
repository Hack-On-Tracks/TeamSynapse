"""M1 robust-baseline detector sub-scores (volume and direction)."""
from __future__ import annotations

import numpy as np
import pandas as pd


def z_subscore(z, offset: float = 1.0, rng: float = 4.0):
    """clip((z - 1) / 4, 0, 1); NaN stays NaN (signal unavailable, not zero)."""
    z = np.asarray(z, dtype=float)
    return np.where(np.isnan(z), np.nan, np.clip((z - offset) / rng, 0.0, 1.0))


def effective_user_z(z_self, z_peer) -> tuple[np.ndarray, np.ndarray]:
    """Combine self and peer z. Both present -> min (must be unusual for the user AND the role).
    Only peer present -> peer (cold-start). Returns (z_eff, cold_start_flag)."""
    s = np.asarray(z_self, dtype=float); p = np.asarray(z_peer, dtype=float)
    both = ~np.isnan(s) & ~np.isnan(p)
    z = np.where(both, np.fmin(s, p), np.where(~np.isnan(p), p, s))
    cold = np.isnan(s) & ~np.isnan(p)
    return z, cold


def volume_subscore(df: pd.DataFrame, cfg: dict, use_peer: bool = True, use_pair: bool = True) -> np.ndarray:
    sc = cfg["weights"]["subscores"]
    zs = df["z_user_self"].values
    zp = df["z_user_peer"].values if use_peer else np.full(len(df), np.nan)
    if use_peer:
        z, _ = effective_user_z(zs, zp)
    else:
        z = zs
    if use_pair:
        zpair = df["ewma_z"].where(df["cusum"] >= 0).values  # EWMA of standardised pair bytes
        z = np.where(np.isnan(z), zpair, np.fmax(z, zpair))
    return z_subscore(z, sc["z_offset"], sc["z_range"])


def direction_subscore(df: pd.DataFrame, cfg: dict) -> np.ndarray:
    """Upload dominance of the pair's traffic (out/in byte ratio), gated by volume."""
    sc = cfg["weights"]["subscores"]
    r = np.log10(df["out_in_ratio"].clip(lower=1e-3).values)
    s = np.clip((r - sc["direction_log10_offset"]) / sc["direction_log10_range"], 0, 1)
    return s * df["volume_gate"].values
