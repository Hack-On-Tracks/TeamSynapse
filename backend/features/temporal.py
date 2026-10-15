"""Per-pair temporal features: standardised log-byte series -> CUSUM, EWMA, periodicity.

Reference (mu, sigma) for the standardisation, strictly from the PAST:
  * new destinations  -> the user's own trailing-28-day pair-day distribution over ESTABLISHED
    destinations (fallback: peer-group pooled);
  * established pairs -> the pair's own trailing history (>=5 observations), else user reference.
Days excluded as part of an already-open case are removed from every reference.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from detectors.periodicity import periodicity_strength
from detectors.temporal_detector import cusum_series, ewma_series
from features.baselines import Grid


def _med_sd(v: np.ndarray, floor: float):
    med = np.median(v)
    mad = np.median(np.abs(v - med))
    return med, max(1.4826 * mad, floor)


def user_reference(pair: pd.DataFrame, grid: Grid, tcfg: dict):
    U, D = grid.U, grid.D
    x = np.log1p(pair["out_bytes"].values)
    usable = ~pair["is_new"].values
    uid = pair["user_id"].map(grid.uidx).values
    day = pair["day"].values
    by_user = {u: np.where(uid == u)[0] for u in range(U)}
    mu = np.full((U, D), np.nan); sd = np.full((U, D), np.nan)
    gmu = np.full((len(grid.groups), D), np.nan); gsd = np.full_like(gmu, np.nan)
    W, minobs, floor = tcfg["reference_window_days"], tcfg["reference_min_obs"], tcfg["sigma_floor"]
    for t in range(1, D):
        pooled: dict[int, list] = {g: [] for g in range(len(grid.groups))}
        for u in range(U):
            ix = by_user[u]
            if len(ix) == 0:
                continue
            d = day[ix]
            sel = (d >= t - W) & (d < t) & usable[ix] & (grid.EX[u, d] > t)
            v = x[ix][sel]
            if len(v):
                pooled[grid.gidx[u]].append(v)
            if len(v) >= minobs:
                mu[u, t], sd[u, t] = _med_sd(v, floor)
        for g, vs in pooled.items():
            if vs:
                v = np.concatenate(vs)
                if len(v) >= minobs:
                    gmu[g, t], gsd[g, t] = _med_sd(v, floor)
    # fallback to group reference
    for u in range(U):
        g = grid.gidx[u]
        miss = np.isnan(mu[u])
        mu[u, miss] = gmu[g, miss]; sd[u, miss] = gsd[g, miss]
    return mu, sd


def pair_temporal(pair: pd.DataFrame, flows: pd.DataFrame, grid: Grid, cfg: dict) -> pd.DataFrame:
    tcfg = cfg["weights"]["temporal"]
    k, h, cap, alpha, floor = tcfg["cusum_k"], tcfg["cusum_h"], tcfg["cusum_cap"], tcfg["ewma_alpha"], tcfg["sigma_floor"]
    ref_mu, ref_sd = user_reference(pair, grid, tcfg)
    x_all = np.log1p(pair["out_bytes"].values)
    n = len(pair)
    z_out = np.full(n, np.nan); cusum = np.zeros(n); alarm = np.zeros(n, dtype=bool); ew = np.zeros(n)
    b7 = np.zeros(n); per = np.full(n, np.nan)
    hrs = (flows["day"] * 24 + flows["hour"]).groupby([flows["user_id"], flows["dst_id"]]).apply(lambda s: np.sort(s.values))
    bytes_ = pair["out_bytes"].values
    is_new = pair["is_new"].values
    for (u, dst), idx in pair.groupby(["user_id", "dst_id"]).indices.items():
        ui = grid.uidx[u]
        days = pair["day"].values[idx]
        order = np.argsort(days); idx = idx[order]; days = days[order]
        xs = x_all[idx]; bs = bytes_[idx]
        z = np.full(len(idx), np.nan)
        for j, t in enumerate(days):
            mu = sd = np.nan
            if not is_new[idx[j]] and j > 0:
                past = xs[:j][(days[:j] >= t - 28) & (grid.EX[ui, days[:j]] > t)]
                if len(past) >= 5:
                    mu, sd = _med_sd(past, floor)
            if np.isnan(mu):
                mu, sd = ref_mu[ui, t], ref_sd[ui, t]
            if not np.isnan(mu):
                z[j] = np.clip((xs[j] - mu) / sd, -6, 6)
            b7[idx[j]] = bs[(days >= t - 6) & (days <= t)].sum()
        # CUSUM per contiguous segment (reset after >7 day gap), EWMA over the whole series
        cut = np.where(np.diff(days) > 7)[0] + 1
        S = np.zeros(len(idx)); A = np.zeros(len(idx), dtype=bool)
        for seg in np.split(np.arange(len(idx)), cut):
            S[seg], A[seg] = cusum_series(z[seg], k, h, cap)
        z_out[idx] = z; cusum[idx] = S; alarm[idx] = A; ew[idx] = ewma_series(z, alpha)
        # periodicity (FFT on trailing 168h) only where there is material volume
        hs = hrs.get((u, dst))
        if hs is not None:
            for j, t in enumerate(days):
                if b7[idx[j]] >= 5e6:
                    lo = 24 * t - 144
                    a, b = np.searchsorted(hs, lo), np.searchsorted(hs, 24 * t + 24)
                    per[idx[j]] = periodicity_strength(hs[a:b] - lo)
    return pd.DataFrame({"z_pair": z_out, "cusum": cusum, "cusum_alarm": alarm, "ewma_z": ew,
                         "bytes_7d": b7, "periodicity": per}, index=pair.index)
