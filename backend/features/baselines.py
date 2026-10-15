"""Robust baselines (median/MAD) over TRAILING clean windows, per-user and per-peer-group.

z = (x - median(B)) / (1.4826 * MAD(B) + eps),  B = trailing 14 clean valid days (>= 7 required),
clipped to [-10, 10]. Only days strictly BEFORE the target day are used.
"""
from __future__ import annotations

import warnings

import numpy as np
import pandas as pd


def robust_z(x: float, baseline, eps: float = 1e-6, clip: float = 10.0, min_days: int = 7) -> float:
    """Robust z-score of ``x`` against baseline values ``B``. NaN if fewer than ``min_days`` valid values."""
    b = np.asarray(baseline, dtype=float)
    b = b[~np.isnan(b)]
    if len(b) < min_days or np.isnan(x):
        return np.nan
    med = np.median(b)
    mad = np.median(np.abs(b - med))
    z = (x - med) / (1.4826 * mad + eps)
    return float(np.clip(z, -clip, clip))


class Grid:
    """Dense [user, day] grid helper plus the clean-baseline exclusion matrix.

    exclusion_known_at[u, d] = first target day on which day ``d`` of user ``u`` is excluded from
    baselines (because it belonged to an already-open case). Default: never.
    """

    def __init__(self, users: pd.DataFrame, n_days: int, exclusion: pd.DataFrame | None = None):
        self.users = users.reset_index(drop=True)
        self.U = len(self.users)
        self.D = n_days
        self.uidx = {u: i for i, u in enumerate(self.users["user_id"])}
        groups = sorted(self.users["peer_group"].unique())
        self.gidx = self.users["peer_group"].map({g: i for i, g in enumerate(groups)}).values
        self.groups = groups
        self.EX = np.full((self.U, self.D), np.inf)
        if exclusion is not None and len(exclusion):
            for r in exclusion.itertuples(index=False):
                i = self.uidx.get(r.user_id)
                if i is not None and 0 <= r.day < self.D:
                    self.EX[i, r.day] = min(self.EX[i, r.day], r.known_at)

    def matrix(self, df: pd.DataFrame, col: str, fill=np.nan) -> np.ndarray:
        M = np.full((self.U, self.D), fill, dtype=float)
        ui = df["user_id"].map(self.uidx).values
        M[ui, df["day"].values] = df[col].values
        return M

    def clean_window(self, M: np.ndarray, t: int, window: int) -> np.ndarray:
        """Trailing window [t-window, t) with excluded days masked to NaN."""
        lo = max(0, t - window)
        W = M[:, lo:t].copy()
        W[self.EX[:, lo:t] <= t] = np.nan
        return W

    def user_day_z(self, df: pd.DataFrame, col: str, window: int = 14, min_days: int = 7,
                   eps: float = 1e-6, clip: float = 10.0, min_peer_obs: int = 30) -> pd.DataFrame:
        """Self and peer robust z-scores of ``col`` for every row of ``df`` (user_id, day)."""
        M = self.matrix(df, col)
        z_self = np.full((self.U, self.D), np.nan)
        z_peer = np.full((self.U, self.D), np.nan)
        n_clean = np.zeros((self.U, self.D))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=RuntimeWarning)
            for t in range(1, self.D):
                W = self.clean_window(M, t, window)
                valid = (~np.isnan(W)).sum(1)
                n_clean[:, t] = valid
                med = np.nanmedian(W, axis=1)
                mad = np.nanmedian(np.abs(W - med[:, None]), axis=1)
                ok = valid >= min_days
                zz = (M[:, t] - med) / (1.4826 * mad + eps)
                z_self[:, t] = np.where(ok, np.clip(zz, -clip, clip), np.nan)
                for g in range(len(self.groups)):
                    members = np.where(self.gidx == g)[0]
                    for u in members:
                        others = members[members != u]
                        pool = W[others].ravel()
                        pool = pool[~np.isnan(pool)]
                        if len(pool) >= min_peer_obs:
                            pm = np.median(pool)
                            pmad = np.median(np.abs(pool - pm))
                            z_peer[u, t] = np.clip((M[u, t] - pm) / (1.4826 * pmad + eps), -clip, clip)
        ui = df["user_id"].map(self.uidx).values
        out = pd.DataFrame({"user_id": df["user_id"].values, "day": df["day"].values,
                            f"z_self_{col}": z_self[ui, df["day"].values],
                            f"z_peer_{col}": z_peer[ui, df["day"].values]})
        if col == "out_bytes":
            out["n_clean_days"] = n_clean[ui, df["day"].values]
        return out


def cold_start_z(z_self: float, z_peer: float) -> tuple[float, bool]:
    """Effective z used for scoring and a cold-start flag.

    Both available -> min (a large upload is only unusual if unusual for the user AND the role).
    Only peer available (new user, <7 clean days) -> peer z, flagged as cold start.
    """
    if not np.isnan(z_self) and not np.isnan(z_peer):
        return min(z_self, z_peer), False
    if not np.isnan(z_peer):
        return z_peer, True
    if not np.isnan(z_self):
        return z_self, False
    return np.nan, True
