"""M4 temporal detector primitives: CUSUM and EWMA on standardised series.

Units: callers pass a series standardised to z = (x - mu)/sigma (here: log-byte domain), so
the CUSUM recursion S_t = max(0, S_{t-1} + (x_t - mu - k*sigma)) becomes
S_t = max(0, S_{t-1} + z_t - k) with alarm threshold h (in sigma units, default 5).
"""
from __future__ import annotations

import numpy as np


def cusum_series(z, k: float = 0.5, h: float = 5.0, cap: float | None = 10.0):
    """Return (S, alarms) for a standardised series ``z`` (NaN steps leave S unchanged)."""
    S = np.zeros(len(z)); alarms = np.zeros(len(z), dtype=bool)
    s = 0.0
    for i, v in enumerate(z):
        if not np.isnan(v):
            s = max(0.0, s + float(v) - k)
            if cap is not None:
                s = min(s, cap)
        S[i] = s
        alarms[i] = s > h
    return S, alarms


def cusum_raw(x, mu: float, sigma: float, k: float = 0.5, h: float = 5.0):
    """CUSUM in original units: S_t = max(0, S_{t-1} + (x_t - mu - k*sigma)); alarm when S_t > h*sigma."""
    S = np.zeros(len(x)); s = 0.0
    for i, v in enumerate(x):
        s = max(0.0, s + (v - mu - k * sigma)); S[i] = s
    return S, S > h * sigma


def ewma_series(z, alpha: float = 0.3):
    """Exponentially weighted moving average (NaN steps carry the previous value)."""
    out = np.zeros(len(z)); e = 0.0
    for i, v in enumerate(z):
        if not np.isnan(v):
            e = alpha * float(v) + (1 - alpha) * e
        out[i] = e
    return out
