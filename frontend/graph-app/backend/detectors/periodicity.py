"""M5 periodicity detector: FFT on a 168-hour residual series (needs >= 6 flows)."""
from __future__ import annotations

import numpy as np


def periodicity_strength(hour_idx, window_hours: int = 168, min_flows: int = 6) -> float:
    """Spectral peak share of an hourly count series.

    ``hour_idx``: integer hour offsets (0..167) of flows within the trailing 168 h window.
    Returns peak_power / total_non_DC_power in [0, 1]; NaN if fewer than ``min_flows`` flows.
    A high value means regular repetition; it is NOT proof of malicious intent.
    """
    hour_idx = np.asarray(hour_idx, dtype=int)
    if len(hour_idx) < min_flows:
        return float("nan")
    x = np.bincount(np.clip(hour_idx, 0, window_hours - 1), minlength=window_hours).astype(float)
    resid = x - x.mean()
    power = np.abs(np.fft.rfft(resid)) ** 2
    power = power[1:]
    total = power.sum()
    if total <= 1e-12:
        return 0.0
    return float(power.max() / total)
