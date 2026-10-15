"""Synthetic employee population: 80 users in four peer groups."""
from __future__ import annotations

import numpy as np
import pandas as pd

GROUP_UPLOAD_SCALE = {"Engineering": 1.8, "Finance": 1.0, "Sales": 1.2, "Support": 0.7}
GROUP_FLOW_SCALE = {"Engineering": 1.25, "Finance": 0.9, "Sales": 1.0, "Support": 0.9}
GROUP_WEEKEND_FACTOR = {"Engineering": 0.12, "Finance": 0.05, "Sales": 0.10, "Support": 0.45}


def _hour_profile(group: str) -> np.ndarray:
    """Hourly activity distribution (UTC hours) with ~4% off-hours mass."""
    h = np.arange(24)
    def bump(mu, sd):
        d = np.minimum(np.abs(h - mu), 24 - np.abs(h - mu))
        return np.exp(-0.5 * (d / sd) ** 2)
    if group == "Engineering":
        p = bump(14, 3.2)
    elif group == "Finance":
        p = bump(12.5, 2.4)
    elif group == "Sales":
        p = bump(13.5, 2.8)
    else:  # Support: two shifts
        p = 0.5 * bump(11, 2.5) + 0.5 * bump(18, 2.5)
    p = p / p.sum()
    p = 0.96 * p + 0.04 / 24
    return p / p.sum()


def hour_profile(group: str) -> np.ndarray:
    return _hour_profile(group)


def build_users(cfg: dict, rng: np.random.Generator) -> pd.DataFrame:
    sim = cfg["settings"]["simulation"]
    rows, n = [], 0
    for group, size in sim["group_sizes"].items():
        for _ in range(size):
            n += 1
            rows.append(
                {
                    "user": f"emp{n:03d}",
                    "device": f"dev{n:03d}",
                    "peer_group": group,
                    "asset_tier": int(rng.choice([1, 2, 3], p=[0.55, 0.30, 0.15])),
                    "activity_scale": float(np.clip(rng.lognormal(0, 0.25), 0.5, 2.0)) * GROUP_FLOW_SCALE[group],
                    "upload_scale": float(np.clip(rng.lognormal(0, 0.3), 0.4, 2.5)) * GROUP_UPLOAD_SCALE[group],
                    "start_day": 0,
                    "src_ip": f"192.0.2.{n}",
                    "base_identity_conf": 0.98,
                }
            )
    users = pd.DataFrame(rows)
    # ~5% of users share a device / NAT'd address -> weaker identity attribution.
    shared = rng.choice(len(users), size=max(1, int(0.05 * len(users))), replace=False)
    users.loc[shared, "base_identity_conf"] = 0.70
    return users
