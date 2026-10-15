"""M3 destination-novelty detector.

novelty_score = first_seen * (0.4 + 0.3*peer_rarity + 0.3*category_prior) * volume_gate

Every input is normalised to [0, 1]. The volume gate (0 at <=1 MB, 1 at >=100 MB, log-linear)
stops tiny incidental connections from becoming high-risk cases.
"""
from __future__ import annotations

import numpy as np


def novelty_score(first_seen, peer_rarity, cat_prior, gate):
    fs = np.asarray(first_seen, dtype=float)
    pr = np.clip(np.nan_to_num(np.asarray(peer_rarity, dtype=float), nan=1.0), 0, 1)
    cp = np.clip(np.asarray(cat_prior, dtype=float), 0, 1)
    g = np.clip(np.asarray(gate, dtype=float), 0, 1)
    return fs * (0.4 + 0.3 * pr + 0.3 * cp) * g
