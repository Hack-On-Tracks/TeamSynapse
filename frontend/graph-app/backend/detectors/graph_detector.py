"""M6 peer-graph detector (P1): peer-destination mismatch and destination-set drift.

Graph construction/queries use NetworkX in ``features.graph_features``. This module turns
the resulting features into a [0, 1] sub-score.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from features.graph_features import build_graph, peer_support  # noqa: F401  (re-exported for analysis)


def graph_subscore(df: pd.DataFrame) -> np.ndarray:
    """A NEW edge that few peers share is suspicious; if several other users created the same
    edge within 48 h it looks like organisational adoption and is discounted (G3)."""
    new = df["is_new"].values.astype(float)
    rar = np.clip(df["peer_rarity"].fillna(1.0).values, 0, 1)
    coord = np.clip(df["same_edge_48h"].values / 2.0, 0, 1)
    drift = np.clip((df["dest_drift"].fillna(0.0).values - 0.3) / 0.5, 0, 1)
    return new * rar * (1 - coord) * (0.5 + 0.5 * drift) * df["volume_gate"].values
