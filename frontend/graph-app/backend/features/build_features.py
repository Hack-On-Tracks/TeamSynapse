"""Feature-building orchestrator: flows -> (user_day, pair_day) feature tables."""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from features.baselines import Grid
from features.flow_features import aggregate, prepare_flows
from features.graph_features import graph_features
from features.temporal import pair_temporal
from features.user_day import build_user_day
from features.user_destination_day import add_destination_context, finalize_pair


@dataclass
class FeatureSet:
    user_day: pd.DataFrame
    pair_day: pd.DataFrame
    flows: pd.DataFrame
    n_days: int
    t0: pd.Timestamp
    dns_visible: bool


def build_features(flows: pd.DataFrame, users: pd.DataFrame, dns: pd.DataFrame | None, cfg: dict,
                   exclusion: pd.DataFrame | None = None, prepared: bool = False,
                   t0: pd.Timestamp | None = None) -> FeatureSet:
    """Build trailing-history-only features.

    ``exclusion`` (user_id, day, known_at) removes days already inside an open case from the
    clean baseline for targets on/after ``known_at``.
    """
    f = flows if prepared else prepare_flows(flows, users, cfg, t0)
    t0 = f.attrs["t0"]
    n_days = int(f["day"].max()) + 1
    pair = aggregate(f, "pair_day", cfg)
    ud = aggregate(f, "user_day", cfg)
    pair = add_destination_context(pair, users, cfg)
    gp, gu = graph_features(pair, users, n_days, cfg)
    pair = pair.join(gp)
    grid = Grid(users, n_days, exclusion)
    ud = build_user_day(ud, pair, f, dns, grid, gu, users, cfg)
    pair = pair.join(pair_temporal(pair, f, grid, cfg))
    pair = finalize_pair(pair, ud, cfg)
    return FeatureSet(user_day=ud, pair_day=pair, flows=f, n_days=n_days, t0=t0, dns_visible=dns is not None)
