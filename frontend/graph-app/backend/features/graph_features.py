"""Peer-destination graph features with NetworkX (bipartite user<->destination graph).

Windows only look BACKWARD from the target day (inclusive of that day's end-of-day state,
which is what an analyst would see when the day closes).
"""
from __future__ import annotations

from collections import defaultdict

import networkx as nx
import numpy as np
import pandas as pd


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return np.nan
    return len(a & b) / len(a | b)


def build_graph(window_sets: dict[str, set]) -> nx.Graph:
    G = nx.Graph()
    for u, dsts in window_sets.items():
        G.add_edges_from((f"U|{u}", f"D|{x}") for x in dsts)
    return G


def peer_support(G: nx.Graph, groups: dict, user: str, dst: str) -> int:
    node = f"D|{dst}"
    if node not in G:
        return 0
    g = groups[user]
    return sum(1 for v in G[node] if v[2:] != user and groups.get(v[2:]) == g)


def graph_features(pair_day: pd.DataFrame, users: pd.DataFrame, n_days: int, cfg: dict):
    """Returns (pair_extra, user_extra).

    pair_extra: peer_rarity (F12), same_edge_48h (G3) per pair-day row.
    user_extra: jaccard_peer (G1), dest_drift (G2) per user-day (rows for active user-days).
    """
    fcfg = cfg["settings"]["features"]
    W = fcfg["peer_window_days"]
    groups = users.set_index("user_id")["peer_group"].to_dict()
    gsize = users.groupby("peer_group").size().to_dict()
    ud: dict[int, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    for r in pair_day[["user_id", "dst_id", "day"]].itertuples(index=False):
        ud[r.day][r.user_id].add(r.dst_id)
    first = pair_day.groupby(["user_id", "dst_id"])["day"].min()
    first_by_dst: dict[str, list] = defaultdict(list)
    for (u, d), fd in first.items():
        first_by_dst[d].append((u, fd))
    rarity = np.full(len(pair_day), np.nan)
    same_edge = np.zeros(len(pair_day))
    rows_by_day = pair_day.groupby("day").indices
    user_rows = []
    active_by_day = pair_day.groupby("day")["user_id"].unique()
    for t in range(n_days):
        def union(lo, hi):
            out: dict[str, set] = defaultdict(set)
            for d in range(max(0, lo), hi + 1):
                for u, s in ud.get(d, {}).items():
                    out[u] |= s
            return out
        win = union(t - W + 1, t)
        G = build_graph(win)
        # F12 peer rarity & G3 same new edge within 48h
        for ri in rows_by_day.get(t, []):
            u = pair_day.iat[ri, pair_day.columns.get_loc("user_id")]
            x = pair_day.iat[ri, pair_day.columns.get_loc("dst_id")]
            gs = gsize[groups[u]] - 1
            rarity[ri] = 1.0 - (peer_support(G, groups, u, x) / gs if gs > 0 else 0.0)
            fu = first[(u, x)]
            same_edge[ri] = sum(1 for (v, fv) in first_by_dst[x] if v != u and abs(fv - fu) <= 2 and fv <= t)
        # G1 / G2 per active user-day
        if t not in active_by_day.index:
            continue
        recent = union(t - 6, t)
        prev = union(t - 20, t - 7)
        # peer-common destinations per group: used by >= 30% of peers
        common: dict[str, set] = {}
        for g in gsize:
            cnt: dict[str, int] = defaultdict(int)
            for u, s in win.items():
                if groups.get(u) == g:
                    for x in s:
                        cnt[x] += 1
            common[g] = {x for x, c in cnt.items() if c >= max(2, 0.3 * gsize[g])}
        for u in active_by_day[t]:
            user_rows.append({"user_id": u, "day": t,
                              "jaccard_peer": _jaccard(win.get(u, set()), common[groups[u]]),
                              "dest_drift": (1 - _jaccard(recent.get(u, set()), prev.get(u, set())))
                              if prev.get(u) else np.nan})
    pe = pd.DataFrame({"peer_rarity": rarity, "same_edge_48h": same_edge}, index=pair_day.index)
    return pe, pd.DataFrame(user_rows)
