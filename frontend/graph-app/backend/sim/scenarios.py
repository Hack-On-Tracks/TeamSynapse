"""Scenario planning and injection (malicious S1-S7 and 12 benign look-alikes B01-B12).

Everything is deterministic given the RNG seed. The plan (users, days, parameters) is
documented in the dataset manifest; the labels go ONLY to the separate ground-truth file.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from sim import destinations as D
from sim.users import hour_profile

N_DAYS_DEFAULT = 60


def plan_scenarios(cfg: dict, rng: np.random.Generator, users: pd.DataFrame) -> list[dict]:
    sim = cfg["settings"]["simulation"]
    n_days = sim["n_days"]
    t0 = sim["test_window_start"]
    avail = list(rng.permutation(users["user"].values))
    grp = users.set_index("user")["peer_group"]
    plans: list[dict] = []

    def take(k=1, group=None):
        out = []
        for u in list(avail):
            if len(out) == k:
                break
            if group is None or grp[u] == group:
                out.append(u)
        for u in out:
            avail.remove(u)
        return out

    pc = list(rng.permutation(np.arange(260, 300)))   # unique personal-cloud destinations
    counts = sim["scenarios"]

    def add(sid, typ, label, us, s, e, dst=None, **params):
        plans.append({"scenario_id": sid, "type": typ, "label": label, "users": us, "start_day": int(s),
                      "end_day": int(min(e, n_days - 1)), "dst_ids": dst or [], "params": params})

    # ---- malicious ----
    for i in range(counts.get("S1", 0)):
        u = take(1)[0]; d = int(rng.integers(t0, n_days - 4))
        add(f"S1-{i+1:02d}", "S1", "malicious", [u], d, d, [D.dst_id(int(pc.pop()))],
            total_bytes=float(rng.uniform(0.8e9, 3e9)))
    for i in range(counts.get("S2", 0)):
        u = take(1)[0]; dur = int(rng.integers(14, 22)); s = int(rng.integers(t0 - 2, n_days - dur + 1))
        add(f"S2-{i+1:02d}", "S2", "malicious", [u], s, s + dur - 1, [D.dst_id(int(pc.pop()))], duration_days=dur)
    for i in range(counts.get("S3", 0)):
        u = take(1)[0]; s = int(rng.integers(t0, n_days - 7 + 1))
        add(f"S3-{i+1:02d}", "S3", "malicious", [u], s, s + 6, [D.dst_id(int(pc.pop()))], transfers_per_night=6)
    for i in range(counts.get("S4", 0)):
        u = take(1)[0]; s = int(rng.integers(t0, n_days - 21 + 1))
        add(f"S4-{i+1:02d}", "S4", "malicious", [u], s, s + 20, None, ramp_multiple=4.0)
    for i in range(counts.get("S5", 0)):
        u = take(1)[0]; nd = sim["s5_rotation_days"]; s = int(rng.integers(t0, n_days - nd + 1))
        add(f"S5-{i+1:02d}", "S5", "malicious", [u], s, s + nd - 1, None)
    for i in range(counts.get("S6", 0)):
        u = take(1)[0]; s = sim["s6_start_day"]
        add(f"S6-{i+1:02d}", "S6", "malicious", [u], s, s + 29, None, daily_growth=0.10)
    for i in range(counts.get("S7", 0)):
        u = take(1)[0]; s = int(rng.integers(t0, n_days - 3 + 1))
        add(f"S7-{i+1:02d}", "S7", "malicious", [u], s, s + 2, ["*dns*"])

    # ---- benign look-alikes ----
    def start(lo=t0, span=14, dur=1):
        return int(rng.integers(lo, max(lo + 1, min(lo + span, n_days - dur + 1))))

    s = int(rng.integers(30, 41)); add("B01-01", "B01", "benign", take(3, "Engineering"), s, n_days - 1, [D.BACKUP_DST])
    sales = [u for u in avail if grp[u] == "Sales"]
    s = start(t0 + 2, 6, 15)
    add("B02-01", "B02", "benign", take(max(len(sales) - 6, 3), "Sales"), s, n_days - 1, [D.TEAM_SAAS_DST])
    s = start(t0, 14, 5); add("B03-01", "B03", "benign", take(1, "Sales"), s, s + 4, ["*"])
    s = start(t0, 18); add("B04-01", "B04", "benign", take(1, "Finance"), s, s, [D.ONEOFF_ALLOWLISTED_DST])
    s = start(t0, 14, 7); add("B05-01", "B05", "benign", take(4, "Sales"), s, s + 6, [D.dst_id(i) for i in range(112, 132)])
    s = start(t0 + 2, 12); add("B06-01", "B06", "benign", list(users["user"]), s, s, [D.dst_id(i) for i in range(157, 172)])
    s = start(t0, 18); add("B07-01", "B07", "benign", take(1, "Engineering"), s, s, ["*"])
    fin = [u for u in avail if grp[u] == "Finance"]
    s = start(t0, 14, 3); add("B08-01", "B08", "benign", take(len(fin), "Finance"), s, s + 2, ["*"])
    s = start(t0, 12, 10); add("B09-01", "B09", "benign", take(3, "Support"), s, s + 9, [D.NEW_APPROVED_APP_DST])
    s = start(t0, 18); add("B10-01", "B10", "benign", take(1, "Sales"), s, s, ["*"])
    s = int(rng.integers(30, 41)); add("B11-01", "B11", "benign", take(2, "Engineering"), s, n_days - 1, [D.AUTOMATION_DST])
    add("B12-01", "B12", "benign", take(1), 38, n_days - 1, ["*"], start_day=38)
    return plans


def _nd(flows, start):
    return ((flows["ts"] - start).dt.total_seconds() // 86400).astype(int)


def inject(cfg, rng, b, users, cat_df, normal: pd.DataFrame, plan: list[dict]) -> list[pd.DataFrame]:
    start = b.start
    nd = _nd(normal, start)
    out: list[pd.DataFrame] = []
    cats = cat_df.set_index("dst_id")["dst_category"]

    def top_dest(user, categories, before=None):
        m = (normal["user"] == user) & normal["dst_category"].isin(categories)
        if before is not None:
            m &= nd < before
        g = normal[m].groupby("dst_id")["orig_bytes"].sum()
        return g.idxmax() if len(g) else None

    def baseline_daily(user, dst, before):
        m = (normal["user"] == user) & (normal["dst_id"] == dst) & (nd < before)
        if not m.any():
            return 2e6
        days = nd[m].nunique()
        return max(float(normal.loc[m, "orig_bytes"].sum()) / max(days, 1), 1e6)

    def emit(user, day, hours, dst, orig, resp=None, tool=0.0, tag=""):
        hours = np.atleast_1d(np.asarray(hours, dtype=float)); orig = np.atleast_1d(np.asarray(orig, dtype=float))
        if resp is None:
            resp = orig * rng.uniform(0.01, 0.04, len(orig))
        out.append(b.make(user, b.ts_from(day, hours, 0.0), dst, orig, np.atleast_1d(resp), tool_share=tool, tool_tag=tag))

    def split(total, n):
        return total * rng.dirichlet(np.ones(n))

    for p in plan:
        t, sid = p["type"], p["scenario_id"]
        us = p["users"]; s, e = p["start_day"], p["end_day"]
        u = us[0]
        # ----------------------------- malicious -----------------------------
        if t == "S1":
            n = int(rng.integers(30, 50))
            emit(u, s, rng.uniform(19, 22.5, n), p["dst_ids"][0], split(p["params"]["total_bytes"], n), tool=0.7, tag=sid)
        elif t == "S2":
            for d in range(s, e + 1):
                n = int(rng.integers(1, 5))
                emit(u, d, rng.uniform(8, 23.5, n), p["dst_ids"][0], split(rng.uniform(5e6, 25e6), n), tool=0.7, tag=sid)
        elif t == "S3":
            for d in range(s, e + 1):
                emit(u, d, 0.5 + np.arange(6) + rng.uniform(-0.05, 0.05, 6), p["dst_ids"][0], rng.uniform(30e6, 60e6, 6), tool=0.7, tag=sid)
        elif t == "S4":
            dst = top_dest(u, ["corporate_cloud"], s)
            p["dst_ids"] = [dst]
            base = baseline_daily(u, dst, s); p["params"]["baseline_daily_bytes"] = base
            for k in range(1, 21):
                emit(u, s + k, rng.uniform(17, 23.5, 3), dst, split(base * 3.0 * k / 20, 3), tag=sid)
        elif t == "S5":
            known = set(normal.loc[normal["user"] == u, "dst_id"])
            cand = [d for d in cat_df["dst_id"] if d not in known and d not in (D.BACKUP_DST, D.AUTOMATION_DST)]
            cand = list(rng.permutation(cand)); used = []
            for d in range(s, e + 1):
                k = int(rng.integers(10, 21)); picks = [cand.pop() for _ in range(k)]; used += picks
                emit(u, d, rng.uniform(9, 23, k), picks, rng.uniform(2e6, 10e6, k), tool=0.5, tag=sid)
            p["dst_ids"] = used + ["*rotation*"]
        elif t == "S6":
            dst = top_dest(u, ["corporate_cloud"], s)
            p["dst_ids"] = [dst]
            base = baseline_daily(u, dst, s); p["params"]["baseline_daily_bytes"] = base
            for d in range(s, e + 1):
                k = d - s + 1
                emit(u, d, rng.uniform(17, 23.5, 3), dst, split(base * (1.1 ** k - 1), 3), tag=sid)
        # S7: DNS statistics only (generated in dns_stats)

        # ------------------------------ benign -------------------------------
        elif t == "B01":
            for uu in us:
                for d in range(s, e + 1):
                    emit(uu, d, [2.0, 2.4, 2.8], D.BACKUP_DST, split(rng.uniform(0.6e9, 1.5e9), 3), tag=sid)
        elif t == "B02":
            for uu in us:
                lag = int(rng.integers(0, 3))
                for d in range(s + lag, e + 1):
                    n = int(rng.integers(2, 6))
                    emit(uu, d, rng.uniform(9, 18, n), D.TEAM_SAAS_DST, split(rng.uniform(20e6, 60e6), n), resp=rng.uniform(1e6, 5e6, n))
        elif t == "B03":
            prof = np.roll(hour_profile("Sales"), 9)
            for d in range(s, e + 1):
                n = 40
                hrs = rng.choice(24, size=n, p=prof) + rng.uniform(0, 0.99, n)
                dst = rng.choice(D.TRAVEL_POOL, size=n)
                emit(u, d, hrs, dst, rng.lognormal(np.log(60e3), 1.4, n), resp=rng.lognormal(np.log(400e3), 1.2, n))
        elif t == "B04":
            emit(u, s, rng.uniform(14, 17, 6), D.ONEOFF_ALLOWLISTED_DST, split(rng.uniform(0.4e9, 1.0e9), 6))
        elif t == "B05":
            for uu in us:
                dst = D.dst_id(int(rng.integers(112, 132)))
                for d in range(s, e + 1):
                    emit(uu, d, rng.uniform(9, 18, 8), dst, split(rng.uniform(0.3e9, 0.6e9), 8), resp=rng.uniform(5e6, 40e6, 8))
        elif t == "B06":
            for uu in us:
                n = int(rng.integers(3, 7))
                emit(uu, s, rng.uniform(9, 11, n), rng.choice([D.dst_id(i) for i in range(157, 172)], size=n),
                     rng.uniform(2e3, 9e3, n), resp=rng.lognormal(np.log(60e6), 0.8, n))
        elif t == "B07":
            dst = top_dest(u, ["corporate_cloud"]) or D.dst_id(61)
            emit(u, s, rng.uniform(10, 17, 12), dst, split(rng.uniform(1.2e9, 2.0e9), 12))
        elif t == "B08":
            for uu in us:
                m = (normal["user"] == uu) & normal["dst_category"].isin(["saas", "corporate_cloud"])
                top = normal[m]["dst_id"].value_counts().index[:5].tolist() or [D.dst_id(61)]
                for d in range(s, e + 1):
                    emit(uu, d, rng.uniform(9, 18, 30), rng.choice(top, size=30), rng.lognormal(np.log(2e6), 1.0, 30),
                         resp=rng.lognormal(np.log(1e6), 1.0, 30))
        elif t == "B09":
            for uu in us:
                for d in range(s, e + 1):
                    emit(uu, d, rng.uniform(9, 17, 4), D.NEW_APPROVED_APP_DST, split(rng.uniform(80e6, 150e6), 4), resp=rng.uniform(2e6, 8e6, 4))
        elif t == "B10":
            dst = top_dest(u, ["saas"]) or D.dst_id(0)
            emit(u, s, rng.uniform(10, 17, 15), dst, split(rng.uniform(250e6, 400e6), 15), resp=rng.uniform(1e6, 6e6, 15))
        elif t == "B11":
            for uu in us:
                for d in range(s, e + 1):
                    emit(uu, d, 1 + np.arange(4) * 0.8, D.AUTOMATION_DST, rng.uniform(5e6, 10e6, 4))
        # B12: no extra flows (user's start_day set to 38 in generate())
    return out
