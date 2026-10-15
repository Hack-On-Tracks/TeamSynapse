"""End-to-end metadata-only pipeline: raw flows -> ingest -> features -> detectors -> cases -> storage.

Usage (from backend/):  python scripts/run_pipeline.py [--raw data/raw]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import duckdb
import numpy as np
import pandas as pd

from common.settings import get_config, path_for
from detectors.isolation_forest import IFDetector
from features.build_features import FeatureSet, build_features
from ingestion.pseudonymizer import Pseudonymizer
from ingestion.validator import validate_dns, validate_flows, validate_users
from scoring.case_builder import CaseResult, annotate_entries, build_bundle, exclusion_from_cases, run_case_engine
from scoring.risk_fusion import SYSTEMS, compute_subscores, fuse, special_entries
from storage.database import connect
from storage.identity_vault import IdentityVault
from storage.repository import Repo


@dataclass
class PipelineResult:
    fs: FeatureSet
    users: pd.DataFrame
    dns: pd.DataFrame | None
    mapping: dict
    ingest_report: dict
    if_model: IFDetector
    entries: pd.DataFrame
    cases: CaseResult
    bundles: dict
    timings: dict = field(default_factory=dict)
    catalogue: pd.DataFrame | None = None


def ingest(flows_raw, users_raw, dns_raw, pseud: Pseudonymizer):
    flows, report = validate_flows(flows_raw)
    users = validate_users(users_raw)
    dns = validate_dns(dns_raw) if dns_raw is not None else None
    pf, m1 = pseud.apply_flows(flows)
    pu, m2 = pseud.apply_users(users)
    mapping = {**m1, **m2}
    missing = set(pf["user_id"]) - set(pu["user_id"])
    if missing:
        pu = pd.concat([pu, pd.DataFrame({"user_id": sorted(missing), "device_id": None, "peer_group": "Unknown", "asset_tier": 2})], ignore_index=True)
    pdns = pseud.apply_dns(dns) if dns is not None else None
    pf = pf.sort_values(["ts", "user_id"], kind="stable").reset_index(drop=True)
    pf["flow_id"] = np.arange(len(pf))
    report["payload_free"] = True
    return pf, pu.reset_index(drop=True), pdns, mapping, report


def fit_if(fs: FeatureSet, cfg: dict) -> IFDetector:
    lo, hi = cfg["settings"]["split"]["fit"]
    train = fs.pair_day[(fs.pair_day["day"] >= lo) & (fs.pair_day["day"] <= hi)]
    return IFDetector(cfg).fit(train)


def score_system(fs: FeatureSet, if_model, cfg: dict, system: str = "B5") -> pd.DataFrame:
    s = SYSTEMS[system]
    use_if = "isolation_forest" in s["components"]
    df = compute_subscores(fs.pair_day, if_model if use_if else None, cfg, s["use_peer"], s["use_pair"])
    df = fuse(df, cfg, s["components"], s["context"], s["temporal"])
    if system == "B5":
        sp = special_entries(fs.user_day, cfg, fs.dns_visible)
        if len(sp):
            df = pd.concat([df, sp], ignore_index=True)
    return df


def detect(flows_raw: pd.DataFrame, users_raw: pd.DataFrame, dns_raw: pd.DataFrame | None, cfg: dict,
           pseud: Pseudonymizer, catalogue: pd.DataFrame | None = None, log=print) -> PipelineResult:
    tm = {}
    t = time.time()
    flows, users, dns, mapping, rep = ingest(flows_raw, users_raw, dns_raw, pseud)
    tm["ingest"] = time.time() - t; t = time.time()
    n_days = None
    # pass 1: features without exclusions -> provisional cases
    fs1 = build_features(flows, users, dns, cfg)
    tm["features_pass1"] = time.time() - t; t = time.time()
    ifm1 = fit_if(fs1, cfg)
    ent1 = annotate_entries(score_system(fs1, ifm1, cfg, "B5"), cfg)
    res1 = run_case_engine(ent1, cfg, fs1.n_days)
    excl = exclusion_from_cases(res1)
    tm["pass1_scoring"] = time.time() - t; t = time.time()
    # pass 2: exclude days of already-open cases from the CLEAN baseline (causally), re-score
    fs2 = build_features(fs1.flows, users, dns, cfg, exclusion=excl, prepared=True)
    ifm = fit_if(fs2, cfg)
    ent2 = annotate_entries(score_system(fs2, ifm, cfg, "B5"), cfg)
    res = run_case_engine(ent2, cfg, fs2.n_days)
    tm["pass2"] = time.time() - t; t = time.time()
    dev = flows.groupby("user_id")["device_id"].first().to_dict()
    bundles = {cid: build_bundle(c, res, fs2, cfg, catalogue, dev) for cid, c in res.cases.items()}
    tm["bundles"] = time.time() - t
    log(f"  cases opened: {len(bundles)} | timings: " + ", ".join(f"{k}={v:.1f}s" for k, v in tm.items()))
    return PipelineResult(fs=fs2, users=users, dns=dns, mapping=mapping, ingest_report=rep, if_model=ifm,
                          entries=ent2, cases=res, bundles=bundles, timings=tm, catalogue=catalogue)


def persist(r: PipelineResult, cfg: dict, raw_dir: Path, db_con=None) -> dict:
    """Write Parquet + DuckDB analytics, models, encrypted vault, cases to the app DB."""
    proc, feat, models = path_for("processed"), path_for("features"), path_for("models")
    r.fs.flows.drop(columns=["peer_group"], errors="ignore").to_parquet(proc / "flows.parquet", index=False)
    r.users.to_parquet(proc / "users.parquet", index=False)
    if r.dns is not None:
        r.dns.to_parquet(proc / "dns.parquet", index=False)
    r.fs.user_day.to_parquet(feat / "user_day.parquet", index=False)
    pd_ = r.fs.pair_day
    pd_.to_parquet(feat / "pair_day.parquet", index=False)
    ent = r.entries.copy()
    for c in ("conf_reasons", "reasons"):
        ent[c] = ent[c].map(lambda x: json.dumps(x))
    ent.to_parquet(feat / "entries.parquet", index=False)
    r.cases.track.to_parquet(feat / "case_track.parquet", index=False)
    r.if_model.save(models / "isolation_forest.joblib")
    con = duckdb.connect(str(proc / "ciphersentinel.duckdb"))
    for name, p in {"flows": proc / "flows.parquet", "user_day": feat / "user_day.parquet", "pair_day": feat / "pair_day.parquet",
                    "entries": feat / "entries.parquet"}.items():
        con.execute(f"CREATE OR REPLACE VIEW {name} AS SELECT * FROM read_parquet('{p.as_posix()}')")
    con.close()
    IdentityVault().save(r.mapping)           # encrypted, separate from the analytical DB
    own = db_con is None
    con2 = db_con or connect()
    repo = Repo(con2)
    ud = r.fs.user_day
    meta = {
        "pipeline": {"run_at": pd.Timestamp.utcnow().isoformat(), "n_flows": int(len(r.fs.flows)), "n_users": int(r.users.shape[0]),
                     "n_days": r.fs.n_days, "n_cases": len(r.bundles), "data_origin": "simulated",
                     "t0": str(r.fs.t0.date()), "model_version": cfg["settings"]["app"]["model_version"],
                     "feature_schema_version": cfg["settings"]["app"]["feature_schema_version"],
                     "ingest_report": r.ingest_report, "timings": r.timings,
                     "dns_visible": bool(r.fs.dns_visible),
                     "hidden_sni_share": float(r.fs.flows["sni_hidden"].mean()),
                     "quic_share": float(r.fs.flows["is_quic"].mean()),
                     "mean_capture_quality": float(r.fs.flows["capture_quality"].mean()),
                     "mean_identity_confidence": float(r.fs.flows["identity_confidence"].mean())},
    }
    repo.save_cases(r.bundles, r.cases.queue, meta)
    repo.audit("system", "system", "pipeline_run", "pipeline", {"cases": len(r.bundles), "flows": int(len(r.fs.flows))})
    if own:
        con2.close()
    return meta["pipeline"]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--raw", default=None, help="directory with flows_raw.parquet etc.")
    a = ap.parse_args()
    cfg = get_config()
    raw = Path(a.raw) if a.raw else path_for("raw")
    if not (raw / "flows_raw.parquet").exists():
        print("No dataset found; generating with seed", cfg["settings"]["simulation"]["seed"])
        from sim.generate_dataset import write_dataset
        from sim.simulator import generate
        write_dataset(generate(cfg), raw)
    print("Loading raw metadata ...")
    flows = pd.read_parquet(raw / "flows_raw.parquet")
    users = pd.read_parquet(raw / "users_raw.parquet")
    dns = pd.read_parquet(raw / "dns_raw.parquet") if (raw / "dns_raw.parquet").exists() else None
    cat = pd.read_parquet(raw / "destinations.parquet") if (raw / "destinations.parquet").exists() else None
    print(f"  {len(flows):,} flows, {len(users)} users")
    r = detect(flows, users, dns, cfg, Pseudonymizer(), cat)
    meta = persist(r, cfg, raw)
    q = r.cases.queue
    print(f"Done. {meta['n_cases']} cases; priority queue rows: {int(q['priority'].sum()) if len(q) else 0}")


if __name__ == "__main__":
    main()
