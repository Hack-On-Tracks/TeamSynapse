"""Generate the synthetic dataset: ``python -m sim.generate_dataset --seed 42``."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from common.settings import get_config, path_for
from sim.ground_truth import save_ground_truth
from sim.simulator import SimResult, generate


def write_dataset(res: SimResult, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    res.flows.to_parquet(out_dir / "flows_raw.parquet", index=False)
    res.users.to_parquet(out_dir / "users_raw.parquet", index=False)
    res.dns.to_parquet(out_dir / "dns_raw.parquet", index=False)
    res.destinations.to_parquet(out_dir / "destinations.parquet", index=False)
    # Ground truth is a SEPARATE file read only by the evaluation module.
    save_ground_truth(res.ground_truth, out_dir / "ground_truth.parquet")
    m = dict(res.manifest)
    m["files"] = {f: hashlib.sha256((out_dir / f).read_bytes()).hexdigest()[:16]
                  for f in ["flows_raw.parquet", "users_raw.parquet", "dns_raw.parquet", "ground_truth.parquet"]}
    (out_dir / "manifest.json").write_text(json.dumps(m, indent=2, default=str), encoding="utf-8")
    return m


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--out", type=str, default=None)
    a = ap.parse_args()
    cfg = get_config()
    seed = a.seed if a.seed is not None else cfg["settings"]["simulation"]["seed"]
    res = generate(cfg, seed)
    out = Path(a.out) if a.out else path_for("raw")
    m = write_dataset(res, out)
    print(f"Generated {m['n_flows']:,} flows ({m['n_users']} users, {m['n_days']} days, seed {seed}) -> {out}")
    print(f"Scenarios: {len(m['scenarios'])}  | ground truth rows: {len(res.ground_truth)} (stored separately)")


if __name__ == "__main__":
    main()
