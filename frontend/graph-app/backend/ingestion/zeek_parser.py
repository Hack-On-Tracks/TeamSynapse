"""Zeek conn.log / ssl.log parser (TSV or JSON). Metadata only -- never payloads.

Handles missing fields explicitly (Zeek field availability depends on version and capture
configuration): missing values stay NaN/None rather than becoming zero.
"""
from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
from pathlib import Path

import numpy as np
import pandas as pd

from common.settings import get_config

CONN_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "duration",
               "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]
SSL_FIELDS = ["uid", "version", "server_name", "ja3"]


def read_zeek_log(path: str | Path) -> pd.DataFrame:
    """Read a Zeek log in TSV (``#fields`` header) or JSON-lines format."""
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if lines and lines[0].lstrip().startswith("{"):
        df = pd.DataFrame([json.loads(ln) for ln in lines])
    else:
        fields, unset, empty, rows = None, "-", "(empty)", []
        for ln in lines:
            if ln.startswith("#fields"):
                fields = ln.split("\t")[1:]
            elif ln.startswith("#unset_field"):
                unset = ln.split("\t")[1]
            elif ln.startswith("#empty_field"):
                empty = ln.split("\t")[1]
            elif not ln.startswith("#"):
                rows.append(ln.split("\t"))
        if fields is None:
            raise ValueError(f"{p}: no #fields header; not a Zeek TSV log")
        df = pd.DataFrame(rows, columns=fields).replace({unset: np.nan, empty: np.nan})
    return df


def _internal_nets():
    return [ipaddress.ip_network(n) for n in get_config()["policies"]["internal_networks"]]


def _is_internal(ip: str, nets) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


def parse_zeek(conn_path: str | Path, ssl_path: str | Path | None = None,
               ip_user_map: dict[str, tuple[str, str]] | None = None,
               catalogue: pd.DataFrame | None = None) -> pd.DataFrame:
    """Convert Zeek logs into canonical flow records.

    ip_user_map: internal IP -> (user, device) attribution (e.g. from DHCP/asset inventory).
    Unattributed hosts use the IP as identity and get reduced identity_confidence.
    """
    conn = read_zeek_log(conn_path)
    for c in CONN_FIELDS:
        if c not in conn.columns:
            conn[c] = np.nan
    nets = _internal_nets()
    o_int = conn["id.orig_h"].map(lambda x: _is_internal(str(x), nets))
    # Direction mapping: "orig" must always be the INTERNAL host (outbound = originator bytes).
    swap = ~o_int & conn["id.resp_h"].map(lambda x: _is_internal(str(x), nets))
    g = lambda a, b: np.where(swap, conn[b], conn[a])
    d = pd.DataFrame({
        "ts": pd.to_datetime(pd.to_numeric(conn["ts"], errors="coerce"), unit="s", utc=True),
        "uid": conn["uid"],
        "src_ip": g("id.orig_h", "id.resp_h"),
        "dst_ip": g("id.resp_h", "id.orig_h"),
        "dst_port": pd.to_numeric(pd.Series(g("id.resp_p", "id.orig_p")), errors="coerce"),
        "proto": conn["proto"],
        "duration": pd.to_numeric(conn["duration"], errors="coerce"),
        "orig_bytes": pd.to_numeric(pd.Series(g("orig_bytes", "resp_bytes")), errors="coerce"),
        "resp_bytes": pd.to_numeric(pd.Series(g("resp_bytes", "orig_bytes")), errors="coerce"),
        "orig_pkts": pd.to_numeric(pd.Series(g("orig_pkts", "resp_pkts")), errors="coerce"),
        "resp_pkts": pd.to_numeric(pd.Series(g("resp_pkts", "orig_pkts")), errors="coerce"),
    })
    d["tls_version"] = None; d["sni"] = None; d["ja3"] = None
    if ssl_path is not None and Path(ssl_path).exists():
        ssl = read_zeek_log(ssl_path)
        for c in SSL_FIELDS:
            if c not in ssl.columns:
                ssl[c] = np.nan
        ssl = ssl.drop_duplicates("uid").set_index("uid")
        d["tls_version"] = d["uid"].map(ssl["version"])
        d["sni"] = d["uid"].map(ssl["server_name"])
        d["ja3"] = d["uid"].map(ssl["ja3"])
    d["is_quic"] = (d["proto"].astype(str).str.lower() == "udp") & (d["dst_port"] == 443)
    d["dst_id"] = d["sni"].where(d["sni"].notna(), d["dst_ip"]).astype(str)
    d["dst_category"] = "unknown"
    if catalogue is not None:
        cat = catalogue.set_index("sni_name")
        hit = d["sni"].map(cat["dst_category"])
        d["dst_category"] = hit.fillna("unknown")
        d["dst_id"] = d["sni"].map(cat["dst_id"]).fillna(d["dst_id"])
    ipm = ip_user_map or {}
    d["user"] = d["src_ip"].map(lambda ip: ipm.get(ip, (ip, ip))[0])
    d["device"] = d["src_ip"].map(lambda ip: ipm.get(ip, (ip, ip))[1])
    d["identity_confidence"] = d["src_ip"].map(lambda ip: 0.95 if ip in ipm else 0.5)
    d["capture_quality"] = np.nan   # not provided by conn.log; missing, not assumed perfect
    return d.drop(columns=["uid"])


def replay_pcap(pcap: str | Path, out_dir: str | Path) -> Path:
    """Replay an AUTHORISED PCAP through Zeek to produce JSON conn/ssl logs. Requires Zeek on PATH.
    Payloads are not extracted or stored; only Zeek's structured metadata logs are written."""
    zeek = shutil.which("zeek")
    if zeek is None:
        raise RuntimeError("Zeek not found on PATH. Install Zeek or use the simulator / CSV-JSON flow ingestion.")
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    subprocess.run([zeek, "-C", "-r", str(pcap), "LogAscii::use_json=T"], cwd=out, check=True, timeout=600)
    return out
