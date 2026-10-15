"""Temporal Network Graph Service for CipherSentinel.

Aggregates network flows and threat telemetry into graph nodes and directed edges,
supporting timeline segmenting, entity connection graphs, and deterministic replay snapshots.
"""
from __future__ import annotations

import datetime
import math
import uuid
from typing import Dict, Any, List, Optional, Set, Tuple
import pandas as pd
import numpy as np

from ..storage.storage import DuckDBStorage


class TemporalGraphService:
    """Extracts, filters, and aggregates network graph topology and risk overlays."""

    def __init__(self, storage: Optional[DuckDBStorage] = None):
        self.storage = storage or DuckDBStorage()

    def _discover_flow_table(self) -> Optional[str]:
        """Find the flow table in DuckDB."""
        try:
            tables_df = self.storage.query("SHOW TABLES")
            names = tables_df["name"].tolist() if not tables_df.empty else []
            for candidate in ["network_flows", "test_flows", "flows_raw", "flows"]:
                if candidate in names:
                    return candidate
            for name in names:
                if "flow" in name.lower():
                    return name
            return None
        except Exception:
            return None

    def get_summary(
        self,
        table_name: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        min_risk: float = 0.0,
    ) -> Dict[str, Any]:
        """Return overall graph metrics: total nodes, edges, flows, and volume."""
        tbl = table_name or self._discover_flow_table()
        if not tbl:
            return self._empty_summary()

        try:
            query = f"SELECT COUNT(*) as flow_count, SUM(bytes_sent) as total_bytes, COUNT(DISTINCT src_ip) as distinct_sources, COUNT(DISTINCT dst_ip) as distinct_dests FROM {tbl}"
            df = self.storage.query(query)
            if df.empty:
                return self._empty_summary()
            row = df.iloc[0]

            # Get case count
            case_count = 0
            try:
                cases_df = self.storage.query("SELECT COUNT(*) as count FROM threat_cases")
                if not cases_df.empty:
                    case_count = int(cases_df["count"][0])
            except Exception:
                pass

            node_count = int(row["distinct_sources"] or 0) + int(row["distinct_dests"] or 0)
            edge_count = int(row["flow_count"] or 0)
            return {
                "table_name": tbl,
                "total_flows": edge_count,
                "total_bytes": float(row["total_bytes"] or 0.0),
                "unique_sources": int(row["distinct_sources"] or 0),
                "unique_destinations": int(row["distinct_dests"] or 0),
                "open_cases": case_count,
                "node_count": node_count,
                "edge_count": edge_count,
                "critical_entities": case_count,
                "graph_density": round(float(row["distinct_sources"] or 0) / max(1, float(row["distinct_dests"] or 1)), 3),
            }
        except Exception:
            return self._empty_summary()

    def _empty_summary(self) -> Dict[str, Any]:
        return {
            "table_name": "none",
            "total_flows": 0,
            "total_bytes": 0.0,
            "unique_sources": 0,
            "unique_destinations": 0,
            "open_cases": 0,
            "node_count": 0,
            "edge_count": 0,
            "critical_entities": 0,
            "graph_density": 0.0,
        }

    def get_graph_elements(
        self,
        table_name: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        entity_id: Optional[str] = None,
        protocol: Optional[str] = None,
        category: Optional[str] = None,
        min_risk: float = 0.0,
        scenario: Optional[str] = None,
        limit_edges: int = 250,
    ) -> Dict[str, Any]:
        """Aggregate flow records into Cytoscape.js compatible nodes and edges."""
        tbl = table_name or self._discover_flow_table()
        if not tbl:
            return {"nodes": [], "edges": []}

        conditions = ["1=1"]
        params = []

        if start_time:
            conditions.append("timestamp >= ?")
            params.append(start_time)
        if end_time:
            conditions.append("timestamp <= ?")
            params.append(end_time)
        if entity_id:
            conditions.append("(user_id = ? OR src_ip = ? OR dst_ip = ?)")
            params.extend([entity_id, entity_id, entity_id])
        if protocol and protocol.upper() != "ALL":
            conditions.append("UPPER(proto) = ?")
            params.append(protocol.upper())
        if category and category.lower() != "all":
            conditions.append("LOWER(dst_category) = ?")
            params.append(category.lower())
        if scenario and scenario != "ALL":
            conditions.append("scenario = ?")
            params.append(scenario)

        where_clause = " AND ".join(conditions)

        # Check existing threat scores for node risk overlays
        threat_scores_map = {}
        try:
            scores_df = self.storage.query("SELECT entity_id, composite_score, severity FROM threat_scores")
            if not scores_df.empty:
                for _, r in scores_df.iterrows():
                    threat_scores_map[str(r["entity_id"])] = {
                        "score": float(r["composite_score"]),
                        "severity": str(r["severity"]),
                    }
        except Exception:
            pass

        # Query aggregated edges to avoid thousands of individual edges
        query = f"""
            SELECT
                src_ip,
                dst_ip,
                MIN(user_id) as user_id,
                MIN(dst_category) as category,
                MIN(proto) as proto,
                MIN(app) as app,
                COUNT(*) as flow_count,
                SUM(bytes_sent) as total_bytes_sent,
                SUM(bytes_rev) as total_bytes_rev,
                AVG(duration) as avg_duration,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                MAX(CASE WHEN allowlisted THEN 1 ELSE 0 END) as is_allowlisted
            FROM {tbl}
            WHERE {where_clause}
            GROUP BY src_ip, dst_ip
            ORDER BY total_bytes_sent DESC
            LIMIT {int(limit_edges)}
        """

        try:
            df = self.storage.query(query, tuple(params) if params else None)
        except Exception:
            return {"nodes": [], "edges": []}

        if df.empty:
            return {"nodes": [], "edges": []}

        nodes_dict: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, Any]] = []

        for _, row in df.iterrows():
            src = str(row["src_ip"])
            dst = str(row["dst_ip"])
            user = str(row["user_id"]) if pd.notna(row["user_id"]) else src
            cat = str(row["category"]) if pd.notna(row["category"]) else "general"
            flow_cnt = int(row["flow_count"] or 1)
            b_sent = float(row["total_bytes_sent"] or 0.0)
            b_rev = float(row["total_bytes_rev"] or 0.0)
            allowlisted = bool(row["is_allowlisted"] == 1)

            # Node 1: Source Node (Employee / Host)
            if src not in nodes_dict:
                user_risk = threat_scores_map.get(user, {"score": 10.0, "severity": "LOW"})
                nodes_dict[src] = {
                    "data": {
                        "id": src,
                        "label": f"{user} ({src})",
                        "entity_id": user,
                        "ip": src,
                        "type": "employee_endpoint",
                        "risk_score": user_risk["score"],
                        "severity": user_risk["severity"],
                        "total_volume": b_sent,
                        "degree": 1,
                    }
                }
            else:
                nodes_dict[src]["data"]["total_volume"] += b_sent
                nodes_dict[src]["data"]["degree"] += 1

            # Node 2: Destination Node (Internal server or External Cloud)
            if dst not in nodes_dict:
                is_internal = dst.startswith("10.") or dst.startswith("192.168.")
                dst_type = "internal_service" if is_internal else f"external_{cat}"
                dst_risk = 75.0 if cat == "personal_cloud" and not allowlisted else 15.0
                dst_sev = "HIGH" if dst_risk >= 60 else "LOW"
                nodes_dict[dst] = {
                    "data": {
                        "id": dst,
                        "label": f"{dst} [{cat}]",
                        "entity_id": dst,
                        "ip": dst,
                        "type": dst_type,
                        "risk_score": dst_risk,
                        "severity": dst_sev,
                        "total_volume": b_rev,
                        "degree": 1,
                    }
                }
            else:
                nodes_dict[dst]["data"]["total_volume"] += b_rev
                nodes_dict[dst]["data"]["degree"] += 1

            # Edge definition
            edge_id = f"e_{src}_{dst}"
            edge_risk = 85.0 if b_sent > 50_000_000 and not allowlisted else (50.0 if b_sent > 10_000_000 else 15.0)
            edges.append({
                "data": {
                    "id": edge_id,
                    "source": src,
                    "target": dst,
                    "flow_count": flow_cnt,
                    "bytes_sent": round(b_sent, 1),
                    "bytes_rev": round(b_rev, 1),
                    "protocol": str(row["proto"]),
                    "category": cat,
                    "first_seen": str(row["first_seen"]),
                    "last_seen": str(row["last_seen"]),
                    "risk_score": edge_risk,
                    "allowlisted": allowlisted,
                    "width": min(8.0, 1.5 + math.log10(max(1, b_sent)) * 0.8),
                }
            })

        # Calculate node sizes based on traffic volume and degree
        for node in nodes_dict.values():
            vol = node["data"]["total_volume"]
            deg = node["data"]["degree"]
            node["data"]["size"] = min(45, 20 + deg * 3 + int(math.log10(max(10, vol))))

        return {
            "nodes": list(nodes_dict.values()),
            "edges": edges,
        }

    def get_timeline(
        self,
        table_name: Optional[str] = None,
        bucket: str = "hour",
    ) -> List[Dict[str, Any]]:
        """Return time-binned traffic volume and anomaly counts for scrubber."""
        tbl = table_name or self._discover_flow_table()
        if not tbl:
            return []

        try:
            query = f"""
                SELECT
                    SUBSTRING(timestamp, 1, 13) as time_bucket,
                    COUNT(*) as flow_count,
                    SUM(bytes_sent) as total_bytes,
                    COUNT(DISTINCT user_id) as active_users
                FROM {tbl}
                WHERE timestamp IS NOT NULL
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
            """
            df = self.storage.query(query)
            if df.empty:
                return []
            return df.to_dict(orient="records")
        except Exception:
            return []

    def get_entity_connections(self, entity_id: str, table_name: Optional[str] = None) -> Dict[str, Any]:
        """Deep dive into a single entity's connections and behavioral radar."""
        tbl = table_name or self._discover_flow_table()
        if not tbl:
            return {"entity_id": entity_id, "connections": [], "stats": {}}

        query = f"""
            SELECT
                dst_ip,
                dst_category,
                proto,
                COUNT(*) as flows,
                SUM(bytes_sent) as bytes_out,
                SUM(bytes_rev) as bytes_in,
                MIN(timestamp) as first_contact,
                MAX(timestamp) as last_contact
            FROM {tbl}
            WHERE (user_id = ? OR src_ip = ?)
            GROUP BY dst_ip, dst_category, proto
            ORDER BY bytes_out DESC
        """
        try:
            df = self.storage.query(query, (entity_id, entity_id))
            connections = df.to_dict(orient="records") if not df.empty else []
            total_bytes = sum(c["bytes_out"] for c in connections)
            unique_dests = len(set(c["dst_ip"] for c in connections))
            return {
                "entity_id": entity_id,
                "connections": connections,
                "stats": {
                    "total_outbound_bytes": total_bytes,
                    "unique_destinations": unique_dests,
                    "total_flows": sum(c["flows"] for c in connections),
                },
            }
        except Exception as e:
            return {"entity_id": entity_id, "error": str(e), "connections": []}
