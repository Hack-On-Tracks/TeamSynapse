"""Cross-table risk scoring and threat aggregation engine for CipherSentinel.

Aggregates behavioral telemetry and anomaly signals across multiple tables (network,
authentication, DNS, file/USB transfers) to compute entity-level composite risk scores,
confidence indices, MITRE ATT&CK tactic mappings, and prioritized investigation cases.
"""
from __future__ import annotations

import datetime
import math
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional
from ..storage.storage import DuckDBStorage


DEFAULT_WEIGHTS = {
    "volume": 0.30,
    "novelty": 0.25,
    "auth": 0.20,
    "dns": 0.15,
    "timing": 0.10,
}

MITRE_MAPPING = {
    "volume": {"technique": "T1048.003", "tactic": "Exfiltration", "name": "Exfiltration Over Unencrypted Protocol"},
    "novelty": {"technique": "T1071.001", "tactic": "Command and Control", "name": "Web Protocols / First-Seen Destination"},
    "auth": {"technique": "T1078.002", "tactic": "Initial Access", "name": "Valid Accounts: Domain Accounts"},
    "dns": {"technique": "T1071.004", "tactic": "Command and Control", "name": "DNS Tunneling / High Entropy Exfil"},
    "timing": {"technique": "T1029", "tactic": "Execution", "name": "Scheduled Transfer / Off-Hours Activity"},
}


def score_to_severity(score: float) -> str:
    """Map a 0-100 risk score to standard SOC severity."""
    if score >= 80.0:
        return "CRITICAL"
    elif score >= 60.0:
        return "HIGH"
    elif score >= 35.0:
        return "MEDIUM"
    return "LOW"


class CrossTableScoringEngine:
    """Orchestrates cross-table correlation and composite risk scoring."""

    def __init__(self, storage: Optional[DuckDBStorage] = None, weights: Optional[Dict[str, float]] = None):
        self.storage = storage or DuckDBStorage()
        self.weights = weights or DEFAULT_WEIGHTS
        self._ensure_tables()

    def _ensure_tables(self):
        """Ensure threat_scores and threat_cases tables exist in DuckDB."""
        self.storage.execute("""
            CREATE TABLE IF NOT EXISTS threat_scores (
                entity_id VARCHAR PRIMARY KEY,
                composite_score DOUBLE,
                severity VARCHAR,
                confidence DOUBLE,
                sub_volume DOUBLE,
                sub_novelty DOUBLE,
                sub_auth DOUBLE,
                sub_dns DOUBLE,
                sub_timing DOUBLE,
                mitre_tactics VARCHAR,
                primary_indicator VARCHAR,
                table_sources VARCHAR,
                updated_at TIMESTAMP
            );
        """)
        self.storage.execute("""
            CREATE TABLE IF NOT EXISTS threat_cases (
                case_id VARCHAR PRIMARY KEY,
                entity_id VARCHAR,
                priority_rank INTEGER,
                case_score DOUBLE,
                severity VARCHAR,
                confidence DOUBLE,
                status VARCHAR,
                title VARCHAR,
                description VARCHAR,
                evidence_summary VARCHAR,
                created_at TIMESTAMP
            );
        """)

    def _find_entity_col(self, columns: List[str]) -> Optional[str]:
        """Detect entity/user column across common telemetry schemas."""
        candidates = ["user_id", "entity_id", "username", "src_ip", "source_ip", "host_id", "account"]
        for c in candidates:
            if c in columns:
                return c
        return None

    def aggregate_tables(
        self,
        table_names: Optional[List[str]] = None,
        weights: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        """Aggregate signals across multiple DuckDB tables and compute composite risk scores.

        Args:
            table_names: List of table names to scan. If None, discovers available tables.
            weights: Optional custom weight overrides for signal categories.
        """
        w = weights or self.weights

        # Discover tables in DuckDB if not explicitly specified
        if not table_names:
            tables_df = self.storage.query("SHOW TABLES")
            if tables_df.empty:
                return {"entities_scored": 0, "cases_opened": 0, "results": []}
            candidate_names = tables_df["name"].tolist()
            # Exclude internal tables
            table_names = [t for t in candidate_names if t not in ["users", "audit_logs", "threat_scores", "threat_cases"]]

        if not table_names:
            return {"entities_scored": 0, "cases_opened": 0, "results": []}

        entity_signals: Dict[str, Dict[str, Any]] = {}

        for tbl in table_names:
            try:
                df = self.storage.query(f"SELECT * FROM {tbl}")
            except Exception:
                continue

            if df.empty:
                continue

            ent_col = self._find_entity_col(df.columns.tolist())
            if not ent_col:
                # If no explicit entity column, skip table
                continue

            # Process each row into entity signal bins
            cols = df.columns.tolist()
            for _, row in df.iterrows():
                entity_id = str(row[ent_col])
                if not entity_id or entity_id == "nan":
                    continue

                if entity_id not in entity_signals:
                    entity_signals[entity_id] = {
                        "entity_id": entity_id,
                        "tables": set(),
                        "volume_bytes": 0.0,
                        "event_count": 0,
                        "anomaly_flags": 0,
                        "anomaly_scores": [],
                        "is_new_dest": False,
                        "auth_failures": 0,
                        "dns_queries": 0,
                        "dns_entropy": 0.0,
                        "off_hours_count": 0,
                        "asset_tier": 1,
                        "allowlisted": False,
                    }

                rec = entity_signals[entity_id]
                rec["tables"].add(tbl)
                rec["event_count"] += 1

                # 1. Volume indicators
                for bcol in ["bytes", "out_bytes", "bytes_sent", "flow_size", "transfer_bytes"]:
                    if bcol in cols and pd.notna(row[bcol]):
                        try:
                            rec["volume_bytes"] += float(row[bcol])
                        except Exception:
                            pass

                # 2. Anomaly flags & scores from detectors
                if "anomaly_flag" in cols and pd.notna(row["anomaly_flag"]):
                    if int(row["anomaly_flag"]) == -1:
                        rec["anomaly_flags"] += 1
                if "anomaly_score" in cols and pd.notna(row["anomaly_score"]):
                    try:
                        rec["anomaly_scores"].append(float(row["anomaly_score"]))
                    except Exception:
                        pass

                # 3. Novelty / destination indicators
                if "is_new" in cols and bool(row["is_new"]):
                    rec["is_new_dest"] = True
                if "dst_category" in cols and str(row["dst_category"]).lower() in ["rare", "unseen", "multiple"]:
                    rec["is_new_dest"] = True

                # 4. Auth failures
                if "failed_logins" in cols and pd.notna(row["failed_logins"]):
                    rec["auth_failures"] += int(row["failed_logins"])
                elif "auth_status" in cols and str(row["auth_status"]).upper() in ["FAIL", "FAILED", "FAILURE"]:
                    rec["auth_failures"] += 1

                # 5. DNS metrics
                if "dns_queries" in cols and pd.notna(row["dns_queries"]):
                    rec["dns_queries"] += int(row["dns_queries"])
                if "dns_entropy" in cols and pd.notna(row["dns_entropy"]):
                    rec["dns_entropy"] = max(rec["dns_entropy"], float(row["dns_entropy"]))

                # 6. Off hours
                if "timestamp" in cols and pd.notna(row["timestamp"]):
                    try:
                        dt = pd.to_datetime(row["timestamp"])
                        if dt.hour < 7 or dt.hour > 19 or dt.dayofweek >= 5:
                            rec["off_hours_count"] += 1
                    except Exception:
                        pass
                elif "hour" in cols and pd.notna(row["hour"]):
                    h = int(row["hour"])
                    if h < 7 or h > 19:
                        rec["off_hours_count"] += 1

                # 7. Asset context
                if "asset_tier" in cols and pd.notna(row["asset_tier"]):
                    try:
                        rec["asset_tier"] = max(rec["asset_tier"], int(row["asset_tier"]))
                    except Exception:
                        pass
                if "allowlisted" in cols and bool(row["allowlisted"]):
                    rec["allowlisted"] = True

        scored_entities = []
        cases_to_insert = []
        now = datetime.datetime.now(datetime.timezone.utc)

        for entity_id, sig in entity_signals.items():
            # Calculate subscores in [0.0, 1.0]
            # Volume subscore: logistic scale on transfer bytes
            v_bytes = sig["volume_bytes"]
            sub_vol = min(1.0, 1.0 / (1.0 + math.exp(-0.000002 * (v_bytes - 1_000_000)))) if v_bytes > 0 else 0.0

            # Novelty subscore
            sub_nov = 0.8 if sig["is_new_dest"] else 0.1
            if sig["anomaly_flags"] > 0:
                sub_nov = min(1.0, sub_nov + 0.15 * min(sig["anomaly_flags"], 3))

            # Auth subscore
            sub_auth = min(1.0, sig["auth_failures"] * 0.25)

            # DNS subscore
            sub_dns = 0.0
            if sig["dns_entropy"] > 3.8:
                sub_dns = min(1.0, 0.4 + (sig["dns_entropy"] - 3.8) * 0.4)
            if sig["dns_queries"] > 500:
                sub_dns = min(1.0, sub_dns + 0.3)

            # Timing subscore
            timing_ratio = sig["off_hours_count"] / max(sig["event_count"], 1)
            sub_timing = min(1.0, timing_ratio * 1.5)

            # Context multiplier
            context_mult = 1.0
            if sig["allowlisted"]:
                context_mult *= 0.35  # dampened for sanctioned operations
            if sig["asset_tier"] == 3:
                context_mult *= 1.30  # critical infrastructure multiplier
            elif sig["asset_tier"] == 2:
                context_mult *= 1.15

            # Weighted sum
            weighted_sum = (
                w["volume"] * sub_vol
                + w["novelty"] * sub_nov
                + w["auth"] * sub_auth
                + w["dns"] * sub_dns
                + w["timing"] * sub_timing
            )

            # Composite Score (0 - 100)
            composite_score = float(np.clip(weighted_sum * 100.0 * context_mult, 0.0, 100.0))

            # Confidence Index (0.0 to 1.0)
            # Higher confidence if multi-table telemetry exists and substantial events observed
            table_count = len(sig["tables"])
            confidence = min(1.0, 0.4 + 0.25 * min(table_count, 3) + 0.15 * min(sig["event_count"] / 20.0, 1.0))

            severity = score_to_severity(composite_score)

            # Determine primary indicator & MITRE tactics
            sub_scores_map = {
                "volume": sub_vol,
                "novelty": sub_nov,
                "auth": sub_auth,
                "dns": sub_dns,
                "timing": sub_timing,
            }
            primary_key = max(sub_scores_map, key=sub_scores_map.get)
            mitre_info = MITRE_MAPPING.get(primary_key, {"technique": "T1078", "tactic": "Defense Evasion"})

            tables_str = ",".join(sorted(list(sig["tables"])))

            record = {
                "entity_id": entity_id,
                "composite_score": round(composite_score, 2),
                "severity": severity,
                "confidence": round(confidence, 2),
                "sub_volume": round(sub_vol, 3),
                "sub_novelty": round(sub_nov, 3),
                "sub_auth": round(sub_auth, 3),
                "sub_dns": round(sub_dns, 3),
                "sub_timing": round(sub_timing, 3),
                "mitre_tactics": f"{mitre_info['technique']} - {mitre_info['tactic']}",
                "primary_indicator": f"{primary_key.capitalize()} anomaly ({mitre_info['name']})",
                "table_sources": tables_str,
                "updated_at": now,
            }
            scored_entities.append(record)

        # Sort by composite score descending to assign priority ranks
        scored_entities.sort(key=lambda x: x["composite_score"], reverse=True)

        # Save to threat_scores in DuckDB
        if scored_entities:
            scores_df = pd.DataFrame(scored_entities)
            self.storage.insert_dataframe(scores_df, "threat_scores")

            # Open cases for entities with score >= 35 (MEDIUM, HIGH, CRITICAL)
            case_records = []
            for rank, item in enumerate(scored_entities, start=1):
                if item["composite_score"] >= 35.0:
                    case_id = f"CASE-{item['entity_id']}-{now.strftime('%Y%m%d')}"
                    case_records.append({
                        "case_id": case_id,
                        "entity_id": item["entity_id"],
                        "priority_rank": rank,
                        "case_score": item["composite_score"],
                        "severity": item["severity"],
                        "confidence": item["confidence"],
                        "status": "OPEN",
                        "title": f"Suspicious Activity Detected for {item['entity_id']}",
                        "description": f"Entity scored {item['composite_score']}/100 based on {item['primary_indicator']}. Sources: {item['table_sources']}.",
                        "evidence_summary": f"Volume={item['sub_volume']}, Novelty={item['sub_novelty']}, Auth={item['sub_auth']}, DNS={item['sub_dns']}",
                        "created_at": now,
                    })

            if case_records:
                cases_df = pd.DataFrame(case_records)
                self.storage.insert_dataframe(cases_df, "threat_cases")

        return {
            "entities_scored": len(scored_entities),
            "cases_opened": len([e for e in scored_entities if e["composite_score"] >= 35.0]),
            "results": scored_entities[:20],
        }

    def get_threat_scores(
        self,
        min_score: float = 0.0,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query aggregated threat scores with optional filtering."""
        query = "SELECT * FROM threat_scores WHERE composite_score >= ?"
        params = [float(min_score)]
        if severity and severity.upper() != "ALL":
            query += " AND severity = ?"
            params.append(severity.upper())
        query += f" ORDER BY composite_score DESC LIMIT {int(limit)}"

        try:
            df = self.storage.query(query, tuple(params))
            return df.to_dict(orient="records")
        except Exception:
            return []

    def get_cases(self, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Query threat cases for SOC triage."""
        query = "SELECT * FROM threat_cases"
        params = []
        if status and status.upper() != "ALL":
            query += " WHERE status = ?"
            params.append(status.upper())
        query += f" ORDER BY priority_rank ASC LIMIT {int(limit)}"

        try:
            df = self.storage.query(query, tuple(params) if params else None)
            return df.to_dict(orient="records")
        except Exception:
            return []

    def get_entity_detail(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve complete scoring and case history for a specific entity."""
        try:
            scores_df = self.storage.query("SELECT * FROM threat_scores WHERE entity_id = ?", (entity_id,))
            if scores_df.empty:
                return None
            cases_df = self.storage.query("SELECT * FROM threat_cases WHERE entity_id = ? ORDER BY created_at DESC", (entity_id,))
            record = scores_df.iloc[0].to_dict()
            record["cases"] = cases_df.to_dict(orient="records") if not cases_df.empty else []
            return record
        except Exception:
            return None
