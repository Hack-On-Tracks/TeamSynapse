"""Repository: all application reads/writes go through here (parameterised SQL only)."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pandas as pd

from storage.database import append_audit, now_iso


class Repo:
    def __init__(self, con: sqlite3.Connection):
        self.con = con

    # ------------------------------------------------------------------ cases
    def save_cases(self, bundles: dict[str, dict], queue: pd.DataFrame, meta: dict) -> None:
        c = self.con
        existing = {r["case_id"]: (r["disposition"], r["created_at"]) for r in c.execute("SELECT case_id, disposition, created_at FROM cases")}
        c.execute("DELETE FROM queue")
        for cid, b in bundles.items():
            disp, created = existing.get(cid, ("new", now_iso()))
            b["disposition"]["status"] = disp
            c.execute("INSERT OR REPLACE INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (cid, b["user_id"], b["destination"]["dst_id"], b["peer_group"], b["opened_day"], b["last_day"], b["status"],
                       b["tier"], b["peak_tier"], b["risk"]["current_score"], b["risk"]["peak_score"], b["confidence"]["score"],
                       b["confidence"]["level"], disp, json.dumps(b), created, now_iso()))
        if len(queue):
            c.executemany("INSERT INTO queue VALUES (?,?,?,?,?)",
                          [(int(r.day), int(r.rank), r.case_id, float(r.case_score), int(r.priority)) for r in queue.itertuples()])
        for k, v in meta.items():
            c.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (k, json.dumps(v, default=str)))
        c.commit()

    def get_meta(self, key: str, default=None):
        r = self.con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(r["value"]) if r else default

    def list_cases(self, page=1, page_size=50, min_score=None, tier=None, status=None, peer_group=None,
                   confidence_level=None, destination=None, sort="peak_score", day=None, disposition=None):
        q, args = "SELECT case_id,user_id,dst_id,peer_group,opened_day,last_day,status,tier,peak_tier,case_score,peak_score,confidence,confidence_level,disposition FROM cases WHERE 1=1", []
        for col, val in (("tier", tier), ("status", status), ("peer_group", peer_group), ("confidence_level", confidence_level),
                         ("dst_id", destination), ("disposition", disposition)):
            if val:
                q += f" AND {col}=?"; args.append(val)
        if min_score is not None:
            q += " AND peak_score>=?"; args.append(min_score)
        if day is not None:
            q += " AND case_id IN (SELECT case_id FROM queue WHERE day=?)"; args.append(day)
        total = self.con.execute(f"SELECT count(*) FROM ({q})", args).fetchone()[0]
        order = {"peak_score": "peak_score DESC", "opened_day": "opened_day DESC", "case_score": "case_score DESC"}.get(sort, "peak_score DESC")
        q += f" ORDER BY {order} LIMIT ? OFFSET ?"
        args += [page_size, (page - 1) * page_size]
        return total, [dict(r) for r in self.con.execute(q, args)]

    def get_case(self, case_id: str) -> dict | None:
        r = self.con.execute("SELECT bundle_json, disposition FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if not r:
            return None
        b = json.loads(r["bundle_json"])
        b["disposition"] = {"status": r["disposition"], "feedback": self.feedback_for(case_id)}
        return b

    def all_bundles(self) -> list[dict]:
        return [json.loads(r["bundle_json"]) for r in self.con.execute("SELECT bundle_json FROM cases")]

    def queue_for_day(self, day: int, limit: int | None = None) -> list[dict]:
        q = ("SELECT q.rank,q.case_score,q.priority,c.* FROM queue q JOIN cases c USING(case_id) WHERE q.day=? ORDER BY q.rank")
        rows = [dict(r) for r in self.con.execute(q, (day,))]
        for r in rows:
            r.pop("bundle_json", None)
        return rows[:limit] if limit else rows

    def queue_days(self) -> list[int]:
        return [r[0] for r in self.con.execute("SELECT DISTINCT day FROM queue ORDER BY day")]

    # --------------------------------------------------------------- feedback
    def add_feedback(self, case_id: str, analyst: str, disposition: str, note: str) -> int:
        cur = self.con.execute("INSERT INTO feedback(case_id,analyst,disposition,note,ts) VALUES (?,?,?,?,?)",
                               (case_id, analyst, disposition, note, now_iso()))
        self.con.execute("UPDATE cases SET disposition=? WHERE case_id=?", (disposition, case_id))
        self.con.commit()
        return cur.lastrowid

    def feedback_for(self, case_id: str) -> list[dict]:
        return [dict(r) for r in self.con.execute("SELECT * FROM feedback WHERE case_id=? ORDER BY id", (case_id,))]

    # ---------------------------------------------------------------- reveals
    def create_reveal(self, case_id: str, pseudonym: str, requester: str, reason: str) -> int:
        cur = self.con.execute("INSERT INTO reveal_requests(case_id,pseudonym,requester,reason,status,requested_at) VALUES (?,?,?,?,?,?)",
                               (case_id, pseudonym, requester, reason, "pending", now_iso()))
        self.con.commit()
        return cur.lastrowid

    def get_reveal(self, rid: int) -> dict | None:
        r = self.con.execute("SELECT * FROM reveal_requests WHERE id=?", (rid,)).fetchone()
        return dict(r) if r else None

    def decide_reveal(self, rid: int, approver: str, approve: bool, note: str) -> None:
        self.con.execute("UPDATE reveal_requests SET status=?,approver=?,decision_note=?,decided_at=? WHERE id=?",
                         ("approved" if approve else "rejected", approver, note, now_iso(), rid))
        self.con.commit()

    def list_reveals(self) -> list[dict]:
        return [dict(r) for r in self.con.execute("SELECT * FROM reveal_requests ORDER BY id DESC")]

    # ---------------------------------------------------------------- policies
    def add_policy(self, kind: str, value: str, who: str) -> int:
        cur = self.con.execute("INSERT INTO policy_entries(kind,value,added_by,ts) VALUES (?,?,?,?)", (kind, value, who, now_iso()))
        self.con.commit()
        return cur.lastrowid

    def list_policies(self) -> list[dict]:
        return [dict(r) for r in self.con.execute("SELECT * FROM policy_entries WHERE active=1 ORDER BY id")]

    # ------------------------------------------------------------------- audit
    def audit(self, actor: str, role: str, action: str, resource: str = "", detail=None) -> int:
        return append_audit(self.con, actor, role, action, resource, detail)

    def list_audit(self, page=1, page_size=100, action=None, actor=None):
        q, args = "SELECT * FROM audit_events WHERE 1=1", []
        if action:
            q += " AND action=?"; args.append(action)
        if actor:
            q += " AND actor=?"; args.append(actor)
        total = self.con.execute(f"SELECT count(*) FROM ({q})", args).fetchone()[0]
        q += " ORDER BY id DESC LIMIT ? OFFSET ?"; args += [page_size, (page - 1) * page_size]
        return total, [dict(r) for r in self.con.execute(q, args)]

    # --------------------------------------------------------------- retention
    def apply_retention(self, cases_days: int, now: datetime | None = None) -> dict:
        """Delete cases/feedback older than the retention window. The audit log is append-only and
        is retained (archive/rotate externally)."""
        cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=cases_days)).isoformat(timespec="seconds")
        old = [r[0] for r in self.con.execute("SELECT case_id FROM cases WHERE created_at < ?", (cutoff,))]
        for cid in old:
            self.con.execute("DELETE FROM feedback WHERE case_id=?", (cid,))
            self.con.execute("DELETE FROM queue WHERE case_id=?", (cid,))
            self.con.execute("DELETE FROM cases WHERE case_id=?", (cid,))
        self.con.commit()
        return {"deleted_cases": len(old), "cutoff": cutoff}
