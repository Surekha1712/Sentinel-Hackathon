from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Iterable, Optional


SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  repo_full_name TEXT NOT NULL,
  pr_number INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  comment_id INTEGER,
  findings_json TEXT,
  UNIQUE(repo_full_name, pr_number)
);

CREATE TABLE IF NOT EXISTS style_rules (
  rule TEXT PRIMARY KEY,
  accepted_count INTEGER NOT NULL DEFAULT 0,
  rejected_count INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

-- Feature 4: Toil Reduction Metrics Table
CREATE TABLE IF NOT EXISTS metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at INTEGER NOT NULL,
  metric_type TEXT NOT NULL,
  metric_value INTEGER NOT NULL DEFAULT 0,
  repo_full_name TEXT,
  pr_number INTEGER
);

-- Index for efficient metric queries
CREATE INDEX IF NOT EXISTS idx_metrics_type ON metrics(metric_type);
CREATE INDEX IF NOT EXISTS idx_metrics_created ON metrics(created_at);
"""


@dataclass(frozen=True)
class ReviewRecord:
    repo_full_name: str
    pr_number: int
    comment_id: Optional[int]
    findings: dict


@dataclass(frozen=True)
class ReviewListItem:
    repo_full_name: str
    pr_number: int
    created_at: int
    comment_id: Optional[int]
    findings: dict[str, Any]


@dataclass(frozen=True)
class StyleRuleRow:
    rule: str
    accepted_count: int
    rejected_count: int
    updated_at: int


def init_db(db_path: str) -> None:
    with sqlite3.connect(db_path) as con:
        con.executescript(SCHEMA)


def upsert_review(db_path: str, repo_full_name: str, pr_number: int, comment_id: Optional[int], findings: dict) -> None:
    now = int(time.time())
    with sqlite3.connect(db_path) as con:
        con.executescript(SCHEMA)
        con.execute(
            """
            INSERT INTO reviews (repo_full_name, pr_number, created_at, comment_id, findings_json)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(repo_full_name, pr_number)
            DO UPDATE SET
              created_at=excluded.created_at,
              comment_id=excluded.comment_id,
              findings_json=excluded.findings_json
            """,
            (repo_full_name, pr_number, now, comment_id, json.dumps(findings)),
        )


def get_review(db_path: str, repo_full_name: str, pr_number: int) -> Optional[ReviewRecord]:
    with sqlite3.connect(db_path) as con:
        con.executescript(SCHEMA)
        row = con.execute(
            "SELECT comment_id, findings_json FROM reviews WHERE repo_full_name=? AND pr_number=?",
            (repo_full_name, pr_number),
        ).fetchone()
    if not row:
        return None
    comment_id, findings_json = row
    findings = {}
    if findings_json:
        try:
            findings = json.loads(findings_json)
        except Exception:
            findings = {}
    return ReviewRecord(repo_full_name=repo_full_name, pr_number=pr_number, comment_id=comment_id, findings=findings)


def apply_style_feedback(db_path: str, accepted_rules: Iterable[str] = (), rejected_rules: Iterable[str] = ()) -> None:
    now = int(time.time())
    with sqlite3.connect(db_path) as con:
        con.executescript(SCHEMA)
        for r in accepted_rules:
            con.execute(
                """
                INSERT INTO style_rules(rule, accepted_count, rejected_count, updated_at)
                VALUES(?, 1, 0, ?)
                ON CONFLICT(rule) DO UPDATE SET accepted_count=accepted_count+1, updated_at=excluded.updated_at
                """,
                (r.strip(), now),
            )
        for r in rejected_rules:
            con.execute(
                """
                INSERT INTO style_rules(rule, accepted_count, rejected_count, updated_at)
                VALUES(?, 0, 1, ?)
                ON CONFLICT(rule) DO UPDATE SET rejected_count=rejected_count+1, updated_at=excluded.updated_at
                """,
                (r.strip(), now),
            )


def get_style_notes(db_path: str, limit: int = 12) -> list[str]:
    with sqlite3.connect(db_path) as con:
        con.executescript(SCHEMA)
        rows = con.execute(
            """
            SELECT rule, accepted_count, rejected_count
            FROM style_rules
            ORDER BY (accepted_count - rejected_count) DESC, accepted_count DESC, updated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    notes: list[str] = []
    for rule, a, r in rows:
        if not rule:
            continue
        score = int(a) - int(r)
        notes.append(f"{rule} (score {score})")
    return notes


def list_recent_reviews(db_path: str, repo_full_name: str, limit: int = 50) -> list[ReviewListItem]:
    with sqlite3.connect(db_path) as con:
        con.executescript(SCHEMA)
        rows = con.execute(
            """
            SELECT pr_number, created_at, comment_id, findings_json
            FROM reviews
            WHERE repo_full_name=?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (repo_full_name, limit),
        ).fetchall()
    out: list[ReviewListItem] = []
    for pr_number, created_at, comment_id, findings_json in rows:
        findings: dict[str, Any] = {}
        if findings_json:
            try:
                findings = json.loads(findings_json)
            except Exception:
                findings = {}
        out.append(
            ReviewListItem(
                repo_full_name=repo_full_name,
                pr_number=int(pr_number),
                created_at=int(created_at),
                comment_id=comment_id,
                findings=findings,
            )
        )
    return out


def list_style_rules(db_path: str, limit: int = 50) -> list[StyleRuleRow]:
    with sqlite3.connect(db_path) as con:
        con.executescript(SCHEMA)
        rows = con.execute(
            """
            SELECT rule, accepted_count, rejected_count, updated_at
            FROM style_rules
            ORDER BY (accepted_count - rejected_count) DESC, accepted_count DESC, updated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [
        StyleRuleRow(
            rule=str(rule),
            accepted_count=int(accepted_count),
            rejected_count=int(rejected_count),
            updated_at=int(updated_at),
        )
        for rule, accepted_count, rejected_count, updated_at in rows
    ]


# Feature 4: Toil Reduction Metrics Functions

def record_metric(
    db_path: str,
    metric_type: str,
    metric_value: int = 1,
    repo_full_name: Optional[str] = None,
    pr_number: Optional[int] = None,
) -> None:
    """Record a metric for toil reduction tracking."""
    now = int(time.time())
    with sqlite3.connect(db_path) as con:
        con.execute(
            """
            INSERT INTO metrics (created_at, metric_type, metric_value, repo_full_name, pr_number)
            VALUES (?, ?, ?, ?, ?)
            """,
            (now, metric_type, metric_value, repo_full_name, pr_number),
        )


def get_metrics_summary(db_path: str, days: int = 30) -> dict[str, Any]:
    """Get summary of all metrics for the specified number of days."""
    import datetime
    cutoff = int((datetime.datetime.now() - datetime.timedelta(days=days)).timestamp())
    
    with sqlite3.connect(db_path) as con:
        # Get metrics from metrics table (toil reduction)
        metric_rows = con.execute(
            """
            SELECT metric_type, SUM(metric_value) as total
            FROM metrics
            WHERE created_at >= ?
            GROUP BY metric_type
            """,
            (cutoff,),
        ).fetchall()
        
        # Get severity counts from reviews table
        review_rows = con.execute(
            """
            SELECT findings_json FROM reviews WHERE created_at >= ?
            """,
            (cutoff,),
        ).fetchall()
    
    result = {
        "period_days": days,
        "reviews_completed": 0,
        "lines_reviewed": 0,
        "suggestions_accepted": 0,
        "security_issues_found": 0,
        "estimated_time_saved_minutes": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
    }
    
    # Process metrics table
    for metric_type, total in metric_rows:
        if metric_type == "review_completed":
            result["reviews_completed"] = int(total or 0)
        elif metric_type == "lines_reviewed":
            result["lines_reviewed"] = int(total or 0)
        elif metric_type == "suggestion_accepted":
            result["suggestions_accepted"] = int(total or 0)
        elif metric_type == "security_issue_found":
            result["security_issues_found"] = int(total or 0)
        elif metric_type == "time_saved_minutes":
            result["estimated_time_saved_minutes"] = int(total or 0)
    
    # Process reviews table for severity counts
    critical = 0
    high = 0
    medium = 0
    low = 0
    total_lines = 0
    total_findings = 0
    
    for (findings_json,) in review_rows:
        if findings_json:
            try:
                data = json.loads(findings_json)
                findings = data.get("findings", [])
                diff_meta = data.get("diff_meta", {})
                total_lines += diff_meta.get("total_lines", 0)
                total_findings += len(findings)
                
                for f in findings:
                    sev = (f.get("severity") or "").lower()
                    if sev == "critical":
                        critical += 1
                    elif sev == "high":
                        high += 1
                    elif sev == "medium":
                        medium += 1
                    elif sev == "low":
                        low += 1
            except Exception:
                pass
    
    # Update counts from reviews table
    result["reviews_completed"] = max(result["reviews_completed"], len(review_rows))
    result["lines_reviewed"] = max(result["lines_reviewed"], total_lines)
    result["security_issues_found"] = max(result["security_issues_found"], total_findings)
    result["critical_count"] = critical
    result["high_count"] = high
    result["medium_count"] = medium
    result["low_count"] = low
    
    # Calculate derived values
    if result["reviews_completed"] > 0:
        result["avg_lines_per_review"] = result["lines_reviewed"] // max(1, result["reviews_completed"])
    else:
        result["avg_lines_per_review"] = 0
    
    # Estimate time saved (5 min per review + 1 min per 100 lines)
    result["estimated_time_saved_minutes"] = (result["reviews_completed"] * 5) + (result["lines_reviewed"] // 100)
    
    # Calculate average security score (inverse of issues found)
    if result["reviews_completed"] > 0:
        avg_issues = total_findings / result["reviews_completed"]
        result["avg_security_score"] = max(0, min(100, 100 - (avg_issues * 10)))
    else:
        result["avg_security_score"] = 100
    
    return result
