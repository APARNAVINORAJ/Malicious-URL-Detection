"""
database.py — SQLite persistence for scan history and dashboard stats.
"""
import json
import os
import sqlite3
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                url              TEXT    NOT NULL,
                is_safe          INTEGER NOT NULL,
                safe_probability REAL    NOT NULL,
                rule_triggered   TEXT,
                features         TEXT,
                scanned_at       TEXT    NOT NULL
            )
        """)
        conn.commit()


def save_scan(url, is_safe, safe_probability, rule_triggered=None, features=None):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """INSERT INTO scans
               (url, is_safe, safe_probability, rule_triggered, features, scanned_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                url,
                1 if is_safe else 0,
                safe_probability,
                rule_triggered,
                json.dumps(features) if features else None,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        conn.commit()


def get_recent_scans(limit=100):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY scanned_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats():
    with sqlite3.connect(DB_PATH) as conn:
        total    = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        safe     = conn.execute("SELECT COUNT(*) FROM scans WHERE is_safe=1").fetchone()[0]
        malicious = conn.execute("SELECT COUNT(*) FROM scans WHERE is_safe=0").fetchone()[0]

        # Scans per day for the last 7 days
        daily = []
        for i in range(6, -1, -1):
            day = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
            count = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE scanned_at LIKE ?", (day + "%",)
            ).fetchone()[0]
            daily.append({"date": day, "count": count})

        # Top triggered rules
        rules = conn.execute(
            """SELECT rule_triggered, COUNT(*) as cnt
               FROM scans WHERE rule_triggered IS NOT NULL
               GROUP BY rule_triggered ORDER BY cnt DESC LIMIT 5"""
        ).fetchall()

    return {
        "total": total,
        "safe": safe,
        "malicious": malicious,
        "daily": daily,
        "top_rules": [{"rule": r[0], "count": r[1]} for r in rules],
    }
