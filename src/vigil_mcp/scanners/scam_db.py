"""Community scam database — local SQLite store for scam token reports.

Keyless and self-contained: reports are persisted to a local SQLite file so the
`report_scam` and `check_scam` tools work without any external API. The DB path
is configurable via VIGIL_SCAM_DB (defaults to a file next to the package data).
"""

import os
import sqlite3
import time
from contextlib import closing
from typing import Any, Optional

DEFAULT_DB_PATH = os.getenv("VIGIL_SCAM_DB", os.path.join(os.path.expanduser("~"), ".vigil", "scam_reports.db"))

VALID_EVIDENCE = {"honeypot", "rugpull", "phishing", "scam", "fake"}


class ScamDatabase:
    """Local SQLite-backed scam report store."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or DEFAULT_DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with closing(self._connect()) as conn, conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scam_reports (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    token         TEXT NOT NULL,
                    chain         TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    description   TEXT NOT NULL,
                    reporter      TEXT,
                    created_at    INTEGER NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_token_chain ON scam_reports(token, chain)")

    def report(
        self,
        token: str,
        evidence_type: str,
        description: str,
        chain: str,
        reporter: Optional[str] = None,
    ) -> dict[str, Any]:
        """Store a scam report. Returns the created report id and aggregate count."""
        evidence_type = evidence_type.lower().strip()
        if evidence_type not in VALID_EVIDENCE:
            raise ValueError(f"Invalid evidence_type '{evidence_type}'. Use: {', '.join(sorted(VALID_EVIDENCE))}")

        token_l = token.lower()
        chain_l = chain.lower()
        now = int(time.time())

        with closing(self._connect()) as conn, conn:
            cur = conn.execute(
                """
                INSERT INTO scam_reports
                    (token, chain, evidence_type, description, reporter, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (token_l, chain_l, evidence_type, description, reporter, now),
            )
            report_id = cur.lastrowid
            count = conn.execute(
                "SELECT COUNT(*) AS c FROM scam_reports WHERE token = ? AND chain = ?",
                (token_l, chain_l),
            ).fetchone()["c"]

        return {
            "token": token_l,
            "chain": chain_l,
            "evidence_type": evidence_type,
            "report_id": report_id,
            "status": "stored",
            "total_reports_for_token": count,
            "bounty": "50 $VIGIL (if verified by community consensus)",
        }

    def check(self, token: str, chain: str) -> dict[str, Any]:
        """Look up scam reports for a token. Returns count and report summaries."""
        token_l = token.lower()
        chain_l = chain.lower()

        with closing(self._connect()) as conn:
            rows = conn.execute(
                """
                SELECT evidence_type, description, reporter, created_at
                FROM scam_reports
                WHERE token = ? AND chain = ?
                ORDER BY created_at DESC
                """,
                (token_l, chain_l),
            ).fetchall()

        reports = [
            {
                "evidence_type": r["evidence_type"],
                "description": r["description"],
                "reporter": r["reporter"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]
        # Distinct evidence categories give a quick sense of how it's been flagged.
        evidence_types = sorted({r["evidence_type"] for r in reports})

        return {
            "token": token_l,
            "chain": chain_l,
            "reported": len(reports) > 0,
            "report_count": len(reports),
            "evidence_types": evidence_types,
            "reports": reports[:20],
        }
