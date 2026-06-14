"""Public scan feed — an anonymized, append-only log of VIGIL scans.

Powers vigil.codes/feed: a live view of what's being scanned and the verdict.
Privacy by design — we store ONLY the token address, tool, verdict, and time.
No wallet, no IP, no user identity. This is social proof + a public good:
"here's what VIGIL is catching on Base, in real time."
"""

from __future__ import annotations

import os
import sqlite3
import time
from contextlib import closing
from typing import Any, Optional

_DEFAULT_DB = os.getenv("VIGIL_FEED_DB", os.path.join(os.path.expanduser("~"), ".vigil", "feed.db"))

# Only these tools produce a feed-worthy verdict on a token.
_FEED_TOOLS = {
    "vigil_safety_score",
    "vigil_detect_honeypot",
    "vigil_scan_token",
    "vigil_consensus",
    "vigil_check_scam",
}


class FeedStore:
    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or _DEFAULT_DB
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with closing(sqlite3.connect(self.db_path)) as c, c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS feed (
                    id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    token    TEXT NOT NULL,
                    chain    TEXT NOT NULL,
                    tool     TEXT NOT NULL,
                    verdict  TEXT,
                    score    INTEGER,
                    at       INTEGER NOT NULL
                )
                """
            )

    def record(self, token: str, chain: str, tool: str, verdict: str = "", score: Optional[int] = None) -> None:
        try:
            with closing(sqlite3.connect(self.db_path)) as c, c:
                c.execute(
                    "INSERT INTO feed (token, chain, tool, verdict, score, at) VALUES (?,?,?,?,?,?)",
                    (token.lower(), chain, tool, verdict, score, int(time.time())),
                )
        except Exception:  # noqa: BLE001 — feed logging must never break a scan
            pass

    def recent(self, limit: int = 30) -> list[dict[str, Any]]:
        with closing(sqlite3.connect(self.db_path)) as c:
            rows = c.execute(
                "SELECT token, chain, tool, verdict, score, at FROM feed ORDER BY id DESC LIMIT ?",
                (min(limit, 100),),
            ).fetchall()
        return [{"token": r[0], "chain": r[1], "tool": r[2], "verdict": r[3], "score": r[4], "at": r[5]} for r in rows]

    def totals(self) -> dict[str, Any]:
        with closing(sqlite3.connect(self.db_path)) as c:
            total = c.execute("SELECT COUNT(*) FROM feed").fetchone()[0]
            flagged = c.execute(
                "SELECT COUNT(*) FROM feed WHERE verdict IN ('high','critical') OR verdict='honeypot'"
            ).fetchone()[0]
            day = c.execute("SELECT COUNT(*) FROM feed WHERE at > ?", (int(time.time()) - 86400,)).fetchone()[0]
            tokens = c.execute("SELECT COUNT(DISTINCT token) FROM feed").fetchone()[0]
        return {"total": total, "flagged": flagged, "last_24h": day, "unique_tokens": tokens}


def feed_worthy(tool: str) -> bool:
    return tool in _FEED_TOOLS


def extract_verdict(tool: str, result: dict) -> tuple[str, Optional[int]]:
    """Derive a compact (verdict, score) from a tool result for the feed."""
    if not isinstance(result, dict):
        return "", None
    if tool == "vigil_detect_honeypot":
        return ("honeypot" if result.get("is_honeypot") else "clear", None)
    if tool == "vigil_check_scam":
        return ("reported" if result.get("reported") else "clean", None)
    # safety_score / scan_token / consensus expose risk_level + score
    verdict = result.get("risk_level") or result.get("verdict") or ""
    score = result.get("score")
    return (verdict, score if isinstance(score, int) else None)
