"""VIGIL Sentinel — the autonomous security loop.

This is what makes VIGIL an *agent* and not just a tool server: it runs on its
own schedule, watches a list of wallets without being asked, decides which
findings are new, persists state across runs, and emits notifications.

Loop:  perceive (scan)  ->  decide (diff vs last state)  ->  act (store + notify)

State is kept in SQLite so the loop is stateful across restarts and only
surfaces genuinely new alerts (no repeat spam).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import time
from contextlib import closing
from typing import Any, Optional

import httpx

from vigil_mcp.monitors.wallet_monitor import WalletMonitor

logger = logging.getLogger("vigil-sentinel")

DEFAULT_DB = os.getenv(
    "VIGIL_SENTINEL_DB", os.path.join(os.path.expanduser("~"), ".vigil", "sentinel.db")
)


class SentinelStore:
    """SQLite-backed watchlist + alert-dedup state for the Sentinel loop."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or DEFAULT_DB
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.db_path)
        c.row_factory = sqlite3.Row
        return c

    def _init(self) -> None:
        with closing(self._conn()) as conn, conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS watchlist (
                    wallet     TEXT NOT NULL,
                    chain      TEXT NOT NULL,
                    label      TEXT,
                    added_at   INTEGER NOT NULL,
                    PRIMARY KEY (wallet, chain)
                )
                """
            )
            # seen_alerts dedups by a stable fingerprint of each alert.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS seen_alerts (
                    fingerprint TEXT PRIMARY KEY,
                    wallet      TEXT NOT NULL,
                    chain       TEXT NOT NULL,
                    severity    TEXT,
                    message     TEXT,
                    first_seen  INTEGER NOT NULL
                )
                """
            )

    # ── watchlist ────────────────────────────────────────────
    def add(self, wallet: str, chain: str, label: Optional[str] = None) -> dict[str, Any]:
        w, ch = wallet.lower(), chain.lower()
        with closing(self._conn()) as conn, conn:
            conn.execute(
                "INSERT OR REPLACE INTO watchlist (wallet, chain, label, added_at) "
                "VALUES (?, ?, ?, ?)",
                (w, ch, label, int(time.time())),
            )
        return {"wallet": w, "chain": ch, "label": label, "status": "watching"}

    def remove(self, wallet: str, chain: str) -> dict[str, Any]:
        w, ch = wallet.lower(), chain.lower()
        with closing(self._conn()) as conn, conn:
            cur = conn.execute(
                "DELETE FROM watchlist WHERE wallet = ? AND chain = ?", (w, ch)
            )
            removed = cur.rowcount
        return {"wallet": w, "chain": ch, "removed": removed > 0}

    def list(self) -> list[dict[str, Any]]:
        with closing(self._conn()) as conn:
            rows = conn.execute(
                "SELECT wallet, chain, label, added_at FROM watchlist ORDER BY added_at"
            ).fetchall()
        return [dict(r) for r in rows]

    # ── alert dedup ──────────────────────────────────────────
    @staticmethod
    def _fingerprint(wallet: str, chain: str, alert: dict) -> str:
        # Stable across runs: identity is wallet+chain+category+message+key detail.
        details = alert.get("details") or {}
        key = details.get("tx") or details.get("spender") or details.get("contract") or ""
        return f"{wallet}:{chain}:{alert.get('category')}:{alert.get('message')}:{key}"

    def filter_new(self, wallet: str, chain: str, alerts: list[dict]) -> list[dict]:
        """Return only alerts not seen before, and record them."""
        w, ch = wallet.lower(), chain.lower()
        fresh: list[dict] = []
        with closing(self._conn()) as conn, conn:
            for a in alerts:
                fp = self._fingerprint(w, ch, a)
                exists = conn.execute(
                    "SELECT 1 FROM seen_alerts WHERE fingerprint = ?", (fp,)
                ).fetchone()
                if exists:
                    continue
                conn.execute(
                    "INSERT OR IGNORE INTO seen_alerts "
                    "(fingerprint, wallet, chain, severity, message, first_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (fp, w, ch, a.get("severity"), a.get("message"), int(time.time())),
                )
                fresh.append(a)
        return fresh


async def _notify(payload: dict) -> None:
    """Send a notification via webhook AND/OR Telegram (both optional)."""
    # Webhook (legacy / custom integrations)
    url = os.getenv("VIGIL_SENTINEL_WEBHOOK", "")
    if url:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                await client.post(url, json=payload)
        except Exception as e:  # noqa: BLE001 — notification is best-effort
            logger.warning("Sentinel webhook failed: %s", e)

    # Telegram (user-facing alerts)
    from vigil_mcp.autonomous.telegram import is_configured, send_alert

    if is_configured():
        ok = await send_alert(payload)
        if not ok:
            logger.warning("Sentinel Telegram alert failed")


class Sentinel:
    """Autonomous monitoring loop over a wallet watchlist."""

    def __init__(self, store: Optional[SentinelStore] = None) -> None:
        self.store = store or SentinelStore()
        self.monitor = WalletMonitor()
        self.interval = int(os.getenv("VIGIL_SENTINEL_INTERVAL", "3600"))  # seconds
        self.lookback = int(os.getenv("VIGIL_SENTINEL_LOOKBACK_BLOCKS", "5000"))
        # Only alerts at or above this severity trigger a notification.
        self.min_severity = os.getenv("VIGIL_SENTINEL_MIN_SEVERITY", "high")

    _SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    async def run_once(self) -> dict[str, Any]:
        """Scan every watched wallet once and surface only new alerts."""
        targets = self.store.list()
        results = []
        threshold = self._SEV_ORDER.get(self.min_severity, 3)

        for t in targets:
            wallet, chain = t["wallet"], t["chain"]
            try:
                report = await self.monitor.monitor(wallet, chain, self.lookback)
                alerts = [a.model_dump() for a in report.alerts]
                new_alerts = self.store.filter_new(wallet, chain, alerts)
                notify_worthy = [
                    a for a in new_alerts
                    if self._SEV_ORDER.get(a.get("severity"), 0) >= threshold
                ]
                if notify_worthy:
                    await _notify(
                        {
                            "wallet": wallet,
                            "chain": chain,
                            "label": t.get("label"),
                            "new_alerts": notify_worthy,
                            "at": int(time.time()),
                        }
                    )
                results.append(
                    {
                        "wallet": wallet,
                        "chain": chain,
                        "new_alerts": len(new_alerts),
                        "notified": len(notify_worthy),
                    }
                )
                logger.info(
                    "Sentinel scanned %s (%s): %d new, %d notified",
                    wallet, chain, len(new_alerts), len(notify_worthy),
                )
            except Exception as e:  # noqa: BLE001 — one wallet shouldn't kill the loop
                logger.error("Sentinel scan failed for %s: %s", wallet, e)
                results.append({"wallet": wallet, "chain": chain, "error": str(e)})

        return {"scanned": len(targets), "results": results, "at": int(time.time())}

    async def run_forever(self) -> None:
        """Run the autonomous loop on a fixed interval."""
        logger.info("VIGIL Sentinel starting (interval=%ds)", self.interval)
        while True:
            try:
                summary = await self.run_once()
                logger.info("Sentinel cycle: %s", json.dumps(summary))
            except Exception as e:  # noqa: BLE001 — never let the loop die
                logger.error("Sentinel cycle error: %s", e)
            await asyncio.sleep(self.interval)


def main() -> None:
    logging.basicConfig(
        level=getattr(logging, os.getenv("VIGIL_LOG_LEVEL", "INFO")),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    asyncio.run(Sentinel().run_forever())


if __name__ == "__main__":
    main()
