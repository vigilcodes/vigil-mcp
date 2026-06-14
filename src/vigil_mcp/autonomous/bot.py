"""VIGIL Telegram bot — scan tokens straight from a chat.

A long-polling bot that lets anyone run VIGIL scans where traders already hang
out. Reuses the in-process scanners (no HTTP round-trip), so it stays keyless
and fast.

Commands:
  /start, /help            — usage
  /scan <0x...>            — full read: safety score + honeypot + scam check
  /honeypot <0x...>        — honeypot-only check
  /score <0x...>           — safety score only

Run:
  VIGIL_TELEGRAM_BOT_TOKEN=... python3 -m vigil_mcp.autonomous.bot

The same bot token used for Sentinel alerts works here. The bot only responds
to commands; it never sends unsolicited messages.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sqlite3
import time
from contextlib import closing
from typing import Any, Optional

import httpx

from vigil_mcp.scanners.honeypot import HoneypotDetector
from vigil_mcp.scanners.safety_score import SafetyScorer
from vigil_mcp.scanners.scam_db import ScamDatabase

logger = logging.getLogger("vigil-bot")

TELEGRAM_API = "https://api.telegram.org"
_ADDR_RE = re.compile(r"0[xX][0-9a-fA-F]{40}")

_DEFAULT_DB = os.path.join(os.path.expanduser("~"), ".vigil", "bot_usage.db")

_RISK_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "safe": "✅",
}


class UsageStore:
    """SQLite-backed usage log so we can measure bot adoption.

    Records one row per command (chat id, command, target address, verdict).
    Used for /stats and to know whether the bot is actually being used.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or _DEFAULT_DB
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with closing(sqlite3.connect(self.db_path)) as c, c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS usage (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id   INTEGER,
                    command   TEXT,
                    target    TEXT,
                    verdict   TEXT,
                    at        INTEGER NOT NULL
                )
                """
            )

    def log(self, chat_id: int, command: str, target: str = "", verdict: str = "") -> None:
        try:
            with closing(sqlite3.connect(self.db_path)) as c, c:
                c.execute(
                    "INSERT INTO usage (chat_id, command, target, verdict, at) VALUES (?,?,?,?,?)",
                    (chat_id, command, target, verdict, int(time.time())),
                )
        except Exception as e:  # noqa: BLE001 — logging must never break the bot
            logger.warning("usage log failed: %s", e)

    def stats(self) -> dict[str, Any]:
        with closing(sqlite3.connect(self.db_path)) as c:
            total = c.execute("SELECT COUNT(*) FROM usage WHERE target != ''").fetchone()[0]
            users = c.execute("SELECT COUNT(DISTINCT chat_id) FROM usage").fetchone()[0]
            day = c.execute("SELECT COUNT(*) FROM usage WHERE at > ?", (int(time.time()) - 86400,)).fetchone()[0]
            top = c.execute(
                "SELECT target, COUNT(*) n FROM usage WHERE target != '' GROUP BY target ORDER BY n DESC LIMIT 5"
            ).fetchall()
        return {"total_scans": total, "unique_users": users, "scans_24h": day, "top": top}


class VigilBot:
    def __init__(self) -> None:
        self.token = os.getenv("VIGIL_TELEGRAM_BOT_TOKEN", "")
        self.admin_chat = os.getenv("VIGIL_TELEGRAM_CHAT_ID", "")
        self.scorer = SafetyScorer()
        self.honeypot = HoneypotDetector()
        self.scam_db = ScamDatabase()
        self.usage = UsageStore()
        self.offset = 0

    # ── telegram io ──────────────────────────────────────────
    async def _send(self, client: httpx.AsyncClient, chat_id: int, text: str) -> None:
        try:
            await client.post(
                f"{TELEGRAM_API}/bot{self.token}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                },
            )
        except Exception as e:  # noqa: BLE001 — best effort
            logger.warning("send failed: %s", e)

    # ── address parsing ──────────────────────────────────────
    @staticmethod
    def _extract_addr(text: str) -> Optional[str]:
        m = _ADDR_RE.search(text or "")
        return m.group(0).lower() if m else None

    # ── command handlers ─────────────────────────────────────
    async def _cmd_help(self, client: httpx.AsyncClient, chat_id: int) -> None:
        await self._send(
            client,
            chat_id,
            "🛡️ <b>VIGIL</b> — onchain security scanner for Base\n\n"
            "<b>Commands</b>\n"
            "/scan <code>&lt;0x token&gt;</code> — safety score + honeypot + scam check\n"
            "/honeypot <code>&lt;0x token&gt;</code> — honeypot only\n"
            "/score <code>&lt;0x token&gt;</code> — safety score only\n\n"
            "No API key needed. Try it in your browser too: vigil.codes/scan",
        )

    async def _cmd_scan(self, client: httpx.AsyncClient, chat_id: int, addr: str) -> None:
        try:
            score = await self.scorer.score(addr, "base")
            hp = await self.honeypot.detect(addr, "base")
            scam = self.scam_db.check(addr, "base")
        except Exception as e:  # noqa: BLE001
            await self._send(client, chat_id, f"⚠️ Scan failed: {e}")
            return

        name = hp.token_name
        sym = hp.token_symbol
        if name and sym:
            ident = f" <b>{name}</b> (${sym})"
        elif sym:
            ident = f" <b>${sym}</b>"
        elif name:
            ident = f" <b>{name}</b>"
        else:
            ident = ""
        icon = _RISK_ICON.get(score.risk_level, "❓")
        hp_txt = "🔴 HONEYPOT" if hp.is_honeypot else "✅ not a honeypot"
        scam_txt = f"🔴 {scam.get('report_count', 0)} report(s)" if scam.get("reported") else "✅ none"
        buy = "—" if hp.buy_tax is None else f"{hp.buy_tax * 100:.0f}%"
        sell = "—" if hp.sell_tax is None else f"{hp.sell_tax * 100:.0f}%"

        msg = (
            f"🛡️ <b>VIGIL scan</b>{ident}\n"
            f"<code>{addr}</code> · base\n\n"
            f"{icon} <b>{score.score}/100</b> — {score.risk_level.upper()}\n"
            f"Honeypot: {hp_txt}\n"
            f"Buy/Sell tax: {buy} / {sell}\n"
            f"Scam reports: {scam_txt}\n\n"
            f"🔗 vigil.codes/scan"
        )
        await self._send(client, chat_id, msg)

    async def _cmd_honeypot(self, client: httpx.AsyncClient, chat_id: int, addr: str) -> None:
        try:
            hp = await self.honeypot.detect(addr, "base")
        except Exception as e:  # noqa: BLE001
            await self._send(client, chat_id, f"⚠️ Check failed: {e}")
            return
        name = hp.token_name
        sym = hp.token_symbol
        if name and sym:
            ident = f" <b>{name}</b> (${sym})"
        elif sym:
            ident = f" <b>${sym}</b>"
        elif name:
            ident = f" <b>{name}</b>"
        else:
            ident = ""
        verdict = "🔴 HONEYPOT — cannot sell" if hp.is_honeypot else "✅ Not a honeypot"
        await self._send(
            client,
            chat_id,
            f"🛡️ <b>Honeypot check</b>{ident}\n<code>{addr}</code>\n\n"
            f"{verdict}\nCan buy: {hp.can_buy} · Can sell: {hp.can_sell}",
        )

    async def _cmd_score(self, client: httpx.AsyncClient, chat_id: int, addr: str) -> None:
        try:
            score = await self.scorer.score(addr, "base")
        except Exception as e:  # noqa: BLE001
            await self._send(client, chat_id, f"⚠️ Score failed: {e}")
            return
        icon = _RISK_ICON.get(score.risk_level, "❓")
        await self._send(
            client,
            chat_id,
            f"🛡️ <b>Safety score</b>\n<code>{addr}</code>\n\n"
            f"{icon} <b>{score.score}/100</b> — {score.risk_level.upper()}\n{score.recommendation}",
        )

    # ── dispatch ─────────────────────────────────────────────
    async def _handle(self, client: httpx.AsyncClient, msg: dict[str, Any]) -> None:
        chat_id = msg.get("chat", {}).get("id")
        text = (msg.get("text") or "").strip()
        if chat_id is None or not text:
            return
        cmd = text.split()[0].lower().split("@")[0]  # strip @botname in groups

        if cmd in ("/start", "/help"):
            self.usage.log(chat_id, cmd)
            await self._cmd_help(client, chat_id)
            return
        if cmd == "/stats":
            await self._cmd_stats(client, chat_id)
            return
        if cmd in ("/scan", "/honeypot", "/score"):
            addr = self._extract_addr(text)
            if not addr:
                await self._send(
                    client,
                    chat_id,
                    "Send a token address: <code>" + cmd + " 0x…</code> (40 hex chars).",
                )
                return
            self.usage.log(chat_id, cmd, addr)
            if cmd == "/scan":
                await self._cmd_scan(client, chat_id, addr)
            elif cmd == "/honeypot":
                await self._cmd_honeypot(client, chat_id, addr)
            else:
                await self._cmd_score(client, chat_id, addr)

    async def _cmd_stats(self, client: httpx.AsyncClient, chat_id: int) -> None:
        # Admin-only — stats are visible to the configured owner chat only.
        if not self.admin_chat or str(chat_id) != str(self.admin_chat):
            await self._send(client, chat_id, "🛡️ VIGIL bot — try /scan &lt;0x token&gt;")
            return
        s = self.usage.stats()
        top_lines = "\n".join(f"  {t} — {n}×" for t, n in s["top"]) or "  (none yet)"
        await self._send(
            client,
            chat_id,
            "📊 <b>VIGIL bot stats</b>\n\n"
            f"Total scans: <b>{s['total_scans']}</b>\n"
            f"Scans (24h): <b>{s['scans_24h']}</b>\n"
            f"Unique users: <b>{s['unique_users']}</b>\n\n"
            f"<b>Top tokens</b>\n{top_lines}",
        )

    # ── poll loop ────────────────────────────────────────────
    async def run(self) -> None:
        if not self.token:
            raise SystemExit("VIGIL_TELEGRAM_BOT_TOKEN not set")
        logger.info("VIGIL Telegram bot starting (long-poll)")
        async with httpx.AsyncClient(timeout=40) as client:
            while True:
                try:
                    resp = await client.get(
                        f"{TELEGRAM_API}/bot{self.token}/getUpdates",
                        params={"offset": self.offset, "timeout": 30},
                    )
                    data = resp.json()
                    for upd in data.get("result", []):
                        self.offset = upd["update_id"] + 1
                        message = upd.get("message") or upd.get("edited_message")
                        if message:
                            await self._handle(client, message)
                except Exception as e:  # noqa: BLE001 — never die
                    logger.error("poll error: %s", e)
                    await asyncio.sleep(3)


def main() -> None:
    logging.basicConfig(
        level=getattr(logging, os.getenv("VIGIL_LOG_LEVEL", "INFO")),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    asyncio.run(VigilBot().run())


if __name__ == "__main__":
    main()
