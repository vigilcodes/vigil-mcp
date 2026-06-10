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
from typing import Any, Optional

import httpx

from vigil_mcp.scanners.honeypot import HoneypotDetector
from vigil_mcp.scanners.safety_score import SafetyScorer
from vigil_mcp.scanners.scam_db import ScamDatabase

logger = logging.getLogger("vigil-bot")

TELEGRAM_API = "https://api.telegram.org"
_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}")

_RISK_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "safe": "✅",
}


class VigilBot:
    def __init__(self) -> None:
        self.token = os.getenv("VIGIL_TELEGRAM_BOT_TOKEN", "")
        self.scorer = SafetyScorer()
        self.honeypot = HoneypotDetector()
        self.scam_db = ScamDatabase()
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

        name = hp.token_symbol or hp.token_name or ""
        ident = f" <b>{name}</b>" if name else ""
        icon = _RISK_ICON.get(score.risk_level, "❓")
        hp_txt = "🔴 HONEYPOT" if hp.is_honeypot else "✅ not a honeypot"
        scam_txt = (
            f"🔴 {scam.get('report_count', 0)} report(s)"
            if scam.get("reported")
            else "✅ none"
        )
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
        name = hp.token_symbol or hp.token_name or ""
        ident = f" <b>{name}</b>" if name else ""
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
            await self._cmd_help(client, chat_id)
            return
        if cmd in ("/scan", "/honeypot", "/score"):
            addr = self._extract_addr(text)
            if not addr:
                await self._send(
                    client, chat_id,
                    "Send a token address: <code>" + cmd + " 0x…</code> (40 hex chars).",
                )
                return
            if cmd == "/scan":
                await self._cmd_scan(client, chat_id, addr)
            elif cmd == "/honeypot":
                await self._cmd_honeypot(client, chat_id, addr)
            else:
                await self._cmd_score(client, chat_id, addr)

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
