"""Telegram notification adapter for VIGIL Sentinel.

When VIGIL_TELEGRAM_BOT_TOKEN and VIGIL_TELEGRAM_CHAT_ID are set, the
Sentinel loop sends new high-severity alerts to a Telegram chat (personal
DM, group, or channel). Completely opt-in; without these env vars set the
module does nothing.

Setup:
1. Create a bot via @BotFather on Telegram → get the token.
2. Start a chat with the bot (or add it to a group).
3. Get your chat ID (send /start to @userinfobot or check bot updates).
4. Set in .env:
     VIGIL_TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
     VIGIL_TELEGRAM_CHAT_ID=your_chat_id
"""

import os
from typing import Any

import httpx

TELEGRAM_API = "https://api.telegram.org"


def is_configured() -> bool:
    return bool(os.getenv("VIGIL_TELEGRAM_BOT_TOKEN")) and bool(
        os.getenv("VIGIL_TELEGRAM_CHAT_ID")
    )


def _format_alert(payload: dict[str, Any]) -> str:
    """Format a Sentinel alert payload into a readable Telegram message."""
    wallet = payload.get("wallet", "?")
    chain = payload.get("chain", "?")
    label = payload.get("label") or ""
    alerts = payload.get("new_alerts", [])

    header = "🚨 <b>VIGIL Sentinel Alert</b>\n"
    header += f"Wallet: <code>{wallet}</code>"
    if label:
        header += f" ({label})"
    header += f"\nChain: {chain}\n"

    lines = []
    for a in alerts[:10]:  # cap to avoid Telegram message limit
        sev = a.get("severity", "?").upper()
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(sev, "⚪")
        msg = a.get("message", "")
        lines.append(f"{icon} [{sev}] {msg}")

    body = "\n".join(lines) if lines else "No details."
    footer = "\n\n🔗 vigil.codes"

    return header + "\n" + body + footer


async def send_alert(payload: dict[str, Any]) -> bool:
    """Send a Sentinel alert to the configured Telegram chat.

    Returns True if sent successfully, False otherwise (never raises).
    """
    token = os.getenv("VIGIL_TELEGRAM_BOT_TOKEN", "")
    chat_id = os.getenv("VIGIL_TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return False

    text = _format_alert(payload)
    url = f"{TELEGRAM_API}/bot{token}/sendMessage"

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                url,
                json={
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                },
            )
            return resp.status_code == 200
    except Exception:  # noqa: BLE001 — notification is best-effort
        return False
