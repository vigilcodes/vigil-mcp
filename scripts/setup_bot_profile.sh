#!/usr/bin/env bash
# Register the VIGIL Telegram bot's command menu + descriptions with Telegram.
# Idempotent — safe to re-run. Requires VIGIL_TELEGRAM_BOT_TOKEN in env/.env.
set -euo pipefail

TOKEN="${VIGIL_TELEGRAM_BOT_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -f "$(dirname "$0")/../.env" ]; then
  TOKEN="$(grep -E '^VIGIL_TELEGRAM_BOT_TOKEN=' "$(dirname "$0")/../.env" | cut -d= -f2-)"
fi
[ -z "$TOKEN" ] && { echo "VIGIL_TELEGRAM_BOT_TOKEN not set"; exit 1; }

api() { curl -sS -m 15 -X POST "https://api.telegram.org/bot${TOKEN}/$1" -H "Content-Type: application/json" -d "$2"; echo; }

api setMyCommands '{"commands":[
  {"command":"scan","description":"Full scan — safety score, honeypot, scam check"},
  {"command":"honeypot","description":"Honeypot check only"},
  {"command":"score","description":"Safety score only (0-100)"},
  {"command":"help","description":"How to use VIGIL"}
]}'

api setMyDescription '{"description":"Onchain security scanner for Base. Scan any token for honeypots, rugpull risk, and safety score — right in chat. Send /scan <token address>. No API key needed. vigil.codes"}'

api setMyShortDescription '{"short_description":"Scan any Base token for honeypots & rugs. /scan <address>"}'

echo "VIGIL bot profile registered."
