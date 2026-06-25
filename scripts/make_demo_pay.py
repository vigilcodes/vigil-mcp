#!/usr/bin/env python3
"""Demo: pay-and-scan with VIGIL's first-party x402 client (builder-code-aware).

Shows how an internal VIGIL component can PAY for a premium tool while ensuring
VIGIL's Builder Code (``a``) lands onchain — using
``vigil_mcp.payments.client``. The point of the demo is the attribution: the
payment payload always echoes the app code via ``client_echo_extension``.

Safety
------
- DRY RUN by default: builds + signs the payment, prints the attribution it
  WOULD carry, and sends nothing.
- ``--send`` performs a real paid call (moves USDC). Defaults to base-sepolia
  testnet; pass ``--network base`` for mainnet (real funds).
- Payer key comes from PAYER_PRIVATE_KEY env only — never logged.

Run:
  # dry run (no funds move)
  PAYER_PRIVATE_KEY=0x... VIGIL_X402_APP_CODE=bc_kz42eeiy \
      python3 scripts/make_demo_pay.py

  # real testnet pay-and-scan
  PAYER_PRIVATE_KEY=0x... VIGIL_X402_APP_CODE=bc_kz42eeiy \
      python3 scripts/make_demo_pay.py --send
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vigil_mcp.payments import client as pay_client  # noqa: E402
from vigil_mcp.payments import x402  # noqa: E402

# A well-known safe token to scan in the demo (USDC on Base).
DEMO_TOKEN = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
TOOL = "vigil_scan_token"


def main():
    ap = argparse.ArgumentParser(description="VIGIL pay-and-scan demo")
    ap.add_argument("--network", default="base-sepolia", choices=list(pay_client.NETWORK_ALIASES))
    ap.add_argument("--token", default=DEMO_TOKEN)
    ap.add_argument("--send", action="store_true", help="actually pay + call (moves USDC)")
    args = ap.parse_args()

    key = os.getenv("PAYER_PRIVATE_KEY", "").strip()
    pay_to = os.getenv("VIGIL_X402_PAY_TO", "")
    if not key or not pay_to:
        print("Set PAYER_PRIVATE_KEY and VIGIL_X402_PAY_TO first.", file=sys.stderr)
        sys.exit(1)

    from eth_account import Account

    payer = Account.from_key(key)
    price = x402.price_for(TOOL) or 0.005

    print("VIGIL pay-and-scan demo")
    print(f"  payer    : {payer.address}")
    print(f"  pays to  : {pay_to}")
    print(f"  tool     : {TOOL}  (${price})")
    print(f"  network  : {args.network}")
    print(f"  app code : {x402.builder_code() or '(unset!)'}\n")

    # Build the payment the same way pay_and_call does, so we can show exactly
    # what attribution it carries before anything is sent.
    payload = pay_client.build_payment_payload(payer, network=args.network, pay_to=pay_to, price_usd=price)
    echo = payload.get("extensions", {}).get(x402.BUILDER_CODE_EXT, {}).get("info", {})
    print(f"Attribution the payment WILL carry onchain: {echo or '(none — would be LOST)'}")

    if not args.send:
        print("\n[DRY RUN] Nothing sent. Re-run with --send to pay for real.")
        return

    endpoint = os.getenv("VIGIL_ENDPOINT", "https://mcp.vigil.codes/tools/call")
    print(f"\nPaying and calling {TOOL} via {endpoint} ...")
    result = asyncio.run(
        pay_client.pay_and_call(
            endpoint,
            TOOL,
            {"token": args.token, "chain": "base"},
            account=payer,
            network=args.network,
            pay_to=pay_to,
            price_usd=price,
        )
    )
    print("HTTP", result["status"])
    if result.get("settlement_tx"):
        print("settlement tx:", result["settlement_tx"])
        print("→ verify attribution: python3 scripts/vigil_check_attribution.py")
    verdict = (result.get("body") or {}).get("result", {})
    if verdict:
        print(json.dumps({k: verdict.get(k) for k in ("token_symbol", "safety_score", "risk_level")}, indent=2))


if __name__ == "__main__":
    main()
