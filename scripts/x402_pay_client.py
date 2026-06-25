#!/usr/bin/env python3
"""x402_pay_client.py — CLI over VIGIL's first-party x402 paying client.

VIGIL (the seller) declares its Builder Code in the 402 response, but the CDP
facilitator only encodes the app code (``a``) onchain when the *paying client*
echoes it in the X-PAYMENT payload. This CLI uses
``vigil_mcp.payments.client`` (the shared, tested implementation) so the echo
always happens and VIGIL's attribution lands onchain.

Safety
------
- DRY RUN by default: signs and prints the X-PAYMENT payload, sends NOTHING.
- ``--send`` performs a real paid call (moves USDC). Defaults to base-sepolia
  (testnet) so no mainnet funds move unless you pass ``--network base``.
- The payer key is read from PAYER_PRIVATE_KEY env (never a CLI arg, never
  logged). The signing happens in-process and the key never leaves the host.

Env:
  PAYER_PRIVATE_KEY   payer EOA private key (testnet wallet recommended)
  VIGIL_X402_APP_CODE app builder code to echo as ``a`` (e.g. bc_kz42eeiy)
  VIGIL_ENDPOINT      tools/call URL (default https://mcp.vigil.codes/tools/call)

Usage:
  # dry-run: sign + show the payload that WOULD be sent (no funds move)
  PAYER_PRIVATE_KEY=0x... python3 scripts/x402_pay_client.py vigil_scan_token \
      --token 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913

  # live mainnet call (moves real USDC on Base)
  PAYER_PRIVATE_KEY=0x... python3 scripts/x402_pay_client.py vigil_scan_token \
      --token 0x... --network base --send
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

# Make the in-repo package importable when run as a standalone script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vigil_mcp.payments import client as pay_client  # noqa: E402
from vigil_mcp.payments import x402  # noqa: E402

# Default per-tool USD price for CLI display/value; the server is the source of
# truth, this just mirrors x402.price_for for known tools.
_FALLBACK_PRICE = 0.005

# ── Compatibility re-exports (used by tests and older callers) ──────────────
CAIP2 = pay_client.NETWORK_ALIASES
USDC = {alias: pay_client.USDC_BY_NETWORK[caip2][0] for alias, caip2 in pay_client.NETWORK_ALIASES.items()}
USDC_NAME = {alias: pay_client.USDC_BY_NETWORK[caip2][1] for alias, caip2 in pay_client.NETWORK_ALIASES.items()}
_eip3009_typed_data = pay_client._eip3009_typed_data


def build_signed_payment(account, *, network, pay_to, price_usd, app_code, service_codes):
    """Thin shim -> vigil_mcp.payments.client.build_payment_payload (kept for tests)."""
    return pay_client.build_payment_payload(
        account,
        network=network,
        pay_to=pay_to,
        price_usd=price_usd,
        app_code=app_code,
        service_codes=service_codes or None,
    )


def main():
    p = argparse.ArgumentParser(description="Builder-code-aware x402 paying client for VIGIL")
    p.add_argument("tool", help="tool name, e.g. vigil_scan_token")
    p.add_argument("--token", help="token/contract address argument", default="")
    p.add_argument("--chain", default="base", help="scan chain argument (default base)")
    p.add_argument(
        "--network", default="base-sepolia", choices=list(pay_client.NETWORK_ALIASES), help="settlement network"
    )
    p.add_argument("--pay-to", default=os.getenv("VIGIL_X402_PAY_TO", ""), help="seller payout address")
    p.add_argument("--service-code", action="append", default=[], help="client service code(s) for s")
    p.add_argument("--send", action="store_true", help="actually send the paid call (moves USDC)")
    args = p.parse_args()

    key = os.getenv("PAYER_PRIVATE_KEY", "").strip()
    if not key:
        print("Error: set PAYER_PRIVATE_KEY (use a testnet wallet).", file=sys.stderr)
        sys.exit(1)
    if not args.pay_to:
        print("Error: --pay-to or VIGIL_X402_PAY_TO required.", file=sys.stderr)
        sys.exit(1)

    from eth_account import Account

    account = Account.from_key(key)
    price = x402.price_for(args.tool) or _FALLBACK_PRICE
    app_code = x402.builder_code()

    print(f"payer      : {account.address}")
    print(f"network    : {args.network} ({pay_client._resolve_network(args.network)})")
    print(f"tool/price : {args.tool}  ${price}")
    print(f"app code(a): {app_code or '(none — attribution will be LOST)'}")
    print(f"svc code(s): {args.service_code or '(none)'}\n")

    payload = pay_client.build_payment_payload(
        account,
        network=args.network,
        pay_to=args.pay_to,
        price_usd=price,
        service_codes=args.service_code or None,
    )
    header = pay_client.encode_payment_header(payload)
    echoed = payload.get("extensions", {}).get(x402.BUILDER_CODE_EXT, {}).get("info", {})
    print("Builder-code echo in payload:", echoed or "(absent)")
    print(f"X-PAYMENT header bytes      : {len(header)}")

    if not args.send:
        print("\n[DRY RUN] No call sent. Re-run with --send to settle for real.")
        print("Signed payment payload:")
        print(json.dumps(payload, indent=2))
        return

    arguments = {}
    if args.token:
        arguments["contract" if args.tool == "vigil_safety_score" else "token"] = args.token
        arguments["chain"] = args.chain

    endpoint = os.getenv("VIGIL_ENDPOINT", "https://mcp.vigil.codes/tools/call")
    print(f"\n[SEND] POST {endpoint}")
    result = asyncio.run(
        pay_client.pay_and_call(
            endpoint,
            args.tool,
            arguments,
            account=account,
            network=args.network,
            pay_to=args.pay_to,
            price_usd=price,
            service_codes=args.service_code or None,
        )
    )
    print("HTTP", result["status"])
    if result.get("settlement_tx"):
        print("settlement tx:", result["settlement_tx"])
        print("verify onchain attribution with: scripts/vigil_check_attribution.py")
    else:
        print("No settlement tx (payment not settled).")
    print("body:", json.dumps(result["body"])[:800])


if __name__ == "__main__":
    main()
