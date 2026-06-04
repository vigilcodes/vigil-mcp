"""x402 pay-per-call support for VIGIL tools (Coinbase HTTP 402 protocol).

Lets any AI agent pay a few cents in USDC on Base per scan — no API key, no
account. This makes VIGIL composable revenue infrastructure: a trading agent
can call `vigil_detect_honeypot`, pay $0.001 in USDC, and get the verdict.

Design notes
- Fully OPT-IN. Disabled unless VIGIL_X402_ENABLED=1, so the public endpoint
  keeps working for free exactly as today until you flip it on.
- Stateless, per the x402 spec: on an unpaid request we return HTTP 402 with
  payment requirements; the client retries with an X-PAYMENT header carrying a
  signed payload, which a facilitator verifies + settles.
- Verification/settlement is delegated to an x402 facilitator (recommended by
  Coinbase) so we never custody keys here.
"""

import os
from typing import Any, Optional

# USDC on Base (6 decimals). $0.001 == 1000 base units.
USDC_BASE = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
USDC_DECIMALS = 6


def is_enabled() -> bool:
    return os.getenv("VIGIL_X402_ENABLED", "") in ("1", "true", "yes")


def _price_units(usd: float) -> str:
    """Convert a USD price to USDC base-unit string."""
    return str(int(round(usd * (10 ** USDC_DECIMALS))))


# Per-tool USD price. Tools not listed here are free even when x402 is on.
def _default_prices() -> dict[str, float]:
    base = float(os.getenv("VIGIL_X402_PRICE_USD", "0.001"))
    return {
        "vigil_scan_token": base,
        "vigil_detect_honeypot": base,
        "vigil_safety_score": base,
        "vigil_token_market": base,
        "vigil_deployer_check": base,
        "vigil_batch_scan": base * 5,  # heavier: scans many tokens
        "vigil_wallet_report": base * 2,
    }


def price_for(tool: str) -> Optional[float]:
    """USD price for a tool, or None if it's free."""
    return _default_prices().get(tool)


def payment_requirements(tool: str, price_usd: float) -> dict[str, Any]:
    """Build the x402 payment-requirements object for a 402 response."""
    pay_to = os.getenv("VIGIL_X402_PAY_TO", "")
    network = os.getenv("VIGIL_X402_NETWORK", "base")
    return {
        "x402Version": 1,
        "accepts": [
            {
                "scheme": "exact",
                "network": network,
                "maxAmountRequired": _price_units(price_usd),
                "resource": f"/tools/call#{tool}",
                "description": f"VIGIL {tool} scan",
                "mimeType": "application/json",
                "payTo": pay_to,
                "maxTimeoutSeconds": 60,
                "asset": USDC_BASE,
                "extra": {"name": "USD Coin", "decimals": USDC_DECIMALS, "priceUSD": price_usd},
            }
        ],
    }


async def verify_payment(header_value: str, tool: str, price_usd: float) -> bool:
    """Verify a signed x402 payment payload via the configured facilitator.

    Returns True if the payment is valid for the requested tool/price. If no
    facilitator is configured, verification fails closed (returns False).
    """
    facilitator = os.getenv("VIGIL_X402_FACILITATOR", "")
    if not facilitator or not header_value:
        return False
    try:
        import httpx

        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                f"{facilitator.rstrip('/')}/verify",
                json={
                    "x402Version": 1,
                    "paymentPayload": header_value,
                    "paymentRequirements": payment_requirements(tool, price_usd)["accepts"][0],
                },
            )
            if resp.status_code != 200:
                return False
            return bool(resp.json().get("isValid"))
    except Exception:  # noqa: BLE001 — fail closed on any verification error
        return False
