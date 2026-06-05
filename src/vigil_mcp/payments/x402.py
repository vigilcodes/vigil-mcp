"""x402 pay-per-call support for VIGIL tools (Coinbase HTTP 402 protocol).

Lets any AI agent pay a few cents in USDC on Base per scan — no API key, no
account. This makes VIGIL composable revenue infrastructure: a trading agent
can call `vigil_detect_honeypot`, pay USDC, and get the verdict.

Design notes
- Fully OPT-IN. Disabled unless VIGIL_X402_ENABLED=1, so the public endpoint
  keeps working for free exactly as today until you flip it on.
- Stateless per the x402 spec: on an unpaid request we return HTTP 402 with
  payment requirements; the client retries with an X-PAYMENT header carrying a
  signed payload, which a facilitator verifies + settles.
- Verification/settlement is delegated to an x402 facilitator so we never
  custody keys here. CDP's facilitator is recommended (1k/mo free).

References
- Quickstart: https://docs.cdp.coinbase.com/x402/quickstart-for-sellers
- Facilitator: https://docs.cdp.coinbase.com/x402/core-concepts/facilitator
- Networks (CAIP-2): https://docs.cdp.coinbase.com/x402/network-support
"""

import os
from typing import Any, Optional

# USDC on Base (6 decimals). $0.001 == 1000 atomic units.
USDC_BASE = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
USDC_DECIMALS = 6

# CAIP-2 network identifiers — required by the CDP facilitator.
# Map our internal chain name to its CAIP-2 ID.
CAIP2_NETWORKS = {
    "base": "eip155:8453",
    "base-sepolia": "eip155:84532",
    "polygon": "eip155:137",
    "arbitrum": "eip155:42161",
}

# CDP's hosted facilitator (mainnet). 1,000 transactions / month free, then
# $0.001/tx. Includes KYT compliance screening for sanctioned addresses.
CDP_FACILITATOR_URL = "https://api.cdp.coinbase.com/platform/v2/x402"

# OpenX402 — permissionless public facilitator. No signup, no API keys, free.
# Supports Base mainnet + CAIP-2. Ideal fallback when CDP signup is blocked.
# Docs: https://docs.openx402.ai/
OPENX402_FACILITATOR_URL = "https://facilitator.openx402.ai"


def is_enabled() -> bool:
    """Master gate. Off by default — endpoint stays free until flipped on."""
    return os.getenv("VIGIL_X402_ENABLED", "") in ("1", "true", "yes")


def _price_units(usd: float) -> str:
    """Convert a USD price to USDC atomic-unit string (6 decimals)."""
    return str(int(round(usd * (10 ** USDC_DECIMALS))))


def _default_prices() -> dict[str, float]:
    """Per-tool USD price. Tools not listed here stay free even when x402 is on.

    Defaults are tuned so that after the CDP facilitator's $0.001/tx fee
    (post-quota), there's still margin. Defensive tools AND core pre-trade
    checks stay free on purpose — adoption > micro-revenue on the tools that
    make agents want to use VIGIL in the first place.
    """
    base = float(os.getenv("VIGIL_X402_PRICE_USD", "0.005"))
    return {
        "vigil_scan_token": base,
        "vigil_token_market": base * 0.6,    # lighter call (DexScreener)
        "vigil_deployer_check": base,
        "vigil_batch_scan": base * 5,        # heavy: scans many tokens
        "vigil_wallet_report": base * 2,     # aggregates several scans
        # Intentionally NOT priced (stay free):
        # vigil_detect_honeypot — core pre-trade check, must be barrier-free
        # vigil_safety_score   — core pre-trade check, must be barrier-free
        # vigil_scan_approvals, vigil_check_scam, vigil_monitor_wallet,
        # vigil_sentinel_status
    }


def price_for(tool: str) -> Optional[float]:
    """USD price for a tool, or None if it's free."""
    return _default_prices().get(tool)


def _resolve_network() -> str:
    """Resolve the CAIP-2 network ID. Allows a raw override for forward-compat."""
    raw = os.getenv("VIGIL_X402_NETWORK", "base").lower()
    return CAIP2_NETWORKS.get(raw, raw)


def payment_requirements(tool: str, price_usd: float) -> dict[str, Any]:
    """Build the x402 payment-requirements object for a 402 response.

    Shape follows the x402 v2 spec used by the CDP facilitator.
    """
    pay_to = os.getenv("VIGIL_X402_PAY_TO", "")
    network = _resolve_network()
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
                "extra": {
                    "name": "USD Coin",
                    "decimals": USDC_DECIMALS,
                    "priceUSD": price_usd,
                },
            }
        ],
    }


def _facilitator_url() -> str:
    """Active facilitator URL.

    Resolution order:
    1. VIGIL_X402_FACILITATOR (explicit override)
    2. CDP if CDP_API_KEY_ID/SECRET are set (recommended for production)
    3. OpenX402 public facilitator (no signup, free, supports Base mainnet)
    """
    override = os.getenv("VIGIL_X402_FACILITATOR", "").strip()
    if override:
        return override
    if os.getenv("CDP_API_KEY_ID") and os.getenv("CDP_API_KEY_SECRET"):
        return CDP_FACILITATOR_URL
    return OPENX402_FACILITATOR_URL


def _facilitator_headers() -> dict[str, str]:
    """Bearer auth header for the CDP facilitator. Empty for public facilitators."""
    key_id = os.getenv("CDP_API_KEY_ID", "")
    key_secret = os.getenv("CDP_API_KEY_SECRET", "")
    if key_id and key_secret:
        # CDP uses standard Bearer auth on the facilitator endpoint.
        return {"Authorization": f"Bearer {key_secret}", "X-CDP-Key-Id": key_id}
    return {}


async def verify_payment(header_value: str, tool: str, price_usd: float) -> bool:
    """Verify a signed x402 payment payload via the configured facilitator.

    Returns True if the payment is valid for the requested tool/price. If no
    facilitator is configured or verification fails for any reason, this
    returns False (fail closed) so unpaid requests cannot pass.
    """
    facilitator = _facilitator_url()
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
                headers=_facilitator_headers(),
            )
            if resp.status_code != 200:
                return False
            return bool(resp.json().get("isValid"))
    except Exception:  # noqa: BLE001 — fail closed on any verification error
        return False
