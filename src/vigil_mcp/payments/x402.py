"""x402 pay-per-call support for VIGIL tools (Coinbase HTTP 402 protocol).

Lets any AI agent pay a few cents in USDC on Base per scan — no API key, no
account. This makes VIGIL composable revenue infrastructure: a trading agent
can call ``vigil_scan_token``, pay USDC, and get the verdict.

How a paid request flows
------------------------
1. Agent calls a paid tool with no ``X-PAYMENT`` header → we return HTTP 402
   with ``payment_requirements`` (the price, asset, payTo, and our builder-code
   declaration).
2. Agent signs an EIP-3009 USDC transfer authorization and retries with an
   ``X-PAYMENT`` header (base64-encoded JSON payment payload).
3. We ``verify`` the payload with the CDP facilitator. If valid, we run the
   tool, then ``settle`` — the facilitator broadcasts the USDC transfer onchain
   and appends our Builder Code (ERC-8021) to the settlement calldata.
4. We return the result plus an ``X-PAYMENT-RESPONSE`` header carrying the
   settlement transaction hash.

Design notes
- Fully OPT-IN. Disabled unless ``VIGIL_X402_ENABLED=1``.
- We are a *seller* only — we never custody keys or sign payments. Verification
  and settlement are delegated to the CDP facilitator.
- CDP auth uses a short-lived Bearer JWT (EdDSA/Ed25519) signed per-request with
  the CDP API key secret. Tokens are valid 2 minutes; we mint a fresh one per
  call (verify and settle need different ``uris`` claims).
- Builder Code attribution (``a`` = our app code) is declared in the 402
  response and echoed by the client; the facilitator encodes it onchain at
  settle time. This unlocks Base rewards/analytics/visibility for VIGIL.

  IMPORTANT — declaration alone is NOT enough. Per the CDP facilitator spec,
  the app code that lands onchain is read from the *payment payload* (the
  client's echo), not from ``paymentRequirements``. At settle the facilitator:
    1. checks the client's echoed ``a`` matches our declared ``a`` (mismatch =
       settlement rejected),
    2. reads ``a``/``s`` from the payment payload,
    3. adds its own wallet code ``w`` (e.g. ``cdp_facil``), and
    4. CBOR-encodes the ERC-8021 Schema-2 suffix onto the calldata.
  So if a paying client does NOT echo ``a`` into its X-PAYMENT payload, only
  the facilitator's ``w`` lands onchain and OUR attribution is lost — even
  though our 402 declared the code correctly. First-party/test clients must use
  ``client_echo_extension()`` (below) to populate the payload.
  Refs: https://docs.cdp.coinbase.com/x402/core-concepts/builder-codes

References
- Quickstart:   https://docs.cdp.coinbase.com/x402/quickstart-for-sellers
- Verify:       https://docs.cdp.coinbase.com/api-reference/v2/rest-api/x402-facilitator/verify-payment
- Settle:       https://docs.cdp.coinbase.com/api-reference/v2/rest-api/x402-facilitator/settle-payment
- JWT auth:     https://docs.cdp.coinbase.com/api-reference/v2/authentication
- Builder Code: https://docs.x402.org/extensions/builder-code
"""

import base64
import json
import logging
import os
import random
import time
from typing import Any, Optional

logger = logging.getLogger("vigil-mcp.x402")

# USDC on Base (6 decimals). $0.001 == 1000 atomic units.
USDC_BASE = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
USDC_DECIMALS = 6

# CAIP-2 network identifiers — required by the CDP facilitator.
CAIP2_NETWORKS = {
    "base": "eip155:8453",
    "base-sepolia": "eip155:84532",
    "polygon": "eip155:137",
    "arbitrum": "eip155:42161",
}

# CDP's hosted facilitator (mainnet). 1,000 transactions / month free, then
# $0.001/tx. Includes KYT compliance screening for sanctioned addresses, and
# encodes Builder Code attribution onchain at settlement.
CDP_FACILITATOR_URL = "https://api.cdp.coinbase.com/platform/v2/x402"
CDP_HOST = "api.cdp.coinbase.com"
CDP_BASE_PATH = "/platform/v2/x402"

# Builder Code extension key (ERC-8021 attribution). Pattern is enforced by the
# facilitator: lowercase letters, digits, underscores, 1-32 chars.
BUILDER_CODE_EXT = "builder-code"
BUILDER_CODE_PATTERN = r"^[a-z0-9_]{1,32}$"

# x402 protocol version used on the wire to the CDP facilitator. CDP's REST
# facilitator expects v2 shapes (paymentRequirements uses `amount`/`payTo`,
# the payment payload embeds `accepted`). This is verified against the live
# /verify endpoint — a v1 body is rejected with a schema error.
X402_VERSION = 2

# Public host VIGIL serves from, used in the v2 `resource` block.
PUBLIC_BASE_URL = os.getenv("VIGIL_PUBLIC_URL", "https://mcp.vigil.codes")


def is_enabled() -> bool:
    """Master gate. Off by default — endpoint stays free until flipped on."""
    return os.getenv("VIGIL_X402_ENABLED", "") in ("1", "true", "yes")


def _price_units(usd: float) -> str:
    """Convert a USD price to USDC atomic-unit string (6 decimals)."""
    return str(int(round(usd * (10**USDC_DECIMALS))))


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
        "vigil_token_market": base * 0.6,  # lighter call (DexScreener)
        "vigil_deployer_check": base,
        "vigil_batch_scan": base * 5,  # heavy: scans many tokens
        "vigil_wallet_report": base * 2,  # aggregates several scans
        "vigil_consensus": base * 1.5,  # aggregates several independent sources
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


def builder_code() -> str:
    """Our Base Builder Code (ERC-8021 app code), or empty if unset."""
    return os.getenv("VIGIL_X402_APP_CODE", "").strip()


def _builder_code_extension() -> Optional[dict[str, Any]]:
    """Declare the builder-code extension for the 402 response, or None.

    The client echoes ``info.a`` back in the payment payload; the CDP
    facilitator validates the echo and encodes the code onchain at settle.
    """
    code = builder_code()
    if not code:
        return None
    return {
        BUILDER_CODE_EXT: {
            "info": {"a": code},
            "schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "a": {"type": "string", "pattern": BUILDER_CODE_PATTERN, "description": "App builder code"},
                    "w": {"type": "string", "pattern": BUILDER_CODE_PATTERN, "description": "Wallet builder code"},
                    "s": {
                        "type": "array",
                        "items": {"type": "string", "pattern": BUILDER_CODE_PATTERN},
                        "description": "Service builder codes",
                    },
                },
                "additionalProperties": False,
            },
        }
    }


def client_echo_extension(service_codes: Optional[list[str]] = None) -> Optional[dict[str, Any]]:
    """Build the builder-code echo a *paying client* must put in its payload.

    This is the piece that actually gets VIGIL's app code (``a``) onchain. The
    CDP facilitator reads ``a``/``s`` from the payment payload at settle time —
    a seller-side declaration in the 402 is necessary but not sufficient. A
    first-party or test client should merge this into the ``extensions`` block
    of the X-PAYMENT payload it signs and sends.

    Args:
        service_codes: optional client/intermediary service code(s) (``s``).

    Returns:
        ``{"builder-code": {"info": {"a": <app>, "s": [...]}}}`` or None if no
        app code is configured.
    """
    code = builder_code()
    if not code:
        return None
    info: dict[str, Any] = {"a": code}
    if service_codes:
        info["s"] = list(service_codes)
    return {BUILDER_CODE_EXT: {"info": info}}


def _accepts_entry(tool: str, price_usd: float) -> dict[str, Any]:
    """Build a single x402 v2 ``PaymentRequirements`` entry.

    v2 shape (verified against CDP's live facilitator): ``amount`` (not
    ``maxAmountRequired``), ``payTo``, and ``extra`` carrying the EIP-712 token
    ``name``/``version`` the facilitator needs to validate the USDC signature.
    """
    pay_to = os.getenv("VIGIL_X402_PAY_TO", "")
    network = _resolve_network()
    return {
        "scheme": "exact",
        "network": network,
        "asset": USDC_BASE,
        "amount": _price_units(price_usd),
        "payTo": pay_to,
        "maxTimeoutSeconds": 60,
        # EIP-712 domain the facilitator uses to verify the EIP-3009 signature.
        # MUST match the USDC contract's onchain domain ("USD Coin", version 2)
        # or both signature verification and onchain settlement revert.
        "extra": {"name": "USD Coin", "version": "2"},
    }


def _resource_block(tool: str) -> dict[str, Any]:
    """The v2 ``resource`` descriptor for a tool."""
    return {
        "url": f"{PUBLIC_BASE_URL}/tools/call#{tool}",
        "description": f"VIGIL {tool} scan",
        "mimeType": "application/json",
    }


def payment_requirements(tool: str, price_usd: float) -> dict[str, Any]:
    """Build the x402 v2 ``PaymentRequired`` object for a 402 response.

    Includes the builder-code extension declaration when an app code is set so
    clients echo it and the facilitator can attribute the payment onchain.
    """
    body: dict[str, Any] = {
        "x402Version": X402_VERSION,
        "error": "Payment required",
        "resource": _resource_block(tool),
        "accepts": [_accepts_entry(tool, price_usd)],
    }
    ext = _builder_code_extension()
    if ext:
        body["extensions"] = ext
    return body


# ─────────────────────────────────────────────────────────────
# CDP facilitator auth (Bearer JWT, EdDSA/Ed25519 or ES256)
# ─────────────────────────────────────────────────────────────


def _generate_nonce() -> str:
    return "".join(random.choices("0123456789", k=16))


def _parse_cdp_private_key(key_data: str):
    """Parse a CDP API key secret (PEM EC key or base64 Ed25519 seed)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    if "\\n" in key_data:
        key_data = key_data.replace("\\n", "\n")

    # PEM EC key (ES256)
    try:
        key = serialization.load_pem_private_key(key_data.encode(), password=None)
        if isinstance(key, ec.EllipticCurvePrivateKey):
            return key, "ES256"
    except Exception:  # noqa: BLE001 — fall through to Ed25519 attempt
        pass

    # base64 Ed25519 (64 bytes: 32 seed + 32 public)
    try:
        decoded = base64.b64decode(key_data)
        if len(decoded) == 64:
            seed = decoded[:32]
            return ed25519.Ed25519PrivateKey.from_private_bytes(seed), "EdDSA"
    except Exception:  # noqa: BLE001
        pass

    raise ValueError("CDP key must be a PEM EC key or base64 Ed25519 key")


def _cdp_bearer_jwt(method: str, path: str) -> Optional[str]:
    """Mint a short-lived CDP Bearer JWT for ``METHOD api.cdp.coinbase.com<path>``.

    Returns None if CDP keys are not configured.
    """
    key_id = os.getenv("CDP_API_KEY_ID", "").strip()
    key_secret = os.getenv("CDP_API_KEY_SECRET", "").strip()
    if not key_id or not key_secret:
        return None

    import jwt as pyjwt

    private_key, algorithm = _parse_cdp_private_key(key_secret)
    now = int(time.time())
    header = {"alg": algorithm, "kid": key_id, "typ": "JWT", "nonce": _generate_nonce()}
    claims = {
        "sub": key_id,
        "iss": "cdp",
        "aud": None,
        "nbf": now,
        "exp": now + 120,
        "uris": [f"{method} {CDP_HOST}{path}"],
    }
    return pyjwt.encode(claims, private_key, algorithm=algorithm, headers=header)


def _using_cdp() -> bool:
    return bool(os.getenv("CDP_API_KEY_ID") and os.getenv("CDP_API_KEY_SECRET"))


def _facilitator_url() -> str:
    """Active facilitator base URL.

    Resolution order:
    1. VIGIL_X402_FACILITATOR (explicit override)
    2. CDP if CDP_API_KEY_ID/SECRET are set (required for Builder Code onchain)
    """
    override = os.getenv("VIGIL_X402_FACILITATOR", "").strip()
    if override:
        return override
    return CDP_FACILITATOR_URL


def _auth_headers(method: str, endpoint: str) -> dict[str, str]:
    """Authorization header for a CDP facilitator endpoint (``/verify`` etc)."""
    if not _using_cdp():
        return {}
    token = _cdp_bearer_jwt(method, f"{CDP_BASE_PATH}{endpoint}")
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


# ─────────────────────────────────────────────────────────────
# X-PAYMENT header decoding + facilitator request shaping
# ─────────────────────────────────────────────────────────────


def decode_payment_header(header_value: str) -> Optional[dict[str, Any]]:
    """Decode a base64-encoded X-PAYMENT header into a payment payload dict.

    Returns None if the header is empty or cannot be decoded.
    """
    if not header_value:
        return None
    try:
        raw = base64.b64decode(header_value)
        return json.loads(raw)
    except Exception:  # noqa: BLE001 — malformed payload is treated as unpaid
        try:
            # Some clients send raw JSON instead of base64.
            return json.loads(header_value)
        except Exception:  # noqa: BLE001
            return None


def _facilitator_body(payload: dict[str, Any], tool: str, price_usd: float) -> dict[str, Any]:
    """Build the verify/settle request body for the facilitator.

    The builder-code extension is attached to ``paymentRequirements`` so the
    facilitator can match the client's echoed ``a`` against our declared ``a``
    (a mismatch is rejected). NOTE: the value actually encoded onchain is read
    from ``paymentPayload`` (the client echo), not from here — see the module
    docstring. Attaching it here does not inject ``a`` on its own; the paying
    client must echo it via ``client_echo_extension()``.
    """
    requirements = _accepts_entry(tool, price_usd)
    ext = _builder_code_extension()
    if ext:
        requirements["extensions"] = ext
    return {
        "x402Version": X402_VERSION,
        "paymentPayload": payload,
        "paymentRequirements": requirements,
    }


async def _post(endpoint: str, body: dict[str, Any]) -> Optional[dict[str, Any]]:
    """POST to a facilitator endpoint; return parsed JSON or None on error."""
    base = _facilitator_url().rstrip("/")
    try:
        import httpx

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{base}{endpoint}",
                json=body,
                headers={"Content-Type": "application/json", **_auth_headers("POST", endpoint)},
            )
            if resp.status_code != 200:
                logger.warning("facilitator %s -> HTTP %s: %s", endpoint, resp.status_code, resp.text[:300])
                return None
            return resp.json()
    except Exception as e:  # noqa: BLE001 — fail closed on any transport error
        logger.warning("facilitator %s error: %s", endpoint, e)
        return None


async def verify_payment(header_value: str, tool: str, price_usd: float) -> bool:
    """Verify a signed x402 payment payload via the configured facilitator.

    Returns True only if the facilitator reports the payment as valid. Fails
    closed (False) on any missing config, malformed payload, or error.
    """
    payload = decode_payment_header(header_value)
    if payload is None:
        return False
    result = await _post("/verify", _facilitator_body(payload, tool, price_usd))
    if not result:
        return False
    return bool(result.get("isValid"))


async def settle_payment(header_value: str, tool: str, price_usd: float) -> Optional[dict[str, Any]]:
    """Settle a verified payment onchain via the facilitator.

    Returns the settlement result dict (containing ``transaction``,
    ``payer``, ``network``) on success, or None on failure. The facilitator
    broadcasts the USDC transfer and appends our Builder Code to the calldata.
    """
    payload = decode_payment_header(header_value)
    if payload is None:
        return None
    result = await _post("/settle", _facilitator_body(payload, tool, price_usd))
    if not result:
        return None
    if not result.get("success"):
        logger.warning(
            "settle failed for %s: %s %s",
            tool,
            result.get("errorReason"),
            result.get("errorMessage"),
        )
        return None
    return result


def settlement_response_header(settle_result: dict[str, Any]) -> str:
    """Encode a settlement result as a base64 X-PAYMENT-RESPONSE header value."""
    payload = {
        "success": True,
        "transaction": settle_result.get("transaction"),
        "network": settle_result.get("network"),
        "payer": settle_result.get("payer"),
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()
