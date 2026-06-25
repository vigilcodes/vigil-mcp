"""First-party x402 paying client for VIGIL.

VIGIL is primarily a *seller*, but internal components (demos, agent-to-agent
flows, first-party bots) sometimes need to PAY an x402 endpoint. When they do,
the payment MUST echo VIGIL's Builder Code (``a``) into the payload — the
seller-side 402 declaration alone does not put ``a`` onchain (see
``x402`` module docstring). This module centralizes that logic so every
first-party payment attributes correctly and consistently.

It produces an x402 **v2** ``exact`` EVM PaymentPayload (EIP-3009
``transferWithAuthorization``), signs it with a provided key, and merges the
builder-code echo from :func:`x402.client_echo_extension`.

Security: this module signs locally with a caller-provided key. It never
custodies, logs, or transmits the key anywhere except into the local signature.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Any, Optional

from vigil_mcp.payments import x402

# USDC contract + EIP-712 domain name differ per deployment. Signing with the
# wrong name makes the facilitator reject the signature.
USDC_BY_NETWORK = {
    "eip155:8453": ("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "USD Coin"),
    "eip155:84532": ("0x036cbd53842c5426634e7929541ec2318f3dcf7e", "USDC"),
}
USDC_DECIMALS = 6
# Friendly aliases → CAIP-2.
NETWORK_ALIASES = {"base": "eip155:8453", "base-sepolia": "eip155:84532"}


def _resolve_network(network: str) -> str:
    return NETWORK_ALIASES.get(network, network)


def _eip3009_typed_data(
    chain_id: int,
    verifying_contract: str,
    token_name: str,
    frm: str,
    to: str,
    value: int,
    valid_after: int,
    valid_before: int,
    nonce_hex: str,
) -> dict[str, Any]:
    """EIP-712 TransferWithAuthorization (EIP-3009) typed-data payload."""
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"},
            ],
        },
        "domain": {
            "name": token_name,
            "version": "2",
            "chainId": chain_id,
            "verifyingContract": verifying_contract,
        },
        "primaryType": "TransferWithAuthorization",
        "message": {
            "from": frm,
            "to": to,
            "value": value,
            "validAfter": valid_after,
            "validBefore": valid_before,
            "nonce": nonce_hex,
        },
    }


def build_payment_payload(
    account,
    *,
    network: str,
    pay_to: str,
    price_usd: float,
    app_code: Optional[str] = None,
    service_codes: Optional[list[str]] = None,
    valid_for_seconds: int = 600,
) -> dict[str, Any]:
    """Sign an EIP-3009 authorization and build a builder-code-aware payload.

    Args:
        account: an ``eth_account`` ``LocalAccount`` (the payer).
        network: CAIP-2 id or alias (``base`` / ``base-sepolia``).
        pay_to: seller payout address.
        price_usd: price in USD (converted to USDC atomic units).
        app_code: Builder Code app code to echo. Defaults to the configured
            ``VIGIL_X402_APP_CODE`` via :func:`x402.client_echo_extension`.
        service_codes: optional client service code(s) (``s``).
        valid_for_seconds: authorization validity window.

    Returns:
        An x402 v2 ``exact`` EVM PaymentPayload dict ready to base64-encode.
    """
    from eth_account.messages import encode_typed_data
    from eth_utils import to_checksum_address

    caip2 = _resolve_network(network)
    if caip2 not in USDC_BY_NETWORK:
        raise ValueError(f"unsupported network: {network}")
    usdc, token_name = USDC_BY_NETWORK[caip2]
    usdc = to_checksum_address(usdc)
    pay_to = to_checksum_address(pay_to)
    chain_id = int(caip2.split(":")[1])
    value = int(round(price_usd * (10**USDC_DECIMALS)))
    now = int(time.time())
    valid_after = 0
    valid_before = now + valid_for_seconds
    nonce = "0x" + secrets.token_hex(32)

    typed = _eip3009_typed_data(
        chain_id, usdc, token_name, account.address, pay_to, value, valid_after, valid_before, nonce
    )
    signed = account.sign_message(encode_typed_data(full_message=typed))
    # CDP schema requires a 0x-prefixed signature (^0x[0-9a-fA-F]{130,}$);
    # HexBytes.hex() may omit the prefix depending on the library version.
    sig = signed.signature.hex()
    if not sig.startswith("0x"):
        sig = "0x" + sig

    payload: dict[str, Any] = {
        "x402Version": 2,
        "accepted": {
            "scheme": "exact",
            "network": caip2,
            "asset": usdc,
            "amount": str(value),
            "payTo": pay_to,
            "maxTimeoutSeconds": 60,
            "extra": {"assetTransferMethod": "eip3009", "name": token_name, "version": "2"},
        },
        "payload": {
            "signature": sig,
            "authorization": {
                "from": account.address,
                "to": pay_to,
                "value": str(value),
                "validAfter": str(valid_after),
                "validBefore": str(valid_before),
                "nonce": nonce,
            },
        },
    }

    # THE attribution step: echo the Builder Code so `a` lands onchain.
    # Defaults to VIGIL's configured app code unless an explicit one is given.
    if app_code is not None:
        ext = {x402.BUILDER_CODE_EXT: {"info": {"a": app_code}}} if app_code else None
        if ext and service_codes:
            ext[x402.BUILDER_CODE_EXT]["info"]["s"] = list(service_codes)
    else:
        ext = x402.client_echo_extension(service_codes)
    if ext:
        payload["extensions"] = ext
    return payload


def encode_payment_header(payload: dict[str, Any]) -> str:
    """Base64-encode a payment payload for the ``X-PAYMENT`` header."""
    return base64.b64encode(json.dumps(payload).encode()).decode()


async def pay_and_call(
    endpoint: str,
    tool: str,
    arguments: dict[str, Any],
    *,
    account,
    network: str = "base",
    pay_to: str,
    price_usd: float,
    service_codes: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Pay for and call a VIGIL (or any x402) tool, attributing VIGIL's code.

    Builds the builder-code-aware payment, attaches the ``X-PAYMENT`` header and
    POSTs the JSON-RPC ``tools/call``. Returns a dict with the HTTP status, the
    JSON body, and the settlement tx hash (if the server settled).
    """
    import httpx

    payload = build_payment_payload(
        account,
        network=network,
        pay_to=pay_to,
        price_usd=price_usd,
        service_codes=service_codes,
    )
    header = encode_payment_header(payload)
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            endpoint,
            json=body,
            headers={"Content-Type": "application/json", "X-PAYMENT": header},
        )
        settle_hdr = resp.headers.get("X-PAYMENT-RESPONSE", "")
        tx = None
        if settle_hdr:
            try:
                tx = json.loads(base64.b64decode(settle_hdr)).get("transaction")
            except Exception:  # noqa: BLE001
                tx = None
        try:
            data = resp.json()
        except Exception:  # noqa: BLE001
            data = {"raw": resp.text[:1000]}
        return {"status": resp.status_code, "body": data, "settlement_tx": tx}
