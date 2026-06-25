"""Onchain attribution reporting for VIGIL's x402 settlements.

Reads, from public Base data, which USDC settlements into the payout wallet
carried VIGIL's Builder Code (ERC-8021 app code ``a``) onchain — turning the
private "is attribution working?" question into a public, verifiable proof
that VIGIL is paid for and credited on Base.

Read-only: no keys, no signing, no fund movement. All inputs are public chain
data + a free explorer.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Optional

USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
BLOCKSCOUT = "https://base.blockscout.com/api/v2"
# transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)
EIP3009_SELECTOR = "0xe3ee160e"
STD_CALLDATA_HEXLEN = 2 + 8 + 9 * 64  # "0x" + selector + 9 ABI words


def _rpc_url() -> str:
    return os.getenv("BASE_RPC", "https://mainnet.base.org")


def _rpc(method: str, params: list) -> Any:
    req = urllib.request.Request(
        _rpc_url(),
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r).get("result")


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "vigil-attribution/1.0", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.load(r)


def _cbor_decode_codes(b: bytes) -> dict:
    """Minimal CBOR decode for the ERC-8021 attribution map {a?,w?,s?}."""
    out: dict[str, str] = {}
    try:
        if not b or b[0] >> 5 != 5:  # major type 5 = map
            return out
        n = b[0] & 0x1F
        i = 1
        for _ in range(n):
            klen = b[i] & 0x1F
            key = b[i + 1 : i + 1 + klen].decode()
            i += 1 + klen
            if b[i] >> 5 == 3:  # text string value
                vlen = b[i] & 0x1F
                val = b[i + 1 : i + 1 + vlen].decode()
                i += 1 + vlen
                out[key] = val
            else:
                break
    except Exception:  # noqa: BLE001
        pass
    return out


def _decode_attribution(tx_hash: str) -> dict:
    tx = _rpc("eth_getTransactionByHash", [tx_hash]) or {}
    inp = tx.get("input", "") or ""
    if not inp.startswith(EIP3009_SELECTOR) or len(inp) <= STD_CALLDATA_HEXLEN:
        return {}
    try:
        return _cbor_decode_codes(bytes.fromhex(inp[STD_CALLDATA_HEXLEN:]))
    except Exception:  # noqa: BLE001
        return {}


def _incoming_usdc(addr: str) -> Optional[list[dict]]:
    url = f"{BLOCKSCOUT}/addresses/{addr}/token-transfers?type=ERC-20&token={USDC}"
    try:
        items = _get(url).get("items", [])
    except Exception:  # noqa: BLE001
        return None
    out = []
    for it in items:
        to = (it.get("to") or {}).get("hash", "").lower()
        if to == addr.lower():
            out.append(
                {
                    "tx": it.get("transaction_hash"),
                    "value_usdc": int(it.get("total", {}).get("value", "0")) / 1e6,
                    "timestamp": it.get("timestamp"),
                }
            )
    return out


def build_attribution_report(max_txs: int = 25) -> dict[str, Any]:
    """Public proof: VIGIL's x402 settlements + which carry our builder code onchain.

    Returns a JSON-able dict. Never raises — explorer/RPC failures degrade to a
    partial report with an explanatory note (so the endpoint stays up).
    """
    pay_to = os.getenv("VIGIL_X402_PAY_TO", "")
    app_code = os.getenv("VIGIL_X402_APP_CODE", "").strip()
    report: dict[str, Any] = {
        "pay_to": pay_to,
        "builder_code": app_code,
        "network": "base",
        "asset": "USDC",
        "settlements": [],
        "attributed_count": 0,
        "total_count": 0,
        "note": "",
    }
    if not pay_to:
        report["note"] = "VIGIL_X402_PAY_TO not configured"
        return report

    txs = _incoming_usdc(pay_to)
    if txs is None:
        report["note"] = "explorer unavailable; could not enumerate settlements"
        return report

    attributed = 0
    settlements = []
    for t in txs[:max_txs]:
        try:
            codes = _decode_attribution(t["tx"]) if t.get("tx") else {}
        except Exception:  # noqa: BLE001 — one bad tx must not sink the whole report
            codes = {}
        is_attr = bool(app_code) and codes.get("a") == app_code
        if is_attr:
            attributed += 1
        settlements.append(
            {
                "tx": t["tx"],
                "value_usdc": t["value_usdc"],
                "timestamp": t["timestamp"],
                "builder_codes": codes,
                "attributed": is_attr,
            }
        )
    report["settlements"] = settlements
    report["total_count"] = len(settlements)
    report["attributed_count"] = attributed
    report["note"] = "attribution decoded from ERC-8021 suffix in settlement calldata"
    return report
