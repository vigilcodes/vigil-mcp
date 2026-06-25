#!/usr/bin/env python3
"""vigil_check_attribution.py — verify x402 Builder Code attribution ONCHAIN.

Read-only. Moves no funds, signs nothing. Answers one question with hard
evidence: are VIGIL's x402 settlements actually carrying our Builder Code
(ERC-8021 app code ``a``) onchain — i.e. would they count on the Base
leaderboard — or only the facilitator's own wallet code (``w``)?

Method
------
1. Live USDC balanceOf(payTo) via Base RPC (ground truth).
2. USDC transfers into payTo via Blockscout (free, no key, full history).
3. For each settlement tx: pull calldata, strip the standard EIP-3009
   transferWithAuthorization args, CBOR-decode the ERC-8021 suffix, and report
   which builder codes (a/w/s) actually landed onchain.

Env: VIGIL_X402_PAY_TO, VIGIL_X402_APP_CODE, BASE_RPC (optional).
"""

import json
import os
import sys
import urllib.request

USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
RPC = os.getenv("BASE_RPC", "https://mainnet.base.org")
BLOCKSCOUT = "https://base.blockscout.com/api/v2"
# transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)
EIP3009_SELECTOR = "0xe3ee160e"
STD_CALLDATA_HEXLEN = 2 + 8 + 9 * 64  # "0x" + selector + 9 words = 586 chars


def _rpc(method, params):
    req = urllib.request.Request(
        RPC,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r).get("result")


def _get(url):
    headers = {"User-Agent": "vigil-attribution-check/1.0", "Accept": "application/json"}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.load(r)


def _mask(url: str) -> str:
    """Hide any API key embedded in a private RPC URL before printing."""
    try:
        from urllib.parse import urlsplit

        p = urlsplit(url)
        return f"{p.scheme}://{p.netloc}/…" if p.path not in ("", "/") else f"{p.scheme}://{p.netloc}"
    except Exception:  # noqa: BLE001
        return "(rpc configured)"


def usdc_balance(addr):
    data = "0x70a08231" + "0" * 24 + addr[2:].lower()
    res = _rpc("eth_call", [{"to": USDC, "data": data}, "latest"])
    return int(res, 16) / 1e6 if res and res != "0x" else 0.0


def incoming_usdc_txs(addr):
    url = f"{BLOCKSCOUT}/addresses/{addr}/token-transfers?type=ERC-20&token={USDC}"
    try:
        items = _get(url).get("items", [])
    except Exception as e:  # noqa: BLE001
        print(f"  (blockscout lookup failed: {e})")
        return None
    out = []
    for it in items:
        to = (it.get("to") or {}).get("hash", "").lower()
        if to == addr.lower():
            out.append(
                {
                    "tx": it.get("transaction_hash"),
                    "value": int(it.get("total", {}).get("value", "0")) / 1e6,
                    "from": (it.get("from") or {}).get("hash", "?"),
                    "ts": it.get("timestamp", "?"),
                }
            )
    return out


def _cbor_decode_codes(b: bytes) -> dict:
    """Minimal CBOR decode for the ERC-8021 attribution map {a?,w?,s?}."""
    out = {}
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


def decode_attribution(tx_hash):
    inp = _rpc("eth_getTransactionByHash", [tx_hash]).get("input", "")
    if not inp.startswith(EIP3009_SELECTOR):
        return {"selector": inp[:10], "codes": {}, "note": "not transferWithAuthorization"}
    if len(inp) <= STD_CALLDATA_HEXLEN:
        return {"selector": inp[:10], "codes": {}, "note": "no ERC-8021 suffix appended"}
    suffix_hex = inp[STD_CALLDATA_HEXLEN:]
    b = bytes.fromhex(suffix_hex)
    # CBOR payload is the leading bytes; the trailing 0x8021 repeats are the magic marker.
    codes = _cbor_decode_codes(b)
    return {"selector": inp[:10], "suffix": suffix_hex, "codes": codes}


def main():
    pay_to = (len(sys.argv) > 1 and sys.argv[1]) or os.getenv("VIGIL_X402_PAY_TO", "")
    app_code = os.getenv("VIGIL_X402_APP_CODE", "").strip()
    if not pay_to:
        print("Error: set VIGIL_X402_PAY_TO or pass the wallet as arg 1.", file=sys.stderr)
        sys.exit(1)

    print("👁  VIGIL x402 onchain attribution check")
    print(f"    wallet      : {pay_to}")
    print(f"    expected app: {app_code or '(unset)'}")
    print(f"    rpc         : {_mask(RPC)}\n")

    bal = usdc_balance(pay_to)
    print(f"Live USDC balance (payTo): {bal} USDC")

    txs = incoming_usdc_txs(pay_to)
    if txs is None:
        print("\nVERDICT: ⚠️  Explorer unavailable — could not enumerate settlements.")
        print(f"         Balance is {bal} USDC (nonce-0 wallets only receive), so funds DID arrive.")
        print("         Re-run when the explorer is reachable to decode onchain attribution.")
        return
    print(f"Indexed incoming USDC settlements: {len(txs)}\n")

    app_seen = False
    for t in txs:
        attr = decode_attribution(t["tx"])
        codes = attr.get("codes", {})
        if codes.get("a") == app_code and app_code:
            app_seen = True
        print(f"• {t['value']} USDC  {t['ts']}")
        print(f"  tx   https://basescan.org/tx/{t['tx']}")
        print(f"  from {t['from']}")
        print(f"  onchain builder codes: {codes or '(none)'}  {attr.get('note', '')}\n")

    print("─" * 60)
    if not txs:
        print("VERDICT: ❌ No indexed settlements. Builder code NOT on leaderboard.")
    elif app_seen:
        print(f"VERDICT: ✅ App code '{app_code}' IS encoded onchain — counts on the leaderboard.")
    else:
        print(f"VERDICT: ⚠️  Settlements landed, but app code '{app_code}' is NOT onchain.")
        print("         Only the facilitator's wallet code (w) is attributed.")
        print("         => VIGIL is NOT credited on the Base leaderboard yet.")


if __name__ == "__main__":
    main()
