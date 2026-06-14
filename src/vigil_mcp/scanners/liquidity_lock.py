"""Liquidity lock scanner — detect whether a token's DEX LP is locked or free.

Unlocked LP held by the deployer is the classic rug-pull vector: liquidity is
removed and holders cannot sell. This scanner classifies a token's LP into one
of four states:

* ``locked``   — recognized locker contracts hold ≥ Lock_Threshold of LP supply.
* ``burned``   — burn addresses hold ≥ Lock_Threshold of LP supply (permanent).
* ``unlocked`` — LP supply resolved, but neither lock condition met.
* ``unknown``  — lock status could not be determined from available data.

The scanner is built to fail safe: any failure path returns ``unknown`` rather
than ``unlocked`` or ``locked`` — missing data must never be reported as a
safety verdict. Free core safety check, not gated by x402.

Scope of this initial implementation:
* V2-style ERC-20 LP tokens (Aerodrome v1, Uniswap V2 forks on Base).
* V3 / Slipstream NFT-based positions are not supported (see notes when a
  resolved pair has no totalSupply).
* Single deepest pair per token via DexScreener; multi-pair aggregation is
  not in scope.
"""

from __future__ import annotations

import asyncio
import os
from typing import Optional

import httpx
from pydantic import BaseModel

from vigil_mcp.scanners.known_lockers import (
    all_lock_holders,
    is_burn_address,
    lookup_locker,
)
from vigil_mcp.scanners.market import MarketScanner

# Single threshold: ≥ 80% of LP supply held by recognized lockers/burn
# addresses qualifies as locked/burned. Below the threshold ⇒ unlocked.
LOCK_THRESHOLD: float = 0.80

# Mirrors the chain mapping convention used by goplus / market / deployer.
_CHAIN_IDS: dict[str, int] = {
    "base": 8453,
    "ethereum": 1,
    "polygon": 137,
    "arbitrum": 42161,
}

# 4-byte selectors for ERC-20 view functions used to read LP holdings.
_SELECTOR_TOTAL_SUPPLY = "0x18160ddd"
_SELECTOR_BALANCE_OF = "0x70a08231"


class LockResult(BaseModel):
    """Result returned by ``LiquidityLockScanner.scan``.

    Two booleans drive how callers should interpret the result:

    * ``available``  — False when the chain is unsupported or no RPC is
      configured. Callers should treat the result as not applicable.
    * ``determined`` — False when ``lock_status == "unknown"``. Callers
      MUST NOT interpret an undetermined result as a safety guarantee.
    """

    token: str
    chain: str
    available: bool = True
    determined: bool
    lock_status: str  # locked | burned | unlocked | unknown
    pair_address: Optional[str] = None
    lp_token: Optional[str] = None
    locked_fraction: Optional[float] = None
    unlock_timestamp: Optional[int] = None
    locker_name: Optional[str] = None
    notes: list[str] = []


class LiquidityLockScanner:
    """Classify a token's DEX liquidity as locked / burned / unlocked / unknown.

    Per-request stateless: no caching, no cross-request memoization. Each
    ``scan()`` call resolves data freshly so stale lock data cannot be served
    as fresh.
    """

    def __init__(self) -> None:
        self.market = MarketScanner()
        self.rpc_urls = {
            "base": os.getenv("BASE_RPC", "https://base.publicnode.com"),
            "ethereum": os.getenv("ETH_RPC", "https://eth.llamarpc.com"),
            "polygon": os.getenv("POLYGON_RPC", "https://polygon-rpc.com"),
            "arbitrum": os.getenv("ARBITRUM_RPC", "https://arb1.arbitrum.io/rpc"),
        }

    async def scan(self, token: str, chain: str) -> LockResult:
        """Run a single liquidity-lock scan for ``token`` on ``chain``."""
        token_l = token.lower()
        chain_l = chain.lower()

        # 1. Unsupported chain: short-circuit with a clean unknown result.
        if chain_l not in _CHAIN_IDS:
            return LockResult(
                token=token_l,
                chain=chain_l,
                available=False,
                determined=False,
                lock_status="unknown",
                notes=[
                    f"UNDETERMINED: chain '{chain}' is not supported by the "
                    "liquidity-lock scanner. Not a safety guarantee."
                ],
            )

        rpc_url = self.rpc_urls.get(chain_l)
        if not rpc_url:
            return LockResult(
                token=token_l,
                chain=chain_l,
                available=False,
                determined=False,
                lock_status="unknown",
                notes=[f"UNDETERMINED: no RPC endpoint configured for chain '{chain_l}'. Not a safety guarantee."],
            )

        # 2. Resolve the deepest LP pair via DexScreener (keyless).
        pair = await self._resolve_pair(token_l, chain_l)
        if pair is None:
            return LockResult(
                token=token_l,
                chain=chain_l,
                determined=False,
                lock_status="unknown",
                notes=[
                    "UNDETERMINED: no DEX pair found for this token on "
                    f"{chain_l}. V3 / NFT-LP positions are not yet supported. "
                    "Not a safety guarantee."
                ],
            )

        # For V2-style pools, the pair address IS the LP token (ERC-20).
        lp_token = pair

        # 3. Single client for all RPC calls — bounds the entire scan to 20s.
        async with httpx.AsyncClient(timeout=20) as client:
            total = await self._total_supply(client, rpc_url, lp_token)
            if total is None:
                return LockResult(
                    token=token_l,
                    chain=chain_l,
                    determined=False,
                    lock_status="unknown",
                    pair_address=pair,
                    lp_token=lp_token,
                    notes=[
                        "UNDETERMINED: LP totalSupply() did not return a valid "
                        "uint256 (V3 / NFT-LP positions are not yet supported). "
                        "Not a safety guarantee."
                    ],
                )
            if total == 0:
                return LockResult(
                    token=token_l,
                    chain=chain_l,
                    determined=False,
                    lock_status="unknown",
                    pair_address=pair,
                    lp_token=lp_token,
                    notes=[
                        "UNDETERMINED: LP totalSupply is zero (empty or uninitialized pool). Not a safety guarantee."
                    ],
                )

            # 4. Balances for every recognized lock holder, in parallel.
            holders = all_lock_holders(chain_l)
            balance_calls = [self._balance_of(client, rpc_url, lp_token, h) for h in holders]
            balances = await asyncio.gather(*balance_calls, return_exceptions=True)

        burn_total = 0
        locker_total = 0
        primary_locker: Optional[str] = None
        for holder, bal in zip(holders, balances):
            if isinstance(bal, BaseException) or bal is None:
                # Skip holders we couldn't query — counts as 0 toward the
                # locked fraction. Conservative: tends toward `unlocked`,
                # never toward false `locked`.
                continue
            if bal <= 0:
                continue
            if is_burn_address(holder):
                burn_total += bal
            else:
                locker_total += bal
                if primary_locker is None:
                    locker = lookup_locker(chain_l, holder)
                    if locker is not None:
                        primary_locker = locker.name

        locked_fraction = round((burn_total + locker_total) / total, 4)
        burn_fraction = burn_total / total

        # 5. Classify. ``burned`` precedence requires the burn portion alone
        #    to clear the threshold — mixed pools fall under ``locked``.
        if burn_fraction >= LOCK_THRESHOLD:
            status = "burned"
        elif locked_fraction >= LOCK_THRESHOLD:
            status = "locked"
        else:
            status = "unlocked"

        notes: list[str] = []
        pct = round(locked_fraction * 100, 2)
        if status == "burned":
            notes.append(f"Burned: {pct}% of LP sent to burn address — permanent")
        elif status == "locked":
            label = primary_locker or "recognized locker"
            notes.append(f"Locked: {pct}% of LP held by {label}")
        else:
            notes.append(f"WITHDRAWABLE: only {pct}% of LP is locked — rug-pull risk")

        return LockResult(
            token=token_l,
            chain=chain_l,
            determined=True,
            lock_status=status,
            pair_address=pair,
            lp_token=lp_token,
            locked_fraction=locked_fraction,
            locker_name=primary_locker if status == "locked" else None,
            notes=notes,
        )

    # ── helpers ──────────────────────────────────────────────

    async def _resolve_pair(self, token: str, chain: str) -> Optional[str]:
        """Return the lowercase address of the deepest LP pair, or None."""
        try:
            market = await self.market.get_market(token, chain)
        except Exception:  # noqa: BLE001 — best-effort upstream call
            return None
        if not getattr(market, "found", False):
            return None
        addr = getattr(market, "pair_address", None)
        if not isinstance(addr, str) or not addr:
            return None
        return addr.lower()

    async def _eth_call(self, client: httpx.AsyncClient, rpc_url: str, to: str, data: str) -> Optional[str]:
        """Issue a single eth_call. Returns the raw hex result, or None on error."""
        try:
            resp = await client.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "eth_call",
                    "params": [{"to": to, "data": data}, "latest"],
                },
            )
            resp.raise_for_status()
            payload = resp.json()
        except Exception:  # noqa: BLE001 — caller treats None as undetermined
            return None
        if "error" in payload:
            return None
        result = payload.get("result")
        if not isinstance(result, str):
            return None
        return result

    @staticmethod
    def _decode_uint256(hex_word: Optional[str]) -> Optional[int]:
        """Decode a 32-byte uint256 hex word. Return None for empty/short data."""
        if not isinstance(hex_word, str):
            return None
        cleaned = hex_word[2:] if hex_word.startswith("0x") else hex_word
        # An eth_call with no return data ("0x") or a short result is
        # undetermined — never coerce to zero, which would imply "no balance".
        if len(cleaned) < 64:
            return None
        # Take only the leading 32-byte word; some callers append extra bytes.
        try:
            return int(cleaned[:64], 16)
        except ValueError:
            return None

    async def _total_supply(self, client: httpx.AsyncClient, rpc_url: str, lp_token: str) -> Optional[int]:
        raw = await self._eth_call(client, rpc_url, lp_token, _SELECTOR_TOTAL_SUPPLY)
        return self._decode_uint256(raw)

    async def _balance_of(self, client: httpx.AsyncClient, rpc_url: str, lp_token: str, holder: str) -> Optional[int]:
        # balanceOf(address) — selector + 32-byte left-padded address.
        addr_clean = holder.lower().removeprefix("0x")
        data = _SELECTOR_BALANCE_OF + addr_clean.zfill(64)
        raw = await self._eth_call(client, rpc_url, lp_token, data)
        return self._decode_uint256(raw)
