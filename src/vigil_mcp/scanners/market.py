"""Market context — token price, liquidity, and pool age via DexScreener (no API key).

DexScreener's public API is free and keyless. We use it to add market context to
security verdicts: a low safety score combined with thin liquidity and a brand-new
pool is a much stronger rug signal than the bytecode alone.
"""

import os
import time
from typing import Optional

import httpx
from pydantic import BaseModel

DEXSCREENER_BASE = os.getenv("DEXSCREENER_API", "https://api.dexscreener.com")

# Map our chain names to DexScreener chain ids.
_CHAIN_IDS = {
    "base": "base",
    "ethereum": "ethereum",
    "polygon": "polygon",
    "arbitrum": "arbitrum",
}


class MarketInfo(BaseModel):
    found: bool = False
    price_usd: Optional[float] = None
    liquidity_usd: Optional[float] = None
    volume_24h_usd: Optional[float] = None
    fdv_usd: Optional[float] = None
    pair_address: Optional[str] = None
    dex: Optional[str] = None
    pair_created_at: Optional[int] = None  # unix ms
    pool_age_hours: Optional[float] = None
    liquidity_risk: str = "unknown"  # critical, high, medium, low, unknown
    notes: list[str] = []


def _assess_liquidity_risk(liquidity_usd: Optional[float], age_hours: Optional[float]) -> str:
    """Heuristic liquidity/age risk used to enrich security verdicts."""
    if liquidity_usd is None:
        return "unknown"
    if liquidity_usd < 1_000:
        return "critical"
    if liquidity_usd < 10_000:
        return "high"
    if liquidity_usd < 50_000:
        # Very new pools with modest liquidity stay riskier for longer.
        if age_hours is not None and age_hours < 24:
            return "high"
        return "medium"
    return "low"


class MarketScanner:
    """Fetch market context for a token from DexScreener (keyless)."""

    def __init__(self) -> None:
        self.base = DEXSCREENER_BASE

    async def get_market(self, token: str, chain: str) -> MarketInfo:
        """Return market context for the most liquid pair of `token` on `chain`."""
        chain_id = _CHAIN_IDS.get(chain.lower())
        url = f"{self.base}/latest/dex/tokens/{token}"

        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:  # noqa: BLE001 — market data is best-effort context
            return MarketInfo(found=False, notes=[f"DexScreener lookup failed: {e}"])

        pairs = data.get("pairs") or []
        if chain_id:
            pairs = [p for p in pairs if (p.get("chainId") or "").lower() == chain_id] or pairs
        if not pairs:
            return MarketInfo(found=False, notes=["No DEX pairs found for this token"])

        # Pick the deepest pool (highest liquidity) as the canonical pair.
        def _liq(p: dict) -> float:
            return float((p.get("liquidity") or {}).get("usd") or 0)

        token_l = token.lower()

        # Prefer pairs where the requested token is the BASE token, because
        # DexScreener's priceUsd refers to the base token. This avoids reporting
        # the counter-asset's price (e.g. WETH) when our token is the quote side.
        base_pairs = [
            p for p in pairs if ((p.get("baseToken") or {}).get("address") or "").lower() == token_l
        ]
        price_pairs = base_pairs or pairs
        best = max(price_pairs, key=_liq)

        # Liquidity should reflect the deepest pool across ALL pairs for the token.
        deepest = max(pairs, key=_liq)
        liquidity_usd = _liq(deepest) or None

        # Only trust priceUsd when our token is actually the base token of `best`.
        is_base = ((best.get("baseToken") or {}).get("address") or "").lower() == token_l
        price_usd = float(best["priceUsd"]) if (is_base and best.get("priceUsd")) else None
        volume_24h = float((best.get("volume") or {}).get("h24") or 0) or None
        fdv = float(best.get("fdv")) if best.get("fdv") else None
        created_ms = best.get("pairCreatedAt") or deepest.get("pairCreatedAt")

        age_hours: Optional[float] = None
        if created_ms:
            age_hours = round((time.time() * 1000 - created_ms) / 3_600_000, 1)

        risk = _assess_liquidity_risk(liquidity_usd, age_hours)

        notes: list[str] = []
        if liquidity_usd is not None and liquidity_usd < 10_000:
            notes.append(f"Thin liquidity (~${liquidity_usd:,.0f}) — easy to manipulate or rug")
        if age_hours is not None and age_hours < 24:
            notes.append(f"Very new pool (~{age_hours}h old) — limited track record")

        return MarketInfo(
            found=True,
            price_usd=price_usd,
            liquidity_usd=liquidity_usd,
            volume_24h_usd=volume_24h,
            fdv_usd=fdv,
            pair_address=best.get("pairAddress"),
            dex=best.get("dexId"),
            pair_created_at=created_ms,
            pool_age_hours=age_hours,
            liquidity_risk=risk,
            notes=notes,
        )
