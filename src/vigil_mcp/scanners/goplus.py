"""GoPlus Security API client — keyless token risk data.

GoPlus exposes a free, keyless token-security endpoint that returns rich
risk signals (honeypot flag, buy/sell tax, mint/proxy/blacklist flags,
holder counts, open-source status). VIGIL uses it as the primary signal for
honeypot detection and contract scanning, falling back to on-chain RPC
heuristics when GoPlus has no data for a token.
"""

import hashlib
import os
import time
from typing import Any, Optional

import httpx
from pydantic import BaseModel

GOPLUS_BASE = os.getenv("GOPLUS_API", "https://api.gopluslabs.io/api/v1")

# VIGIL chain name -> GoPlus numeric chain id
_CHAIN_IDS = {
    "base": "8453",
    "ethereum": "1",
    "polygon": "137",
    "arbitrum": "42161",
}


def _b(v: Any) -> Optional[bool]:
    """GoPlus encodes booleans as "1"/"0" strings; None when unknown/absent."""
    if v is None or v == "":
        return None
    return str(v) == "1"


def _f(v: Any) -> Optional[float]:
    try:
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


class GoPlusResult(BaseModel):
    available: bool = True
    token_name: Optional[str] = None
    token_symbol: Optional[str] = None
    is_honeypot: Optional[bool] = None
    cannot_sell_all: Optional[bool] = None
    buy_tax: Optional[float] = None
    sell_tax: Optional[float] = None
    is_mintable: Optional[bool] = None
    is_proxy: Optional[bool] = None
    transfer_pausable: Optional[bool] = None
    hidden_owner: Optional[bool] = None
    can_take_back_ownership: Optional[bool] = None
    is_blacklisted: Optional[bool] = None
    is_open_source: Optional[bool] = None
    owner_address: Optional[str] = None
    creator_address: Optional[str] = None
    holder_count: Optional[int] = None
    note: str = ""


class GoPlusScanner:
    """Keyless GoPlus token-security client.

    Works anonymously, but if GOPLUS_APP_KEY/GOPLUS_APP_SECRET are set it
    authenticates for higher rate limits. The access token is cached and
    refreshed automatically; auth failures fall back to anonymous access.
    """

    def __init__(self) -> None:
        self.base = GOPLUS_BASE
        self.app_key = os.getenv("GOPLUS_APP_KEY", "")
        self.app_secret = os.getenv("GOPLUS_APP_SECRET", "")
        self._token: Optional[str] = None
        self._token_exp: float = 0.0

    async def _get_token(self, client: httpx.AsyncClient) -> Optional[str]:
        """Fetch (and cache) a GoPlus access token. Returns None if unavailable."""
        if not (self.app_key and self.app_secret):
            return None
        # Reuse cached token until ~5 min before expiry.
        if self._token and time.time() < self._token_exp - 300:
            return self._token
        try:
            t = str(int(time.time()))
            sign = hashlib.sha1(f"{self.app_key}{t}{self.app_secret}".encode()).hexdigest()
            resp = await client.post(
                f"{self.base}/token",
                json={"app_key": self.app_key, "time": int(t), "sign": sign},
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("code") == 1:
                res = data.get("result") or {}
                self._token = res.get("access_token")
                # expires_in is a TTL in seconds (GoPlus returns 7200 = 2h).
                ttl = float(res.get("expires_in") or 3600)
                self._token_exp = time.time() + ttl
                return self._token
        except Exception:  # noqa: BLE001 — auth is optional, fall back to anonymous
            return None
        return None

    async def token_security(self, token: str, chain: str) -> GoPlusResult:
        chain_id = _CHAIN_IDS.get(chain.lower())
        if not chain_id:
            return GoPlusResult(
                available=False, note=f"GoPlus: unsupported chain '{chain}'"
            )

        url = f"{self.base}/token_security/{chain_id}"
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                headers = {}
                access = await self._get_token(client)
                if access:
                    headers["Authorization"] = access
                resp = await client.get(
                    url, params={"contract_addresses": token}, headers=headers
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:  # noqa: BLE001 — best-effort enrichment
            return GoPlusResult(available=False, note=f"GoPlus lookup failed: {e}")

        if data.get("code") != 1:
            return GoPlusResult(
                available=False, note=f"GoPlus: {data.get('message', 'no data')}"
            )

        result_map = data.get("result") or {}
        row = result_map.get(token.lower()) or (
            next(iter(result_map.values()), None) if result_map else None
        )
        if not row:
            return GoPlusResult(available=False, note="GoPlus: no record for token")

        return GoPlusResult(
            available=True,
            token_name=row.get("token_name") or None,
            token_symbol=row.get("token_symbol") or None,
            is_honeypot=_b(row.get("is_honeypot")),
            cannot_sell_all=_b(row.get("cannot_sell_all")),
            buy_tax=_f(row.get("buy_tax")),
            sell_tax=_f(row.get("sell_tax")),
            is_mintable=_b(row.get("is_mintable")),
            is_proxy=_b(row.get("is_proxy")),
            transfer_pausable=_b(row.get("transfer_pausable")),
            hidden_owner=_b(row.get("hidden_owner")),
            can_take_back_ownership=_b(row.get("can_take_back_ownership")),
            is_blacklisted=_b(row.get("is_blacklisted")),
            is_open_source=_b(row.get("is_open_source")),
            owner_address=row.get("owner_address") or None,
            creator_address=row.get("creator_address") or None,
            holder_count=int(row["holder_count"]) if row.get("holder_count") else None,
            note="GoPlus Security",
        )
