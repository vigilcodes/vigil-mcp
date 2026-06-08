"""Token approval scanner — list and flag risky ERC-20/ERC-721 approvals."""

import asyncio
import os
from typing import Optional

import httpx
from pydantic import BaseModel

from vigil_mcp.scanners.goplus import GoPlusScanner
from vigil_mcp.scanners.known_contracts import lookup_known_contract


class Approval(BaseModel):
    token_address: str
    token_symbol: str
    token_name: str
    spender_address: str
    spender_name: Optional[str] = None
    amount: str
    amount_usd: Optional[float] = None
    risk: str  # critical, high, medium, low, safe
    approved_at: Optional[str] = None
    last_used: Optional[str] = None


class ApprovalScanResult(BaseModel):
    wallet: str
    chain: str
    approvals: list[Approval]
    total: int
    summary: dict[str, int]


# Unlimited approval sentinel
UNLIMITED = "115792089237316195423570985008687907853269984665640564039457584007913129639935"

# Known risky spender patterns
RISKY_SPENDERS = {
    "critical": [
        "unknown",
        "unverified",
        "proxy-no-verify",
    ],
    "high": [
        "unverified-router",
        "deprecated-protocol",
    ],
}

# Known safe spenders (whitelist)
SAFE_SPENDERS = {
    "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD".lower(),  # Uniswap Universal Router
    "0x2626664c2603336E57B271c5C0b26F421741e481".lower(),  # Uniswap V3 Router (Base)
    "0xE592427A0AEce92De3Edee1F18E0157C05861564".lower(),  # Uniswap V3 Router
    "0xDef1C0ded9bec7F1a1670819833240f027b25EfF".lower(),  # 0x Exchange Proxy
    "0x1111111254fb6c44bAC0beD2854e76F90643097d".lower(),  # 1inch Router
    "0x1111111254EEB25477B68fb85Ed929f73A960582".lower(),  # 1inch V5 Router
}

# Human-readable labels for safe spenders (used to populate spender_name).
# Lookup is lowercase-keyed to match SAFE_SPENDERS.
SAFE_SPENDER_NAMES: dict[str, str] = {
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router",
    "0x2626664c2603336e57b271c5c0b26f421741e481": "Uniswap V3 Router (Base)",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
    "0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch Router",
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch V5 Router",
}


class ApprovalScanner:
    """Scan wallet token approvals via VIGIL API or direct RPC."""

    def __init__(self):
        self.api_base = os.getenv("VIGIL_API", "")
        self.api_key = os.getenv("BANKR_API_KEY", "")
        self.goplus = GoPlusScanner()
        self.rpc_urls = {
            "base": os.getenv("BASE_RPC", "https://base.publicnode.com"),
            "ethereum": os.getenv("ETH_RPC", "https://eth.llamarpc.com"),
            "polygon": os.getenv("POLYGON_RPC", "https://polygon-rpc.com"),
            "arbitrum": os.getenv("ARBITRUM_RPC", "https://arb1.arbitrum.io/rpc"),
        }

    async def scan(
        self, wallet: str, chain: str, risk_filter: Optional[str] = None
    ) -> ApprovalScanResult:
        """Scan all approvals for a wallet."""
        # Try API first, fallback to direct RPC
        if self.api_base and self.api_key:
            return await self._scan_via_api(wallet, chain, risk_filter)
        return await self._scan_via_rpc(wallet, chain, risk_filter)

    async def _scan_via_api(
        self, wallet: str, chain: str, risk_filter: Optional[str]
    ) -> ApprovalScanResult:
        """Scan via VIGIL hosted API."""
        params = {"wallet": wallet, "chain": chain}
        if risk_filter:
            params["risk"] = risk_filter

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.api_base}/approvals",
                params=params,
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            resp.raise_for_status()
            data = resp.json()

        approvals = [Approval(**a) for a in data["approvals"]]
        summary = data.get("summary", {})

        return ApprovalScanResult(
            wallet=wallet,
            chain=chain,
            approvals=approvals,
            total=len(approvals),
            summary=summary,
        )

    async def _scan_via_rpc(
        self, wallet: str, chain: str, risk_filter: Optional[str]
    ) -> ApprovalScanResult:
        """Scan via direct RPC — reads Approval events from chain."""
        rpc_url = self.rpc_urls.get(chain)
        if not rpc_url:
            raise ValueError(f"No RPC configured for chain '{chain}'")

        # ERC-20 Approval event signature
        approval_topic = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
        wallet_padded = "0x" + wallet[2:].lower().zfill(64)

        async with httpx.AsyncClient(timeout=30) as client:
            # Determine the current head so we can scan a BOUNDED recent window.
            # An unbounded fromBlock=0x1..latest query is rejected by most RPC
            # providers (QuickNode returns HTTP 413 "Request Entity Too Large").
            head_resp = await client.post(
                rpc_url,
                json={"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber"},
            )
            head_resp.raise_for_status()
            head_hex = head_resp.json().get("result", "0x0")
            head = int(head_hex, 16) if head_hex not in (None, "0x") else 0

            # Scan the most recent ~lookback blocks in fixed-size chunks. Base
            # produces ~2s blocks (~43k/day), so the default ~200k window covers
            # several days of recent activity while staying fast and within the
            # provider's per-request log limits. Chunks run concurrently.
            lookback = int(os.getenv("VIGIL_APPROVAL_LOOKBACK_BLOCKS", "200000"))
            chunk = int(os.getenv("VIGIL_APPROVAL_LOG_CHUNK", "9000"))
            start = max(0, head - lookback)

            ranges: list[tuple[int, int]] = []
            frm = start
            while frm <= head:
                to = min(frm + chunk, head)
                ranges.append((frm, to))
                frm = to + 1

            async def _fetch(frm_to: tuple[int, int]) -> list[dict]:
                lo, hi = frm_to
                r = await client.post(
                    rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "eth_getLogs",
                        "params": [
                            {
                                "topics": [approval_topic, wallet_padded],
                                "fromBlock": hex(lo),
                                "toBlock": hex(hi),
                            }
                        ],
                    },
                )
                if r.status_code == 200:
                    out = r.json().get("result")
                    if isinstance(out, list):
                        return out
                return []

            chunk_results = await asyncio.gather(*(_fetch(rg) for rg in ranges))
            logs: list[dict] = [log for sub in chunk_results for log in sub]

        approvals = []
        seen = set()

        for log in logs:
            token_addr = log["address"].lower()
            spender = "0x" + log["topics"][2][26:]
            amount_hex = log.get("data", "0x0")

            key = f"{token_addr}:{spender}"
            if key in seen:
                continue
            seen.add(key)

            amount_int = int(amount_hex, 16) if amount_hex != "0x" else 0
            is_unlimited = amount_int >= int(UNLIMITED)
            is_zero = amount_int == 0

            if is_zero:
                continue  # Skip revoked approvals

            risk = self._assess_risk(token_addr, spender, is_unlimited)

            approvals.append(
                Approval(
                    token_address=token_addr,
                    token_symbol=token_addr[:10],
                    token_name="Unknown",
                    spender_address=spender,
                    amount="unlimited" if is_unlimited else str(amount_int),
                    risk=risk,
                )
            )

        # Enrich token_symbol/token_name and spender_name with real labels:
        # blue-chip registry first (instant, accurate), then GoPlus (concurrent).
        await self._enrich_approvals(approvals, chain)

        # Filter by risk level if specified
        if risk_filter:
            risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "safe": 4}
            min_risk = risk_order.get(risk_filter, 4)
            approvals = [a for a in approvals if risk_order.get(a.risk, 4) <= min_risk]

        summary = {}
        for level in ["critical", "high", "medium", "low", "safe"]:
            summary[level] = sum(1 for a in approvals if a.risk == level)

        return ApprovalScanResult(
            wallet=wallet,
            chain=chain,
            approvals=approvals,
            total=len(approvals),
            summary=summary,
        )

    async def _enrich_approvals(self, approvals: list, chain: str) -> None:
        """Fill in token_symbol / token_name and spender_name on each approval.

        Strategy: try the blue-chip registry first (free, instant). For tokens
        not in the registry, fan out concurrent GoPlus lookups. Spenders get
        labels from the SAFE_SPENDER_NAMES dict and the registry as well.
        """
        # Spender labels first — cheap, sync.
        for a in approvals:
            sp_lower = a.spender_address.lower()
            label = SAFE_SPENDER_NAMES.get(sp_lower)
            if not label:
                known = lookup_known_contract(chain, sp_lower)
                if known:
                    label = known.name
            if label:
                a.spender_name = label

        # Token labels — registry pass first, then GoPlus for the rest.
        unresolved: list = []
        for a in approvals:
            known = lookup_known_contract(chain, a.token_address)
            if known:
                a.token_symbol = known.symbol
                a.token_name = known.name
            else:
                unresolved.append(a)

        if not unresolved:
            return

        # GoPlus is keyless and rate-limited; one lookup per unique address.
        unique_addrs: dict[str, list] = {}
        for a in unresolved:
            unique_addrs.setdefault(a.token_address, []).append(a)

        async def _one(addr: str):
            try:
                return addr, await self.goplus.token_security(addr, chain)
            except Exception:  # noqa: BLE001 — best-effort enrichment
                return addr, None

        results = await asyncio.gather(*(_one(addr) for addr in unique_addrs))
        for addr, gp in results:
            if not gp or not gp.available:
                continue
            symbol = gp.token_symbol or None
            name = gp.token_name or None
            for a in unique_addrs[addr]:
                if symbol:
                    a.token_symbol = symbol
                if name:
                    a.token_name = name

    def _assess_risk(self, token: str, spender: str, is_unlimited: bool) -> str:
        """Assess risk level for an approval."""
        if spender.lower() in SAFE_SPENDERS:
            return "low" if is_unlimited else "safe"

        if is_unlimited:
            return "critical"
        return "medium"
