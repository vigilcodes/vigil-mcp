"""Token approval scanner — list and flag risky ERC-20/ERC-721 approvals."""

import os
from typing import Optional

import httpx
from pydantic import BaseModel


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


class ApprovalScanner:
    """Scan wallet token approvals via VIGIL API or direct RPC."""

    def __init__(self):
        self.api_base = os.getenv("VIGIL_API", "https://api.bankr.bot/vigil")
        self.api_key = os.getenv("BANKR_API_KEY", "")
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
        if self.api_key:
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
            # Get Approval events where wallet is the owner
            resp = await client.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "eth_getLogs",
                    "params": [
                        {
                            "topics": [approval_topic, wallet_padded],
                            "fromBlock": "0x1",  # Would use indexed blocks in production
                            "toBlock": "latest",
                        }
                    ],
                },
            )
            resp.raise_for_status()
            logs = resp.json().get("result", [])

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

    def _assess_risk(self, token: str, spender: str, is_unlimited: bool) -> str:
        """Assess risk level for an approval."""
        if spender.lower() in SAFE_SPENDERS:
            return "low" if is_unlimited else "safe"

        if is_unlimited:
            return "critical"
        return "medium"
