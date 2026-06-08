"""Base MCP bridge — connect VIGIL security layer to Base MCP protocol.

Base MCP allows AI agents to interact with DeFi on Base via natural language.
VIGIL adds a security pre-check layer: 'AI prepares, VIGIL verifies, human approves'.
"""

import os
from typing import Any

import httpx
from pydantic import BaseModel


class SecurityCheckResult(BaseModel):
    wallet: str
    safe_to_proceed: bool
    risk_level: str
    warnings: list[str]
    pre_trade_checks: dict[str, Any]
    recommendations: list[str]


class BaseMCPBridge:
    """Bridge between VIGIL security scanning and Base MCP agent workflows."""

    def __init__(self):
        self.api_base = os.getenv("VIGIL_API", "")
        self.api_key = os.getenv("BANKR_API_KEY", "")

    async def security_check(self, wallet: str) -> SecurityCheckResult:
        """Run pre-trade security check for Base MCP agent workflow.

        Called before an AI agent executes any trade/swap/lend on Base.
        Returns go/no-go decision with warnings.
        """
        warnings: list[str] = []
        recommendations: list[str] = []
        pre_trade: dict[str, Any] = {}

        # 1. Check for dangerous approvals
        approvals = await self._get_approvals(wallet, "base")
        critical = sum(1 for a in approvals if a.get("risk") == "critical")
        high = sum(1 for a in approvals if a.get("risk") == "high")
        unlimited = sum(1 for a in approvals if a.get("amount") == "unlimited")

        pre_trade["critical_approvals"] = critical
        pre_trade["high_approvals"] = high
        pre_trade["unlimited_approvals"] = unlimited

        if critical > 0:
            warnings.append(f"🔴 {critical} critical approvals detected — revoke before trading")
            recommendations.append("Run vigil_batch_revoke to clean up dangerous approvals")

        # 2. Check for recent scam token interactions
        scam_count = await self._check_scam_history(wallet, "base")
        pre_trade["scam_interactions"] = scam_count
        if scam_count > 0:
            warnings.append(f"⚠️ {scam_count} interactions with flagged scam tokens detected")

        # 3. Determine go/no-go
        risk_level = "safe"
        safe_to_proceed = True

        if critical > 3:
            risk_level = "critical"
            safe_to_proceed = False
        elif critical > 0:
            risk_level = "high"
            safe_to_proceed = True  # Warn but allow
        elif high > 5:
            risk_level = "medium"
        elif unlimited > 10:
            risk_level = "medium"

        if safe_to_proceed and not warnings:
            recommendations.append("✅ Wallet security looks good — safe to proceed")

        return SecurityCheckResult(
            wallet=wallet,
            safe_to_proceed=safe_to_proceed,
            risk_level=risk_level,
            warnings=warnings,
            pre_trade_checks=pre_trade,
            recommendations=recommendations,
        )

    async def _get_approvals(self, wallet: str, chain: str) -> list[dict]:
        """Fetch approvals for wallet."""
        if not self.api_key:
            return []

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"{self.api_base}/approvals",
                    params={"wallet": wallet, "chain": chain},
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                if resp.status_code == 200:
                    return resp.json().get("approvals", [])
        except Exception:
            pass
        return []

    async def _check_scam_history(self, wallet: str, chain: str) -> int:
        """Check scam interaction count."""
        if not self.api_key:
            return 0

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"{self.api_base}/report/scam-history",
                    params={"wallet": wallet, "chain": chain},
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                if resp.status_code == 200:
                    return len(resp.json().get("interactions", []))
        except Exception:
            pass
        return 0

    def get_mcp_tools_schema(self) -> dict[str, Any]:
        """Return VIGIL tool schemas for Base MCP registration."""
        return {
            "vigil_security_check": {
                "description": (
                    "Run pre-trade security check before executing DeFi operations on Base"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "wallet": {"type": "string", "description": "Wallet address to check"},
                    },
                    "required": ["wallet"],
                },
            },
            "vigil_scan_token": {
                "description": "Scan a token for rugpull/honeypot indicators before trading",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "token": {"type": "string", "description": "Token contract address"},
                        "chain": {"type": "string", "default": "base"},
                    },
                    "required": ["token"],
                },
            },
            "vigil_revoke_approval": {
                "description": "Revoke a dangerous token approval",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "token": {"type": "string"},
                        "spender": {"type": "string"},
                        "chain": {"type": "string", "default": "base"},
                    },
                    "required": ["token", "spender"],
                },
            },
        }
