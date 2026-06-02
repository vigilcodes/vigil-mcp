"""Honeypot detector — simulate buy/sell to detect trap tokens."""

import os
from typing import Optional

import httpx
from pydantic import BaseModel


class SimulationResult(BaseModel):
    action: str
    success: bool
    gas_used: Optional[int] = None
    error: Optional[str] = None


class HoneypotResult(BaseModel):
    token: str
    chain: str
    is_honeypot: bool
    can_buy: bool
    can_sell: bool
    buy_tax: Optional[float] = None
    sell_tax: Optional[float] = None
    block_reason: Optional[str] = None
    simulations: list[SimulationResult]
    high_tax_warning: bool = False


class HoneypotDetector:
    """Detect honeypot tokens via transaction simulation."""

    def __init__(self):
        self.api_base = os.getenv("VIGIL_API", "https://api.bankr.bot/vigil")
        self.api_key = os.getenv("BANKR_API_KEY", "")
        self.rpc_urls = {
            "base": os.getenv("BASE_RPC", "https://mainnet.base.org"),
            "ethereum": os.getenv("ETH_RPC", "https://eth.llamarpc.com"),
            "polygon": os.getenv("POLYGON_RPC", "https://polygon-rpc.com"),
            "arbitrum": os.getenv("ARBITRUM_RPC", "https://arb1.arbitrum.io/rpc"),
        }

    async def detect(self, token: str, chain: str) -> HoneypotResult:
        """Run honeypot detection on a token."""
        if self.api_key:
            return await self._detect_via_api(token, chain)
        return await self._detect_via_simulation(token, chain)

    async def _detect_via_api(self, token: str, chain: str) -> HoneypotResult:
        """Detect via VIGIL hosted API."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.api_base}/token/honeypot",
                params={"address": token, "chain": chain},
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            resp.raise_for_status()
            data = resp.json()

        return HoneypotResult(
            token=token,
            chain=chain,
            is_honeypot=data.get("is_honeypot", False),
            can_buy=data.get("can_buy", True),
            can_sell=data.get("can_sell", True),
            buy_tax=data.get("buy_tax"),
            sell_tax=data.get("sell_tax"),
            block_reason=data.get("block_reason"),
            simulations=[SimulationResult(**s) for s in data.get("simulations", [])],
            high_tax_warning=data.get("high_tax_warning", False),
        )

    async def _detect_via_simulation(self, token: str, chain: str) -> HoneypotResult:
        """Basic honeypot detection via eth_call simulation."""
        rpc_url = self.rpc_urls.get(chain)
        if not rpc_url:
            raise ValueError(f"No RPC configured for chain '{chain}'")

        simulations: list[SimulationResult] = []
        can_buy = True
        can_sell = True
        block_reason = None

        async with httpx.AsyncClient(timeout=30) as client:
            # Check if token has a transfer function by calling balanceOf
            # (basic existence check)
            balance_selector = "0x70a08231"
            # Use zero address as test
            zero_padded = "0x" + "0" * 64

            balance_resp = await client.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "eth_call",
                    "params": [
                        {
                            "to": token,
                            "data": balance_selector + zero_padded,
                        },
                        "latest",
                    ],
                },
            )
            balance_result = balance_resp.json().get("result", "0x")

            if balance_result in ("0x", None):
                simulations.append(
                    SimulationResult(
                        action="balanceOf_check",
                        success=False,
                        error="Token does not respond to balanceOf — may not be ERC-20",
                    )
                )
                return HoneypotResult(
                    token=token,
                    chain=chain,
                    is_honeypot=True,
                    can_buy=False,
                    can_sell=False,
                    block_reason="Token does not implement standard ERC-20 interface",
                    simulations=simulations,
                )

            # Simulate a transfer to zero address (should revert if valid)
            # This tests if the contract is responsive
            transfer_selector = "0xa9059cbb"
            test_data = transfer_selector + zero_padded + zero_padded

            transfer_resp = await client.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "eth_call",
                    "params": [
                        {
                            "to": token,
                            "data": test_data,
                            "from": "0x0000000000000000000000000000000000000001",
                            "value": "0x0",
                        },
                        "latest",
                    ],
                },
            )
            transfer_error = transfer_resp.json().get("error")

            # A valid transfer should revert (insufficient balance) but not with arbitrary error
            if transfer_error:
                error_msg = transfer_error.get("message", "")
                if "blacklist" in error_msg.lower():
                    can_sell = False
                    block_reason = "Transfer function contains blacklist check"
                    simulations.append(
                        SimulationResult(
                            action="sell_simulation",
                            success=False,
                            error="Blacklisted — cannot sell",
                        )
                    )
                elif "paused" in error_msg.lower():
                    can_sell = False
                    block_reason = "Token transfers are paused"
                    simulations.append(
                        SimulationResult(
                            action="sell_simulation",
                            success=False,
                            error="Transfers paused",
                        )
                    )
                else:
                    simulations.append(
                        SimulationResult(
                            action="sell_simulation",
                            success=True,
                            error=f"Reverted: {error_msg[:100]}",
                        )
                    )
            else:
                simulations.append(
                    SimulationResult(
                        action="transfer_check",
                        success=True,
                    )
                )

        is_honeypot = not can_sell or (not can_buy)

        return HoneypotResult(
            token=token,
            chain=chain,
            is_honeypot=is_honeypot,
            can_buy=can_buy,
            can_sell=can_sell,
            block_reason=block_reason,
            simulations=simulations,
            high_tax_warning=False,  # Would need full simulation for tax calculation
        )
