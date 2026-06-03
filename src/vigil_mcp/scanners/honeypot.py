"""Honeypot detector — simulate buy/sell to detect trap tokens."""

import os
from typing import Optional

import httpx
from pydantic import BaseModel

from vigil_mcp.scanners.known_contracts import lookup_known_contract


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
            "base": os.getenv("BASE_RPC", "https://base.publicnode.com"),
            "ethereum": os.getenv("ETH_RPC", "https://eth.llamarpc.com"),
            "polygon": os.getenv("POLYGON_RPC", "https://polygon-rpc.com"),
            "arbitrum": os.getenv("ARBITRUM_RPC", "https://arb1.arbitrum.io/rpc"),
        }

    async def detect(self, token: str, chain: str) -> HoneypotResult:
        """Run honeypot detection on a token."""
        # Fast-path: known blue-chip contracts are not honeypots
        known = lookup_known_contract(chain, token)
        if known:
            return HoneypotResult(
                token=token,
                chain=chain,
                is_honeypot=False,
                can_buy=True,
                can_sell=True,
                block_reason=None,
                simulations=[
                    SimulationResult(
                        action="known_contract_lookup",
                        success=True,
                        error=f"{known.name} ({known.symbol}) is a verified blue-chip contract",
                    )
                ],
                high_tax_warning=False,
            )

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
            # First confirm the address actually has contract code.
            # Empty / EOA addresses are flagged; valid contracts proceed.
            code_resp = await client.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 0,
                    "method": "eth_getCode",
                    "params": [token, "latest"],
                },
            )
            code = code_resp.json().get("result", "0x")
            if code in ("0x", "0x0", None):
                simulations.append(
                    SimulationResult(
                        action="contract_existence",
                        success=False,
                        error="Address has no contract code",
                    )
                )
                return HoneypotResult(
                    token=token,
                    chain=chain,
                    is_honeypot=True,
                    can_buy=False,
                    can_sell=False,
                    block_reason="No contract code at address",
                    simulations=simulations,
                )

            # balanceOf(0x0) should respond with 32-byte word for ERC-20.
            # A response of '0x' (truly empty) means no balanceOf — non-ERC-20.
            # Note: '0x' + 64 zeros is a VALID balanceOf return (zero balance).
            balance_selector = "0x70a08231"
            zero_padded = "0" * 64
            balance_resp = await client.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "eth_call",
                    "params": [
                        {
                            "to": token,
                            "data": balance_selector + "0x" + zero_padded,
                        },
                        "latest",
                    ],
                },
            )
            balance_result = balance_resp.json().get("result")

            # Treat a real ERC-20 as one that returns at least a 32-byte word.
            # Strip 0x prefix; any 64+ hex chars is a valid uint256 response.
            normalized = (balance_result or "").lower().removeprefix("0x")
            if balance_result is None or len(normalized) < 64:
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

            simulations.append(
                SimulationResult(
                    action="balanceOf_check",
                    success=True,
                )
            )

            # Simulate transfer(0x0, 0). For a typical ERC-20 this either succeeds
            # (with zero amount) or reverts with insufficient-balance — both fine.
            # We flag explicit blacklist / paused reverts as honeypot signals.
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

            if transfer_error:
                error_msg = transfer_error.get("message", "")
                lower_msg = error_msg.lower()
                if "blacklist" in lower_msg:
                    can_sell = False
                    block_reason = "Transfer function contains blacklist check"
                    simulations.append(
                        SimulationResult(
                            action="transfer_simulation",
                            success=False,
                            error="Blacklisted — cannot sell",
                        )
                    )
                elif "paused" in lower_msg or "pausable" in lower_msg:
                    can_sell = False
                    block_reason = "Token transfers are paused"
                    simulations.append(
                        SimulationResult(
                            action="transfer_simulation",
                            success=False,
                            error="Transfers paused",
                        )
                    )
                else:
                    # Generic revert (e.g. insufficient balance) is normal.
                    simulations.append(
                        SimulationResult(
                            action="transfer_simulation",
                            success=True,
                            error=f"Reverted (expected): {error_msg[:100]}",
                        )
                    )
            else:
                simulations.append(
                    SimulationResult(
                        action="transfer_simulation",
                        success=True,
                    )
                )

        is_honeypot = (not can_sell) or (not can_buy)

        return HoneypotResult(
            token=token,
            chain=chain,
            is_honeypot=is_honeypot,
            can_buy=can_buy,
            can_sell=can_sell,
            block_reason=block_reason,
            simulations=simulations,
            high_tax_warning=False,
        )
