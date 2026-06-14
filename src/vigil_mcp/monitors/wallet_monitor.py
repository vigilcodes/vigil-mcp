"""Wallet monitor — real-time alerts for suspicious wallet activity."""

import os
import time
from typing import Optional

import httpx
from pydantic import BaseModel


class Alert(BaseModel):
    severity: str  # critical, high, medium, low, info
    category: str  # approval, transfer, contract_interaction
    message: str
    details: Optional[dict] = None
    timestamp: Optional[float] = None


class MonitorResult(BaseModel):
    wallet: str
    chain: str
    monitored_at: float
    alerts: list[Alert]
    summary: dict
    recommendations: list[dict]


class WalletMonitor:
    """Monitor wallet for suspicious activity."""

    def __init__(self):
        # Per-chain RPC list. The configured env URL (e.g. BASE_RPC pointing to
        # QuickNode) goes first, with public nodes as fallback. We dedupe so
        # the same URL never appears twice if env happens to match a default.
        def _list(env_key: str, *fallbacks: str) -> list[str]:
            primary = os.getenv(env_key, "")
            seen: set[str] = set()
            out: list[str] = []
            for u in [primary, *fallbacks]:
                if u and u not in seen:
                    seen.add(u)
                    out.append(u)
            return out

        self.rpc_urls = {
            "base": _list(
                "BASE_RPC",
                "https://base.publicnode.com",
                "https://mainnet.base.org",
            ),
            "ethereum": _list(
                "ETH_RPC",
                "https://eth.llamarpc.com",
                "https://ethereum.publicnode.com",
            ),
            "polygon": _list(
                "POLYGON_RPC",
                "https://polygon.llamarpc.com",
                "https://polygon-rpc.com",
            ),
            "arbitrum": _list(
                "ARBITRUM_RPC",
                "https://arbitrum.llamarpc.com",
                "https://arb1.arbitrum.io/rpc",
            ),
        }
        # Known safe spender patterns
        self.known_safe_spenders = {
            "base": {
                "0x2626664c2603336e57b271c5c0b26f421741e481": "Uniswap V3 Router",
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD": "Uniswap Universal Router",
                "0x6fd58f4a25d4e24bb448bd07007cca1578729511": "Base Bridge",
                "0x49048044d57e1c92a77f79988d21fa8faf74e97e": "Base Bridge (L1)",
            },
            "ethereum": {
                "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap V3 Router",
                "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
                "0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch Router",
            },
        }

    async def _rpc_post(self, client: httpx.AsyncClient, rpc_list: list[str], payload: dict) -> dict:
        """POST a JSON-RPC payload, falling back through rpc_list on failure.

        Tries the first RPC (typically the configured QuickNode); if it errors
        or returns non-200, walks the remaining public-node fallbacks.
        """
        last_err: Optional[Exception] = None
        for url in rpc_list:
            try:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    return resp.json()
            except Exception as e:  # noqa: BLE001 — try the next URL
                last_err = e
        if last_err:
            raise last_err
        return {}

    async def monitor(self, wallet: str, chain: str, lookback_blocks: int = 1000) -> MonitorResult:
        """Monitor wallet for recent suspicious activity."""
        alerts: list[Alert] = []
        now = time.time()

        rpc_list = self.rpc_urls.get(chain, [])
        if not rpc_list:
            raise ValueError(f"No RPC configured for chain '{chain}'")

        async with httpx.AsyncClient(timeout=30) as client:
            # Get recent approval events for this wallet
            approval_alerts = await self._check_recent_approvals(client, wallet, chain, rpc_list, lookback_blocks)
            alerts.extend(approval_alerts)

            # Check for interactions with known risky patterns
            risk_alerts = await self._check_risky_interactions(client, wallet, chain, rpc_list, lookback_blocks)
            alerts.extend(risk_alerts)

            # Check balance changes
            balance_alerts = await self._check_balance_changes(client, wallet, chain, rpc_list, lookback_blocks)
            alerts.extend(balance_alerts)

        # Generate summary
        critical = sum(1 for a in alerts if a.severity == "critical")
        high = sum(1 for a in alerts if a.severity == "high")
        medium = sum(1 for a in alerts if a.severity == "medium")
        low = sum(1 for a in alerts if a.severity == "low")

        summary = {
            "total_alerts": len(alerts),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "status": ("CRITICAL" if critical > 0 else "WARNING" if high > 0 else "ATTENTION" if medium > 0 else "OK"),
        }

        # Generate recommendations
        recommendations = []
        if critical > 0:
            recommendations.append(
                {
                    "priority": "critical",
                    "action": "Immediately revoke critical approvals",
                    "detail": f"Found {critical} critical alerts requiring immediate attention",
                }
            )
        if high > 0:
            recommendations.append(
                {
                    "priority": "high",
                    "action": "Review high-risk approvals",
                    "detail": f"Found {high} high-risk items",
                }
            )
        if len(alerts) == 0:
            recommendations.append(
                {
                    "priority": "info",
                    "action": "No suspicious activity detected",
                    "detail": f"Wallet looks clean for the last {lookback_blocks} blocks",
                }
            )

        return MonitorResult(
            wallet=wallet,
            chain=chain,
            monitored_at=now,
            alerts=alerts,
            summary=summary,
            recommendations=recommendations,
        )

    async def _check_recent_approvals(
        self, client: httpx.AsyncClient, wallet: str, chain: str, rpc_list: list, lookback: int
    ) -> list[Alert]:
        """Check for recent Approval events."""
        alerts = []
        try:
            # Get current block
            block_resp = await self._rpc_post(
                client,
                rpc_list,
                {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []},
            )
            current_block = int(block_resp.get("result", "0x0"), 16)
            from_block = hex(max(0, current_block - lookback))

            # Approval event signature: Approval(address,address,uint256)
            approval_topic = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

            # Get logs for this wallet
            logs_resp = await self._rpc_post(
                client,
                rpc_list,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "eth_getLogs",
                    "params": [
                        {
                            "fromBlock": from_block,
                            "toBlock": "latest",
                            "topics": [
                                approval_topic,
                                "0x" + wallet[2:].lower().zfill(64),
                            ],
                        }
                    ],
                },
            )
            logs = logs_resp.get("result", [])

            for log in logs:
                spender = "0x" + log.get("topics", [b"", b""])[1][-40:] if len(log.get("topics", [])) > 1 else "unknown"
                token = log.get("address", "unknown")
                value = log.get("data", "0x")

                # Check if unlimited approval
                is_unlimited = value == "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

                known_spender = self.known_safe_spenders.get(chain, {}).get(spender.lower())

                if known_spender:
                    severity = "info"
                    msg = f"Approval to known contract: {known_spender}"
                elif is_unlimited:
                    severity = "high"
                    msg = f"Unlimited approval granted to unknown contract {spender[:10]}..."
                else:
                    severity = "medium"
                    msg = f"New approval to {spender[:10]}..."

                alerts.append(
                    Alert(
                        severity=severity,
                        category="approval",
                        message=msg,
                        details={
                            "token": token,
                            "spender": spender,
                            "unlimited": is_unlimited,
                            "block": log.get("blockNumber"),
                            "tx": log.get("transactionHash"),
                        },
                        timestamp=time.time(),
                    )
                )

        except Exception as e:
            alerts.append(
                Alert(
                    severity="info",
                    category="system",
                    message=f"Could not fetch approval events: {str(e)[:100]}",
                )
            )

        return alerts

    async def _check_risky_interactions(
        self, client: httpx.AsyncClient, wallet: str, chain: str, rpc_list: list, lookback: int
    ) -> list[Alert]:
        """Check for interactions with known risky patterns."""
        alerts = []
        try:
            block_resp = await self._rpc_post(
                client,
                rpc_list,
                {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []},
            )
            current_block = int(block_resp.get("result", "0x0"), 16)
            from_block = hex(max(0, current_block - lookback))

            # Get normal transactions
            tx_resp = await self._rpc_post(
                client,
                rpc_list,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "eth_getLogs",
                    "params": [
                        {
                            "fromBlock": from_block,
                            "toBlock": "latest",
                            "topics": [
                                None,
                                "0x" + wallet[2:].lower().zfill(64),
                            ],
                        }
                    ],
                },
            )
            logs = tx_resp.get("result", [])

            # Track unique contracts interacted with
            contracts = set()
            for log in logs[:20]:  # Limit to recent
                contracts.add(log.get("address", "").lower())

            # Check if any are unverified or suspicious
            for contract in contracts:
                if contract and contract not in self.known_safe_spenders.get(chain, {}):
                    # Check if contract has code
                    code_resp = await self._rpc_post(
                        client,
                        rpc_list,
                        {
                            "jsonrpc": "2.0",
                            "id": 4,
                            "method": "eth_getCode",
                            "params": [contract, "latest"],
                        },
                    )
                    code = code_resp.get("result", "0x")
                    if code in ("0x", "0x0"):
                        alerts.append(
                            Alert(
                                severity="medium",
                                category="contract_interaction",
                                message=f"Interaction with contract that has no code: {contract[:10]}...",
                                details={"contract": contract},
                            )
                        )

        except Exception:
            pass

        return alerts

    async def _check_balance_changes(
        self, client: httpx.AsyncClient, wallet: str, chain: str, rpc_list: list, lookback: int
    ) -> list[Alert]:
        """Check for significant balance changes."""
        alerts = []
        try:
            # Get current ETH balance
            bal_resp = await self._rpc_post(
                client,
                rpc_list,
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "eth_getBalance",
                    "params": [wallet, "latest"],
                },
            )
            balance_hex = bal_resp.get("result", "0x0")
            balance = int(balance_hex, 16)
            balance_eth = balance / 1e18

            if balance_eth < 0.001:
                alerts.append(
                    Alert(
                        severity="low",
                        category="balance",
                        message=f"Low ETH balance: {balance_eth:.6f} ETH",
                        details={"balance_wei": balance, "balance_eth": balance_eth},
                    )
                )

        except Exception:
            pass

        return alerts
