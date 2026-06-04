"""Deployer reputation — who deployed a contract, is it verified, how old is it.

Uses the Basescan (Etherscan-family) API. If no API key is configured the module
degrades gracefully: it returns a neutral result with `available=False` instead of
raising, so the rest of VIGIL keeps working without a key.
"""

import os
import time
from typing import Optional

import httpx
from pydantic import BaseModel

# Etherscan v2 multichain API: one base URL, chainid selects the network.
ETHERSCAN_V2_BASE = os.getenv("ETHERSCAN_API", "https://api.etherscan.io/v2/api")

_CHAIN_IDS = {
    "base": 8453,
    "ethereum": 1,
    "polygon": 137,
    "arbitrum": 42161,
}


class DeployerInfo(BaseModel):
    available: bool = True
    address: str
    chain: str
    deployer: Optional[str] = None
    creation_tx: Optional[str] = None
    verified: Optional[bool] = None
    contract_name: Optional[str] = None
    age_days: Optional[float] = None
    risk_factors: list[str] = []
    positive_factors: list[str] = []
    note: str = ""


class DeployerScanner:
    """Look up contract deployment and verification metadata via Basescan."""

    def __init__(self) -> None:
        self.base = ETHERSCAN_V2_BASE
        # Accept either a Base-specific key or a generic Etherscan v2 key.
        self.api_key = os.getenv("BASESCAN_API_KEY", "") or os.getenv("ETHERSCAN_API_KEY", "")

    async def check(self, address: str, chain: str) -> DeployerInfo:
        chain_id = _CHAIN_IDS.get(chain.lower())
        if not chain_id:
            return DeployerInfo(
                available=False,
                address=address,
                chain=chain,
                note=f"Unsupported chain for deployer lookup: {chain}",
            )
        if not self.api_key:
            return DeployerInfo(
                available=False,
                address=address,
                chain=chain,
                note="No BASESCAN_API_KEY configured — deployer reputation unavailable",
            )

        risk_factors: list[str] = []
        positive_factors: list[str] = []
        deployer: Optional[str] = None
        creation_tx: Optional[str] = None
        verified: Optional[bool] = None
        contract_name: Optional[str] = None
        age_days: Optional[float] = None
        plan_limited = False

        try:
            async with httpx.AsyncClient(timeout=20) as client:
                # 1. Contract creation (deployer + tx hash).
                # NOTE: on the free Etherscan v2 plan this endpoint is blocked for
                # non-mainnet chains (returns NOTOK "upgrade your api plan"). We
                # detect that and degrade gracefully instead of returning silent nulls.
                cre = await client.get(
                    self.base,
                    params={
                        "chainid": chain_id,
                        "module": "contract",
                        "action": "getcontractcreation",
                        "contractaddresses": address,
                        "apikey": self.api_key,
                    },
                )
                cre.raise_for_status()
                cre_json = cre.json()
                cre_msg = str(cre_json.get("result", ""))
                if cre_json.get("status") == "1" and isinstance(cre_json.get("result"), list):
                    row = cre_json["result"][0]
                    deployer = row.get("contractCreator")
                    creation_tx = row.get("txHash")
                elif "api plan" in cre_msg.lower() or "not supported for this chain" in cre_msg.lower():
                    plan_limited = True

                # 2. Source verification + contract name (works on free tier for Base)
                src = await client.get(
                    self.base,
                    params={
                        "chainid": chain_id,
                        "module": "contract",
                        "action": "getsourcecode",
                        "address": address,
                        "apikey": self.api_key,
                    },
                )
                src.raise_for_status()
                src_json = src.json()
                if src_json.get("status") == "1" and isinstance(src_json.get("result"), list):
                    info = src_json["result"][0]
                    src_code = info.get("SourceCode") or ""
                    verified = bool(src_code.strip())
                    contract_name = info.get("ContractName") or None

                # 3. Approximate age via the deployment tx timestamp (needs creation_tx)
                if creation_tx:
                    rcpt = await client.get(
                        self.base,
                        params={
                            "chainid": chain_id,
                            "module": "proxy",
                            "action": "eth_getTransactionByHash",
                            "txhash": creation_tx,
                            "apikey": self.api_key,
                        },
                    )
                    rcpt.raise_for_status()
                    tx = (rcpt.json() or {}).get("result") or {}
                    block_hex = tx.get("blockNumber")
                    if block_hex:
                        blk = await client.get(
                            self.base,
                            params={
                                "chainid": chain_id,
                                "module": "proxy",
                                "action": "eth_getBlockByNumber",
                                "tag": block_hex,
                                "boolean": "false",
                                "apikey": self.api_key,
                            },
                        )
                        blk.raise_for_status()
                        block = (blk.json() or {}).get("result") or {}
                        ts_hex = block.get("timestamp")
                        if ts_hex:
                            ts = int(ts_hex, 16)
                            age_days = round((time.time() - ts) / 86_400, 1)
        except Exception as e:  # noqa: BLE001 — reputation is best-effort context
            return DeployerInfo(
                available=False,
                address=address,
                chain=chain,
                note=f"Basescan lookup failed: {e}",
            )

        if verified:
            positive_factors.append("Source code verified on explorer")
        elif verified is False:
            risk_factors.append("Source code NOT verified — cannot audit logic")

        if age_days is not None:
            if age_days < 3:
                risk_factors.append(f"Very new contract (~{age_days} days old)")
            elif age_days > 180:
                positive_factors.append(f"Established contract (~{age_days} days old)")

        note = "Deployer reputation via Basescan"
        if plan_limited:
            note = (
                "Verification available; deployer address and contract age require a "
                "paid Basescan plan for this chain"
            )

        return DeployerInfo(
            available=True,
            address=address,
            chain=chain,
            deployer=deployer,
            creation_tx=creation_tx,
            verified=verified,
            contract_name=contract_name,
            age_days=age_days,
            risk_factors=risk_factors,
            positive_factors=positive_factors,
            note=note,
        )
