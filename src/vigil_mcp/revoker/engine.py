"""Revocation engine — build and submit approval revocations via Bankr."""

import os
from typing import Any

import httpx
from pydantic import BaseModel


class RevokeResult(BaseModel):
    token: str
    spender: str
    chain: str
    tx_hash: str
    status: str
    explorer_url: str


EXPLORER_URLS = {
    "base": "https://basescan.org/tx/",
    "ethereum": "https://etherscan.io/tx/",
    "polygon": "https://polygonscan.com/tx/",
    "arbitrum": "https://arbiscan.io/tx/",
}

APPROVE_SELECTOR = "0x095ea7b3"


class RevocationEngine:
    """Build and submit revocation transactions."""

    def __init__(self):
        self.api_base = os.getenv("VIGIL_API", "https://api.bankr.bot/vigil")
        self.api_key = os.getenv("BANKR_API_KEY", "")
        self.rpc_urls = {
            "base": os.getenv("BASE_RPC", "https://mainnet.base.org"),
            "ethereum": os.getenv("ETH_RPC", "https://eth.llamarpc.com"),
            "polygon": os.getenv("POLYGON_RPC", "https://polygon-rpc.com"),
            "arbitrum": os.getenv("ARBITRUM_RPC", "https://arb1.arbitrum.io/rpc"),
        }

    def _check_auth(self):
        if not self.api_key:
            raise ValueError(
                "BANKR_API_KEY required for revocation. "
                "Set it with: export BANKR_API_KEY=bk_your_key"
            )

    async def revoke_single(self, token: str, spender: str, chain: str) -> dict[str, Any]:
        """Revoke a single token approval."""
        self._check_auth()

        if self.api_key.startswith("bk_"):
            return await self._revoke_via_bankr(token, spender, chain)
        return await self._revoke_via_rpc(token, spender, chain)

    async def _revoke_via_bankr(self, token: str, spender: str, chain: str) -> dict[str, Any]:
        """Build and submit revocation via Bankr API."""
        async with httpx.AsyncClient(timeout=60) as client:
            build_resp = await client.post(
                f"{self.api_base}/revoke/build",
                json={"token": token, "spender": spender, "chain": chain},
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            build_resp.raise_for_status()
            build_data = build_resp.json()

            submit_resp = await client.post(
                f"{self.api_base}/revoke/submit",
                json={"unsigned_tx": build_data["unsigned_tx"], "chain": chain},
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            submit_resp.raise_for_status()
            submit_data = submit_resp.json()

        tx_hash = submit_data.get("tx_hash", submit_data.get("transactionHash", ""))
        explorer = EXPLORER_URLS.get(chain, "")

        return {
            "token": token,
            "spender": spender,
            "chain": chain,
            "tx_hash": tx_hash,
            "status": "success",
            "explorer_url": f"{explorer}{tx_hash}" if explorer else "",
        }

    async def _revoke_via_rpc(self, token: str, spender: str, chain: str) -> dict[str, Any]:
        """Build revocation calldata for direct submission."""
        spender_padded = "0x" + spender[2:].lower().zfill(64)
        zero_padded = "0x" + "0" * 64
        calldata = APPROVE_SELECTOR + spender_padded[2:] + zero_padded[2:]

        return {
            "token": token,
            "spender": spender,
            "chain": chain,
            "calldata": calldata,
            "to": token,
            "value": "0x0",
            "status": "calldata_ready",
            "note": "Sign and submit this transaction to revoke the approval",
        }

    async def report_scam(
        self, token: str, evidence_type: str, description: str, chain: str
    ) -> dict[str, Any]:
        """Submit a scam report to the community database."""
        self._check_auth()

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.api_base}/report/submit",
                json={
                    "token": token,
                    "evidence_type": evidence_type,
                    "description": description,
                    "chain": chain,
                },
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            resp.raise_for_status()
            data = resp.json()

        return {
            "token": token,
            "evidence_type": evidence_type,
            "chain": chain,
            "report_id": data.get("report_id", ""),
            "status": data.get("status", "submitted"),
            "bounty": "50 $VIGIL (if verified)",
        }
