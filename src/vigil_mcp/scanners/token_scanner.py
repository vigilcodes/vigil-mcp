"""Token scanner — analyze token contracts for rugpull and scam indicators."""

import os
from typing import Any, Optional

import httpx
from pydantic import BaseModel

from vigil_mcp.scanners.known_contracts import lookup_known_contract


class Finding(BaseModel):
    severity: str  # critical, high, medium, low
    category: str
    message: str


class ContractInfo(BaseModel):
    owner: Optional[str] = None
    is_proxy: bool = False
    verified: bool = False
    ownership_renounced: bool = False


class LiquidityInfo(BaseModel):
    total_locked_usd: Optional[float] = None
    lock_duration: Optional[str] = None
    lp_holders: Optional[int] = None


class HolderInfo(BaseModel):
    top10_percentage: Optional[float] = None
    total: Optional[int] = None
    whales: Optional[int] = None


class TaxInfo(BaseModel):
    buy: Optional[float] = None
    sell: Optional[float] = None
    modifiable: bool = False


class HoneypotInfo(BaseModel):
    detected: bool = False
    reason: Optional[str] = None


class TokenScanResult(BaseModel):
    token_name: str
    token_symbol: str
    safety_score: int
    risk_level: str
    findings: list[Finding]
    contract: ContractInfo
    liquidity: LiquidityInfo
    holders: HolderInfo
    tax: TaxInfo
    honeypot: HoneypotInfo
    recommendation: str


class ScamInteraction(BaseModel):
    token_name: str
    token_address: str
    type: str
    date: str


# Common rugpull function selectors
RUG_SIGNATURES = {
    "0x70a08231": "balanceOf",
    "0xa9059cbb": "transfer",
    "0x23b872dd": "transferFrom",
    "0x095ea7b3": "approve",
    "0x40c10f19": "mint",  # Hidden mint — critical
    "0x8da5cb5b": "owner",
    "0x715018a6": "renounceOwnership",
    "0xf2fde38b": "transferOwnership",
    "0x39509351": "increaseAllowance",
    "0xa457c2d7": "decreaseAllowance",
    "0x8b95dd71": "setFees",  # Modifiable tax
    "0xd3aa7e02": "setTax",  # Modifiable tax
    "0x4f558e79": "addBlacklist",  # Blacklist function
    "0xe47d6060": "isBlacklisted",  # Blacklist check
}

# Honeypot indicators in bytecode
HONEYPOT_BYTECODE_PATTERNS = [
    "selfdestruct",
    "delegatecall",
]


def _has_selfdestruct(code_hex: str) -> bool:
    """Heuristic check for SELFDESTRUCT (0xff) opcode in bytecode.

    Walks bytes and skips PUSH immediates so 0xff bytes that are PUSH data
    (very common in constants) are not flagged. False positives are still
    possible in non-standard EVM dispatch tables, but this avoids the worst
    of the noise from a naive substring search.
    """
    raw = code_hex.lower().removeprefix("0x")
    if not raw:
        return False
    try:
        data = bytes.fromhex(raw)
    except ValueError:
        return False
    i = 0
    while i < len(data):
        op = data[i]
        # PUSH1..PUSH32 are 0x60..0x7f and consume the next (op - 0x5f) bytes.
        if 0x60 <= op <= 0x7F:
            i += 1 + (op - 0x5F)
            continue
        if op == 0xFF:
            return True
        i += 1
    return False


class TokenScanner:
    """Analyze token contracts for safety."""

    def __init__(self):
        self.api_base = os.getenv("VIGIL_API", "https://api.bankr.bot/vigil")
        self.api_key = os.getenv("BANKR_API_KEY", "")
        self.rpc_urls = {
            "base": os.getenv("BASE_RPC", "https://base.publicnode.com"),
            "ethereum": os.getenv("ETH_RPC", "https://eth.llamarpc.com"),
            "polygon": os.getenv("POLYGON_RPC", "https://polygon-rpc.com"),
            "arbitrum": os.getenv("ARBITRUM_RPC", "https://arb1.arbitrum.io/rpc"),
        }

    async def scan(self, token: str, chain: str) -> TokenScanResult:
        """Full token safety scan."""
        known = lookup_known_contract(chain, token)
        if known:
            return TokenScanResult(
                token_name=known.name,
                token_symbol=known.symbol,
                safety_score=known.safety_score,
                risk_level=known.risk_level,
                findings=[],
                contract=ContractInfo(verified=True, ownership_renounced=True),
                liquidity=LiquidityInfo(),
                holders=HolderInfo(),
                tax=TaxInfo(),
                honeypot=HoneypotInfo(detected=False),
                recommendation=f"Score: {known.safety_score}/100 — {known.name} is a known, verified contract",
            )
        if self.api_key:
            return await self._scan_via_api(token, chain)
        return await self._scan_via_rpc(token, chain)

    async def _scan_via_api(self, token: str, chain: str) -> TokenScanResult:
        """Scan via VIGIL hosted API."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.api_base}/token/scan",
                params={"address": token, "chain": chain},
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            resp.raise_for_status()
            data = resp.json()

        return TokenScanResult(
            token_name=data.get("token_name", "Unknown"),
            token_symbol=data.get("token_symbol", "???"),
            safety_score=data.get("safety_score", 0),
            risk_level=data.get("risk_level", "unknown"),
            findings=[Finding(**f) for f in data.get("findings", [])],
            contract=ContractInfo(**data.get("contract", {})),
            liquidity=LiquidityInfo(**data.get("liquidity", {})),
            holders=HolderInfo(**data.get("holders", {})),
            tax=TaxInfo(**data.get("tax", {})),
            honeypot=HoneypotInfo(**data.get("honeypot", {})),
            recommendation=data.get("recommendation", "Unable to determine"),
        )

    async def _scan_via_rpc(self, token: str, chain: str) -> TokenScanResult:
        """Basic scan via direct RPC queries."""
        rpc_url = self.rpc_urls.get(chain)
        if not rpc_url:
            raise ValueError(f"No RPC configured for chain '{chain}'")

        findings: list[Finding] = []
        score = 50  # Start neutral

        async with httpx.AsyncClient(timeout=30) as client:
            # Check if contract has code
            code_resp = await client.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "eth_getCode",
                    "params": [token, "latest"],
                },
            )
            code = code_resp.json().get("result", "0x")

            if code in ("0x", "0x0"):
                return TokenScanResult(
                    token_name="Unknown",
                    token_symbol="???",
                    safety_score=0,
                    risk_level="critical",
                    findings=[
                        Finding(
                            severity="critical",
                            category="contract",
                            message="No contract code at address",
                        )
                    ],
                    contract=ContractInfo(),
                    liquidity=LiquidityInfo(),
                    holders=HolderInfo(),
                    tax=TaxInfo(),
                    honeypot=HoneypotInfo(detected=True, reason="No contract exists"),
                    recommendation="DO NOT INTERACT — No contract at this address",
                )

            # Check for proxy patterns (EIP-1967)
            is_proxy = "363d3d373d3d3d363d73" in code[:50]  # Minimal proxy
            impl_slot = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
            impl_resp = await client.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "eth_getStorageAt",
                    "params": [token, "0x" + impl_slot, "latest"],
                },
            )
            impl_addr = impl_resp.json().get("result", "0x")
            has_implementation = impl_addr != "0x" + "0" * 64

            if is_proxy or has_implementation:
                findings.append(
                    Finding(
                        severity="high",
                        category="contract",
                        message="Proxy contract — implementation can be changed by owner",
                    )
                )
                score -= 15

            # Check for mint function
            if "40c10f19" in code:
                findings.append(
                    Finding(
                        severity="critical",
                        category="ownership",
                        message=(
                            "Contract contains mint function — owner can create unlimited tokens"
                        ),
                    )
                )
                score -= 30

            # Check for blacklist function
            if "4f558e79" in code or "e47d6060" in code:
                findings.append(
                    Finding(
                        severity="high",
                        category="manipulation",
                        message=(
                            "Blacklist function detected — owner can block addresses from selling"
                        ),
                    )
                )
                score -= 20

            # Check for fee/tax modification
            if "8b95dd71" in code or "d3aa7e02" in code:
                findings.append(
                    Finding(
                        severity="high",
                        category="tax",
                        message=(
                            "Tax modification function detected — owner can change buy/sell tax"
                        ),
                    )
                )
                score -= 15

            # Check for selfdestruct opcode (0xff). This is intentionally conservative:
            # the literal byte 0xff is extremely common in normal bytecode constants,
            # so we look for the SELFDESTRUCT opcode in a position that suggests it
            # is reachable rather than embedded in PUSH data. We require the opcode
            # to NOT be preceded by a PUSH (0x60..0x7f) in the immediately prior byte.
            if _has_selfdestruct(code):
                findings.append(
                    Finding(
                        severity="medium",
                        category="contract",
                        message="Contract may contain selfdestruct — could be destroyed by owner",
                    )
                )
                score -= 10

        if not findings:
            findings.append(
                Finding(
                    severity="low",
                    category="general",
                    message="Basic scan passed — no obvious red flags in bytecode",
                )
            )

        score = max(0, min(100, score))
        risk_level = (
            "critical"
            if score < 30
            else "high"
            if score < 50
            else "medium"
            if score < 70
            else "low"
            if score < 90
            else "safe"
        )

        return TokenScanResult(
            token_name="Unknown",
            token_symbol="???",
            safety_score=score,
            risk_level=risk_level,
            findings=findings,
            contract=ContractInfo(
                is_proxy=is_proxy or has_implementation,
                verified=False,  # Would need explorer API
            ),
            liquidity=LiquidityInfo(),
            holders=HolderInfo(),
            tax=TaxInfo(),
            honeypot=HoneypotInfo(),
            recommendation=(
                f"Score: {score}/100 — "
                + (
                    "Run full scan via API for deeper analysis"
                    if score >= 50
                    else "HIGH RISK — Proceed with extreme caution"
                )
            ),
        )

    async def check_scam_interactions(self, wallet: str, chain: str) -> list[dict[str, Any]]:
        """Check if wallet has interacted with known scam tokens."""
        if not self.api_key:
            return []

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{self.api_base}/report/scam-history",
                    params={"wallet": wallet, "chain": chain},
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                if resp.status_code == 200:
                    return resp.json().get("interactions", [])
        except Exception:
            pass
        return []
