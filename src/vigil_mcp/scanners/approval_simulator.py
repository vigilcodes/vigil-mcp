"""Approval simulator — risk-assess a spender BEFORE you sign.

Existing approval scanners audit the past (what you already approved).
This tool answers a different question: "If I approve THIS spender
right now, what could they do?"

It profiles the spender address using multiple signals:
- Is it a contract or an EOA?
- Is it in the known-safe spender registry?
- Is it flagged by GoPlus or the community scam DB?
- How much code does it have? (complexity heuristic)
- Does its bytecode contain `transferFrom` (can drain approved tokens)?
- Is the requested amount unlimited?

Returns a risk verdict + human-readable reasons + recommendation.
Free core safety check — not gated by x402.
"""

from __future__ import annotations

import os
from typing import Optional

import httpx
from pydantic import BaseModel

from vigil_mcp.scanners.approvals import SAFE_SPENDER_NAMES, SAFE_SPENDERS
from vigil_mcp.scanners.goplus import GoPlusScanner
from vigil_mcp.scanners.known_contracts import lookup_known_contract
from vigil_mcp.scanners.scam_db import ScamDatabase

# Unlimited approval sentinel (same as approvals.py)
UNLIMITED = "115792089237316195423570985008687907853269984665640564039457584007913129639935"

# transferFrom selector: 0x23b872dd
_TRANSFER_FROM_SIG = "23b872dd"


class SpenderProfile(BaseModel):
    """Profile of the spender address."""

    address: str
    is_contract: bool
    has_code: bool
    code_size_bytes: int = 0
    is_known_safe: bool = False
    safe_name: Optional[str] = None
    is_known_contract: Optional[str] = None  # name from registry if known
    has_transfer_from: bool = False  # bytecode contains transferFrom selector
    goplus_flagged: bool = False
    goplus_notes: list[str] = []
    scam_reported: bool = False
    scam_count: int = 0


class SimulationResult(BaseModel):
    """Result of simulating an approval before signing."""

    spender: str
    token: str
    chain: str
    amount: str  # "unlimited" or numeric string
    risk: str  # safe | suspicious | dangerous
    spender_profile: SpenderProfile
    reasons: list[str]
    recommendation: str


class ApprovalSimulator:
    """Simulate and risk-assess a token approval before signing."""

    def __init__(self) -> None:
        self.goplus = GoPlusScanner()
        self.scam_db = ScamDatabase()
        self.rpc_urls = {
            "base": os.getenv("BASE_RPC", "https://base.publicnode.com"),
            "ethereum": os.getenv("ETH_RPC", "https://eth.llamarpc.com"),
            "polygon": os.getenv("POLYGON_RPC", "https://polygon-rpc.com"),
            "arbitrum": os.getenv("ARBITRUM_RPC", "https://arb1.arbitrum.io/rpc"),
        }

    async def simulate(
        self, spender: str, token: str, amount: str = "unlimited", chain: str = "base"
    ) -> SimulationResult:
        """Simulate approving `spender` for `token` and return risk assessment."""
        spender_l = spender.lower()
        token_l = token.lower()
        chain_l = chain.lower()
        is_unlimited = amount.lower() == "unlimited" or amount == UNLIMITED

        rpc_url = self.rpc_urls.get(chain_l)

        # Build spender profile from multiple signals
        profile = await self._profile_spender(spender_l, token_l, chain_l, rpc_url)

        # Assess risk from profile + amount
        risk, reasons = self._assess_risk(profile, is_unlimited)

        # Generate recommendation
        recommendation = self._recommend(risk, profile, is_unlimited)

        return SimulationResult(
            spender=spender_l,
            token=token_l,
            chain=chain_l,
            amount="unlimited" if is_unlimited else amount,
            risk=risk,
            spender_profile=profile,
            reasons=reasons,
            recommendation=recommendation,
        )

    async def _profile_spender(self, spender: str, token: str, chain: str, rpc_url: Optional[str]) -> SpenderProfile:
        """Build a risk profile for the spender address."""
        profile = SpenderProfile(address=spender, is_contract=False, has_code=False)

        # 1. Known safe spender?
        if spender in SAFE_SPENDERS:
            profile.is_known_safe = True
            profile.safe_name = SAFE_SPENDER_NAMES.get(spender)

        # 2. Known contract in VIGIL registry?
        known = lookup_known_contract(chain, spender)
        if known:
            profile.is_known_contract = known.name

        # 3. Check if spender has code (contract vs EOA) + analyze bytecode
        if rpc_url:
            try:
                async with httpx.AsyncClient(timeout=20) as client:
                    resp = await client.post(
                        rpc_url,
                        json={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "eth_getCode",
                            "params": [spender, "latest"],
                        },
                    )
                    code = resp.json().get("result", "0x")
                    code_len = (len(code) - 2) // 2 if code not in ("0x", "0x0") else 0
                    profile.has_code = code_len > 0
                    profile.is_contract = code_len > 0
                    profile.code_size_bytes = code_len

                    # Check if bytecode contains transferFrom selector
                    if code_len > 0 and _TRANSFER_FROM_SIG in code.lower():
                        profile.has_transfer_from = True
            except Exception:  # noqa: BLE001 — best effort
                pass

        # 4. GoPlus check on the spender (treat as a token address — GoPlus
        #    may have data if it's a known contract)
        try:
            gp = await self.goplus.token_security(spender, chain)
            if gp.available:
                notes = []
                if gp.is_honeypot:
                    profile.goplus_flagged = True
                    notes.append("honeypot flag on spender contract")
                if gp.hidden_owner:
                    profile.goplus_flagged = True
                    notes.append("hidden owner")
                if gp.can_take_back_ownership:
                    notes.append("can reclaim ownership")
                if gp.is_mintable:
                    notes.append("mintable")
                profile.goplus_notes = notes
        except Exception:  # noqa: BLE001
            pass

        # 5. Community scam DB check on spender
        try:
            scam = self.scam_db.check(spender, chain)
            if scam.get("reported"):
                profile.scam_reported = True
                profile.scam_count = scam.get("report_count", 0)
        except Exception:  # noqa: BLE001
            pass

        return profile

    def _assess_risk(self, profile: SpenderProfile, is_unlimited: bool) -> tuple[str, list[str]]:
        """Determine risk level from spender profile + approval amount."""
        reasons: list[str] = []
        danger_signals = 0
        suspicious_signals = 0

        # Known safe → fast path
        if profile.is_known_safe:
            reasons.append(f"Known safe spender: {profile.safe_name or profile.address[:10]}")
            if is_unlimited:
                reasons.append("Unlimited amount — standard for DEX routers but monitor periodically")
                return "safe", reasons
            return "safe", reasons

        if profile.is_known_contract:
            reasons.append(f"Known contract: {profile.is_known_contract}")
            if is_unlimited:
                return "safe", reasons
            return "safe", reasons

        # Scam DB hit
        if profile.scam_reported:
            danger_signals += 2
            reasons.append(f"SCAM REPORTED: {profile.scam_count} community report(s) on this address")

        # GoPlus flags
        if profile.goplus_flagged:
            danger_signals += 1
            reasons.append(f"GoPlus flags: {', '.join(profile.goplus_notes)}")

        # Not a contract (EOA)
        if not profile.is_contract:
            danger_signals += 1
            reasons.append("Spender is an EOA (not a contract) — unusual for legitimate approvals")

        # Small or empty contract
        elif profile.code_size_bytes < 100:
            suspicious_signals += 1
            reasons.append(f"Very small contract ({profile.code_size_bytes} bytes) — possibly a proxy or shell")

        # Has transferFrom capability
        if profile.has_transfer_from and not profile.is_known_safe:
            suspicious_signals += 1
            reasons.append("Contract contains transferFrom — can move your approved tokens")

        # Unlimited amount to unknown spender
        if is_unlimited and not profile.is_known_safe:
            suspicious_signals += 1
            reasons.append("Unlimited approval to an unrecognized spender — max exposure")

        # No code check possible (no RPC)
        if not profile.has_code and not profile.is_contract and profile.code_size_bytes == 0:
            # Could be EOA or could be RPC failure. If RPC worked and code is
            # empty, it's an EOA. If RPC failed, we already got has_code=False.
            pass

        # Classify
        if danger_signals >= 2:
            return "dangerous", reasons
        if danger_signals >= 1:
            return "dangerous", reasons
        if suspicious_signals >= 2:
            return "suspicious", reasons
        if suspicious_signals >= 1:
            return "suspicious", reasons

        reasons.append("No known risk signals — but spender is not in the verified safe registry")
        return "suspicious", reasons  # Default to suspicious for unknown spenders

    def _recommend(self, risk: str, profile: SpenderProfile, is_unlimited: bool) -> str:
        """Generate human-readable recommendation."""
        if risk == "safe":
            if is_unlimited:
                return (
                    f"This is a recognized protocol ({profile.safe_name or profile.is_known_contract or 'verified'}). "
                    "Unlimited approval is standard for DEX routers. Safe to proceed, "
                    "but consider revoking after use if you don't trade frequently."
                )
            return "Recognized safe spender. Proceed."

        if risk == "dangerous":
            return (
                "DO NOT APPROVE. Multiple danger signals detected. "
                "This spender is likely malicious or has been reported as a scam. "
                "Signing this approval could result in total loss of the approved token."
            )

        # suspicious
        if is_unlimited:
            return (
                "Proceed with extreme caution. This spender is not in any verified registry, "
                "and the approval amount is unlimited. Consider: (1) approving only the exact "
                "amount needed, (2) revoking immediately after the transaction, "
                "(3) verifying the spender contract on Basescan first."
            )
        return (
            "Proceed with caution. This spender is not in any verified registry. "
            "Verify the contract on Basescan before signing. If unsure, do not approve."
        )
