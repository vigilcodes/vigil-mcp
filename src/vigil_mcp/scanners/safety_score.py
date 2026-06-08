"""Safety score calculator — 0-100 rating for any contract."""

import os

import httpx
from pydantic import BaseModel

from vigil_mcp.scanners.goplus import GoPlusScanner
from vigil_mcp.scanners.known_contracts import lookup_known_contract


class ScoreBreakdown(BaseModel):
    category: str
    score: int
    note: str


class SafetyScoreResult(BaseModel):
    address: str
    chain: str
    score: int
    risk_level: str
    breakdown: list[ScoreBreakdown]
    risk_factors: list[str]
    positive_factors: list[str]
    recommendation: str


class SafetyScorer:
    """Calculate safety scores for contracts."""

    def __init__(self):
        # Hosted API is opt-in only. The old api.bankr.bot/vigil endpoint never
        # shipped, so we default to empty and fall back to keyless analysis
        # (GoPlus + RPC). Setting BANKR_API_KEY alone must NOT route to a dead
        # endpoint — that was causing 404s in other agents' setups.
        self.api_base = os.getenv("VIGIL_API", "")
        self.api_key = os.getenv("BANKR_API_KEY", "")
        self.goplus = GoPlusScanner()
        self.rpc_urls = {
            "base": os.getenv("BASE_RPC", "https://base.publicnode.com"),
            "ethereum": os.getenv("ETH_RPC", "https://eth.llamarpc.com"),
            "polygon": os.getenv("POLYGON_RPC", "https://polygon-rpc.com"),
            "arbitrum": os.getenv("ARBITRUM_RPC", "https://arb1.arbitrum.io/rpc"),
        }

    async def score(self, address: str, chain: str) -> SafetyScoreResult:
        """Calculate safety score."""
        # Fast-path: blue-chip lookup
        known = lookup_known_contract(chain, address)
        if known:
            return SafetyScoreResult(
                address=address,
                chain=chain,
                score=known.safety_score,
                risk_level=known.risk_level,
                breakdown=[
                    ScoreBreakdown(
                        category="Verified Registry",
                        score=known.safety_score,
                        note=f"{known.name} ({known.symbol}) — {known.notes}",
                    )
                ],
                risk_factors=[],
                positive_factors=[
                    f"Listed in VIGIL verified registry as {known.name}",
                ],
                recommendation=(
                    f"Score: {known.safety_score}/100 — {known.name} is a known, "
                    f"verified contract. Risk level: {known.risk_level}."
                ),
            )
        if self.api_base and self.api_key:
            return await self._score_via_api(address, chain)
        return await self._score_via_analysis(address, chain)

    async def _score_via_api(self, address: str, chain: str) -> SafetyScoreResult:
        """Score via VIGIL hosted API."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.api_base}/score",
                params={"address": address, "chain": chain},
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            resp.raise_for_status()
            data = resp.json()

        return SafetyScoreResult(
            address=address,
            chain=chain,
            score=data.get("score", 0),
            risk_level=data.get("risk_level", "unknown"),
            breakdown=[ScoreBreakdown(**b) for b in data.get("breakdown", [])],
            risk_factors=data.get("risk_factors", []),
            positive_factors=data.get("positive_factors", []),
            recommendation=data.get("recommendation", "Unable to determine"),
        )

    async def _score_via_analysis(self, address: str, chain: str) -> SafetyScoreResult:
        """Basic scoring via direct contract analysis."""
        rpc_url = self.rpc_urls.get(chain)
        if not rpc_url:
            raise ValueError(f"No RPC configured for chain '{chain}'")

        breakdown: list[ScoreBreakdown] = []
        risk_factors: list[str] = []
        positive_factors: list[str] = []
        total_score = 0

        # Pull GoPlus security signals up front (keyless). Used to replace the
        # old placeholder "age" heuristic with real reputation data.
        gp = await self.goplus.token_security(address, chain)

        async with httpx.AsyncClient(timeout=30) as client:
            # 1. Code analysis (40 points max)
            code_resp = await client.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "eth_getCode",
                    "params": [address, "latest"],
                },
            )
            code = code_resp.json().get("result", "0x")
            code_len = (len(code) - 2) // 2  # bytes

            if code in ("0x", "0x0"):
                return SafetyScoreResult(
                    address=address,
                    chain=chain,
                    score=0,
                    risk_level="critical",
                    breakdown=[ScoreBreakdown(category="Code", score=0, note="No contract code")],
                    risk_factors=["No contract code at address"],
                    positive_factors=[],
                    recommendation="DO NOT INTERACT — No contract exists",
                )

            code_score = min(40, code_len // 10)
            if "40c10f19" in code:  # mint
                code_score -= 15
                risk_factors.append("Contains mint function")
            if "4f558e79" in code:  # blacklist
                code_score -= 10
                risk_factors.append("Contains blacklist function")
            if "363d3d373d3d3d363d73" in code[:50]:
                code_score -= 5
                risk_factors.append("Minimal proxy pattern")

            code_score = max(0, code_score)
            total_score += code_score
            breakdown.append(
                ScoreBreakdown(
                    category="Code Quality",
                    score=code_score,
                    note=f"Contract size: {code_len} bytes",
                )
            )

            # 2. Reputation / security signals (20 points) — GoPlus-backed.
            # Replaces the old placeholder age heuristic with real data when
            # available; falls back to a neutral score otherwise.
            await client.post(
                rpc_url,
                json={"jsonrpc": "2.0", "id": 2, "method": "eth_blockNumber"},
            )

            if gp.available:
                rep_score = 20
                rep_notes = []
                if gp.is_open_source is True:
                    rep_notes.append("verified/open-source")
                    positive_factors.append("Source code is open / verified")
                elif gp.is_open_source is False:
                    rep_score -= 8
                    risk_factors.append("Source code not verified")
                if gp.is_honeypot is True:
                    rep_score -= 20
                    risk_factors.append("GoPlus flags token as honeypot")
                if gp.is_mintable is True:
                    rep_score -= 6
                    risk_factors.append("Token is mintable")
                if gp.can_take_back_ownership is True:
                    rep_score -= 6
                    risk_factors.append("Owner can reclaim ownership")
                if gp.hidden_owner is True:
                    rep_score -= 6
                    risk_factors.append("Hidden owner detected")
                if gp.holder_count is not None:
                    rep_notes.append(f"{gp.holder_count} holders")
                    if gp.holder_count >= 500:
                        positive_factors.append(f"Broad holder base ({gp.holder_count})")
                age_score = max(0, min(20, rep_score))
                breakdown.append(
                    ScoreBreakdown(
                        category="Reputation",
                        score=age_score,
                        note="GoPlus: " + (", ".join(rep_notes) if rep_notes else "analyzed"),
                    )
                )
            else:
                age_score = 10  # Neutral default when GoPlus has no data
                breakdown.append(
                    ScoreBreakdown(
                        category="Reputation",
                        score=age_score,
                        note="No external reputation data available",
                    )
                )
            total_score += age_score

            # 3. Bytecode uniqueness (20 points)
            unique_score = 15  # Default positive
            if len(code) < 100:
                unique_score = 5
                risk_factors.append("Very small contract — may be minimal proxy")
            else:
                positive_factors.append("Substantial contract code")
            total_score += unique_score
            breakdown.append(
                ScoreBreakdown(
                    category="Complexity",
                    score=unique_score,
                    note=f"Bytecode length: {code_len} bytes",
                )
            )

            # 4. Basic safety patterns (20 points)
            safety_score = 15
            if "715018a6" in code:  # renounceOwnership
                safety_score += 3
                positive_factors.append("Has renounceOwnership function")
            if "3b16aa6f" in code:  # OnlyOwner patterns
                safety_score -= 2

            total_score += min(20, safety_score)
            breakdown.append(
                ScoreBreakdown(
                    category="Safety Patterns",
                    score=min(20, safety_score),
                    note="Basic pattern analysis",
                )
            )

        total_score = max(0, min(100, total_score))
        risk_level = (
            "critical"
            if total_score < 30
            else "high"
            if total_score < 50
            else "medium"
            if total_score < 70
            else "low"
            if total_score < 90
            else "safe"
        )

        if not positive_factors:
            positive_factors.append("Contract has deployed code")

        return SafetyScoreResult(
            address=address,
            chain=chain,
            score=total_score,
            risk_level=risk_level,
            breakdown=breakdown,
            risk_factors=risk_factors,
            positive_factors=positive_factors,
            recommendation=(
                f"Score: {total_score}/100 — "
                + (
                    "Run full API scan for deeper analysis"
                    if total_score >= 50
                    else "HIGH RISK — Exercise extreme caution"
                )
            ),
        )
