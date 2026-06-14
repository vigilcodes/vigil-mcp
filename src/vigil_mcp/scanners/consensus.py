"""Multi-source consensus — agreement across independent signals.

The whole VIGIL thesis is "low false positives." A single source flagging a
token is noise; multiple independent sources agreeing is signal. This module
queries the independent scanners VIGIL already has, lets each cast an
INDEPENDENT vote (safe / risk / unknown), and reports the consensus plus how
many sources agreed.

Sources (each votes independently):
  1. GoPlus Security        — honeypot / tax / mint / ownership flags
  2. Onchain bytecode       — contract code presence + safety-pattern score
  3. DexScreener market     — liquidity depth + pool age
  4. Deployer / verification— source-verified + deployer reputation
  5. Community scam DB       — crowd-reported scam evidence

A verdict is only "critical"/"high" when MULTIPLE sources concur, which is how
we keep one noisy source from producing a false positive.
"""

from __future__ import annotations

import asyncio
from typing import Any

from pydantic import BaseModel

from vigil_mcp.scanners.deployer import DeployerScanner
from vigil_mcp.scanners.goplus import GoPlusScanner
from vigil_mcp.scanners.known_contracts import lookup_known_contract
from vigil_mcp.scanners.market import MarketScanner
from vigil_mcp.scanners.safety_score import SafetyScorer
from vigil_mcp.scanners.scam_db import ScamDatabase

# Vote values
SAFE = "safe"
RISK = "risk"
UNKNOWN = "unknown"


class SourceVote(BaseModel):
    source: str
    vote: str  # safe | risk | unknown
    weight: float  # how strongly this source's risk vote counts
    reasons: list[str] = []


class ConsensusResult(BaseModel):
    token: str
    chain: str
    verdict: str  # safe | low | medium | high | critical | unknown
    confidence: float  # 0..1 — share of participating sources that agree
    risk_sources: int  # how many sources voted RISK
    safe_sources: int
    unknown_sources: int
    total_sources: int
    votes: list[SourceVote]
    summary: str


class ConsensusEngine:
    """Aggregate independent scanner signals into one agreement-based verdict."""

    def __init__(self) -> None:
        self.goplus = GoPlusScanner()
        self.scorer = SafetyScorer()
        self.market = MarketScanner()
        self.deployer = DeployerScanner()
        self.scam_db = ScamDatabase()

    async def evaluate(self, token: str, chain: str) -> ConsensusResult:
        """Query all sources concurrently and compute the consensus verdict."""
        # Blue-chip fast-path: a verified registry hit is itself a strong,
        # independent "safe" signal; still gather the rest for transparency.
        known = lookup_known_contract(chain, token)

        gp_task = self.goplus.token_security(token, chain)
        score_task = self.scorer.score(token, chain)
        market_task = self.market.get_market(token, chain)
        deployer_task = self.deployer.check(token, chain)

        gp, score, market, deployer = await asyncio.gather(
            gp_task, score_task, market_task, deployer_task, return_exceptions=True
        )
        scam = self.scam_db.check(token, chain)

        votes: list[SourceVote] = [
            self._vote_goplus(gp),
            self._vote_score(score),
            self._vote_market(market),
            self._vote_deployer(deployer, known is not None),
            self._vote_scam(scam),
        ]

        return self._tally(token, chain, votes)

    # ── per-source voting ────────────────────────────────────
    def _vote_goplus(self, gp: Any) -> SourceVote:
        if isinstance(gp, Exception) or gp is None or not getattr(gp, "available", False):
            return SourceVote(source="goplus", vote=UNKNOWN, weight=0.0, reasons=["no data"])
        reasons: list[str] = []
        risk = False
        if gp.is_honeypot:
            risk = True
            reasons.append("honeypot flag")
        if gp.cannot_sell_all:
            risk = True
            reasons.append("cannot sell all")
        if (gp.buy_tax and gp.buy_tax > 0.10) or (gp.sell_tax and gp.sell_tax > 0.10):
            risk = True
            reasons.append("high tax (>10%)")
        if gp.hidden_owner:
            risk = True
            reasons.append("hidden owner")
        if gp.can_take_back_ownership:
            reasons.append("owner can reclaim ownership")
        if risk:
            return SourceVote(source="goplus", vote=RISK, weight=1.0, reasons=reasons)
        return SourceVote(source="goplus", vote=SAFE, weight=1.0, reasons=reasons or ["no honeypot/tax flags"])

    def _vote_score(self, score: Any) -> SourceVote:
        if isinstance(score, Exception) or score is None:
            return SourceVote(source="onchain_score", vote=UNKNOWN, weight=0.0, reasons=["no data"])
        lvl = getattr(score, "risk_level", "unknown")
        val = getattr(score, "score", None)
        reasons = [f"score {val}/100 ({lvl})"] if val is not None else [lvl]
        if lvl in ("critical", "high"):
            return SourceVote(source="onchain_score", vote=RISK, weight=0.8, reasons=reasons)
        if lvl in ("safe", "low"):
            return SourceVote(source="onchain_score", vote=SAFE, weight=0.8, reasons=reasons)
        return SourceVote(source="onchain_score", vote=UNKNOWN, weight=0.0, reasons=reasons)

    def _vote_market(self, market: Any) -> SourceVote:
        if isinstance(market, Exception) or market is None or not getattr(market, "found", False):
            return SourceVote(source="market", vote=UNKNOWN, weight=0.0, reasons=["no pool data"])
        lr = getattr(market, "liquidity_risk", "unknown")
        reasons = [f"liquidity risk: {lr}"]
        if lr in ("critical", "high"):
            return SourceVote(source="market", vote=RISK, weight=0.6, reasons=reasons)
        if lr in ("low", "medium"):
            return SourceVote(source="market", vote=SAFE, weight=0.6, reasons=reasons)
        return SourceVote(source="market", vote=UNKNOWN, weight=0.0, reasons=reasons)

    def _vote_deployer(self, deployer: Any, is_known: bool) -> SourceVote:
        if isinstance(deployer, Exception) or deployer is None or not getattr(deployer, "available", False):
            if is_known:
                return SourceVote(source="deployer", vote=SAFE, weight=0.5, reasons=["verified registry contract"])
            return SourceVote(source="deployer", vote=UNKNOWN, weight=0.0, reasons=["no data"])
        if getattr(deployer, "verified", None) is True:
            return SourceVote(source="deployer", vote=SAFE, weight=0.5, reasons=["source verified"])
        if getattr(deployer, "verified", None) is False:
            return SourceVote(source="deployer", vote=RISK, weight=0.5, reasons=["source NOT verified"])
        return SourceVote(source="deployer", vote=UNKNOWN, weight=0.0, reasons=["verification unknown"])

    def _vote_scam(self, scam: dict) -> SourceVote:
        if not isinstance(scam, dict):
            return SourceVote(source="scam_db", vote=UNKNOWN, weight=0.0, reasons=["no data"])
        if scam.get("reported"):
            n = scam.get("report_count", 0)
            return SourceVote(source="scam_db", vote=RISK, weight=1.0, reasons=[f"{n} community scam report(s)"])
        return SourceVote(source="scam_db", vote=SAFE, weight=0.4, reasons=["no community reports"])

    # ── tally ────────────────────────────────────────────────
    def _tally(self, token: str, chain: str, votes: list[SourceVote]) -> ConsensusResult:
        risk_votes = [v for v in votes if v.vote == RISK]
        safe_votes = [v for v in votes if v.vote == SAFE]
        unknown_votes = [v for v in votes if v.vote == UNKNOWN]
        participating = len(risk_votes) + len(safe_votes)

        risk_weight = sum(v.weight for v in risk_votes)
        n_risk = len(risk_votes)

        # Verdict is driven by how many INDEPENDENT sources flag risk. One lone
        # source can't push past "medium" — that's the false-positive guard.
        if n_risk == 0:
            verdict = "safe"
        elif n_risk == 1:
            verdict = "medium" if risk_weight >= 0.8 else "low"
        elif n_risk == 2:
            verdict = "high"
        else:  # 3+ sources agree on risk
            verdict = "critical"

        if participating == 0:
            verdict = "unknown"
            confidence = 0.0
        else:
            agree = n_risk if verdict not in ("safe",) else len(safe_votes)
            confidence = round(agree / participating, 2)

        all_reasons: list[str] = []
        for v in risk_votes:
            all_reasons.extend(f"{v.source}: {r}" for r in v.reasons)

        if verdict == "safe":
            summary = f"{len(safe_votes)}/{participating} sources agree: no risk signals detected."
        elif verdict == "unknown":
            summary = "Insufficient data from independent sources to reach a verdict."
        else:
            summary = f"{n_risk} independent source(s) flagged risk → {verdict.upper()}. " + "; ".join(all_reasons)

        return ConsensusResult(
            token=token.lower(),
            chain=chain,
            verdict=verdict,
            confidence=confidence,
            risk_sources=n_risk,
            safe_sources=len(safe_votes),
            unknown_sources=len(unknown_votes),
            total_sources=len(votes),
            votes=votes,
            summary=summary,
        )
