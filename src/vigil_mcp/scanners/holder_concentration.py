"""Holder concentration / whale-risk scanner.

Other VIGIL tools ask "is the contract malicious?". This asks a different
question that sinks plenty of non-malicious tokens: *how concentrated is the
supply, and could a handful of wallets dump on you?*

Reads GoPlus token-security holder data (top holders + percentages) and
computes concentration over the wallets that can actually sell — deliberately
**excluding**:
  - LP pools / DEX pairs (that's liquidity, not a dump risk)
  - burn / dead addresses (permanently removed supply)
  - locked holders (vesting/locker contracts; can't sell yet)
  - the contract itself

A token where one EOA holds 60% of the float is a concentration risk even if
the contract is perfectly clean. Fail-safe: missing holder data returns
``unknown`` (never ``safe``).
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel

from vigil_mcp.scanners.goplus import GoPlusScanner
from vigil_mcp.scanners.known_contracts import lookup_known_contract

# Addresses that are not "dumpable float": burn/dead sinks.
_BURN_ADDRESSES = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
}

# Concentration thresholds on the top holder / top-5 share of dumpable float.
_TOP1_HIGH = 0.25  # one wallet > 25% of float
_TOP1_DANGER = 0.50  # one wallet > 50% — can nuke the chart alone
_TOP5_HIGH = 0.50  # top 5 > 50%
_TOP5_DANGER = 0.75  # top 5 > 75%


class HolderConcentrationResult(BaseModel):
    token: str
    chain: str
    available: bool = True
    determined: bool
    risk: str  # safe | caution | high | dangerous | unknown
    token_name: Optional[str] = None
    token_symbol: Optional[str] = None
    holder_count: Optional[int] = None
    top1_percent: Optional[float] = None  # largest dumpable holder (fraction)
    top5_percent: Optional[float] = None  # sum of top 5 dumpable holders
    top10_percent: Optional[float] = None
    largest_holder: Optional[str] = None
    excluded: list[str] = []  # why holders were excluded (pool/burn/locked)
    notes: list[str] = []


class HolderConcentrationScanner:
    """Assess supply concentration among wallets that can actually sell."""

    def __init__(self, goplus: Optional[GoPlusScanner] = None) -> None:
        self.goplus = goplus or GoPlusScanner()

    async def scan(self, token: str, chain: str) -> HolderConcentrationResult:
        token_l = token.lower()
        chain_l = chain.lower()

        known = lookup_known_contract(chain_l, token_l)
        if known:
            return HolderConcentrationResult(
                token=token_l,
                chain=chain_l,
                determined=True,
                risk="safe",
                token_name=known.name,
                token_symbol=known.symbol,
                notes=[f"{known.name} ({known.symbol}) is a verified blue-chip with broad distribution."],
            )

        g = await self.goplus.token_security(token_l, chain_l)
        if not g.available:
            return HolderConcentrationResult(
                token=token_l,
                chain=chain_l,
                available=False,
                determined=False,
                risk="unknown",
                notes=[f"UNDETERMINED: no holder data available ({g.note}). Not a safety guarantee."],
            )

        if not g.holders:
            return HolderConcentrationResult(
                token=token_l,
                chain=chain_l,
                determined=False,
                risk="unknown",
                token_name=g.token_name,
                token_symbol=g.token_symbol,
                holder_count=g.holder_count,
                notes=["UNDETERMINED: GoPlus returned no holder breakdown for this token. Not a safety guarantee."],
            )

        dumpable, excluded = self._dumpable_holders(g.holders, token_l)
        risk, notes = self._assess(dumpable, excluded, g.holder_count)

        top1 = dumpable[0]["pct"] if dumpable else None
        top5 = round(sum(h["pct"] for h in dumpable[:5]), 6) if dumpable else None
        top10 = round(sum(h["pct"] for h in dumpable[:10]), 6) if dumpable else None
        largest = dumpable[0]["address"] if dumpable else None

        return HolderConcentrationResult(
            token=token_l,
            chain=chain_l,
            determined=True,
            risk=risk,
            token_name=g.token_name,
            token_symbol=g.token_symbol,
            holder_count=g.holder_count,
            top1_percent=top1,
            top5_percent=top5,
            top10_percent=top10,
            largest_holder=largest,
            excluded=excluded,
            notes=notes,
        )

    def _dumpable_holders(self, holders: list, token: str) -> tuple[list[dict[str, Any]], list[str]]:
        """Filter to wallets that can actually sell; return (dumpable, exclusion_notes)."""
        dumpable: list[dict[str, Any]] = []
        excluded: list[str] = []
        for h in holders:
            if not isinstance(h, dict):
                continue
            addr = str(h.get("address", "")).lower()
            try:
                pct = float(h.get("percent", 0) or 0)
            except (TypeError, ValueError):
                pct = 0.0
            tag = str(h.get("tag", "") or "").lower()
            is_contract = bool(h.get("is_contract"))
            is_locked = bool(h.get("is_locked"))

            if addr == token:
                excluded.append(f"{addr[:10]}… (token contract, {pct * 100:.1f}%)")
                continue
            if addr in _BURN_ADDRESSES:
                excluded.append(f"{addr[:10]}… (burn, {pct * 100:.1f}%)")
                continue
            if is_locked:
                excluded.append(f"{addr[:10]}… (locked, {pct * 100:.1f}%)")
                continue
            # Pool / locker / bridge style tags are liquidity, not dump risk.
            if any(t in tag for t in ("pool", "lp", "uniswap", "aerodrome", "pair", "locker", "lock", "bridge")):
                excluded.append(f"{addr[:10]}… ({tag or 'pool'}, {pct * 100:.1f}%)")
                continue
            dumpable.append({"address": addr, "pct": pct, "is_contract": is_contract})
        dumpable.sort(key=lambda x: x["pct"], reverse=True)
        return dumpable, excluded

    def _assess(self, dumpable: list, excluded: list, holder_count: Optional[int]) -> tuple[str, list[str]]:
        notes: list[str] = []
        if not dumpable:
            notes.append(
                "No dumpable wallets in the top holders — supply sits in pools/locks/burns "
                "(per the top-holder sample). Low concentration risk from this view."
            )
            if excluded:
                notes.append("Excluded (not dumpable float): " + "; ".join(excluded[:6]))
            return "safe", notes

        top1 = dumpable[0]["pct"]
        top5 = sum(h["pct"] for h in dumpable[:5])
        risk = "safe"
        order = ["safe", "caution", "high", "dangerous"]

        def escalate(level: str) -> None:
            nonlocal risk
            if order.index(level) > order.index(risk):
                risk = level

        if top1 >= _TOP1_DANGER:
            escalate("dangerous")
            notes.append(
                f"DANGEROUS: a single wallet holds {top1 * 100:.1f}% of the dumpable float — "
                "it can crater the price alone."
            )
        elif top1 >= _TOP1_HIGH:
            escalate("high")
            notes.append(f"HIGH: the largest wallet holds {top1 * 100:.1f}% of the dumpable float.")

        if top5 >= _TOP5_DANGER:
            escalate("dangerous")
            notes.append(
                f"DANGEROUS: the top 5 wallets hold {top5 * 100:.1f}% combined — coordinated or cascading dump risk."
            )
        elif top5 >= _TOP5_HIGH:
            escalate("high")
            notes.append(f"HIGH: the top 5 wallets hold {top5 * 100:.1f}% of the dumpable float.")

        if risk == "safe":
            if top1 > 0.10:
                escalate("caution")
                notes.append(f"Largest wallet holds {top1 * 100:.1f}% — moderate concentration, watch for large moves.")
            else:
                notes.append(f"Float looks distributed — largest dumpable wallet is {top1 * 100:.1f}%.")

        if holder_count is not None:
            notes.append(f"Total holders: {holder_count:,}.")
        if excluded:
            notes.append("Excluded from concentration (pools/locks/burns): " + "; ".join(excluded[:5]))

        return risk, notes
