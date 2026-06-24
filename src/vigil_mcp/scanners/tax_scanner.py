"""Token tax / transfer-fee scanner — surface punishing or mutable trade taxes.

A token can be perfectly sellable (so the honeypot check passes) yet still bleed
you on every trade through buy/sell/transfer tax — or, worse, carry tax that the
owner can *change* after you buy ("0% today, 99% tomorrow"). This scanner reads
GoPlus token-security data and assesses the tax surface specifically:

  - buy_tax / sell_tax / transfer_tax — the actual fees on each action
  - slippage_modifiable — owner can change the tax rate at will
  - personal_slippage_modifiable — owner can set a per-address (targeted) tax
  - trading_cooldown — forced delay between trades
  - cannot_buy — buying is blocked outright

Why separate from honeypot: honeypot answers "can I sell at all?"; this answers
"what will it cost me, and can that cost change?" High but fixed tax is a
yellow flag; *modifiable* tax is the real trap and is treated as dangerous.

Fail-safe: when GoPlus has no tax data for a token, the verdict is ``unknown``
(never ``safe``). Missing data is not a safety guarantee.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

from vigil_mcp.scanners.goplus import GoPlusScanner
from vigil_mcp.scanners.known_contracts import lookup_known_contract

# Tax thresholds (GoPlus encodes tax as a fraction: 0.10 == 10%).
_HIGH_TAX = 0.10  # >10% on a side is punishing
_SEVERE_TAX = 0.50  # >50% is effectively a soft honeypot


class TaxResult(BaseModel):
    token: str
    chain: str
    available: bool = True
    determined: bool
    risk: str  # safe | caution | high | dangerous | unknown
    token_name: Optional[str] = None
    token_symbol: Optional[str] = None
    buy_tax: Optional[float] = None
    sell_tax: Optional[float] = None
    transfer_tax: Optional[float] = None
    tax_modifiable: Optional[bool] = None
    personal_tax_modifiable: Optional[bool] = None
    trading_cooldown: Optional[bool] = None
    cannot_buy: Optional[bool] = None
    notes: list[str] = []


class TaxScanner:
    """Assess a token's trade-tax surface via GoPlus token-security data."""

    def __init__(self, goplus: Optional[GoPlusScanner] = None) -> None:
        self.goplus = goplus or GoPlusScanner()

    async def scan(self, token: str, chain: str) -> TaxResult:
        token_l = token.lower()
        chain_l = chain.lower()

        # Fast-path: verified blue-chips are standard zero-tax tokens.
        known = lookup_known_contract(chain_l, token_l)
        if known:
            return TaxResult(
                token=token_l,
                chain=chain_l,
                determined=True,
                risk="safe",
                token_name=known.name,
                token_symbol=known.symbol,
                buy_tax=0.0,
                sell_tax=0.0,
                transfer_tax=0.0,
                tax_modifiable=False,
                personal_tax_modifiable=False,
                trading_cooldown=False,
                cannot_buy=False,
                notes=[f"{known.name} ({known.symbol}) is a verified blue-chip with no trade tax."],
            )

        g = await self.goplus.token_security(token_l, chain_l)

        # No data at all -> undetermined. Never report "safe" on missing data.
        if not g.available:
            return TaxResult(
                token=token_l,
                chain=chain_l,
                available=False,
                determined=False,
                risk="unknown",
                notes=[f"UNDETERMINED: no tax data available ({g.note}). Not a safety guarantee."],
            )

        # GoPlus responded but every tax-related field is absent -> undetermined.
        tax_fields = (
            g.buy_tax,
            g.sell_tax,
            g.transfer_tax,
            g.slippage_modifiable,
            g.personal_slippage_modifiable,
        )
        if all(v is None for v in tax_fields):
            return TaxResult(
                token=token_l,
                chain=chain_l,
                determined=False,
                risk="unknown",
                token_name=g.token_name,
                token_symbol=g.token_symbol,
                notes=["UNDETERMINED: GoPlus returned no tax fields for this token. Not a safety guarantee."],
            )

        risk, notes = self._assess(g)

        return TaxResult(
            token=token_l,
            chain=chain_l,
            determined=True,
            risk=risk,
            token_name=g.token_name,
            token_symbol=g.token_symbol,
            buy_tax=g.buy_tax,
            sell_tax=g.sell_tax,
            transfer_tax=g.transfer_tax,
            tax_modifiable=g.slippage_modifiable,
            personal_tax_modifiable=g.personal_slippage_modifiable,
            trading_cooldown=g.trading_cooldown,
            cannot_buy=g.cannot_buy,
            notes=notes,
        )

    @staticmethod
    def _pct(v: Optional[float]) -> str:
        return f"{v * 100:.1f}%" if v is not None else "unknown"

    def _assess(self, g) -> tuple[str, list[str]]:  # noqa: ANN001 — GoPlusResult
        notes: list[str] = []
        risk = "safe"

        def escalate(level: str) -> None:
            nonlocal risk
            order = ["safe", "caution", "high", "dangerous"]
            if order.index(level) > order.index(risk):
                risk = level

        buy, sell, transfer = g.buy_tax, g.sell_tax, g.transfer_tax
        worst = max((v for v in (buy, sell, transfer) if v is not None), default=None)

        # Modifiable tax is the real trap: a benign rate today can become a
        # honeypot tomorrow. This dominates the verdict.
        if g.slippage_modifiable:
            escalate("dangerous")
            notes.append(
                "DANGEROUS: trade tax is OWNER-MODIFIABLE. The current rate can be raised "
                "at any time (the classic '0% now, 99% later' rug). Treat any displayed tax as non-binding."
            )
        if g.personal_slippage_modifiable:
            escalate("dangerous")
            notes.append(
                "DANGEROUS: owner can set a PER-ADDRESS tax — your wallet could be singled out "
                "for a punitive rate while others trade normally."
            )

        # Outright buy block.
        if g.cannot_buy:
            escalate("high")
            notes.append("HIGH RISK: buying is blocked for ordinary wallets (whitelist-gated).")

        # Magnitude of the (current) tax.
        if worst is not None:
            if worst >= _SEVERE_TAX:
                escalate("dangerous")
                notes.append(
                    f"DANGEROUS: severe trade tax (up to {self._pct(worst)}). "
                    "Most of any trade is taken as fee — effectively a soft honeypot."
                )
            elif worst >= _HIGH_TAX:
                escalate("high")
                notes.append(
                    f"HIGH TAX: up to {self._pct(worst)} per trade "
                    f"(buy {self._pct(buy)}, sell {self._pct(sell)}, transfer {self._pct(transfer)})."
                )
            elif worst > 0:
                escalate("caution")
                notes.append(
                    f"Has a trade tax: buy {self._pct(buy)}, sell {self._pct(sell)}, "
                    f"transfer {self._pct(transfer)}. Factor this into entry/exit."
                )

        if g.trading_cooldown:
            escalate("caution")
            notes.append("Token enforces a trading cooldown — a forced delay between trades.")

        if risk == "safe":
            notes.append(
                f"No punitive or modifiable tax detected (buy {self._pct(buy)}, sell {self._pct(sell)}, "
                f"transfer {self._pct(transfer)}). Tax is fixed at the current rate."
            )

        return risk, notes
