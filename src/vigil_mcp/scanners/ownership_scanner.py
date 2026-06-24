"""Owner / permission risk scanner — who controls this contract, and what can they do?

Honeypot answers "can I sell?", tax answers "what will it cost?", clone answers
"is this a copy?". None answer the question behind most rugs: *who holds the keys,
and what powers do those keys grant?* This scanner reads GoPlus token-security
data and assesses owner-controlled capabilities specifically:

  - is_mintable            — owner can mint new supply (dilution / infinite print)
  - transfer_pausable      — owner can freeze all transfers (soft honeypot switch)
  - can_take_back_ownership — ownership can be reclaimed after a "renounce"
  - hidden_owner           — real owner is obscured
  - owner_change_balance   — owner can edit balances directly
  - selfdestruct           — contract can be destroyed
  - is_blacklisted         — owner can blacklist addresses from selling
  - is_whitelisted         — trading gated to a whitelist
  - external_call          — contract calls arbitrary external addresses

The safest signal is a *renounced* owner (owner == 0x0 / null): no one can
exercise these powers. A live owner holding mint+pause+blacklist is a loaded gun.

Fail-safe: when GoPlus has no data, the verdict is ``unknown`` (never ``safe``).
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

from vigil_mcp.scanners.goplus import GoPlusScanner
from vigil_mcp.scanners.known_contracts import lookup_known_contract

# Addresses that mean "ownership renounced" (no controlling owner).
_NULL_OWNERS = {
    "",
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
}


class OwnershipResult(BaseModel):
    token: str
    chain: str
    available: bool = True
    determined: bool
    risk: str  # safe | caution | high | dangerous | unknown
    token_name: Optional[str] = None
    token_symbol: Optional[str] = None
    owner_address: Optional[str] = None
    ownership_renounced: Optional[bool] = None
    owner_percent: Optional[float] = None
    powers: list[str] = []  # active owner capabilities detected
    notes: list[str] = []


class OwnershipScanner:
    """Assess owner-controlled permissions on a token via GoPlus data."""

    def __init__(self, goplus: Optional[GoPlusScanner] = None) -> None:
        self.goplus = goplus or GoPlusScanner()

    async def scan(self, token: str, chain: str) -> OwnershipResult:
        token_l = token.lower()
        chain_l = chain.lower()

        known = lookup_known_contract(chain_l, token_l)
        if known:
            return OwnershipResult(
                token=token_l,
                chain=chain_l,
                determined=True,
                risk="safe",
                token_name=known.name,
                token_symbol=known.symbol,
                ownership_renounced=None,
                powers=[],
                notes=[f"{known.name} ({known.symbol}) is a verified blue-chip contract."],
            )

        g = await self.goplus.token_security(token_l, chain_l)
        if not g.available:
            return OwnershipResult(
                token=token_l,
                chain=chain_l,
                available=False,
                determined=False,
                risk="unknown",
                notes=[f"UNDETERMINED: no ownership data available ({g.note}). Not a safety guarantee."],
            )

        # If GoPlus returned no permission signals at all, stay undetermined.
        signal_fields = (
            g.is_mintable,
            g.transfer_pausable,
            g.can_take_back_ownership,
            g.hidden_owner,
            g.owner_change_balance,
            g.selfdestruct,
            g.is_blacklisted,
            g.is_whitelisted,
            g.external_call,
        )
        if all(v is None for v in signal_fields) and g.owner_address is None:
            return OwnershipResult(
                token=token_l,
                chain=chain_l,
                determined=False,
                risk="unknown",
                token_name=g.token_name,
                token_symbol=g.token_symbol,
                notes=["UNDETERMINED: GoPlus returned no ownership/permission fields. Not a safety guarantee."],
            )

        renounced = self._is_renounced(g.owner_address)
        risk, powers, notes = self._assess(g, renounced)

        return OwnershipResult(
            token=token_l,
            chain=chain_l,
            determined=True,
            risk=risk,
            token_name=g.token_name,
            token_symbol=g.token_symbol,
            owner_address=g.owner_address,
            ownership_renounced=renounced,
            owner_percent=g.owner_percent,
            powers=powers,
            notes=notes,
        )

    @staticmethod
    def _is_renounced(owner: Optional[str]) -> Optional[bool]:
        if owner is None:
            return None
        return owner.lower() in _NULL_OWNERS

    def _assess(self, g, renounced: Optional[bool]) -> tuple[str, list[str], list[str]]:  # noqa: ANN001
        powers: list[str] = []
        notes: list[str] = []
        risk = "safe"

        order = ["safe", "caution", "high", "dangerous"]

        def escalate(level: str) -> None:
            nonlocal risk
            if order.index(level) > order.index(risk):
                risk = level

        # Catalogue the active owner powers (highest-severity framing per flag).
        if g.is_mintable:
            powers.append("mint")
        if g.transfer_pausable:
            powers.append("pause_transfers")
        if g.is_blacklisted:
            powers.append("blacklist")
        if g.is_whitelisted:
            powers.append("whitelist_gating")
        if g.can_take_back_ownership:
            powers.append("reclaim_ownership")
        if g.hidden_owner:
            powers.append("hidden_owner")
        if g.owner_change_balance:
            powers.append("modify_balances")
        if g.selfdestruct:
            powers.append("selfdestruct")
        if g.external_call:
            powers.append("external_call")

        # Renounced ownership neutralizes most owner powers — strongest positive.
        if renounced and not (g.can_take_back_ownership or g.hidden_owner):
            notes.append(
                "Ownership is renounced (owner = null address) and cannot be reclaimed. "
                "Owner-gated powers can no longer be exercised."
            )
            # Even renounced, a selfdestruct/external_call path is worth a note.
            if g.selfdestruct:
                escalate("caution")
                notes.append("Contract retains a selfdestruct path despite renounced ownership.")
            return risk, powers, notes

        # The dangerous trio: can reclaim ownership, hidden owner, or modify balances.
        if g.can_take_back_ownership:
            escalate("dangerous")
            notes.append(
                "DANGEROUS: ownership can be taken back after being renounced — "
                "a renounce here is not final and can be reversed."
            )
        if g.hidden_owner:
            escalate("dangerous")
            notes.append("DANGEROUS: the real owner is hidden/obscured — control is not transparent.")
        if g.owner_change_balance:
            escalate("dangerous")
            notes.append("DANGEROUS: owner can directly modify wallet balances.")
        if g.selfdestruct:
            escalate("dangerous")
            notes.append("DANGEROUS: contract can self-destruct, which can strand or zero out holdings.")

        # High-impact but more common powers.
        if g.is_mintable:
            escalate("high")
            notes.append("HIGH RISK: owner can mint new supply (dilution / infinite-print risk).")
        if g.transfer_pausable:
            escalate("high")
            notes.append("HIGH RISK: owner can pause all transfers — a one-switch soft honeypot.")
        if g.is_blacklisted:
            escalate("high")
            notes.append("HIGH RISK: owner can blacklist addresses, blocking them from selling.")

        # Softer signals.
        if g.is_whitelisted:
            escalate("caution")
            notes.append("Trading is whitelist-gated — only approved addresses may transact freely.")
        if g.external_call:
            escalate("caution")
            notes.append("Contract makes external calls to other addresses — review what it depends on.")
        if g.owner_percent is not None and g.owner_percent >= 0.30:
            escalate("caution")
            notes.append(
                f"Owner holds a large supply share (~{g.owner_percent * 100:.0f}%) — concentrated sell pressure risk."
            )

        if risk == "safe":
            if renounced is False:
                notes.append(
                    "Owner is active but no dangerous permissions were detected. Standard owner controls only."
                )
            else:
                notes.append("No dangerous owner permissions detected.")

        return risk, powers, notes
