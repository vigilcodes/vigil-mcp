"""Hardcoded registry of recognized LP-token lock holders.

Used by the liquidity-lock scanner to decide whether LP tokens are locked,
burned, or freely withdrawable. Mirrors the per-chain, lowercase-key pattern
used by ``known_contracts.py``.

Adding entries
--------------
Every locker address MUST be sourced from official documentation AND verified
on-chain (eth_getCode returns non-empty bytecode) before merge. Shipping with
a wrong address would create false `locked` verdicts — the exact failure mode
the liquidity-lock scanner exists to prevent.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class KnownLocker:
    """Metadata for a recognized LP lock holder."""

    name: str
    kind: str  # "locker" | "burn"
    note: str = ""
    # Optional 4-byte selector for a public unlock-timestamp getter on this
    # locker. Currently unused — best-effort enrichment for a future iteration.
    unlock_selector: Optional[str] = field(default=None)


# Burn addresses are universal across chains. LP tokens sent here cannot be
# recovered, which is the strongest possible "locked" signal.
BURN_ADDRESSES: frozenset[str] = frozenset(
    {
        "0x0000000000000000000000000000000000000000",
        "0x000000000000000000000000000000000000dead",
    }
)


# Per-chain locker registry. Keys MUST be lowercase hex addresses.
#
# Verification log (re-run before extending this registry):
#   - Base, UNCX V2 (0xc4e6...4131): 12,432 bytes bytecode confirmed via
#     base.publicnode.com. Source: docs.uncx.network/guides/for-developers/
#     liquidity-lockers/lockers-v2/contracts.
#
# Intentionally absent:
#   - Team.Finance / TrustSwap: no per-chain contract address published in
#     official docs accessible at design time. Adding a guessed address would
#     risk false `locked` verdicts. Add only after sourcing from a verified
#     Team.Finance lock transaction on Basescan.
#   - UNCX V3: uses NFT positions (NonfungiblePositionManager) rather than
#     ERC-20 LP tokens; out of scope for the v1 scanner.
KNOWN_LOCKERS: dict[str, dict[str, KnownLocker]] = {
    "base": {
        "0xc4e637d37113192f4f1f060daebd7758de7f4131": KnownLocker(
            name="UNCX Network Locker V2",
            kind="locker",
            note="UNCX V2 LP locker — verifies LP holdings via balanceOf().",
        ),
    },
    "ethereum": {},
    "polygon": {},
    "arbitrum": {},
}


def is_burn_address(addr: str) -> bool:
    """Return True if the address is a recognized universal burn address."""
    return addr.lower() in BURN_ADDRESSES


def lookup_locker(chain: str, addr: str) -> Optional[KnownLocker]:
    """Return locker metadata for a known locker contract on `chain`, else None."""
    return KNOWN_LOCKERS.get(chain.lower(), {}).get(addr.lower())


def all_lock_holders(chain: str) -> list[str]:
    """Return all addresses (burn + lockers on this chain) we should query.

    Order is stable: burn addresses first, then lockers in registry order.
    """
    return list(BURN_ADDRESSES) + list(KNOWN_LOCKERS.get(chain.lower(), {}).keys())
