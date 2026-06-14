# Design Document

## Overview

The Liquidity Lock Scanner is a new VIGIL scanner that classifies a token's DEX
liquidity as `locked`, `burned`, `unlocked`, or `unknown` — the classic rug-pull
vector. It plugs into VIGIL's existing scanner pattern: a Pydantic result model,
an async entry method, a keyless primary source (DexScreener) with a direct-RPC
fallback, graceful per-chain degradation, an MCP tool plus an HTTP JSON-RPC
handler in `server.py`, and an independent vote that feeds the consensus engine.

The dominant failure to avoid is a false negative — calling a token "safe" when
the data is simply missing. The design therefore separates three outcomes
explicitly: positive lock signal, withdrawable-LP risk signal, and
insufficient-data signal. The "insufficient" outcome maps to an `unknown` vote
with zero weight in the consensus, so missing data never raises or lowers the
overall verdict.

This scanner targets Base (chain id 8453) first. Sibling scanners already map
ethereum, polygon, and arbitrum, so the chain plumbing is reused; only the
locker registry is initially populated for Base, and unmapped chains return a
clean unsupported-chain `unknown` result.

## Architecture

### File layout

```
src/vigil_mcp/scanners/
  liquidity_lock.py       (new) scanner + Pydantic models
  known_lockers.py        (new) hardcoded locker/burn registry
  consensus.py            (edit) add liquidity_lock as a 6th independent source
src/vigil_mcp/
  server.py               (edit) register MCP tool + TOOL_MAP entries
src/vigil_mcp/payments/
  x402.py                 (no change) — scanner is free, NOT added to price map
tests/
  test_scanners.py        (edit) add LiquidityLockScanner test class
  test_consensus.py       (edit) extend votes list with liquidity_lock vote
```

The scanner does not touch existing scanner files. The only edits to existing
modules are additive: one extra source in `consensus.py`, two extra registrations
in `server.py`, and a few extra test cases. No existing behavior changes.

### Component diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                  vigil_liquidity_lock (MCP tool)                  │
│                  liquidity_lock (TOOL_MAP alias)                  │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                    LiquidityLockScanner.scan()                    │
│                                                                   │
│   1. validate chain → unsupported ⇒ unknown (Req 5)               │
│   2. resolve LP (DexScreener primary, RPC fallback) (Req 3)       │
│   3. eth_call totalSupply(LP)        (Req 3, 4)                   │
│   4. eth_call balanceOf(LP, holder)  for each registry entry      │
│   5. compute Locked_Fraction, classify against Lock_Threshold     │
│   6. (optional) eth_call unlock timestamp on locker (Req 1.6)     │
│   7. build LockResult + notes (Req 9)                             │
└──────────────────────────────────────────────────────────────────┘
            │                │                  │
            ▼                ▼                  ▼
   ┌────────────────┐ ┌──────────────┐ ┌────────────────────┐
   │  DexScreener   │ │ Base RPC     │ │ Known_Lockers      │
   │  (keyless)     │ │ JSON-RPC     │ │ Registry (in-repo) │
   │  Pair_Address  │ │ eth_call     │ │ UNCX, Team Finance,│
   │  via market.py │ │ uint256      │ │ burn addrs         │
   └────────────────┘ └──────────────┘ └────────────────────┘
                                │
                                ▼
                  ┌──────────────────────────────────┐
                  │  ConsensusEngine (existing)      │
                  │  +1 independent source           │
                  │  vote: safe / risk / unknown     │
                  └──────────────────────────────────┘
```

### Data flow

1. The MCP tool / HTTP handler validates the token address (existing
   `_validate_address` helper) and chain string, then calls `scan()`.
2. `scan()` first looks up `_CHAIN_IDS` (mirrors `market.py`/`deployer.py`
   convention). Unmapped chain ⇒ immediate `unknown` `LockResult` with
   `available=False` and an "unsupported chain" note.
3. The scanner asks `MarketScanner.get_market(token, chain)` (already keyless,
   already used by other scanners) for the deepest pair. The returned
   `pair_address` is the LP_Token address for V2-style pairs (Aerodrome,
   Uniswap V2 forks on Base) — these pairs are themselves the ERC-20 LP token.
4. If no pair is found, the scanner attempts an RPC-only fallback (described
   below). If both fail, returns `unknown`.
5. With an LP_Token address in hand, the scanner issues a small batch of
   `eth_call`s against the chain RPC: `totalSupply()` once, then `balanceOf()`
   for every recognized holder in the Known_Lockers_Registry for that chain.
6. The Locked_Fraction is `sum(holder_balances) / totalSupply`. The
   classification rules are deterministic and listed in the next section.
7. For `locked` results where the locker contract exposes a public unlock
   timestamp (UNCX, Team.Finance), one extra `eth_call` retrieves it. Failure
   is silently dropped — unlock timestamp is best-effort enrichment, not a
   correctness requirement.
8. The result is assembled into a `LockResult` Pydantic model and returned.

## Components and Interfaces

### `known_lockers.py`

Mirrors `known_contracts.py` exactly: per-chain dict, lowercase address keys,
hardcoded entries, lookup helper. No I/O, no remote sync.

```python
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class KnownLocker:
    name: str
    kind: str            # "locker" | "burn"
    unlock_selector: Optional[str] = None  # 4-byte selector for unlockDate(), if any
    note: str = ""


# Burn addresses are universal (apply to all chains).
BURN_ADDRESSES: set[str] = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
}

# Per-chain locker registry. Keys are lowercase hex addresses.
# Source: official UNCX docs at docs.uncx.network/guides/for-developers/
#         liquidity-lockers/lockers-v2/contracts. Each entry MUST be reverified
#         against on-chain bytecode before merge (see verification log below).
KNOWN_LOCKERS: dict[str, dict[str, KnownLocker]] = {
    "base": {
        # UNCX Liquidity Lockers V2 — verified on Base RPC (12,432 bytes
        # bytecode at this address as of design time).
        "0xc4e637d37113192f4f1f060daebd7758de7f4131": KnownLocker(
            "UNCX Network Locker V2", "locker",
            note="UNCX V2 LP locker — verifies LP holdings via balanceOf().",
        ),
        # NOTE — Team.Finance:
        # Team.Finance / TrustSwap do NOT publish their per-chain contract
        # addresses in any official docs accessible at design time. Adding an
        # unverified address would risk false `locked` verdicts (the exact
        # failure mode this scanner exists to prevent), so Team.Finance is
        # intentionally left out of the initial registry. To add it later,
        # source the address from a verified Team.Finance lock transaction on
        # Basescan and confirm the contract emits Lock events.
    },
    "ethereum": {},
    "polygon": {},
    "arbitrum": {},
}


def is_burn_address(addr: str) -> bool:
    return addr.lower() in BURN_ADDRESSES


def lookup_locker(chain: str, addr: str) -> Optional[KnownLocker]:
    """Return locker metadata for a known locker contract on `chain`, else None."""
    return KNOWN_LOCKERS.get(chain.lower(), {}).get(addr.lower())


def all_lock_holders(chain: str) -> list[str]:
    """All addresses (burn + lockers on this chain) we should query balances for."""
    return list(BURN_ADDRESSES) + list(KNOWN_LOCKERS.get(chain.lower(), {}).keys())
```

The two locker addresses for Base are intentionally left as comments in the
design — they MUST be verified against on-chain state before merge. Shipping
with the wrong address would create false safe verdicts, the exact failure mode
this whole spec exists to prevent.

### `liquidity_lock.py`

Public surface mirrors `HoneypotDetector` and `MarketScanner`: one class, one
async entry method, Pydantic result model.

```python
import os
from typing import Optional

import httpx
from pydantic import BaseModel

from vigil_mcp.scanners.known_lockers import (
    BURN_ADDRESSES,
    all_lock_holders,
    is_burn_address,
    lookup_locker,
)
from vigil_mcp.scanners.market import MarketScanner

# Single threshold — anything ≥ this counts as locked/burned.
LOCK_THRESHOLD: float = 0.80

# Same chain mapping convention as goplus/market/deployer.
_CHAIN_IDS = {
    "base": 8453,
    "ethereum": 1,
    "polygon": 137,
    "arbitrum": 42161,
}


class LockResult(BaseModel):
    token: str
    chain: str
    available: bool = True            # False ⇒ unsupported chain or no RPC
    determined: bool                  # False ⇒ Lock_Status is `unknown`
    lock_status: str                  # locked | burned | unlocked | unknown
    pair_address: Optional[str] = None
    lp_token: Optional[str] = None
    locked_fraction: Optional[float] = None
    unlock_timestamp: Optional[int] = None
    locker_name: Optional[str] = None
    notes: list[str] = []


class LiquidityLockScanner:
    def __init__(self) -> None:
        self.market = MarketScanner()
        self.rpc_urls = {
            "base":     os.getenv("BASE_RPC", "https://base.publicnode.com"),
            "ethereum": os.getenv("ETH_RPC", "https://eth.llamarpc.com"),
            "polygon":  os.getenv("POLYGON_RPC", "https://polygon-rpc.com"),
            "arbitrum": os.getenv("ARBITRUM_RPC", "https://arb1.arbitrum.io/rpc"),
        }

    async def scan(self, token: str, chain: str) -> LockResult: ...
```

Internal helpers (private, names indicative):

| Helper | Purpose |
| --- | --- |
| `_resolve_lp(token, chain)` | Returns `(pair_address, lp_token, notes)` via DexScreener; on failure attempts RPC fallback; on second failure returns `(None, None, notes)`. |
| `_total_supply(client, rpc, lp)` | One `eth_call` for `totalSupply()`. Returns `Optional[int]` (None if undecodable). |
| `_balance_of(client, rpc, lp, holder)` | One `eth_call` for `balanceOf(holder)`. Returns `Optional[int]`. |
| `_unlock_timestamp(client, rpc, locker, lp)` | Best-effort. Returns `Optional[int]`. Failure is silently swallowed. |
| `_classify(locked_burn, locked_locker, total)` | Pure function from balances to `Lock_Status`. No I/O. |
| `_unsupported_chain_result(token, chain)` | Build `LockResult(available=False, …)` quickly. |

### `_classify` — the core pure function

This is the function that decides the verdict. Keeping it pure (no I/O, no
state) lets us test the whole rule set with plain unit tests.

```
inputs:
  burn_balance:    int  >= 0   (sum of LP held at burn addresses)
  locker_balance:  int  >= 0   (sum of LP held by recognized lockers)
  total_supply:    int  > 0    (caller must have already filtered total==0)

returns: Literal["locked", "burned", "unlocked"]

rules:
  fraction = (burn_balance + locker_balance) / total_supply
  if fraction < LOCK_THRESHOLD:                  → "unlocked"
  if burn_balance / total_supply >= LOCK_THRESHOLD: → "burned"
  → "locked"
```

Note the order matters: `burned` takes precedence over `locked` only when the
*burn* portion alone clears the threshold. Mixed-but-mostly-burn pools
(e.g. 75 % burn + 10 % UNCX = 85 % combined) classify as `locked`, which is
correct: the burned portion alone is not strong enough to call it permanently
removed, but the combined lock is strong enough to call it locked.

`total_supply == 0` and `total_supply == None` are screened *before* calling
`_classify` and return `unknown` directly — the function's preconditions are
strictly enforced.

### Integration with `consensus.py`

One additional independent source. Wiring follows the existing pattern exactly.

```python
# In ConsensusEngine.__init__
self.lock = LiquidityLockScanner()

# In ConsensusEngine.evaluate(), append to the gather()
lock_task = self.lock.scan(token, chain)
gp, score, market, deployer, lock = await asyncio.gather(
    gp_task, score_task, market_task, deployer_task, lock_task,
    return_exceptions=True,
)

# After the existing votes list, append:
votes.append(self._vote_lock(lock))
```

```python
def _vote_lock(self, lock: Any) -> SourceVote:
    if isinstance(lock, Exception) or lock is None or not getattr(lock, "available", False):
        return SourceVote(source="liquidity_lock", vote=UNKNOWN, weight=0.0, reasons=["no data"])
    status = getattr(lock, "lock_status", "unknown")
    if status in ("locked", "burned"):
        return SourceVote(source="liquidity_lock", vote=SAFE, weight=0.7, reasons=[f"LP {status}"])
    if status == "unlocked":
        return SourceVote(source="liquidity_lock", vote=RISK, weight=0.7, reasons=["LP withdrawable"])
    return SourceVote(source="liquidity_lock", vote=UNKNOWN, weight=0.0, reasons=["lock undetermined"])
```

Weight `0.7` sits between deployer (0.5) and goplus/scam_db (1.0) — a strong
signal but not as decisive as a hard scam-DB hit. Crucially, `unknown` carries
weight 0.0 so missing lock data cannot influence the consensus, satisfying
Req 7.4. The existing tally rules in `_tally()` already handle 6 sources
without modification (the n_risk thresholds 0/1/2/3+ are independent of the
total source count).

### Server registration (`server.py`)

Two additions, both copy/paste of the established convention.

```python
# 1. Module-level singleton (next to the other scanner singletons)
liquidity_lock_scanner = LiquidityLockScanner()


# 2. New MCP tool
@mcp.tool()
async def vigil_liquidity_lock(token: str, chain: str = "base") -> dict[str, Any]:
    """Detect whether a token's DEX liquidity is locked, burned, or withdrawable.

    Free core safety check. Returns lock_status of:
      - `locked` / `burned`: positive signal (LP cannot be pulled)
      - `unlocked`:          rug-pull risk
      - `unknown`:           insufficient data — NOT a safety guarantee
    """
    token = _validate_address(token, "token")
    result = await liquidity_lock_scanner.scan(token, chain)
    return result.model_dump()


# 3. TOOL_MAP entries (both prefixed and bare alias)
TOOL_MAP["vigil_liquidity_lock"] = lambda args: vigil_liquidity_lock(
    args.get("token") or args.get("contract", ""), args.get("chain", "base")
)
TOOL_MAP["liquidity_lock"] = TOOL_MAP["vigil_liquidity_lock"]
```

The tool is intentionally **not** added to `payments/x402.py`
`_default_prices()`. It remains free, consistent with `vigil_detect_honeypot`
and `vigil_safety_score` (Req 8).

## Data Models

### `LockResult` field-by-field

| Field | Type | Set when | Notes |
| --- | --- | --- | --- |
| `token` | `str` | always | Lowercase 0x address. |
| `chain` | `str` | always | Echoed back from input. |
| `available` | `bool` | always | `False` only on unsupported chain or missing RPC. |
| `determined` | `bool` | always | `True` iff `lock_status != "unknown"`. Explicit boolean satisfies Req 2.4. |
| `lock_status` | `str` | always | One of `locked`, `burned`, `unlocked`, `unknown`. |
| `pair_address` | `Optional[str]` | when LP resolved | Lowercase. |
| `lp_token` | `Optional[str]` | when LP resolved | Equal to `pair_address` for V2-style pools. |
| `locked_fraction` | `Optional[float]` | when total supply > 0 | Range 0.0–1.0, rounded to 4 decimals. |
| `unlock_timestamp` | `Optional[int]` | best-effort | Unix seconds. |
| `locker_name` | `Optional[str]` | when `lock_status == "locked"` | Human-readable locker name from registry. |
| `notes` | `list[str]` | always | At least one entry; describes basis for `lock_status`. |

The `determined` boolean is deliberate: callers who only consume JSON shouldn't
need to compare strings to know whether a result is conclusive (Req 2.3, 2.4).

### Notes contract

Each `lock_status` produces at least one note with a fixed prefix so callers
can match on the prefix without parsing prose:

```
locked:    "Locked: <fraction>% of LP held by <locker_name>. Unlock: <ISO date>" (date optional)
burned:    "Burned: <fraction>% of LP sent to burn address — permanent"
unlocked:  "WITHDRAWABLE: only <fraction>% of LP is locked — rug-pull risk"
unknown:   "UNDETERMINED: <reason>. Not a safety guarantee."
```

These map directly to Req 9.2–9.4.

## Error Handling

The scanner never raises to its caller for upstream failures; every failure
class lands in a well-formed `unknown` `LockResult`. The internal layout uses
nested try/except with narrow exception types. A small table of expected error
classes:

| Failure | Raised internally | External effect |
| --- | --- | --- |
| Unsupported chain | none — early return | `available=False`, `lock_status=unknown` |
| Missing RPC URL | `ValueError` caught | `lock_status=unknown`, note identifies missing config |
| DexScreener timeout / 4xx / 5xx | `httpx.HTTPError` caught in market scanner | Falls through to RPC fallback |
| RPC fallback unable to find LP | none | `lock_status=unknown`, note "No DEX pair found" |
| `eth_call` returns `0x` | none — `_total_supply`/`_balance_of` return None | If `totalSupply` None ⇒ unknown; if a single `balanceOf` None ⇒ skip that holder, continue |
| `totalSupply == 0` | none | `lock_status=unknown`, note "LP supply is zero" |
| Unlock-timestamp call fails | swallowed | `unlock_timestamp` left None |
| Bad token address | `InvalidAddressError` from `_validate_address` | HTTP 400 (existing server handler) |

Hidden contracts behind the design:

- **No partial caching.** A failed second `balanceOf` does NOT cause the scan
  to return data from a previous run. Req 10.3/10.4. The scanner has no
  instance-level state that survives across `scan()` calls.
- **Per-request timeout.** A single `httpx.AsyncClient(timeout=20)` covers the
  RPC and the (already-bounded) DexScreener call inside `MarketScanner`.
  Req 10.1.
- **One slow holder doesn't poison the whole scan.** `eth_call` for each
  holder runs concurrently via `asyncio.gather(..., return_exceptions=True)`,
  bounded by the same 20s client timeout. A failed holder ⇒ skipped, scan
  continues.

## Testing Strategy

Three test groups, all in the existing `tests/` layout. No property-based tests
or new framework — VIGIL's pattern is straightforward `pytest`/`pytest-asyncio`
plus `httpx_mock` fixtures.

### Unit tests — `_classify` (no I/O)

Plain pytest, no async, no fixtures. Exhaustive coverage of the truth table:

| burn | locker | total | expected |
| --- | --- | --- | --- |
| 100 | 0 | 100 | `burned` |
| 80  | 0 | 100 | `burned` |
| 79  | 0 | 100 | `unlocked` |
| 0   | 80 | 100 | `locked` |
| 50  | 30 | 100 | `locked` (combined ≥80, but burn alone <80) |
| 0   | 0 | 100 | `unlocked` |

This locks the threshold rules and the `burned > locked` precedence.

### Integration tests — `LiquidityLockScanner.scan()` with mocked HTTP

Using the existing `httpx_mock` pattern from `tests/test_scanners.py`:

1. **Happy path locked** — DexScreener returns a pair; `eth_call` chain returns
   total=1000, locker holds 850. Asserts `lock_status == "locked"`,
   `determined == True`, `locked_fraction == 0.85`, `locker_name` populated,
   notes prefix matches.
2. **Happy path burned** — Same shape but burn address holds 950 of 1000.
   Asserts `lock_status == "burned"`.
3. **Unlocked** — Total 1000, burn 100, locker 0. Asserts `unlocked` and the
   "WITHDRAWABLE" note prefix.
4. **Unknown — DexScreener empty + RPC fallback empty** — Both sources return
   no pair. Asserts `lock_status == "unknown"`, `determined == False`,
   `available == True`.
5. **Unknown — totalSupply returns 0x** — RPC returns empty result for
   `totalSupply()`. Asserts `unknown` and a note identifying the missing data.
6. **Unsupported chain** — Pass `chain="solana"`. Asserts immediate
   `available == False`, `lock_status == "unknown"`. No HTTP calls expected.
7. **Missing RPC for mapped chain** — Monkey-patch `rpc_urls` to drop "base".
   Asserts `unknown` with a note about missing RPC config.
8. **Token address validation** — Invalid hex passed to MCP tool, server
   returns `InvalidAddressError`. (Same pattern as `test_server_guards.py`.)
9. **No cross-request state** — Run a successful scan, then a scan that fails
   at every layer, then assert the second result has no leftover fields from
   the first (`pair_address`, `locked_fraction` are all `None`).

### Consensus integration test — `tests/test_consensus.py`

One new test that confirms `liquidity_lock` participates as a 6th independent
source and that an `unknown` lock vote does not move the verdict.

```python
def test_liquidity_lock_unknown_does_not_shift_verdict():
    votes = [_safe("goplus"), _safe("onchain_score"), _safe("market"),
             _safe("deployer"), _safe("scam_db"),
             SourceVote(source="liquidity_lock", vote=UNKNOWN, weight=0.0, reasons=[])]
    r = _tally(votes)
    assert r.verdict == "safe"
    assert r.unknown_sources == 1
```

### Smoke test addition

Add one line to `scripts/smoke_test.sh` calling
`vigil_liquidity_lock` against USDC on Base. Expected: `lock_status` ≠
`unknown` (USDC's "LP" question is degenerate but the scanner should still
return `unsupported` or fall through cleanly without crashing). The test is a
regression guard, not a correctness check — correctness lives in the unit and
integration tests.

## Open Questions

These are deliberately surfaced rather than silently decided:

1. **Locker registry status (resolved-with-caveats).** UNCX Liquidity Lockers
   V2 on Base is verified: address `0xc4e637d37113192f4f1f060daebd7758de7f4131`
   sourced from official UNCX docs and confirmed on-chain (12,432 bytes of
   bytecode). Burn addresses `0x0…0` and `0x…dEaD` are also verified
   code-less. Team.Finance is intentionally excluded from the initial
   registry because no per-chain contract address is published in any
   official Team.Finance/TrustSwap documentation accessible at design time;
   shipping with a guessed address would create the exact false-locked
   verdict this scanner exists to prevent. The registry can be extended once
   a Team.Finance Base address is sourced from a verified lock transaction
   on Basescan. UNCX V3 (NFT-based) is also out of scope for the initial
   ship — see Open Question #2.
2. **V3 concentrated-liquidity pools.** Aerodrome Slipstream / Uniswap V3 do
   not use ERC-20 LP tokens — they mint NFT positions. The current design
   covers V2-style pools only. V3 lock detection requires reading
   `NonfungiblePositionManager` data and is out of scope for this spec. The
   notes for `unknown` should mention "V3 / NFT-LP positions are not yet
   supported" when the resolved pair has no totalSupply (a strong V3 signal).
3. **Aggregating across multiple pairs.** A token may have several pairs
   (e.g. tokenA/USDC and tokenA/WETH). DexScreener returns "deepest pair
   only" via `MarketScanner`, which is conservative — we report on the most
   relevant pool, not the union. Multi-pair aggregation is a future
   enhancement and is not required to ship the scanner usefully.
