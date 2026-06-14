# Requirements Document

## Introduction

The Liquidity Lock Scanner is a new VIGIL security scanner that detects whether a token's
decentralized exchange (DEX) liquidity is locked, burned, or freely withdrawable by the
liquidity owner. Unlocked or owner-held liquidity is the classic "rug pull" vector: the
deployer removes the liquidity pool, leaving holders unable to sell. This scanner deepens
VIGIL's Base (chain id 8453) coverage rather than adding new chains.

VIGIL is a security tool, so the dominant failure to avoid is a **false negative** — telling
a user a token is "safe" when the underlying lock data is simply missing. Accordingly, this
scanner MUST clearly separate three distinct outcomes: liquidity is locked/burned (positive
signal), liquidity is owner-held and withdrawable (risk signal), and lock status could not be
determined (insufficient-data signal). The "could not determine" outcome MUST NOT be reported
as "safe".

The scanner follows VIGIL's established per-scanner conventions: a Pydantic result model, an
async entry method, a keyless primary data source with a direct-RPC fallback, graceful
degradation for unsupported chains, registration in `server.py` as both an MCP tool and a
`TOOL_MAP` HTTP JSON-RPC handler (with a bare alias), and a verdict that can feed the existing
safety score and consensus engine. Recognized lockers and burn addresses are sourced from a
static, in-repo registry modelled on `known_contracts.py` rather than a remote service, and a
single 80% Locked_Fraction threshold separates `locked`/`burned` from `unlocked` so the scanner
returns a binary, actionable verdict rather than a wide ambiguous middle band.

## Glossary

- **Liquidity_Lock_Scanner**: The new scanner component that determines the lock status of a token's DEX liquidity. The primary system under specification.
- **Lock_Status**: The scanner's classification of a token's liquidity, one of: `locked`, `burned`, `unlocked`, or `unknown`.
- **LP_Token**: The ERC-20 liquidity-provider token minted by a DEX pair (e.g. Aerodrome, Uniswap V2-style pair) representing a share of the pool.
- **Pair_Address**: The on-chain address of the DEX pool/pair holding the token's liquidity.
- **Locker_Contract**: A third-party time-lock contract (e.g. UNCX, Team.Finance, or a generic vesting/lock contract) that custodies LP_Tokens until an unlock timestamp.
- **Burn_Address**: A null/dead address (`0x0000...0000` or `0x...dEaD`) that LP_Tokens are sent to in order to permanently remove the ability to withdraw liquidity.
- **Locked_Fraction**: The fraction (0.0–1.0) of the total LP_Token supply held by recognized Locker_Contracts or Burn_Addresses.
- **Lock_Threshold**: The single fraction (0.80) at or above which Locked_Fraction qualifies a token's liquidity as `locked` or `burned`. Below this threshold, when LP_Token supply is resolved, the token is classified as `unlocked`.
- **Unlock_Timestamp**: The Unix timestamp at which a Locker_Contract permits withdrawal of the locked LP_Tokens.
- **Known_Lockers_Registry**: A static, in-repo registry of recognized Locker_Contracts and Burn_Addresses on each Supported_Chain, modelled on the existing `known_contracts.py` registry pattern (per-chain, lowercase address keys, hardcoded entries; no remote lookup).
- **DexScreener**: The keyless market data source already used by VIGIL (`market.py`) that provides the deepest Pair_Address, liquidity USD, and pool age.
- **RPC_Fallback**: Direct JSON-RPC calls (`eth_call`, `eth_getCode`, `eth_getLogs`) used when the primary data source cannot resolve lock status.
- **Supported_Chain**: A chain present in the scanner's chain-id mapping (Base = 8453, plus the existing ethereum, polygon, arbitrum entries used by sibling scanners).
- **Lock_Result**: The Pydantic result model returned by the Liquidity_Lock_Scanner.
- **Safety_Scorer**: The existing `SafetyScorer` component that produces a 0–100 contract safety score.
- **Consensus_Engine**: The existing `ConsensusEngine` that aggregates independent source votes into one agreement-based verdict.
- **Vote**: An independent classification (`safe`, `risk`, or `unknown`) contributed to the Consensus_Engine.

## Requirements

### Requirement 1: Determine liquidity lock status for a token

**User Story:** As a trading agent, I want to know whether a token's liquidity is locked, burned, or withdrawable before I buy, so that I can avoid tokens whose deployer can pull liquidity.

#### Acceptance Criteria

1. WHEN a token address and a Supported_Chain are provided, THE Liquidity_Lock_Scanner SHALL return a Lock_Result containing a Lock_Status of `locked`, `burned`, `unlocked`, or `unknown`.
2. WHERE recognized Burn_Addresses from the Known_Lockers_Registry hold a Locked_Fraction at or above the Lock_Threshold, THE Liquidity_Lock_Scanner SHALL set Lock_Status to `burned`.
3. WHERE recognized Locker_Contracts from the Known_Lockers_Registry hold a Locked_Fraction at or above the Lock_Threshold and the `burned` criterion does not apply, THE Liquidity_Lock_Scanner SHALL set Lock_Status to `locked`.
4. WHERE the LP_Token supply is resolved AND neither the `burned` nor the `locked` criterion applies, THE Liquidity_Lock_Scanner SHALL set Lock_Status to `unlocked`.
5. THE Liquidity_Lock_Scanner SHALL include the resolved Pair_Address, LP_Token address, and Locked_Fraction in the Lock_Result when these values are determined.
6. WHERE a Locker_Contract holds LP_Tokens and exposes an Unlock_Timestamp, THE Liquidity_Lock_Scanner SHALL include the Unlock_Timestamp in the Lock_Result.
7. THE Liquidity_Lock_Scanner SHALL determine recognized Locker_Contracts and Burn_Addresses solely by lookup against the Known_Lockers_Registry; it SHALL NOT infer lock status from the identity, role, or deployer relationship of any other LP_Token holder.

### Requirement 2: Fail safe when lock data is unavailable

**User Story:** As a user relying on VIGIL for pre-trade safety, I want the scanner to clearly distinguish "no lock detected" from "could not determine", so that missing data is never presented to me as a safe result.

#### Acceptance Criteria

1. IF the Pair_Address cannot be resolved for the token, THEN THE Liquidity_Lock_Scanner SHALL set Lock_Status to `unknown` and SHALL record a note identifying the missing data.
2. IF the LP_Token total supply or holder balances cannot be retrieved, THEN THE Liquidity_Lock_Scanner SHALL set Lock_Status to `unknown` and SHALL record a note identifying the missing data.
3. THE Liquidity_Lock_Scanner SHALL represent an `unknown` Lock_Status as distinct from an `unlocked` Lock_Status in the Lock_Result.
4. WHEN Lock_Status is `unknown`, THE Liquidity_Lock_Scanner SHALL set a boolean field that indicates lock status was not determined rather than indicating absence of risk.
5. IF every configured data source fails to return lock data, THEN THE Liquidity_Lock_Scanner SHALL return a Lock_Result with Lock_Status `unknown` rather than raising an unhandled exception, and SHALL NOT substitute any previously cached lock status.

### Requirement 3: Resolve liquidity data via primary source with RPC fallback

**User Story:** As an operator running VIGIL without paid API keys, I want the scanner to use keyless sources first and direct RPC as a fallback, so that lock detection works in the default keyless configuration.

#### Acceptance Criteria

1. THE Liquidity_Lock_Scanner SHALL use DexScreener as the primary source for resolving the deepest Pair_Address of the token.
2. IF DexScreener does not return a Pair_Address, THEN THE Liquidity_Lock_Scanner SHALL attempt to resolve LP_Token holdings via RPC_Fallback before determining any Lock_Status, and SHALL classify Lock_Status as `unknown` only after the RPC_Fallback attempt also fails.
3. WHEN computing the Locked_Fraction, THE Liquidity_Lock_Scanner SHALL retrieve LP_Token total supply and Locker_Contract or Burn_Address balances via `eth_call` against the Supported_Chain RPC endpoint, and WHERE LP_Tokens are held across multiple recognized lock mechanisms, THE Liquidity_Lock_Scanner SHALL sum the held balances when computing the Locked_Fraction.
4. WHEN no RPC endpoint is configured for the requested chain, THE Liquidity_Lock_Scanner SHALL set Lock_Status to `unknown` and SHALL record a note identifying the missing RPC configuration.

### Requirement 4: Decode lock and balance data from on-chain calls

**User Story:** As a developer maintaining VIGIL, I want LP_Token balances and locker unlock data decoded correctly from raw RPC responses, so that the Locked_Fraction and Unlock_Timestamp are accurate.

#### Acceptance Criteria

1. WHEN an `eth_call` returns a 32-byte uint256 word for `balanceOf` or `totalSupply`, THE Liquidity_Lock_Scanner SHALL decode the value into an integer token amount.
2. IF an `eth_call` returns an empty result (`0x`) or a result shorter than 32 bytes, THEN THE Liquidity_Lock_Scanner SHALL treat the value as undetermined and SHALL NOT count it toward the Locked_Fraction.
3. WHEN LP_Token total supply is zero, THE Liquidity_Lock_Scanner SHALL set Lock_Status to `unknown` rather than computing a Locked_Fraction by division.

### Requirement 5: Degrade gracefully for unsupported chains

**User Story:** As a user querying a token on a chain VIGIL does not map, I want a clear unsupported-chain response, so that I am not given a misleading lock verdict.

#### Acceptance Criteria

1. WHEN the requested chain is not a Supported_Chain, THE Liquidity_Lock_Scanner SHALL return a Lock_Result with Lock_Status `unknown` and a note identifying the chain as unsupported, consistent with the `available=False` degradation pattern used by sibling scanners.
2. THE Liquidity_Lock_Scanner SHALL treat Base (chain id 8453) as a Supported_Chain.
3. WHEN the requested chain is a Supported_Chain, THE Liquidity_Lock_Scanner SHALL map the chain name to its numeric chain id using the same mapping convention as the existing market and deployer scanners.
4. IF the chain-id mapping fails for a chain that is otherwise a Supported_Chain, THEN THE Liquidity_Lock_Scanner SHALL raise an error rather than treating the chain as unsupported.

### Requirement 6: Expose the scanner as MCP and HTTP JSON-RPC tools

**User Story:** As an AI agent integrating VIGIL, I want to call the liquidity lock scanner through the same interfaces as other VIGIL tools, so that I can use it via MCP or HTTP JSON-RPC.

#### Acceptance Criteria

1. THE Liquidity_Lock_Scanner SHALL be registered in `server.py` as an MCP tool using the `@mcp.tool()` decorator with a `vigil_`-prefixed name.
2. THE Liquidity_Lock_Scanner SHALL be registered in `TOOL_MAP` with both its `vigil_`-prefixed name and a bare alias, following the existing registration convention.
3. WHEN the tool is invoked, THE Liquidity_Lock_Scanner SHALL accept a token address and an optional chain argument that defaults to `base`.
4. WHEN the tool is invoked, THE Liquidity_Lock_Scanner SHALL return a serialized Lock_Result via `model_dump()`.
5. WHEN the chain argument is provided, THE Liquidity_Lock_Scanner tool SHALL validate the chain using the server's existing chain-validation helper before scanning.

### Requirement 7: Feed the lock verdict into safety score and consensus

**User Story:** As a user who relies on VIGIL's aggregate verdicts, I want liquidity lock status to influence the safety score and the consensus engine, so that a withdrawable-liquidity rug vector lowers the overall verdict.

#### Acceptance Criteria

1. THE Liquidity_Lock_Scanner SHALL expose its result in a form the Consensus_Engine can map to an independent Vote of `safe`, `risk`, or `unknown`.
2. WHEN Lock_Status is `locked` or `burned`, THE Liquidity_Lock_Scanner result SHALL map to a `safe` Vote.
3. WHEN Lock_Status is `unlocked`, THE Liquidity_Lock_Scanner result SHALL map to a `risk` Vote.
4. WHEN Lock_Status is `unknown`, THE Liquidity_Lock_Scanner result SHALL map to an `unknown` Vote with zero weight, so that missing lock data neither raises nor lowers the consensus verdict.
5. WHERE the consensus verdict integration is enabled, THE Consensus_Engine SHALL treat the liquidity lock Vote as one independent source consistent with its existing one-source-cannot-exceed-medium false-positive guard.

### Requirement 8: Classify lock status as free or paid access

**User Story:** As the VIGIL operator, I want a clear decision on whether the liquidity lock scan is free or x402-paid, so that core pre-trade safety checks remain barrier-free.

#### Acceptance Criteria

1. THE Liquidity_Lock_Scanner SHALL be classified as a free core pre-trade safety check and SHALL NOT be assigned a price in the x402 default price map.
2. WHERE x402 payments are enabled, THE Liquidity_Lock_Scanner SHALL remain callable without payment, consistent with other free core safety tools such as honeypot detection and safety score.

### Requirement 9: Provide a human-readable verdict and risk notes

**User Story:** As a user reading a scan result, I want a plain explanation of the lock finding and its rug-pull implication, so that I can act without interpreting raw fractions.

#### Acceptance Criteria

1. THE Liquidity_Lock_Scanner SHALL include a list of human-readable notes describing the basis for the Lock_Status in the Lock_Result.
2. WHEN Lock_Status is `unlocked`, THE Liquidity_Lock_Scanner SHALL include a note stating that liquidity is withdrawable and identifying the rug-pull risk.
3. WHEN Lock_Status is `unknown`, THE Liquidity_Lock_Scanner SHALL include a note stating that lock status could not be determined and that the result is not a safety guarantee.
4. WHEN Lock_Status is `locked` and an Unlock_Timestamp is known, THE Liquidity_Lock_Scanner SHALL include a note stating the unlock date.

### Requirement 10: Bound request time and avoid cross-request state

**User Story:** As an operator hosting VIGIL behind an autonomous agent, I want each scan to complete within a bounded time and to avoid carrying state between requests, so that one slow or failing chain RPC cannot stall the agent and stale lock data cannot be served as fresh.

#### Acceptance Criteria

1. THE Liquidity_Lock_Scanner SHALL bound every outbound HTTP and JSON-RPC request with a per-request timeout consistent with the existing scanner convention (e.g. the 20-second client timeout used by `goplus.py`).
2. IF an outbound request exceeds its timeout, THEN THE Liquidity_Lock_Scanner SHALL treat that data source as unavailable for the current scan and SHALL fall through to the remaining resolution steps defined in Requirement 3.
3. THE Liquidity_Lock_Scanner SHALL NOT cache, persist, or otherwise reuse Lock_Status, Locked_Fraction, Pair_Address, LP_Token address, or Unlock_Timestamp across requests.
4. WHEN the same token is scanned in two successive requests, THE Liquidity_Lock_Scanner SHALL resolve all on-chain and DexScreener data freshly for the second request and SHALL NOT depend on memoized values from the first.
