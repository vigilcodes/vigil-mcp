"""VIGIL MCP Server — FastMCP implementation exposing security scanning tools."""

import logging
import os
import re
import sys
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse

from vigil_mcp.autonomous.sentinel import Sentinel, SentinelStore
from vigil_mcp.bridge.base_mcp import BaseMCPBridge
from vigil_mcp.feed import FeedStore, extract_verdict, feed_worthy
from vigil_mcp.monitors.wallet_monitor import WalletMonitor
from vigil_mcp.payments import x402
from vigil_mcp.revoker.engine import RevocationEngine
from vigil_mcp.scanners.approval_simulator import ApprovalSimulator
from vigil_mcp.scanners.approvals import ApprovalScanner
from vigil_mcp.scanners.consensus import ConsensusEngine
from vigil_mcp.scanners.deployer import DeployerScanner
from vigil_mcp.scanners.honeypot import HoneypotDetector
from vigil_mcp.scanners.liquidity_lock import LiquidityLockScanner
from vigil_mcp.scanners.market import MarketScanner
from vigil_mcp.scanners.safety_score import SafetyScorer
from vigil_mcp.scanners.scam_db import ScamDatabase
from vigil_mcp.scanners.token_scanner import TokenScanner

logging.basicConfig(
    level=getattr(logging, os.getenv("VIGIL_LOG_LEVEL", "INFO")),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("vigil-mcp")

mcp = FastMCP(
    "vigil",
    instructions=(
        "Onchain security scanner — scan token approvals, detect rugpulls, check honeypots, revoke dangerous approvals"
    ),
    host=os.getenv("VIGIL_MCP_HOST", "127.0.0.1"),
    port=int(os.getenv("VIGIL_MCP_PORT", "3100")),
)

# Initialize scanners
approval_scanner = ApprovalScanner()
token_scanner = TokenScanner()
honeypot_detector = HoneypotDetector()
safety_scorer = SafetyScorer()
revocation_engine = RevocationEngine()
base_bridge = BaseMCPBridge()
wallet_monitor = WalletMonitor()
market_scanner = MarketScanner()
deployer_scanner = DeployerScanner()
scam_db = ScamDatabase()
sentinel_store = SentinelStore()
sentinel = Sentinel(store=sentinel_store)
consensus_engine = ConsensusEngine()
feed_store = FeedStore()
liquidity_lock_scanner = LiquidityLockScanner()
approval_simulator = ApprovalSimulator()

SUPPORTED_CHAINS = ["base", "ethereum", "polygon", "arbitrum", "solana"]


def _validate_chain(chain: str) -> str:
    chain = chain.lower().strip()
    if chain not in SUPPORTED_CHAINS:
        raise ValueError(f"Unsupported chain '{chain}'. Use: {', '.join(SUPPORTED_CHAINS)}")
    return chain


# Strict EVM address allowlist: 0x + exactly 40 hex chars. Mirrors the skill
# scripts' validation so the server never produces a verdict for malformed
# input — a bad address must return an error, not a fake "0/critical" score.
_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Which argument keys carry an address, per tool. Used to validate before a
# handler runs so a typo or junk input is rejected instead of silently scored.
_ADDRESS_ARG_KEYS = ("wallet", "token", "contract")


class InvalidAddressError(ValueError):
    """Raised when an address argument is not a well-formed 0x EVM address."""


def _validate_address(addr: str, field: str) -> str:
    if not isinstance(addr, str) or not _ADDR_RE.match(addr):
        raise InvalidAddressError(f"Invalid {field}: expected a 0x-prefixed 40-hex-char address, got '{addr}'")
    return addr.lower()


def _validate_tool_arguments(arguments: dict) -> None:
    """Validate address-bearing arguments before dispatch.

    Checks single-address keys (wallet/token/contract) and the batch_scan
    `tokens` array. Raises InvalidAddressError on the first bad value.
    """
    if not isinstance(arguments, dict):
        return
    for key in _ADDRESS_ARG_KEYS:
        if key in arguments and arguments.get(key) not in (None, ""):
            _validate_address(arguments[key], key)
    if "tokens" in arguments:
        tokens = arguments.get("tokens")
        if not isinstance(tokens, list) or not tokens:
            raise InvalidAddressError("Invalid tokens: expected a non-empty array of 0x addresses")
        for t in tokens:
            _validate_address(t, "token")


# ─────────────────────────────────────────────────────────────
# READ TOOLS (no auth required)
# ─────────────────────────────────────────────────────────────


@mcp.tool()
async def vigil_scan_approvals(wallet: str, chain: str = "base") -> dict[str, Any]:
    """Scan all token approvals for a wallet. Flags unlimited approvals and risky spenders.

    Args:
        wallet: Wallet address (0x...)
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
    """
    chain = _validate_chain(chain)
    logger.info(f"Scanning approvals for {wallet} on {chain}")
    result = await approval_scanner.scan(wallet, chain)
    return result.model_dump()


@mcp.tool()
async def vigil_scan_token(token: str, chain: str = "base") -> dict[str, Any]:
    """Scan a token contract for rugpull indicators.

    Checks for: hidden mint, unlocked liquidity, proxy patterns,
    tax manipulation, blacklist functions.

    Args:
        token: Token contract address (0x...)
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
    """
    chain = _validate_chain(chain)
    logger.info(f"Scanning token {token} on {chain}")
    result = await token_scanner.scan(token, chain)
    return result.model_dump()


@mcp.tool()
async def vigil_detect_honeypot(token: str, chain: str = "base") -> dict[str, Any]:
    """Detect honeypot tokens by simulating buy/sell transactions.

    Checks if token allows buying but blocks selling.

    Args:
        token: Token contract address (0x...)
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
    """
    chain = _validate_chain(chain)
    logger.info(f"Running honeypot detection on {token} ({chain})")
    result = await honeypot_detector.detect(token, chain)
    return result.model_dump()


@mcp.tool()
async def vigil_safety_score(contract: str, chain: str = "base") -> dict[str, Any]:
    """Get a 0-100 safety score for any contract.

    Score breakdown includes code quality, ownership, liquidity,
    holder distribution, and deployer history.

    Args:
        contract: Contract address (0x...)
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
    """
    chain = _validate_chain(chain)
    logger.info(f"Scoring contract {contract} on {chain}")
    result = await safety_scorer.score(contract, chain)
    return result.model_dump()


@mcp.tool()
async def vigil_wallet_report(wallet: str, chain: str = "base") -> dict[str, Any]:
    """Generate a full security report for a wallet.

    Includes all approvals with risk ratings, scam token interaction
    history, and actionable recommendations.

    Args:
        wallet: Wallet address (0x...)
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
    """
    chain = _validate_chain(chain)
    logger.info(f"Generating security report for {wallet} on {chain}")

    approvals = await approval_scanner.scan(wallet, chain)
    scam_history = await token_scanner.check_scam_interactions(wallet, chain)

    critical = sum(1 for a in approvals.approvals if a.risk == "critical")
    high = sum(1 for a in approvals.approvals if a.risk == "high")
    unlimited = sum(1 for a in approvals.approvals if a.amount == "unlimited")

    # Cross-check each risky approval against the local community scam DB.
    # If the spender or token is already flagged, that's a strong signal we
    # should surface in the report.
    flagged_via_scam_db: list[dict[str, Any]] = []
    seen_addrs: set[str] = set()
    for a in approvals.approvals:
        if a.risk not in ("critical", "high"):
            continue
        for addr in (a.token_address, a.spender_address):
            addr_l = addr.lower()
            if addr_l in seen_addrs:
                continue
            seen_addrs.add(addr_l)
            try:
                check = scam_db.check(addr_l, chain)
            except Exception:  # noqa: BLE001 — DB lookup is best-effort
                continue
            if check.get("reported"):
                flagged_via_scam_db.append(
                    {
                        "address": addr_l,
                        "role": "token" if addr_l == a.token_address.lower() else "spender",
                        "report_count": check.get("report_count"),
                        "evidence_types": check.get("evidence_types", []),
                    }
                )

    # Native balance gives the report concrete weight (e.g. "$5K wallet with
    # 3 unlimited approvals" hits harder than just an approval count).
    native_balance_eth = await _get_native_balance_eth(wallet, chain)

    overall_score = max(0, 100 - (critical * 20) - (high * 10) - (unlimited * 5))
    # Each scam-DB hit drags the score down too — those are real, not heuristic.
    overall_score = max(0, overall_score - 15 * len(flagged_via_scam_db))

    risk_level = (
        "critical"
        if overall_score < 30
        else "high"
        if overall_score < 50
        else "medium"
        if overall_score < 70
        else "low"
        if overall_score < 90
        else "safe"
    )

    recommendations = []
    if flagged_via_scam_db:
        recommendations.append(
            {
                "priority": "critical",
                "action": (
                    f"Revoke approvals tied to {len(flagged_via_scam_db)} "
                    "address(es) flagged in the community scam database"
                ),
                "detail": "These are not heuristic flags — others have reported them.",
            }
        )
    if critical > 0:
        recommendations.append(
            {
                "priority": "critical",
                "action": f"Revoke {critical} critical approvals immediately",
                "detail": ("These approvals grant unlimited spending power to potentially risky contracts"),
            }
        )
    if high > 0:
        recommendations.append(
            {
                "priority": "high",
                "action": f"Review {high} high-risk approvals",
                "detail": "Consider revoking if not actively used",
            }
        )
    if unlimited > 0:
        recommendations.append(
            {
                "priority": "medium",
                "action": f"Replace {unlimited} unlimited approvals with exact amounts",
                "detail": "Use specific approval amounts instead of unlimited",
            }
        )

    return {
        "wallet": wallet,
        "chain": chain,
        "overall_score": overall_score,
        "risk_level": risk_level,
        "native_balance_eth": native_balance_eth,
        "approvals": {
            "total": len(approvals.approvals),
            "critical": critical,
            "high": high,
            "unlimited": unlimited,
        },
        "scam_db_hits": flagged_via_scam_db,
        "scam_interactions": scam_history,
        "top_risks": [a.model_dump() for a in approvals.approvals if a.risk in ("critical", "high")][:5],
        "recommendations": recommendations,
    }


async def _get_native_balance_eth(wallet: str, chain: str) -> Optional[float]:
    """Fetch native (ETH/MATIC/etc) balance via the configured RPC.

    Returns balance as a float in whole units, or None if the lookup fails.
    Best-effort enrichment for the wallet report.
    """
    rpc_url = approval_scanner.rpc_urls.get(chain)
    if not rpc_url:
        return None
    try:
        import httpx as _httpx

        async with _httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "eth_getBalance",
                    "params": [wallet, "latest"],
                },
            )
            r.raise_for_status()
            hex_bal = r.json().get("result", "0x0")
            wei = int(hex_bal, 16) if hex_bal not in (None, "0x") else 0
            return round(wei / 1e18, 6)
    except Exception:  # noqa: BLE001 — best-effort enrichment
        return None


# ─────────────────────────────────────────────────────────────
# MONITOR TOOLS (real-time alerts)
# ─────────────────────────────────────────────────────────────


@mcp.tool()
async def vigil_monitor_wallet(wallet: str, chain: str = "base", lookback_blocks: int = 1000) -> dict[str, Any]:
    """Monitor wallet for suspicious activity in recent blocks.

    Checks for: new approvals, unlimited allowances, interactions
    with unknown contracts, and balance changes.

    Args:
        wallet: Wallet address (0x...)
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
        lookback_blocks: How many blocks to look back (default: 1000)
    """
    chain = _validate_chain(chain)
    logger.info(f"Monitoring wallet {wallet} on {chain} (last {lookback_blocks} blocks)")
    result = await wallet_monitor.monitor(wallet, chain, lookback_blocks)
    return result.model_dump()


# ─────────────────────────────────────────────────────────────
# MARKET + REPUTATION TOOLS (read-only, enriches verdicts)
# ─────────────────────────────────────────────────────────────


@mcp.tool()
async def vigil_token_market(token: str, chain: str = "base") -> dict[str, Any]:
    """Get market context for a token: price, liquidity, volume, and pool age.

    Uses DexScreener (no API key). Thin liquidity or a brand-new pool is a strong
    rug signal that pure bytecode analysis cannot see.

    Args:
        token: Token contract address (0x...)
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
    """
    chain = _validate_chain(chain)
    logger.info(f"Fetching market context for {token} on {chain}")
    result = await market_scanner.get_market(token, chain)
    return result.model_dump()


@mcp.tool()
async def vigil_deployer_check(contract: str, chain: str = "base") -> dict[str, Any]:
    """Check a contract's deployer reputation, verification status, and age.

    Uses the Basescan API. Requires BASESCAN_API_KEY; without it the tool returns
    available=false instead of failing.

    Args:
        contract: Contract address (0x...)
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
    """
    chain = _validate_chain(chain)
    logger.info(f"Checking deployer reputation for {contract} on {chain}")
    result = await deployer_scanner.check(contract, chain)
    return result.model_dump()


@mcp.tool()
async def vigil_consensus(token: str, chain: str = "base") -> dict[str, Any]:
    """Multi-source consensus verdict for a token.

    Queries five independent signals (GoPlus, onchain score, market liquidity,
    deployer verification, community scam DB), lets each vote independently, and
    returns a verdict driven by how many sources AGREE. A single source can't
    push past "medium" — this is VIGIL's false-positive guard: risk is only
    "high"/"critical" when multiple independent sources concur.

    Args:
        token: Token contract address (0x...)
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
    """
    chain = _validate_chain(chain)
    logger.info(f"Computing multi-source consensus for {token} on {chain}")
    result = await consensus_engine.evaluate(token, chain)
    return result.model_dump()


@mcp.tool()
async def vigil_liquidity_lock(token: str, chain: str = "base") -> dict[str, Any]:
    """Detect whether a token's DEX liquidity is locked, burned, or withdrawable.

    Free core safety check — the classic rug-pull vector is a deployer pulling
    LP. Returns lock_status of:
      - `locked`   — recognized lockers hold ≥80% of LP supply (positive signal)
      - `burned`   — burn addresses hold ≥80% of LP supply (permanent)
      - `unlocked` — LP is withdrawable; rug-pull risk
      - `unknown`  — insufficient data; NOT a safety guarantee

    Coverage in this version: V2-style ERC-20 LP tokens (Aerodrome v1, Uniswap
    V2 forks on Base). V3 / Slipstream NFT positions are not supported and
    return `unknown` with an explanatory note.

    Args:
        token: Token contract address (0x...)
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
    """
    chain = _validate_chain(chain)
    logger.info(f"Scanning liquidity lock for {token} on {chain}")
    result = await liquidity_lock_scanner.scan(token, chain)
    return result.model_dump()


@mcp.tool()
async def vigil_simulate_approval(
    spender: str, token: str, amount: str = "unlimited", chain: str = "base"
) -> dict[str, Any]:
    """Simulate a token approval BEFORE signing — risk-assess the spender.

    Answers the question other tools can't: "If I approve this spender right
    now, what could they do?" Profiles the spender using code analysis, GoPlus,
    community scam DB, and known-safe registries.

    Returns:
      - risk: safe / suspicious / dangerous
      - spender_profile: contract/EOA, known safe, has transferFrom, flags
      - reasons: list of signals behind the verdict
      - recommendation: human-readable go/no-go

    Free core safety check. No API key needed.

    Args:
        spender: The address you're about to approve (0x...)
        token: The token you're approving (0x...)
        amount: Approval amount — "unlimited" or a numeric string
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
    """
    chain = _validate_chain(chain)
    spender = _validate_address(spender, "spender")
    token = _validate_address(token, "token")
    logger.info(f"Simulating approval: spender={spender} token={token} amount={amount} chain={chain}")
    result = await approval_simulator.simulate(spender, token, amount, chain)
    return result.model_dump()


@mcp.tool()
async def vigil_batch_scan(tokens: list[str], chain: str = "base") -> dict[str, Any]:
    """Scan multiple tokens for safety in one call.

    Returns a per-token safety score and risk level. Useful for checking an
    entire wallet's holdings at once.

    Args:
        tokens: List of token contract addresses (0x...)
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
    """
    chain = _validate_chain(chain)
    logger.info(f"Batch scanning {len(tokens)} tokens on {chain}")

    results = []
    for token in tokens[:25]:  # cap to keep calls bounded
        try:
            score = await safety_scorer.score(token, chain)
            results.append(
                {
                    "token": token,
                    "score": score.score,
                    "risk_level": score.risk_level,
                    "recommendation": score.recommendation,
                }
            )
        except Exception as e:  # noqa: BLE001 — one bad token shouldn't fail the batch
            results.append({"token": token, "error": str(e)})

    ranked = sorted(
        [r for r in results if "score" in r],
        key=lambda r: r["score"],
    )
    return {
        "chain": chain,
        "total": len(results),
        "results": results,
        "riskiest": ranked[:5],
    }


# ─────────────────────────────────────────────────────────────
# WRITE TOOLS (Bankr auth required)
# ─────────────────────────────────────────────────────────────


@mcp.tool()
async def vigil_revoke_approval(token: str, spender: str, chain: str = "base") -> dict[str, Any]:
    """Revoke a single token approval.

    Builds the revocation transaction and submits via Bankr for signing.

    Args:
        token: Token contract address to revoke approval for
        spender: Spender address whose approval to revoke
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
    """
    chain = _validate_chain(chain)
    logger.info(f"Revoking approval: {token} -> {spender} on {chain}")
    result = await revocation_engine.revoke_single(token, spender, chain)
    return result


@mcp.tool()
async def vigil_batch_revoke(wallet: str, chain: str = "base", risk_level: str = "critical") -> dict[str, Any]:
    """Revoke all risky approvals for a wallet in one session.

    Only revokes approvals at or above the specified risk level.

    Args:
        wallet: Wallet address
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
        risk_level: Minimum risk level to revoke (critical, high, medium, all)
    """
    chain = _validate_chain(chain)
    logger.info(f"Batch revoking {risk_level}+ approvals for {wallet} on {chain}")

    approvals = await approval_scanner.scan(wallet, chain, risk_filter=risk_level)
    results = {"total": len(approvals.approvals), "revoked": 0, "failed": 0, "transactions": []}

    for approval in approvals.approvals:
        try:
            tx = await revocation_engine.revoke_single(approval.token_address, approval.spender_address, chain)
            results["revoked"] += 1
            results["transactions"].append(
                {
                    "token": approval.token_symbol,
                    "spender": approval.spender_address[:10],
                    "status": "revoked",
                    "tx_hash": tx.get("tx_hash"),
                }
            )
        except Exception as e:
            results["failed"] += 1
            results["transactions"].append(
                {
                    "token": approval.token_symbol,
                    "spender": approval.spender_address[:10],
                    "status": "failed",
                    "error": str(e),
                }
            )

    return results


@mcp.tool()
async def vigil_report_scam(
    token: str,
    evidence_type: str,
    description: str,
    chain: str = "base",
) -> dict[str, Any]:
    """Submit a scam token report to the community database.

    Earn $VIGIL bounty if report is verified.

    Args:
        token: Scam token contract address
        evidence_type: Type of scam (honeypot, rugpull, phishing, scam, fake)
        description: Brief description of the scam evidence
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
    """
    chain = _validate_chain(chain)
    valid_types = ["honeypot", "rugpull", "phishing", "scam", "fake"]
    if evidence_type not in valid_types:
        raise ValueError(f"Invalid evidence_type. Use: {', '.join(valid_types)}")

    logger.info(f"Submitting scam report for {token} ({evidence_type})")

    # Always persist to the local community DB so the report is durable and
    # immediately queryable via vigil_check_scam — no API key required.
    result = scam_db.report(token, evidence_type, description, chain)

    # If Bankr is configured, also forward to the hosted bounty database.
    try:
        if revocation_engine.api_key:
            remote = await revocation_engine.report_scam(token, evidence_type, description, chain)
            result["remote_report_id"] = remote.get("report_id", "")
            result["remote_status"] = remote.get("status", "")
    except Exception as e:  # noqa: BLE001 — remote sync is best-effort
        result["remote_status"] = f"sync_failed: {e}"

    return result


@mcp.tool()
async def vigil_check_scam(token: str, chain: str = "base") -> dict[str, Any]:
    """Check whether a token has community scam reports.

    Queries the local VIGIL scam database. No API key required.

    Args:
        token: Token contract address (0x...)
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
    """
    chain = _validate_chain(chain)
    logger.info(f"Checking scam reports for {token} on {chain}")
    return scam_db.check(token, chain)


# ─────────────────────────────────────────────────────────────
# AUTONOMOUS SENTINEL (watchlist-driven monitoring loop)
# ─────────────────────────────────────────────────────────────


@mcp.tool()
async def vigil_sentinel_watch(wallet: str, chain: str = "base", label: str = "") -> dict[str, Any]:
    """Add a wallet to the autonomous Sentinel watchlist.

    The Sentinel loop scans watched wallets on a schedule and surfaces only
    new security alerts (no repeats). Use vigil_sentinel_status to inspect.

    Args:
        wallet: Wallet address (0x...)
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
        label: Optional human-friendly label for the wallet
    """
    chain = _validate_chain(chain)
    logger.info(f"Sentinel watch added: {wallet} on {chain}")
    return sentinel_store.add(wallet, chain, label or None)


@mcp.tool()
async def vigil_sentinel_unwatch(wallet: str, chain: str = "base") -> dict[str, Any]:
    """Remove a wallet from the autonomous Sentinel watchlist.

    Args:
        wallet: Wallet address (0x...)
        chain: Blockchain name (base, ethereum, polygon, arbitrum)
    """
    chain = _validate_chain(chain)
    logger.info(f"Sentinel watch removed: {wallet} on {chain}")
    return sentinel_store.remove(wallet, chain)


@mcp.tool()
async def vigil_sentinel_status() -> dict[str, Any]:
    """List the Sentinel watchlist and loop configuration."""
    return {
        "watchlist": sentinel_store.list(),
        "interval_seconds": sentinel.interval,
        "min_severity": sentinel.min_severity,
        "lookback_blocks": sentinel.lookback,
    }


@mcp.tool()
async def vigil_sentinel_run() -> dict[str, Any]:
    """Trigger one Sentinel scan cycle now over all watched wallets.

    Returns per-wallet counts of new alerts found. New alerts are deduped
    against prior runs so repeated findings are not re-reported.
    """
    logger.info("Sentinel manual cycle triggered")
    return await sentinel.run_once()


# ─────────────────────────────────────────────────────────────
# BASE MCP BRIDGE TOOLS
# ─────────────────────────────────────────────────────────────


@mcp.tool()
async def vigil_base_mcp_check(wallet: str) -> dict[str, Any]:
    """Check VIGIL security status via Base MCP bridge.

    Returns security posture before agent executes trades.

    Args:
        wallet: Wallet address to check security for
    """
    logger.info(f"Base MCP security check for {wallet}")
    result = await base_bridge.security_check(wallet)
    return result


# ─────────────────────────────────────────────────────────────
# RESOURCES
# ─────────────────────────────────────────────────────────────


@mcp.resource("vigil://chains")
async def get_supported_chains() -> str:
    """List of supported blockchain networks."""
    return {
        "chains": SUPPORTED_CHAINS,
        "default": "base",
        "descriptions": {
            "base": "Coinbase L2 — primary chain for VIGIL",
            "ethereum": "Ethereum mainnet",
            "polygon": "Polygon PoS",
            "arbitrum": "Arbitrum One L2",
            "solana": "Solana (SPL token approvals)",
        },
    }


@mcp.resource("vigil://risk-levels")
async def get_risk_levels() -> str:
    """Risk level definitions and recommended actions."""
    return {
        "levels": [
            {"level": "critical", "icon": "🔴", "action": "Revoke immediately", "threshold": 0},
            {"level": "high", "icon": "🟠", "action": "Review and likely revoke", "threshold": 30},
            {"level": "medium", "icon": "🟡", "action": "Monitor closely", "threshold": 50},
            {"level": "low", "icon": "🟢", "action": "Low concern", "threshold": 70},
            {"level": "safe", "icon": "✅", "action": "No action needed", "threshold": 90},
        ]
    }


@mcp.resource("vigil://token-info")
async def get_token_info() -> str:
    """$VIGIL token information and utility tiers."""
    return {
        "token": "VIGIL",
        "chain": "base",
        "max_supply": "100,000,000",
        "tiers": [
            {"name": "Free", "stake": 0, "scans": "5/day", "revokes": "1/day"},
            {"name": "Scout", "stake": 100, "scans": "50/day", "revokes": "10/day"},
            {"name": "Guardian", "stake": 500, "scans": "200/day", "revokes": "50/day"},
            {"name": "Sentinel", "stake": 1000, "scans": "Unlimited", "revokes": "Unlimited"},
            {"name": "Archon", "stake": 5000, "scans": "Unlimited", "revokes": "Unlimited"},
        ],
    }


# ─────────────────────────────────────────────────────────────
# HTTP JSON-RPC ENDPOINTS (for curl/bash access)
# ─────────────────────────────────────────────────────────────

TOOL_MAP = {
    "vigil_scan_approvals": lambda args: vigil_scan_approvals(args.get("wallet", ""), args.get("chain", "base")),
    "vigil_scan_token": lambda args: vigil_scan_token(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "vigil_detect_honeypot": lambda args: vigil_detect_honeypot(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "vigil_safety_score": lambda args: vigil_safety_score(
        args.get("contract") or args.get("token", ""), args.get("chain", "base")
    ),
    "vigil_wallet_report": lambda args: vigil_wallet_report(args.get("wallet", ""), args.get("chain", "base")),
    "vigil_monitor_wallet": lambda args: vigil_monitor_wallet(
        args.get("wallet", ""),
        args.get("chain", "base"),
        int(args.get("lookback_blocks", 1000)),
    ),
    "vigil_token_market": lambda args: vigil_token_market(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "vigil_deployer_check": lambda args: vigil_deployer_check(
        args.get("contract") or args.get("token", ""), args.get("chain", "base")
    ),
    "vigil_batch_scan": lambda args: vigil_batch_scan(args.get("tokens", []), args.get("chain", "base")),
    "vigil_check_scam": lambda args: vigil_check_scam(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "vigil_sentinel_status": lambda args: vigil_sentinel_status(),
    "vigil_consensus": lambda args: vigil_consensus(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "scan_approvals": lambda args: vigil_scan_approvals(args.get("wallet", ""), args.get("chain", "base")),
    "scan_token": lambda args: vigil_scan_token(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "detect_honeypot": lambda args: vigil_detect_honeypot(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "safety_score": lambda args: vigil_safety_score(
        args.get("contract") or args.get("token", ""), args.get("chain", "base")
    ),
    "wallet_report": lambda args: vigil_wallet_report(args.get("wallet", ""), args.get("chain", "base")),
    "monitor_wallet": lambda args: vigil_monitor_wallet(
        args.get("wallet", ""),
        args.get("chain", "base"),
        int(args.get("lookback_blocks", 1000)),
    ),
    "token_market": lambda args: vigil_token_market(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "deployer_check": lambda args: vigil_deployer_check(
        args.get("contract") or args.get("token", ""), args.get("chain", "base")
    ),
    "batch_scan": lambda args: vigil_batch_scan(args.get("tokens", []), args.get("chain", "base")),
    "check_scam": lambda args: vigil_check_scam(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "sentinel_status": lambda args: vigil_sentinel_status(),
    "consensus": lambda args: vigil_consensus(args.get("token") or args.get("contract", ""), args.get("chain", "base")),
    "vigil_liquidity_lock": lambda args: vigil_liquidity_lock(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "liquidity_lock": lambda args: vigil_liquidity_lock(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "vigil_simulate_approval": lambda args: vigil_simulate_approval(
        args.get("spender", ""), args.get("token", ""), args.get("amount", "unlimited"), args.get("chain", "base")
    ),
    "simulate_approval": lambda args: vigil_simulate_approval(
        args.get("spender", ""), args.get("token", ""), args.get("amount", "unlimited"), args.get("chain", "base")
    ),
}


# CORS headers so a browser (e.g. the vigil.codes demo page) can call the API
# cross-origin. Read-only scans are public, so a permissive allow-origin is fine.
_CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-PAYMENT",
    "Access-Control-Max-Age": "86400",
}


@mcp.custom_route("/tools/call", methods=["OPTIONS"])
@mcp.custom_route("/tools/list", methods=["OPTIONS"])
async def cors_preflight(request: Request) -> JSONResponse:
    """Answer CORS preflight requests from browsers."""
    return JSONResponse({}, headers=_CORS_HEADERS)


@mcp.custom_route("/tools/list", methods=["GET", "POST"])
async def tools_list(request: Request) -> JSONResponse:
    """List available MCP tools."""
    tools = [
        {
            "name": "vigil_scan_approvals",
            "description": "Scan all token approvals for a wallet. Flags unlimited approvals and risky spenders.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "wallet": {"type": "string", "description": "Wallet address (0x...)"},
                    "chain": {"type": "string", "default": "base"},
                },
                "required": ["wallet"],
            },
        },
        {
            "name": "vigil_scan_token",
            "description": "Scan a token contract for rugpull indicators.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "Token contract address (0x...)"},
                    "chain": {"type": "string", "default": "base"},
                },
                "required": ["token"],
            },
        },
        {
            "name": "vigil_detect_honeypot",
            "description": "Detect honeypot tokens by simulating buy/sell transactions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "Token contract address (0x...)"},
                    "chain": {"type": "string", "default": "base"},
                },
                "required": ["token"],
            },
        },
        {
            "name": "vigil_safety_score",
            "description": "Get a 0-100 safety score for any contract.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "contract": {"type": "string", "description": "Contract address (0x...)"},
                    "chain": {"type": "string", "default": "base"},
                },
                "required": ["contract"],
            },
        },
        {
            "name": "vigil_wallet_report",
            "description": "Generate a full security report for a wallet.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "wallet": {"type": "string", "description": "Wallet address (0x...)"},
                    "chain": {"type": "string", "default": "base"},
                },
                "required": ["wallet"],
            },
        },
        {
            "name": "vigil_monitor_wallet",
            "description": (
                "Monitor wallet for suspicious activity. Checks recent approvals, "
                "risky interactions, and balance changes."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "wallet": {"type": "string", "description": "Wallet address (0x...)"},
                    "chain": {"type": "string", "default": "base"},
                    "lookback_blocks": {
                        "type": "integer",
                        "default": 1000,
                        "description": "How many blocks to look back",
                    },
                },
                "required": ["wallet"],
            },
        },
        {
            "name": "vigil_token_market",
            "description": (
                "Get market context for a token: price, liquidity, 24h volume, and "
                "pool age via DexScreener. No API key required."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "Token contract address (0x...)"},
                    "chain": {"type": "string", "default": "base"},
                },
                "required": ["token"],
            },
        },
        {
            "name": "vigil_deployer_check",
            "description": (
                "Check a contract's deployer reputation, verification status, and age "
                "via Basescan. Requires BASESCAN_API_KEY."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "contract": {"type": "string", "description": "Contract address (0x...)"},
                    "chain": {"type": "string", "default": "base"},
                },
                "required": ["contract"],
            },
        },
        {
            "name": "vigil_batch_scan",
            "description": "Scan multiple tokens for safety in one call; returns per-token scores.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tokens": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of token contract addresses",
                    },
                    "chain": {"type": "string", "default": "base"},
                },
                "required": ["tokens"],
            },
        },
        {
            "name": "vigil_check_scam",
            "description": "Check whether a token has community scam reports (local VIGIL database).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "Token contract address (0x...)"},
                    "chain": {"type": "string", "default": "base"},
                },
                "required": ["token"],
            },
        },
        {
            "name": "vigil_sentinel_status",
            "description": (
                "List the autonomous Sentinel watchlist and loop configuration "
                "(interval, severity threshold, lookback)."
            ),
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "vigil_consensus",
            "description": (
                "Multi-source consensus verdict for a token. Aggregates five "
                "independent signals (GoPlus, onchain score, market liquidity, "
                "deployer verification, community scam DB) and returns a verdict "
                "driven by how many sources agree — risk is only high/critical "
                "when multiple independent sources concur (false-positive guard)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "Token contract address (0x...)"},
                    "chain": {"type": "string", "default": "base"},
                },
                "required": ["token"],
            },
        },
        {
            "name": "vigil_liquidity_lock",
            "description": (
                "Detect whether a token's DEX liquidity is locked, burned, or "
                "withdrawable. Reads LP totalSupply and balances of recognized "
                "lockers / burn addresses; classifies as locked / burned / "
                "unlocked / unknown. Free core safety check. Covers V2-style "
                "ERC-20 LP tokens (Aerodrome v1, Uniswap V2 forks); V3 / NFT "
                "positions return `unknown` with a note. Missing data returns "
                "`unknown` and is NOT a safety guarantee."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "Token contract address (0x...)"},
                    "chain": {"type": "string", "default": "base"},
                },
                "required": ["token"],
            },
        },
        {
            "name": "vigil_simulate_approval",
            "description": (
                "Simulate a token approval BEFORE signing — risk-assess the "
                "spender. Profiles the spender using code analysis, GoPlus, "
                "community scam DB, and known-safe registries. Returns risk "
                "(safe/suspicious/dangerous), spender profile, reasons, and "
                "recommendation. Free core safety check."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "spender": {"type": "string", "description": "Address you're about to approve (0x...)"},
                    "token": {"type": "string", "description": "Token you're approving (0x...)"},
                    "amount": {
                        "type": "string",
                        "description": "Amount: 'unlimited' or numeric",
                        "default": "unlimited",
                    },
                    "chain": {"type": "string", "default": "base"},
                },
                "required": ["spender", "token"],
            },
        },
    ]
    return JSONResponse({"jsonrpc": "2.0", "id": None, "result": {"tools": tools}}, headers=_CORS_HEADERS)


@mcp.custom_route("/tools/call", methods=["POST"])
async def tools_call(request: Request) -> JSONResponse:
    """Call an MCP tool via JSON-RPC HTTP POST."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
            status_code=400,
        )

    req_id = body.get("id", None)
    params = body.get("params", {})
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})

    if not tool_name:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32600, "message": "Missing tool name"}},
            status_code=400,
        )

    handler = TOOL_MAP.get(tool_name)
    if not handler:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}},
            status_code=404,
        )

    # Validate address-bearing arguments up front. A malformed address must
    # return an error, never a fabricated "0/critical" verdict — accuracy is
    # the whole point of a security scanner. Done before the x402 gate so a
    # bad request isn't asked to pay first.
    try:
        _validate_tool_arguments(arguments)
    except InvalidAddressError as e:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": str(e)}},
            status_code=400,
            headers=_CORS_HEADERS,
        )

    # Optional x402 pay-per-call gate (disabled unless VIGIL_X402_ENABLED=1).
    if x402.is_enabled():
        price = x402.price_for(tool_name)
        if price:
            payment_hdr = request.headers.get("X-PAYMENT", "")
            paid = await x402.verify_payment(payment_hdr, tool_name, price)
            if not paid:
                return JSONResponse(
                    x402.payment_requirements(tool_name, price),
                    status_code=402,
                    headers=_CORS_HEADERS,
                )

    try:
        result = await handler(arguments)
        # Anonymized public feed — token + verdict only, no user identity.
        if feed_worthy(tool_name) and isinstance(result, dict):
            target = arguments.get("token") or arguments.get("contract") or ""
            if target:
                verdict, score = extract_verdict(tool_name, result)
                feed_store.record(target, arguments.get("chain", "base"), tool_name, verdict, score)
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result}, headers=_CORS_HEADERS)
    except Exception as e:
        logger.error(f"Tool {tool_name} failed: {e}")
        return JSONResponse(
            {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}},
            status_code=500,
            headers=_CORS_HEADERS,
        )


@mcp.custom_route("/", methods=["GET"])
async def index(request: Request) -> HTMLResponse:
    """Human-friendly landing page.

    mcp.vigil.codes is a JSON-RPC API endpoint, not a website — but people
    paste it into a browser. Return a helpful page instead of a bare 404 so
    visitors know where to go (the site) and how to call it (the API).
    """
    html = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VIGIL MCP — API Endpoint</title>
<style>
  body { margin:0; background:#080808; color:#d4d0c8;
         font-family:'Courier New',monospace; line-height:1.6;
         display:flex; min-height:100vh; align-items:center; justify-content:center; }
  .wrap { max-width:680px; padding:40px 28px; }
  .label { color:#c8a961; font-size:11px; letter-spacing:4px; opacity:.6; }
  h1 { font-family:Georgia,serif; font-size:40px; font-weight:400; margin:14px 0 6px; }
  p { color:#9a968e; }
  a { color:#c8a961; text-decoration:none; }
  a:hover { text-decoration:underline; }
  .card { border:1px solid #1e1e1c; border-radius:10px; padding:20px 22px; margin-top:24px;
          background:#0c0c0c; overflow-x:auto; }
  .ok { color:#6bbd6b; }
  .links { margin-top:28px; display:flex; gap:22px; flex-wrap:wrap; }
  pre { margin:0; white-space:pre-wrap; word-break:break-word; }
</style>
</head>
<body>
  <div class="wrap">
    <div class="label">VIGIL . ONCHAIN SECURITY MCP . BASE</div>
    <h1>This is an API endpoint, not a website.</h1>
    <p>You've reached the VIGIL MCP server. It speaks JSON-RPC 2.0 over HTTP &mdash;
       there's no page to browse here. Looking for the project? Head to
       <a href="https://vigil.codes">vigil.codes</a>.</p>

    <div class="card">
      <div class="label">TRY A LIVE SCAN (no API key)</div>
      <pre>curl -X POST https://mcp.vigil.codes/tools/call \\
  -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"vigil_safety_score",
                 "arguments":{"contract":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","chain":"base"}}}'</pre>
    </div>

    <div class="links">
      <a href="https://vigil.codes">&rarr; Website</a>
      <a href="/tools/list">&rarr; List tools</a>
      <a href="/stats">&rarr; Stats</a>
      <a href="/health">&rarr; Health</a>
      <a href="https://github.com/vigilcodes/vigil-mcp">&rarr; GitHub</a>
    </div>
  </div>
</body>
</html>"""
    return HTMLResponse(html)


@mcp.custom_route("/feed", methods=["GET", "OPTIONS"])
async def public_feed(request: Request) -> JSONResponse:
    """Public, anonymized scan feed — recent scans + totals. No user data."""
    if request.method == "OPTIONS":
        return JSONResponse({}, headers=_CORS_HEADERS)
    try:
        limit = int(request.query_params.get("limit", "30"))
    except ValueError:
        limit = 30
    return JSONResponse(
        {"totals": feed_store.totals(), "recent": feed_store.recent(limit)},
        headers=_CORS_HEADERS,
    )


# ─────────────────────────────────────────────────────────────
# /stats — public stats snapshot (cached 60s)
# Every number is derived live from the feed DB at snapshot time.
# No hand-edited numbers, no PII beyond publicly-scanned token addresses.
# ─────────────────────────────────────────────────────────────

_STATS_CACHE: dict[str, Any] = {"snapshot": None, "at": 0.0}
_STATS_CACHE_TTL = 60.0  # seconds


def _build_stats_snapshot() -> dict[str, Any]:
    """Compose the /stats payload from FeedStore + tool registration count."""
    import time as _time

    public_tools = sum(1 for name in TOOL_MAP if name.startswith("vigil_"))
    return {
        "service": "vigil-mcp",
        "as_of": int(_time.time()),
        "tools_live": public_tools,
        "totals": _stats_totals(feed_store.totals()),
        "tools_by_volume": feed_store.tools_by_volume(5),
        "recent_flagged": feed_store.recent_flagged(5),
    }


def _stats_totals(raw: dict[str, Any]) -> dict[str, Any]:
    """Rename feed totals to the public /stats shape (no behaviour change)."""
    return {
        "total_scans": int(raw.get("total", 0)),
        "flagged": int(raw.get("flagged", 0)),
        "last_24h": int(raw.get("last_24h", 0)),
        "unique_tokens": int(raw.get("unique_tokens", 0)),
    }


def _render_stats_html(snapshot: dict[str, Any]) -> str:
    """Render the public stats page from a snapshot. Pure function, no I/O."""
    import datetime as _dt
    import html as _html

    totals = snapshot.get("totals") or {}
    tools_live = snapshot.get("tools_live", 0)
    tools_by_volume = snapshot.get("tools_by_volume") or []
    recent_flagged = snapshot.get("recent_flagged") or []
    as_of_ts = int(snapshot.get("as_of") or 0)
    as_of_str = _dt.datetime.utcfromtimestamp(as_of_ts).strftime("%Y-%m-%d %H:%M UTC") if as_of_ts else "—"

    def _short(addr: str) -> str:
        a = (addr or "").lower()
        return f"{a[:6]}…{a[-4:]}" if len(a) >= 12 else a

    def _ago(ts: int) -> str:
        if not ts:
            return ""
        now = int(_dt.datetime.now(_dt.timezone.utc).timestamp())
        d = max(0, now - int(ts))
        if d < 60:
            return f"{d}s ago"
        if d < 3600:
            return f"{d // 60}m ago"
        if d < 86400:
            return f"{d // 3600}h ago"
        return f"{d // 86400}d ago"

    tools_rows = (
        "".join(
            f'<tr><td>{_html.escape(str(t.get("tool", "")))}</td><td class="num">{int(t.get("count", 0))}</td></tr>'
            for t in tools_by_volume
        )
        or '<tr><td colspan="2" class="dim">No data yet.</td></tr>'
    )

    flagged_rows = (
        "".join(
            f'<tr><td><a href="https://basescan.org/token/{_html.escape(str(r.get("token", "")))}" '
            f'target="_blank" rel="noreferrer">{_html.escape(_short(str(r.get("token", ""))))}</a></td>'
            f"<td>{_html.escape(str(r.get('verdict', '')))}</td>"
            f"<td>{_html.escape(str(r.get('tool', '')))}</td>"
            f'<td class="dim">{_html.escape(_ago(int(r.get("at") or 0)))}</td></tr>'
            for r in recent_flagged
        )
        or '<tr><td colspan="4" class="dim">No flagged scans yet.</td></tr>'
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VIGIL — Public Stats</title>
<meta http-equiv="refresh" content="60">
<style>
  body {{ margin:0; background:#080808; color:#d4d0c8;
         font-family:'Courier New',monospace; line-height:1.6; }}
  .wrap {{ max-width:920px; margin:0 auto; padding:48px 28px 80px; }}
  .label {{ color:#c8a961; font-size:11px; letter-spacing:4px; opacity:.6; }}
  h1 {{ font-family:Georgia,serif; font-size:42px; font-weight:400; margin:14px 0 4px; }}
  .sub {{ color:#6b6860; font-style:italic; font-size:18px; }}
  .grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin:32px 0; }}
  .stat {{ border:1px solid #1e1e1c; border-radius:10px; padding:18px 20px; background:#0c0c0c; }}
  .stat .n {{ font-family:Georgia,serif; font-size:34px; color:#c8a961; }}
  .stat .k {{ color:#6b6860; font-size:11px; letter-spacing:3px; margin-top:4px; }}
  .panel {{ border:1px solid #1e1e1c; border-radius:10px; padding:18px 22px;
           background:#0c0c0c; margin-top:18px; }}
  .panel h2 {{ font-size:13px; letter-spacing:3px; color:#6b6860; margin:0 0 14px;
              font-family:'Courier New',monospace; font-weight:400; }}
  table {{ width:100%; border-collapse:collapse; font-size:14px; }}
  td {{ padding:8px 10px; border-bottom:1px solid #141413; }}
  tr:last-child td {{ border-bottom:none; }}
  td.num {{ color:#c8a961; text-align:right; }}
  td.dim, .dim {{ color:#6b6860; }}
  a {{ color:#c8a961; text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  .footer {{ color:#6b6860; font-size:12px; margin-top:36px; line-height:1.8; }}
  @media (max-width:640px) {{ .grid {{ grid-template-columns:repeat(2,1fr); }} }}
</style>
</head>
<body>
  <div class="wrap">
    <div class="label">VIGIL . PUBLIC STATS . LIVE FEED</div>
    <h1>Proof, not hype.</h1>
    <p class="sub">Every number below is derived live from the scan log. No projections.</p>

    <div class="grid">
      <div class="stat"><div class="n">{int(totals.get("total_scans", 0))}</div>
        <div class="k">TOTAL SCANS</div></div>
      <div class="stat"><div class="n">{int(totals.get("flagged", 0))}</div>
        <div class="k">FLAGGED</div></div>
      <div class="stat"><div class="n">{int(totals.get("last_24h", 0))}</div>
        <div class="k">LAST 24H</div></div>
      <div class="stat"><div class="n">{int(totals.get("unique_tokens", 0))}</div>
        <div class="k">UNIQUE TOKENS</div></div>
    </div>

    <div class="panel">
      <h2>TOP TOOLS BY VOLUME · {int(tools_live)} TOOLS LIVE</h2>
      <table>{tools_rows}</table>
    </div>

    <div class="panel">
      <h2>RECENT FLAGGED SCANS</h2>
      <table>{flagged_rows}</table>
    </div>

    <p class="footer">
      Snapshot: <span class="dim">{_html.escape(as_of_str)}</span> · Refreshes automatically every 60s.<br>
      All numbers derived live from the VIGIL scan feed. No PII, no wallet identity, no inflated counts.<br>
      <a href="/stats" id="raw-link">View raw JSON</a>
      &nbsp;·&nbsp; <a href="/">Server</a>
      &nbsp;·&nbsp; <a href="https://vigil.codes">vigil.codes</a>
      &nbsp;·&nbsp; <a href="https://github.com/vigilcodes/vigil-mcp">GitHub</a>
    </p>
    <pre id="raw" class="dim" style="margin-top:18px;font-size:12px;"></pre>
    <script>
      document.getElementById('raw-link').addEventListener('click', function(e) {{
        e.preventDefault();
        fetch('/stats', {{ headers: {{ accept: 'application/json' }} }})
          .then(function(r) {{ return r.json(); }})
          .then(function(j) {{
            document.getElementById('raw').textContent = JSON.stringify(j, null, 2);
          }});
      }});
    </script>
  </div>
</body>
</html>"""


@mcp.custom_route("/stats", methods=["GET", "OPTIONS"])
async def public_stats(request: Request) -> JSONResponse:
    """Public stats snapshot — derived live from the feed DB.

    Cached in-process for 60 seconds so the page can poll without DB strain.
    Failure mode: returns HTTP 500 with a minimal error body rather than a
    stale snapshot presented as fresh.

    Content negotiation: callers asking for HTML (browsers) get a rendered
    page; everyone else (agents, curl, JSON-RPC clients) gets the raw JSON.
    """
    if request.method == "OPTIONS":
        return JSONResponse({}, headers=_CORS_HEADERS)

    import time as _time

    now = _time.time()
    cached = _STATS_CACHE.get("snapshot")
    if cached is not None and (now - _STATS_CACHE.get("at", 0.0)) < _STATS_CACHE_TTL:
        snapshot = cached
    else:
        try:
            snapshot = _build_stats_snapshot()
        except Exception as e:  # noqa: BLE001 — fail closed, never serve stale as fresh
            logger.error(f"/stats build failed: {e}")
            return JSONResponse({"error": "stats unavailable"}, status_code=500, headers=_CORS_HEADERS)
        _STATS_CACHE["snapshot"] = snapshot
        _STATS_CACHE["at"] = now

    accept = (request.headers.get("accept") or "").lower()
    wants_html = "text/html" in accept and "application/json" not in accept
    if wants_html:
        return HTMLResponse(_render_stats_html(snapshot), headers=_CORS_HEADERS)
    return JSONResponse(snapshot, headers=_CORS_HEADERS)


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
    """Health check endpoint."""
    # Count only the canonical, advertised tools (vigil_* prefixed). TOOL_MAP
    # also holds unprefixed aliases for backwards compatibility, so counting
    # every key would double the number and disagree with /tools/list.
    public_tools = sum(1 for name in TOOL_MAP if name.startswith("vigil_"))
    return JSONResponse({"status": "ok", "service": "vigil-mcp", "tools": public_tools})


# ─────────────────────────────────────────────────────────────
# AGENT DISCOVERY — /llms.txt and /.well-known/x402
# Makes VIGIL discoverable by x402 directories (x402-list.com,
# agent-tools.cloud) and any agent that scans the standard files.
# All content is generated from live tool registration — no hand
# numbers that can drift from reality.
# ─────────────────────────────────────────────────────────────


# Free vs paid is derived from the x402 price map so it never drifts.
def _tool_pricing() -> tuple[list[str], list[tuple[str, float]]]:
    """Return (free_tool_names, [(paid_tool_name, usd_price)])."""
    free: list[str] = []
    paid: list[tuple[str, float]] = []
    for name in TOOL_MAP:
        if not name.startswith("vigil_"):
            continue
        price = x402.price_for(name)
        if price is None:
            free.append(name)
        else:
            paid.append((name, price))
    return sorted(free), sorted(paid)


@mcp.custom_route("/llms.txt", methods=["GET"])
async def llms_txt(request: Request) -> PlainTextResponse:
    """Machine-readable catalog for AI agents and x402 directories."""
    free, paid = _tool_pricing()
    n_tools = sum(1 for n in TOOL_MAP if n.startswith("vigil_"))
    free_lines = "\n".join(f"- {n}" for n in free)
    paid_lines = "\n".join(f"- {n} — ${p:g} USDC/call (x402)" for n, p in paid) or "- (none)"
    intro = (
        f"> VIGIL is a keyless onchain security scanner for Base. It exposes {n_tools} tools "
        "over JSON-RPC 2.0 so any AI agent can scan a token or wallet BEFORE it signs — "
        "honeypots, rugpulls, liquidity locks, risky approvals, and a 6-source consensus verdict."
    )
    notable = (
        "- vigil_simulate_approval — risk-assess a spender BEFORE you approve it. "
        'Unique: answers "what could this spender do if I sign?"\n'
        "- vigil_liquidity_lock — locked / burned / unlocked / unknown. "
        "Missing data is never reported as safe.\n"
        "- vigil_consensus — 6 independent sources vote; risk only escalates when "
        "multiple agree (false-positive guard)."
    )
    body = f"""# VIGIL — Onchain Security Scanner (MCP)

{intro}

Endpoint: https://mcp.vigil.codes
Protocol: JSON-RPC 2.0 over HTTP (POST /tools/call)
Network: Base (chainid 8453)
Payments: x402 (USDC on Base) for premium tools; core safety checks are free.
Source: https://github.com/vigilcodes/vigil-mcp
Site: https://vigil.codes

## How to call

POST https://mcp.vigil.codes/tools/call
Content-Type: application/json
{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"<tool>","arguments":{{...}}}}}}

List all tools: GET https://mcp.vigil.codes/tools/list
Health:         GET https://mcp.vigil.codes/health
Live stats:     GET https://mcp.vigil.codes/stats
x402 manifest:  GET https://mcp.vigil.codes/.well-known/x402

## Free tools (no API key, no payment)

{free_lines}

## Paid tools (x402 — USDC on Base)

{paid_lines}

## Notable

{notable}

Not financial advice. Read-only intelligence. Always verify independently before signing.
"""
    return PlainTextResponse(body, headers=_CORS_HEADERS)


@mcp.custom_route("/.well-known/x402", methods=["GET", "OPTIONS"])
async def well_known_x402(request: Request) -> JSONResponse:
    """x402 service manifest — advertises VIGIL's payable resources."""
    if request.method == "OPTIONS":
        return JSONResponse({}, headers=_CORS_HEADERS)

    _, paid = _tool_pricing()
    resources = []
    for name, price in paid:
        resources.append(
            {
                "resource": f"https://mcp.vigil.codes/tools/call#{name}",
                "type": "http",
                "x402Version": 1,
                "description": f"VIGIL {name} — onchain security scan on Base",
                "accepts": [
                    {
                        "scheme": "exact",
                        "network": "eip155:8453",
                        "maxAmountRequired": str(int(round(price * 1_000_000))),
                        "asset": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                        "extra": {"name": "USD Coin", "decimals": 6, "priceUSD": price},
                    }
                ],
            }
        )
    return JSONResponse(
        {
            "x402Version": 1,
            "service": "vigil-mcp",
            "name": "VIGIL — Onchain Security Scanner",
            "description": (
                "Keyless onchain security scanner for Base. Scan tokens and wallets before signing: "
                "honeypots, rugpulls, liquidity locks, risky approvals, multi-source consensus."
            ),
            "endpoint": "https://mcp.vigil.codes",
            "documentation": "https://mcp.vigil.codes/llms.txt",
            "tools_list": "https://mcp.vigil.codes/tools/list",
            "network": "eip155:8453",
            "resources": resources,
        },
        headers=_CORS_HEADERS,
    )


# ─────────────────────────────────────────────────────────────
# ENTRYPOINT
# ─────────────────────────────────────────────────────────────


def main():
    """Run VIGIL MCP server."""
    transport = os.getenv("VIGIL_MCP_TRANSPORT", "stdio")

    if transport == "stdio":
        logger.info("Starting VIGIL MCP server (stdio transport)")
        mcp.run(transport="stdio")
    elif transport == "sse":
        logger.info("Starting VIGIL MCP server (SSE transport)")
        mcp.run(transport="sse")
    else:
        logger.error(f"Unknown transport: {transport}")
        sys.exit(1)


if __name__ == "__main__":
    main()
