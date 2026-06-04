"""VIGIL MCP Server — FastMCP implementation exposing security scanning tools."""

import logging
import os
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from vigil_mcp.autonomous.sentinel import Sentinel, SentinelStore
from vigil_mcp.bridge.base_mcp import BaseMCPBridge
from vigil_mcp.monitors.wallet_monitor import WalletMonitor
from vigil_mcp.payments import x402
from vigil_mcp.revoker.engine import RevocationEngine
from vigil_mcp.scanners.approvals import ApprovalScanner
from vigil_mcp.scanners.deployer import DeployerScanner
from vigil_mcp.scanners.honeypot import HoneypotDetector
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
        "Onchain security scanner — scan token approvals, detect rugpulls,"
        " check honeypots, revoke dangerous approvals"
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

SUPPORTED_CHAINS = ["base", "ethereum", "polygon", "arbitrum", "solana"]


def _validate_chain(chain: str) -> str:
    chain = chain.lower().strip()
    if chain not in SUPPORTED_CHAINS:
        raise ValueError(f"Unsupported chain '{chain}'. Use: {', '.join(SUPPORTED_CHAINS)}")
    return chain


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

    overall_score = max(0, 100 - (critical * 20) - (high * 10) - (unlimited * 5))
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
    if critical > 0:
        recommendations.append(
            {
                "priority": "critical",
                "action": f"Revoke {critical} critical approvals immediately",
                "detail": (
                    "These approvals grant unlimited spending power to potentially risky contracts"
                ),
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
        "approvals": {
            "total": len(approvals.approvals),
            "critical": critical,
            "high": high,
            "unlimited": unlimited,
        },
        "scam_interactions": scam_history,
        "top_risks": [
            a.model_dump() for a in approvals.approvals if a.risk in ("critical", "high")
        ][:5],
        "recommendations": recommendations,
    }


# ─────────────────────────────────────────────────────────────
# MONITOR TOOLS (real-time alerts)
# ─────────────────────────────────────────────────────────────


@mcp.tool()
async def vigil_monitor_wallet(
    wallet: str, chain: str = "base", lookback_blocks: int = 1000
) -> dict[str, Any]:
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
async def vigil_batch_revoke(
    wallet: str, chain: str = "base", risk_level: str = "critical"
) -> dict[str, Any]:
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
            tx = await revocation_engine.revoke_single(
                approval.token_address, approval.spender_address, chain
            )
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
async def vigil_sentinel_watch(
    wallet: str, chain: str = "base", label: str = ""
) -> dict[str, Any]:
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
    "vigil_scan_approvals": lambda args: vigil_scan_approvals(
        args.get("wallet", ""), args.get("chain", "base")
    ),
    "vigil_scan_token": lambda args: vigil_scan_token(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "vigil_detect_honeypot": lambda args: vigil_detect_honeypot(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "vigil_safety_score": lambda args: vigil_safety_score(
        args.get("contract") or args.get("token", ""), args.get("chain", "base")
    ),
    "vigil_wallet_report": lambda args: vigil_wallet_report(
        args.get("wallet", ""), args.get("chain", "base")
    ),
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
    "vigil_batch_scan": lambda args: vigil_batch_scan(
        args.get("tokens", []), args.get("chain", "base")
    ),
    "vigil_check_scam": lambda args: vigil_check_scam(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "vigil_sentinel_status": lambda args: vigil_sentinel_status(),
    "scan_approvals": lambda args: vigil_scan_approvals(
        args.get("wallet", ""), args.get("chain", "base")
    ),
    "scan_token": lambda args: vigil_scan_token(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "detect_honeypot": lambda args: vigil_detect_honeypot(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "safety_score": lambda args: vigil_safety_score(
        args.get("contract") or args.get("token", ""), args.get("chain", "base")
    ),
    "wallet_report": lambda args: vigil_wallet_report(
        args.get("wallet", ""), args.get("chain", "base")
    ),
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
    "batch_scan": lambda args: vigil_batch_scan(
        args.get("tokens", []), args.get("chain", "base")
    ),
    "check_scam": lambda args: vigil_check_scam(
        args.get("token") or args.get("contract", ""), args.get("chain", "base")
    ),
    "sentinel_status": lambda args: vigil_sentinel_status(),
}


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
    ]
    return JSONResponse({"jsonrpc": "2.0", "id": None, "result": {"tools": tools}})


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
                )

    try:
        result = await handler(arguments)
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result})
    except Exception as e:
        logger.error(f"Tool {tool_name} failed: {e}")
        return JSONResponse(
            {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}},
            status_code=500,
        )


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
    """Health check endpoint."""
    return JSONResponse({"status": "ok", "service": "vigil-mcp", "tools": len(TOOL_MAP)})


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
