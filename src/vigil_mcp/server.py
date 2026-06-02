"""VIGIL MCP Server — FastMCP implementation exposing security scanning tools."""

import logging
import os
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP

from vigil_mcp.bridge.base_mcp import BaseMCPBridge
from vigil_mcp.revoker.engine import RevocationEngine
from vigil_mcp.scanners.approvals import ApprovalScanner
from vigil_mcp.scanners.honeypot import HoneypotDetector
from vigil_mcp.scanners.safety_score import SafetyScorer
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
    result = await revocation_engine.report_scam(token, evidence_type, description, chain)
    return result


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
# ENTRYPOINT
# ─────────────────────────────────────────────────────────────


def main():
    """Run VIGIL MCP server."""
    transport = os.getenv("VIGIL_MCP_TRANSPORT", "stdio")

    if transport == "stdio":
        logger.info("Starting VIGIL MCP server (stdio transport)")
        mcp.run(transport="stdio")
    elif transport == "sse":
        logger.info(f"Starting VIGIL MCP server (SSE transport)")
        mcp.run(transport="sse")
    else:
        logger.error(f"Unknown transport: {transport}")
        sys.exit(1)


if __name__ == "__main__":
    main()
