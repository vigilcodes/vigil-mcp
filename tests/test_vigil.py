"""Tests for VIGIL MCP server."""

import pytest


def test_import_server():
    """Verify server module imports cleanly."""
    from vigil_mcp.server import main, mcp

    assert mcp is not None
    assert callable(main)


def test_import_scanners():
    """Verify scanner modules import cleanly."""
    from vigil_mcp.scanners.approvals import ApprovalScanner
    from vigil_mcp.scanners.honeypot import HoneypotDetector
    from vigil_mcp.scanners.safety_score import SafetyScorer
    from vigil_mcp.scanners.token_scanner import TokenScanner

    assert ApprovalScanner is not None
    assert TokenScanner is not None
    assert HoneypotDetector is not None
    assert SafetyScorer is not None


def test_import_revoker():
    """Verify revocation engine imports."""
    from vigil_mcp.revoker.engine import RevocationEngine

    assert RevocationEngine is not None


def test_import_bridge():
    """Verify Base MCP bridge imports."""
    from vigil_mcp.bridge.base_mcp import BaseMCPBridge

    assert BaseMCPBridge is not None


def test_approval_model():
    """Test Approval pydantic model."""
    from vigil_mcp.scanners.approvals import Approval

    a = Approval(
        token_address="0x1234567890abcdef1234567890abcdef12345678",
        token_symbol="TEST",
        token_name="Test Token",
        spender_address="0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        amount="unlimited",
        risk="critical",
    )
    assert a.risk == "critical"
    assert a.amount == "unlimited"
    d = a.model_dump()
    assert d["token_symbol"] == "TEST"


def test_honeypot_model():
    """Test HoneypotResult model."""
    from vigil_mcp.scanners.honeypot import HoneypotResult

    h = HoneypotResult(
        token="0x1234",
        chain="base",
        is_honeypot=True,
        can_buy=True,
        can_sell=False,
        block_reason="blacklist",
        simulations=[],
    )
    assert h.is_honeypot is True
    assert h.can_sell is False


def test_chain_validation():
    """Test chain validation in server."""
    from vigil_mcp.server import _validate_chain

    assert _validate_chain("base") == "base"
    assert _validate_chain("ETHEREUM") == "ethereum"

    with pytest.raises(ValueError, match="Unsupported chain"):
        _validate_chain("bitcoin")


def test_approval_scanner_init():
    """Test ApprovalScanner initialization."""
    from vigil_mcp.scanners.approvals import ApprovalScanner

    scanner = ApprovalScanner()
    assert "base" in scanner.rpc_urls
    assert "ethereum" in scanner.rpc_urls


def test_safety_score_model():
    """Test SafetyScoreResult model."""
    from vigil_mcp.scanners.safety_score import SafetyScoreResult, ScoreBreakdown

    result = SafetyScoreResult(
        address="0x1234",
        chain="base",
        score=75,
        risk_level="medium",
        breakdown=[ScoreBreakdown(category="Code", score=40, note="OK")],
        risk_factors=["proxy"],
        positive_factors=["verified"],
        recommendation="Proceed with caution",
    )
    assert result.score == 75
    assert len(result.breakdown) == 1


def test_base_mcp_bridge_init():
    """Test BaseMCPBridge initialization."""
    from vigil_mcp.bridge.base_mcp import BaseMCPBridge

    bridge = BaseMCPBridge()
    schema = bridge.get_mcp_tools_schema()
    assert "vigil_security_check" in schema
    assert "vigil_scan_token" in schema
    assert "vigil_revoke_approval" in schema
