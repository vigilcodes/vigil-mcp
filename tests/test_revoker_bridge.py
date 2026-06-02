"""Tests for VIGIL revoker engine and Base MCP bridge."""

import pytest

from vigil_mcp.bridge.base_mcp import BaseMCPBridge
from vigil_mcp.revoker.engine import APPROVE_SELECTOR, RevocationEngine

TOKEN = "0x1111111111111111111111111111111111111111"
SPENDER = "0x2222222222222222222222222222222222222222"
WALLET = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


class TestRevocationEngine:
    """Test RevocationEngine RPC fallback."""

    @pytest.mark.asyncio
    async def test_build_calldata(self):
        """Verify approve(spender, 0) calldata is correctly built."""
        engine = RevocationEngine()
        result = await engine._revoke_via_rpc(TOKEN, SPENDER, "base")

        assert result["status"] == "calldata_ready"
        assert result["to"] == TOKEN
        assert result["value"] == "0x0"

        calldata = result["calldata"]
        assert calldata.startswith(APPROVE_SELECTOR)
        # spender should be zero-padded to 32 bytes
        assert SPENDER[2:].lower() in calldata.lower()
        # amount should be zero (last 64 hex chars)
        assert calldata[-64:] == "0" * 64

    def test_check_auth_raises_without_key(self, monkeypatch):
        monkeypatch.delenv("BANKR_API_KEY", raising=False)
        engine = RevocationEngine()
        with pytest.raises(ValueError, match="BANKR_API_KEY required"):
            engine._check_auth()

    @pytest.mark.asyncio
    async def test_report_scam_requires_auth(self, monkeypatch):
        monkeypatch.delenv("BANKR_API_KEY", raising=False)
        engine = RevocationEngine()
        with pytest.raises(ValueError, match="BANKR_API_KEY required"):
            await engine.report_scam(TOKEN, "honeypot", "test", "base")


class TestBaseMCPBridge:
    """Test BaseMCPBridge security check logic."""

    @pytest.mark.asyncio
    async def test_security_check_no_api_key(self, monkeypatch):
        monkeypatch.delenv("BANKR_API_KEY", raising=False)
        bridge = BaseMCPBridge()
        result = await bridge.security_check(WALLET)

        assert result.wallet == WALLET
        assert result.safe_to_proceed is True
        assert result.risk_level == "safe"

    def test_tools_schema_structure(self):
        bridge = BaseMCPBridge()
        schema = bridge.get_mcp_tools_schema()

        assert "vigil_security_check" in schema
        assert "vigil_scan_token" in schema
        assert "vigil_revoke_approval" in schema

        check = schema["vigil_security_check"]
        assert "wallet" in check["parameters"]["properties"]
        assert "wallet" in check["parameters"]["required"]
