"""Async tests for VIGIL scanners with mocked HTTP responses."""

import pytest

from vigil_mcp.scanners.approvals import SAFE_SPENDERS, UNLIMITED, ApprovalScanner
from vigil_mcp.scanners.honeypot import HoneypotDetector
from vigil_mcp.scanners.safety_score import SafetyScorer
from vigil_mcp.scanners.token_scanner import TokenScanner

WALLET = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
TOKEN = "0x1111111111111111111111111111111111111111"
SPENDER = "0x2222222222222222222222222222222222222222"


# ─── ApprovalScanner ───────────────────────────────────────


class TestApprovalScannerRPC:
    """Test ApprovalScanner._scan_via_rpc."""

    @pytest.mark.asyncio
    async def test_scan_empty_logs(self, httpx_mock):
        scanner = ApprovalScanner()
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": []})

        result = await scanner._scan_via_rpc(WALLET, "base", None)
        assert result.total == 0
        assert result.approvals == []

    @pytest.mark.asyncio
    async def test_scan_unlimited_approval(self, httpx_mock):
        scanner = ApprovalScanner()
        log = {
            "address": TOKEN,
            "topics": [
                "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
                "0x" + WALLET[2:].lower().zfill(64),
                "0x" + SPENDER[2:].lower().zfill(64),
            ],
            "data": "0x" + UNLIMITED[2:].zfill(64),
        }
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": [log]})

        result = await scanner._scan_via_rpc(WALLET, "base", None)
        assert result.total == 1
        assert result.approvals[0].amount == "unlimited"
        assert result.approvals[0].risk == "critical"

    @pytest.mark.asyncio
    async def test_scan_safe_spender(self, httpx_mock):
        scanner = ApprovalScanner()
        safe = list(SAFE_SPENDERS)[0]
        log = {
            "address": TOKEN,
            "topics": [
                "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
                "0x" + WALLET[2:].lower().zfill(64),
                "0x" + safe[2:].lower().zfill(64),
            ],
            "data": "0x" + hex(10**18)[2:].zfill(64),
        }
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": [log]})

        result = await scanner._scan_via_rpc(WALLET, "base", None)
        assert result.total == 1
        assert result.approvals[0].risk == "safe"

    @pytest.mark.asyncio
    async def test_scan_unlimited_safe_spender(self, httpx_mock):
        scanner = ApprovalScanner()
        safe = list(SAFE_SPENDERS)[0]
        log = {
            "address": TOKEN,
            "topics": [
                "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
                "0x" + WALLET[2:].lower().zfill(64),
                "0x" + safe[2:].lower().zfill(64),
            ],
            "data": "0x" + UNLIMITED[2:].zfill(64),
        }
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": [log]})

        result = await scanner._scan_via_rpc(WALLET, "base", None)
        assert result.total == 1
        assert result.approvals[0].risk == "low"

    @pytest.mark.asyncio
    async def test_scan_deduplicates(self, httpx_mock):
        scanner = ApprovalScanner()
        log = {
            "address": TOKEN,
            "topics": [
                "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
                "0x" + WALLET[2:].lower().zfill(64),
                "0x" + SPENDER[2:].lower().zfill(64),
            ],
            "data": "0x" + hex(10**18)[2:].zfill(64),
        }
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": [log, log, log]})

        result = await scanner._scan_via_rpc(WALLET, "base", None)
        assert result.total == 1

    @pytest.mark.asyncio
    async def test_scan_skips_revoked(self, httpx_mock):
        scanner = ApprovalScanner()
        log = {
            "address": TOKEN,
            "topics": [
                "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
                "0x" + WALLET[2:].lower().zfill(64),
                "0x" + SPENDER[2:].lower().zfill(64),
            ],
            "data": "0x0",
        }
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": [log]})

        result = await scanner._scan_via_rpc(WALLET, "base", None)
        assert result.total == 0

    @pytest.mark.asyncio
    async def test_scan_risk_filter(self, httpx_mock):
        scanner = ApprovalScanner()
        safe = list(SAFE_SPENDERS)[0]
        unlimited_log = {
            "address": TOKEN,
            "topics": [
                "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
                "0x" + WALLET[2:].lower().zfill(64),
                "0x" + SPENDER[2:].lower().zfill(64),
            ],
            "data": "0x" + UNLIMITED[2:].zfill(64),
        }
        safe_log = {
            "address": TOKEN,
            "topics": [
                "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
                "0x" + WALLET[2:].lower().zfill(64),
                "0x" + safe[2:].lower().zfill(64),
            ],
            "data": "0x" + hex(10**18)[2:].zfill(64),
        }
        httpx_mock.add_response(
            json={"jsonrpc": "2.0", "id": 1, "result": [unlimited_log, safe_log]}
        )

        result = await scanner._scan_via_rpc(WALLET, "base", "critical")
        assert result.total == 1
        assert result.approvals[0].risk == "critical"

    @pytest.mark.asyncio
    async def test_scan_unsupported_chain(self):
        scanner = ApprovalScanner()
        with pytest.raises(ValueError, match="No RPC configured"):
            await scanner._scan_via_rpc(WALLET, "solana", None)


# ─── TokenScanner ──────────────────────────────────────────


class TestTokenScannerRPC:
    """Test TokenScanner._scan_via_rpc."""

    @pytest.mark.asyncio
    async def test_no_code(self, httpx_mock):
        scanner = TokenScanner()
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": "0x"})

        result = await scanner._scan_via_rpc(TOKEN, "base")
        assert result.safety_score == 0
        assert result.risk_level == "critical"
        assert result.honeypot.detected is True

    @pytest.mark.asyncio
    async def test_mint_function_detected(self, httpx_mock):
        scanner = TokenScanner()
        # bytecode with mint selector 40c10f19
        code = "0x" + "00" * 20 + "40c10f19" + "00" * 20

        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": code})
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 2, "result": "0x" + "0" * 64})

        result = await scanner._scan_via_rpc(TOKEN, "base")
        assert any("mint" in f.message.lower() for f in result.findings)
        assert result.safety_score < 50

    @pytest.mark.asyncio
    async def test_blacklist_detected(self, httpx_mock):
        scanner = TokenScanner()
        code = "0x" + "00" * 20 + "4f558e79" + "00" * 20

        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": code})
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 2, "result": "0x" + "0" * 64})

        result = await scanner._scan_via_rpc(TOKEN, "base")
        assert any("blacklist" in f.message.lower() for f in result.findings)

    @pytest.mark.asyncio
    async def test_proxy_detected(self, httpx_mock):
        scanner = TokenScanner()
        # Minimal proxy prefix + EIP-1967 implementation slot set
        code = "0x" + "363d3d373d3d3d363d73" + "00" * 30
        impl = "0x" + "0" * 63 + "1"  # non-zero implementation

        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": code})
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 2, "result": impl})

        result = await scanner._scan_via_rpc(TOKEN, "base")
        assert result.contract.is_proxy is True
        assert any("proxy" in f.message.lower() for f in result.findings)

    @pytest.mark.asyncio
    async def test_clean_contract(self, httpx_mock):
        scanner = TokenScanner()
        code = "0x" + "00" * 100

        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": code})
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 2, "result": "0x" + "0" * 64})

        result = await scanner._scan_via_rpc(TOKEN, "base")
        assert result.safety_score >= 50
        assert result.risk_level in ("low", "medium", "safe")

    @pytest.mark.asyncio
    async def test_unsupported_chain(self):
        scanner = TokenScanner()
        with pytest.raises(ValueError, match="No RPC configured"):
            await scanner._scan_via_rpc(TOKEN, "solana")


# ─── HoneypotDetector ──────────────────────────────────────


class TestHoneypotDetector:
    """Test HoneypotDetector._detect_via_simulation."""

    @pytest.mark.asyncio
    async def test_not_honeypot(self, httpx_mock):
        detector = HoneypotDetector()

        # balanceOf returns non-zero
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": "0x" + "0" * 63 + "1"})
        # transfer simulation succeeds (no error)
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 2, "result": "0x1"})

        result = await detector._detect_via_simulation(TOKEN, "base")
        assert result.is_honeypot is False
        assert result.can_sell is True

    @pytest.mark.asyncio
    async def test_blacklist_honeypot(self, httpx_mock):
        detector = HoneypotDetector()

        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": "0x" + "0" * 63 + "1"})
        httpx_mock.add_response(
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "error": {"message": "execution reverted: blacklisted"},
            }
        )

        result = await detector._detect_via_simulation(TOKEN, "base")
        assert result.is_honeypot is True
        assert result.can_sell is False
        assert "blacklist" in result.block_reason.lower()

    @pytest.mark.asyncio
    async def test_paused_honeypot(self, httpx_mock):
        detector = HoneypotDetector()

        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": "0x" + "0" * 63 + "1"})
        httpx_mock.add_response(
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "error": {"message": "execution reverted: paused"},
            }
        )

        result = await detector._detect_via_simulation(TOKEN, "base")
        assert result.is_honeypot is True
        assert "paused" in result.block_reason.lower()

    @pytest.mark.asyncio
    async def test_no_erc20(self, httpx_mock):
        detector = HoneypotDetector()

        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": "0x"})

        result = await detector._detect_via_simulation(TOKEN, "base")
        assert result.is_honeypot is True
        assert result.can_buy is False
        assert result.can_sell is False

    @pytest.mark.asyncio
    async def test_unsupported_chain(self):
        detector = HoneypotDetector()
        with pytest.raises(ValueError, match="No RPC configured"):
            await detector._detect_via_simulation(TOKEN, "solana")


# ─── SafetyScorer ──────────────────────────────────────────


class TestSafetyScorer:
    """Test SafetyScorer._score_via_analysis."""

    @pytest.mark.asyncio
    async def test_no_code(self, httpx_mock):
        scorer = SafetyScorer()
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": "0x"})

        result = await scorer._score_via_analysis(TOKEN, "base")
        assert result.score == 0
        assert result.risk_level == "critical"

    @pytest.mark.asyncio
    async def test_score_with_mint(self, httpx_mock):
        scorer = SafetyScorer()
        code = "0x" + "00" * 50 + "40c10f19" + "00" * 50

        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": code})
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 2, "result": "0x100"})

        result = await scorer._score_via_analysis(TOKEN, "base")
        assert any("mint" in rf.lower() for rf in result.risk_factors)
        assert result.score < 70

    @pytest.mark.asyncio
    async def test_score_with_renounce(self, httpx_mock):
        scorer = SafetyScorer()
        code = "0x" + "00" * 50 + "715018a6" + "00" * 50

        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": code})
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 2, "result": "0x100"})

        result = await scorer._score_via_analysis(TOKEN, "base")
        assert any("renounce" in pf.lower() for pf in result.positive_factors)

    @pytest.mark.asyncio
    async def test_unsupported_chain(self):
        scorer = SafetyScorer()
        with pytest.raises(ValueError, match="No RPC configured"):
            await scorer._score_via_analysis(TOKEN, "solana")


# ─── Risk assessment ───────────────────────────────────────


class TestRiskAssessment:
    """Test _assess_risk logic."""

    def test_unlimited_unknown_spender_is_critical(self):
        scanner = ApprovalScanner()
        risk = scanner._assess_risk(TOKEN, SPENDER, is_unlimited=True)
        assert risk == "critical"

    def test_limited_unknown_spender_is_medium(self):
        scanner = ApprovalScanner()
        risk = scanner._assess_risk(TOKEN, SPENDER, is_unlimited=False)
        assert risk == "medium"

    def test_unlimited_safe_spender_is_low(self):
        scanner = ApprovalScanner()
        safe = list(SAFE_SPENDERS)[0]
        risk = scanner._assess_risk(TOKEN, safe, is_unlimited=True)
        assert risk == "low"

    def test_limited_safe_spender_is_safe(self):
        scanner = ApprovalScanner()
        safe = list(SAFE_SPENDERS)[0]
        risk = scanner._assess_risk(TOKEN, safe, is_unlimited=False)
        assert risk == "safe"
