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

    @pytest.fixture(autouse=True)
    def _bound_lookback(self, monkeypatch):
        # Keep the scan to a single small chunk so one getLogs mock suffices.
        monkeypatch.setenv("VIGIL_APPROVAL_LOOKBACK_BLOCKS", "100")
        monkeypatch.setenv("VIGIL_APPROVAL_LOG_CHUNK", "100")

    @staticmethod
    def _mock_head(httpx_mock, block=1000):
        # First call in the flow is eth_blockNumber.
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": hex(block)})

    @pytest.mark.asyncio
    async def test_scan_empty_logs(self, httpx_mock):
        scanner = ApprovalScanner()
        self._mock_head(httpx_mock)
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": []})

        result = await scanner._scan_via_rpc(WALLET, "base", None)
        assert result.total == 0
        assert result.approvals == []

    @pytest.mark.asyncio
    async def test_scan_unlimited_approval(self, httpx_mock):
        scanner = ApprovalScanner()
        self._mock_head(httpx_mock)
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
        self._mock_head(httpx_mock)
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
        self._mock_head(httpx_mock)
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
        self._mock_head(httpx_mock)
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
        self._mock_head(httpx_mock)
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
        self._mock_head(httpx_mock)
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

    @pytest.fixture(autouse=True)
    def _stub_goplus(self, monkeypatch):
        # Keep these tests focused on RPC bytecode analysis; GoPlus is exercised
        # in its own tests. Make it report "unavailable" so no extra HTTP call
        # consumes the mocked RPC responses.
        from vigil_mcp.scanners.goplus import GoPlusResult, GoPlusScanner

        async def _unavailable(self, token, chain):
            return GoPlusResult(available=False, note="stubbed")

        monkeypatch.setattr(GoPlusScanner, "token_security", _unavailable)

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

        # eth_getCode returns substantial code (contract exists)
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 0, "result": "0x" + "60" * 50})
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

        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 0, "result": "0x" + "60" * 50})
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

        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 0, "result": "0x" + "60" * 50})
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

        # Contract has code, but balanceOf returns empty
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 0, "result": "0x" + "60" * 50})
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": "0x"})

        result = await detector._detect_via_simulation(TOKEN, "base")
        assert result.is_honeypot is True
        assert result.can_buy is False
        assert result.can_sell is False

    @pytest.mark.asyncio
    async def test_no_contract_code(self, httpx_mock):
        detector = HoneypotDetector()

        # eth_getCode returns 0x (no contract)
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 0, "result": "0x"})

        result = await detector._detect_via_simulation(TOKEN, "base")
        assert result.is_honeypot is True
        assert result.block_reason == "No contract code at address"

    @pytest.mark.asyncio
    async def test_zero_balance_valid_erc20_not_flagged(self, httpx_mock):
        """A valid ERC-20 returning a zero balance (0x + 64 zeros) is NOT a honeypot.

        Regression: malformed balanceOf calldata (double 0x) made RPCs return
        null, wrongly flagging real tokens like $VIGIL as non-ERC-20.
        """
        detector = HoneypotDetector()

        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 0, "result": "0x" + "60" * 50})
        # balanceOf returns a valid zero-balance word (64 zeros)
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": "0x" + "0" * 64})
        # transfer simulation succeeds
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 2, "result": "0x1"})

        result = await detector._detect_via_simulation(TOKEN, "base")
        assert result.is_honeypot is False
        assert result.can_sell is True

        # The balanceOf request must use well-formed calldata (no double 0x).
        balance_req = httpx_mock.get_requests()[1]
        import json as _json

        data = _json.loads(balance_req.content)["params"][0]["data"]
        assert data.startswith("0x70a08231")
        assert "0x" not in data[2:]  # no stray 0x in the encoded args

    @pytest.mark.asyncio
    async def test_known_blue_chip_skips_simulation(self, httpx_mock):
        detector = HoneypotDetector()

        # USDC on Base — should bypass any RPC call via known-contract fast-path
        usdc_base = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
        result = await detector.detect(usdc_base, "base")

        assert result.is_honeypot is False
        assert result.can_buy is True
        assert result.can_sell is True
        assert any("verified" in s.error.lower() for s in result.simulations if s.error)

    @pytest.mark.asyncio
    async def test_unsupported_chain(self):
        detector = HoneypotDetector()
        with pytest.raises(ValueError, match="No RPC configured"):
            await detector._detect_via_simulation(TOKEN, "solana")


# ─── SafetyScorer ──────────────────────────────────────────


class TestSafetyScorer:
    """Test SafetyScorer._score_via_analysis."""

    @pytest.fixture(autouse=True)
    def _stub_goplus(self, monkeypatch):
        from vigil_mcp.scanners.goplus import GoPlusResult, GoPlusScanner

        async def _unavailable(self, token, chain):
            return GoPlusResult(available=False, note="stubbed")

        monkeypatch.setattr(GoPlusScanner, "token_security", _unavailable)

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


# ─── MarketScanner ─────────────────────────────────────────


class TestMarketScanner:
    """Test MarketScanner.get_market with mocked DexScreener responses."""

    @pytest.mark.asyncio
    async def test_no_pairs(self, httpx_mock):
        from vigil_mcp.scanners.market import MarketScanner

        httpx_mock.add_response(json={"pairs": []})
        result = await MarketScanner().get_market(TOKEN, "base")
        assert result.found is False

    @pytest.mark.asyncio
    async def test_picks_base_token_price(self, httpx_mock):
        from vigil_mcp.scanners.market import MarketScanner

        # Our token is the BASE token here; priceUsd should be trusted.
        httpx_mock.add_response(
            json={
                "pairs": [
                    {
                        "chainId": "base",
                        "baseToken": {"address": TOKEN},
                        "quoteToken": {"address": SPENDER},
                        "priceUsd": "1.0",
                        "liquidity": {"usd": 250000},
                        "volume": {"h24": 50000},
                        "pairAddress": "0xpair",
                        "dexId": "uniswap",
                    }
                ]
            }
        )
        result = await MarketScanner().get_market(TOKEN, "base")
        assert result.found is True
        assert result.price_usd == 1.0
        assert result.liquidity_usd == 250000
        assert result.liquidity_risk == "low"

    @pytest.mark.asyncio
    async def test_thin_liquidity_is_critical(self, httpx_mock):
        from vigil_mcp.scanners.market import MarketScanner

        httpx_mock.add_response(
            json={
                "pairs": [
                    {
                        "chainId": "base",
                        "baseToken": {"address": TOKEN},
                        "priceUsd": "0.001",
                        "liquidity": {"usd": 500},
                        "volume": {"h24": 10},
                        "pairAddress": "0xpair",
                        "dexId": "uniswap",
                    }
                ]
            }
        )
        result = await MarketScanner().get_market(TOKEN, "base")
        assert result.liquidity_risk == "critical"
        assert any("thin liquidity" in n.lower() for n in result.notes)

    @pytest.mark.asyncio
    async def test_ignores_price_when_token_is_quote(self, httpx_mock):
        from vigil_mcp.scanners.market import MarketScanner

        # Our token is the QUOTE token; priceUsd refers to the base asset, so
        # we must NOT report it as our token's price.
        httpx_mock.add_response(
            json={
                "pairs": [
                    {
                        "chainId": "base",
                        "baseToken": {"address": SPENDER},
                        "quoteToken": {"address": TOKEN},
                        "priceUsd": "3500.0",
                        "liquidity": {"usd": 100000},
                        "pairAddress": "0xpair",
                        "dexId": "uniswap",
                    }
                ]
            }
        )
        result = await MarketScanner().get_market(TOKEN, "base")
        assert result.price_usd is None
        assert result.liquidity_usd == 100000


# ─── DeployerScanner ───────────────────────────────────────


class TestDeployerScanner:
    """Test DeployerScanner.check fallback and parsing."""

    @pytest.mark.asyncio
    async def test_no_api_key_is_unavailable(self, monkeypatch):
        monkeypatch.delenv("BASESCAN_API_KEY", raising=False)
        monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
        from vigil_mcp.scanners.deployer import DeployerScanner

        result = await DeployerScanner().check(TOKEN, "base")
        assert result.available is False
        assert "api_key" in result.note.lower() or "api key" in result.note.lower()

    @pytest.mark.asyncio
    async def test_unsupported_chain(self, monkeypatch):
        monkeypatch.setenv("BASESCAN_API_KEY", "testkey")
        from vigil_mcp.scanners.deployer import DeployerScanner

        result = await DeployerScanner().check(TOKEN, "solana")
        assert result.available is False
        assert "unsupported" in result.note.lower()


# ─── ScamDatabase ──────────────────────────────────────────


class TestScamDatabase:
    """Test the local SQLite scam report store."""

    def _db(self, tmp_path):
        from vigil_mcp.scanners.scam_db import ScamDatabase

        return ScamDatabase(db_path=str(tmp_path / "scam.db"))

    def test_report_and_check(self, tmp_path):
        db = self._db(tmp_path)
        out = db.report(TOKEN, "honeypot", "blocks selling", "base")
        assert out["status"] == "stored"
        assert out["total_reports_for_token"] == 1

        check = db.check(TOKEN, "base")
        assert check["reported"] is True
        assert check["report_count"] == 1
        assert "honeypot" in check["evidence_types"]

    def test_check_unreported_token(self, tmp_path):
        db = self._db(tmp_path)
        check = db.check(TOKEN, "base")
        assert check["reported"] is False
        assert check["report_count"] == 0

    def test_invalid_evidence_type(self, tmp_path):
        db = self._db(tmp_path)
        with pytest.raises(ValueError, match="Invalid evidence_type"):
            db.report(TOKEN, "not_a_type", "desc", "base")

    def test_multiple_reports_aggregate(self, tmp_path):
        db = self._db(tmp_path)
        db.report(TOKEN, "honeypot", "first", "base")
        db.report(TOKEN, "rugpull", "second", "base")
        check = db.check(TOKEN, "base")
        assert check["report_count"] == 2
        assert set(check["evidence_types"]) == {"honeypot", "rugpull"}

    def test_address_case_insensitive(self, tmp_path):
        db = self._db(tmp_path)
        db.report(TOKEN.upper(), "scam", "desc", "base")
        check = db.check(TOKEN.lower(), "base")
        assert check["report_count"] == 1


# ─── GoPlus + honeypot integration ─────────────────────────


class TestGoPlusScanner:
    """Test the keyless GoPlus token-security client."""

    @pytest.mark.asyncio
    async def test_parses_clean_token(self, httpx_mock):
        from vigil_mcp.scanners.goplus import GoPlusScanner

        httpx_mock.add_response(
            json={
                "code": 1,
                "message": "OK",
                "result": {
                    TOKEN.lower(): {
                        "token_name": "Vigil",
                        "token_symbol": "VIGIL",
                        "is_honeypot": "0",
                        "buy_tax": "0",
                        "sell_tax": "0",
                        "is_mintable": "0",
                        "is_open_source": "1",
                        "holder_count": "160",
                    }
                },
            }
        )
        g = await GoPlusScanner().token_security(TOKEN, "base")
        assert g.available is True
        assert g.is_honeypot is False
        assert g.holder_count == 160
        assert g.is_open_source is True

    @pytest.mark.asyncio
    async def test_unsupported_chain(self):
        from vigil_mcp.scanners.goplus import GoPlusScanner

        g = await GoPlusScanner().token_security(TOKEN, "solana")
        assert g.available is False

    @pytest.mark.asyncio
    async def test_no_data_code(self, httpx_mock):
        from vigil_mcp.scanners.goplus import GoPlusScanner

        httpx_mock.add_response(json={"code": 0, "message": "no data", "result": {}})
        g = await GoPlusScanner().token_security(TOKEN, "base")
        assert g.available is False


class TestHoneypotGoPlusPath:
    """HoneypotDetector.detect should use GoPlus as the primary signal."""

    @pytest.mark.asyncio
    async def test_goplus_honeypot_flag(self, httpx_mock):
        detector = HoneypotDetector()
        httpx_mock.add_response(
            json={
                "code": 1,
                "result": {
                    TOKEN.lower(): {
                        "is_honeypot": "1",
                        "buy_tax": "0",
                        "sell_tax": "0.5",
                    }
                },
            }
        )
        result = await detector.detect(TOKEN, "base")
        assert result.is_honeypot is True
        assert result.can_sell is False
        assert "honeypot" in (result.block_reason or "").lower()

    @pytest.mark.asyncio
    async def test_goplus_clean_token(self, httpx_mock):
        detector = HoneypotDetector()
        httpx_mock.add_response(
            json={
                "code": 1,
                "result": {
                    TOKEN.lower(): {
                        "is_honeypot": "0",
                        "buy_tax": "0",
                        "sell_tax": "0",
                    }
                },
            }
        )
        result = await detector.detect(TOKEN, "base")
        assert result.is_honeypot is False
        assert result.can_sell is True


# ─── GoPlus enrichment of token scan + safety score ────────


class TestGoPlusEnrichment:
    """GoPlus data should flow into token scan and safety score results."""

    @pytest.mark.asyncio
    async def test_token_scan_uses_goplus_fields(self, httpx_mock, monkeypatch):
        from vigil_mcp.scanners.goplus import GoPlusResult, GoPlusScanner

        async def _gp(self, token, chain):
            return GoPlusResult(
                available=True,
                token_name="DemoToken",
                token_symbol="DEMO",
                is_honeypot=False,
                buy_tax=0.0,
                sell_tax=0.15,
                is_open_source=True,
                holder_count=1200,
            )

        monkeypatch.setattr(GoPlusScanner, "token_security", _gp)
        scanner = TokenScanner()
        # clean bytecode + non-proxy storage slot
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": "0x" + "00" * 100})
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 2, "result": "0x" + "0" * 64})

        result = await scanner._scan_via_rpc(TOKEN, "base")
        assert result.token_symbol == "DEMO"
        assert result.holders.total == 1200
        assert result.tax.sell == 0.15
        assert result.contract.verified is True
        # high sell tax should produce a finding
        assert any("sell tax" in f.message.lower() for f in result.findings)

    @pytest.mark.asyncio
    async def test_safety_score_reputation_from_goplus(self, httpx_mock, monkeypatch):
        from vigil_mcp.scanners.goplus import GoPlusResult, GoPlusScanner

        async def _gp(self, token, chain):
            return GoPlusResult(
                available=True,
                is_open_source=True,
                is_honeypot=False,
                holder_count=800,
            )

        monkeypatch.setattr(GoPlusScanner, "token_security", _gp)
        scorer = SafetyScorer()
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": "0x" + "00" * 100})
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 2, "result": "0x100"})

        result = await scorer._score_via_analysis(TOKEN, "base")
        assert any(b.category == "Reputation" for b in result.breakdown)
        assert any("open" in p.lower() or "holder" in p.lower() for p in result.positive_factors)


# ─── Sentinel (autonomous loop) ────────────────────────────


class TestSentinelStore:
    """Test the Sentinel watchlist + alert dedup store."""

    def _store(self, tmp_path):
        from vigil_mcp.autonomous.sentinel import SentinelStore

        return SentinelStore(db_path=str(tmp_path / "sentinel.db"))

    def test_add_and_list(self, tmp_path):
        store = self._store(tmp_path)
        store.add(WALLET, "base", "my wallet")
        wl = store.list()
        assert len(wl) == 1
        assert wl[0]["wallet"] == WALLET.lower()
        assert wl[0]["label"] == "my wallet"

    def test_remove(self, tmp_path):
        store = self._store(tmp_path)
        store.add(WALLET, "base")
        assert store.remove(WALLET, "base")["removed"] is True
        assert store.list() == []

    def test_filter_new_dedups(self, tmp_path):
        store = self._store(tmp_path)
        alerts = [
            {"severity": "high", "category": "approval", "message": "unlimited",
             "details": {"spender": "0xabc"}},
        ]
        first = store.filter_new(WALLET, "base", alerts)
        assert len(first) == 1  # new the first time
        second = store.filter_new(WALLET, "base", alerts)
        assert len(second) == 0  # deduped on repeat


class TestSentinelLoop:
    """Test the Sentinel run_once cycle with a stubbed monitor."""

    @pytest.mark.asyncio
    async def test_run_once_surfaces_new_alerts(self, tmp_path, monkeypatch):
        from vigil_mcp.autonomous.sentinel import Sentinel, SentinelStore
        from vigil_mcp.monitors.wallet_monitor import Alert, MonitorResult

        store = SentinelStore(db_path=str(tmp_path / "sentinel.db"))
        store.add(WALLET, "base", "test")

        async def _fake_monitor(self, wallet, chain, lookback):
            return MonitorResult(
                wallet=wallet, chain=chain, monitored_at=0.0,
                alerts=[Alert(severity="critical", category="approval",
                              message="unlimited approval", details={"spender": "0xbad"})],
                summary={}, recommendations=[],
            )

        from vigil_mcp.monitors.wallet_monitor import WalletMonitor

        monkeypatch.setattr(WalletMonitor, "monitor", _fake_monitor)
        monkeypatch.delenv("VIGIL_SENTINEL_WEBHOOK", raising=False)

        sentinel = Sentinel(store=store)
        summary = await sentinel.run_once()
        assert summary["scanned"] == 1
        assert summary["results"][0]["new_alerts"] == 1

        # Second cycle: same alert is deduped, so 0 new.
        summary2 = await sentinel.run_once()
        assert summary2["results"][0]["new_alerts"] == 0
