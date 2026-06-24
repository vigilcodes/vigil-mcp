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

    @pytest.fixture(autouse=True)
    def _stub_goplus(self, monkeypatch):
        # Approval enrichment now does a GoPlus lookup per unresolved token.
        # Stub it so these tests stay focused on the RPC log-parsing logic.
        from vigil_mcp.scanners.goplus import GoPlusResult, GoPlusScanner

        async def _unavailable(self, token, chain):
            return GoPlusResult(available=False, note="stubbed")

        monkeypatch.setattr(GoPlusScanner, "token_security", _unavailable)

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
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": [unlimited_log, safe_log]})

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
            {"severity": "high", "category": "approval", "message": "unlimited", "details": {"spender": "0xabc"}},
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
                wallet=wallet,
                chain=chain,
                monitored_at=0.0,
                alerts=[
                    Alert(
                        severity="critical",
                        category="approval",
                        message="unlimited approval",
                        details={"spender": "0xbad"},
                    )
                ],
                summary={},
                recommendations=[],
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


# ─── x402 pay-per-call ─────────────────────────────────────


class TestX402:
    """Test the opt-in x402 payment helper."""

    def test_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("VIGIL_X402_ENABLED", raising=False)
        from vigil_mcp.payments import x402

        assert x402.is_enabled() is False

    def test_enabled_flag(self, monkeypatch):
        monkeypatch.setenv("VIGIL_X402_ENABLED", "1")
        from vigil_mcp.payments import x402

        assert x402.is_enabled() is True

    def test_price_for_known_tool(self, monkeypatch):
        monkeypatch.setenv("VIGIL_X402_PRICE_USD", "0.005")
        from vigil_mcp.payments import x402

        # Premium tools are priced
        assert x402.price_for("vigil_scan_token") == 0.005
        # batch scan is priced higher
        assert x402.price_for("vigil_batch_scan") > x402.price_for("vigil_scan_token")
        # Core pre-trade checks are FREE (None = not priced)
        assert x402.price_for("vigil_detect_honeypot") is None
        assert x402.price_for("vigil_safety_score") is None
        # Defensive tools also free
        assert x402.price_for("vigil_check_scam") is None

    def test_payment_requirements_shape(self, monkeypatch):
        monkeypatch.setenv("VIGIL_X402_PAY_TO", "0x" + "1" * 40)
        monkeypatch.delenv("VIGIL_X402_NETWORK", raising=False)
        from vigil_mcp.payments import x402

        req = x402.payment_requirements("vigil_safety_score", 0.001)
        # CDP facilitator requires x402 v2 shapes.
        assert req["x402Version"] == 2
        assert req["error"] == "Payment required"
        assert req["resource"]["url"].endswith("#vigil_safety_score")
        accept = req["accepts"][0]
        # CDP facilitator requires CAIP-2 network identifiers.
        assert accept["network"] == "eip155:8453"
        # $0.001 in USDC 6-decimals == 1000 base units (v2 uses `amount`)
        assert accept["amount"] == "1000"
        assert accept["payTo"] == "0x" + "1" * 40
        assert accept["asset"].lower() == x402.USDC_BASE
        # EIP-712 token metadata the facilitator needs to validate the signature.
        assert accept["extra"] == {"name": "USDC", "version": "2"}

    def test_default_price_above_facilitator_fee(self, monkeypatch):
        """Default price must exceed the CDP facilitator's $0.001/tx post-quota fee."""
        monkeypatch.delenv("VIGIL_X402_PRICE_USD", raising=False)
        from vigil_mcp.payments import x402

        # scan_token is a paid tool — should leave margin.
        assert x402.price_for("vigil_scan_token") > 0.001

    def test_caip2_resolution(self, monkeypatch):
        """Internal chain names map to CAIP-2 IDs the facilitator expects."""
        from vigil_mcp.payments import x402

        for plain, caip2 in [
            ("base", "eip155:8453"),
            ("polygon", "eip155:137"),
            ("arbitrum", "eip155:42161"),
        ]:
            monkeypatch.setenv("VIGIL_X402_NETWORK", plain)
            req = x402.payment_requirements("vigil_safety_score", 0.005)
            assert req["accepts"][0]["network"] == caip2

    @pytest.mark.asyncio
    async def test_verify_fails_closed_with_empty_payload(self, monkeypatch):
        """An empty payment header must fail verification (fail closed)."""
        monkeypatch.delenv("VIGIL_X402_FACILITATOR", raising=False)
        monkeypatch.delenv("CDP_API_KEY_ID", raising=False)
        monkeypatch.delenv("CDP_API_KEY_SECRET", raising=False)
        from vigil_mcp.payments import x402

        ok = await x402.verify_payment("", "vigil_safety_score", 0.001)
        assert ok is False

    @pytest.mark.asyncio
    async def test_settle_returns_none_with_empty_payload(self):
        """Settling an empty/missing payment header must return None."""
        from vigil_mcp.payments import x402

        result = await x402.settle_payment("", "vigil_safety_score", 0.001)
        assert result is None

    def test_facilitator_defaults_to_cdp(self, monkeypatch):
        """Without an override, the facilitator is CDP (required for Builder Code)."""
        monkeypatch.delenv("VIGIL_X402_FACILITATOR", raising=False)
        from vigil_mcp.payments import x402

        assert x402._facilitator_url() == x402.CDP_FACILITATOR_URL

    def test_facilitator_explicit_override_wins(self, monkeypatch):
        monkeypatch.setenv("VIGIL_X402_FACILITATOR", "https://my.facilitator.example")
        monkeypatch.setenv("CDP_API_KEY_ID", "kid")
        monkeypatch.setenv("CDP_API_KEY_SECRET", "sec")
        from vigil_mcp.payments import x402

        assert x402._facilitator_url() == "https://my.facilitator.example"

    def test_decode_payment_header_base64_json(self):
        """X-PAYMENT is base64-encoded JSON; decode round-trips."""
        import base64
        import json

        from vigil_mcp.payments import x402

        payload = {"x402Version": 1, "scheme": "exact", "payload": {"signature": "0xabc"}}
        header = base64.b64encode(json.dumps(payload).encode()).decode()
        assert x402.decode_payment_header(header) == payload

    def test_decode_payment_header_raw_json_fallback(self):
        """Some clients send raw JSON instead of base64 — accept that too."""
        import json

        from vigil_mcp.payments import x402

        payload = {"x402Version": 1}
        assert x402.decode_payment_header(json.dumps(payload)) == payload

    def test_decode_payment_header_empty_and_garbage(self):
        from vigil_mcp.payments import x402

        assert x402.decode_payment_header("") is None
        assert x402.decode_payment_header("!!!not-base64-not-json!!!") is None

    def test_builder_code_extension_present_when_set(self, monkeypatch):
        monkeypatch.setenv("VIGIL_X402_APP_CODE", "bc_kz42eeiy")
        from vigil_mcp.payments import x402

        req = x402.payment_requirements("vigil_scan_token", 0.005)
        assert "extensions" in req
        ext = req["extensions"][x402.BUILDER_CODE_EXT]
        assert ext["info"]["a"] == "bc_kz42eeiy"
        # Schema must be present so the facilitator can validate the echo.
        assert ext["schema"]["properties"]["a"]["pattern"] == x402.BUILDER_CODE_PATTERN

    def test_builder_code_extension_absent_when_unset(self, monkeypatch):
        monkeypatch.delenv("VIGIL_X402_APP_CODE", raising=False)
        from vigil_mcp.payments import x402

        req = x402.payment_requirements("vigil_scan_token", 0.005)
        assert "extensions" not in req

    def test_cdp_bearer_jwt_none_without_keys(self, monkeypatch):
        monkeypatch.delenv("CDP_API_KEY_ID", raising=False)
        monkeypatch.delenv("CDP_API_KEY_SECRET", raising=False)
        from vigil_mcp.payments import x402

        assert x402._cdp_bearer_jwt("POST", "/platform/v2/x402/verify") is None

    def test_cdp_bearer_jwt_ed25519(self, monkeypatch):
        """A synthetic Ed25519 key produces a verifiable EdDSA JWT with uris claim."""
        import base64

        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric import ed25519

        # Build a base64 64-byte CDP-style secret (seed || pubkey).
        priv = ed25519.Ed25519PrivateKey.generate()
        from cryptography.hazmat.primitives import serialization

        seed = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        secret_b64 = base64.b64encode(seed + pub).decode()

        monkeypatch.setenv("CDP_API_KEY_ID", "test-kid")
        monkeypatch.setenv("CDP_API_KEY_SECRET", secret_b64)
        from vigil_mcp.payments import x402

        token = x402._cdp_bearer_jwt("POST", "/platform/v2/x402/verify")
        assert token is not None
        # Decode with the matching public key to confirm signature + claims.
        decoded = pyjwt.decode(
            token,
            priv.public_key(),
            algorithms=["EdDSA"],
            options={"verify_aud": False},
        )
        assert decoded["iss"] == "cdp"
        assert decoded["uris"] == ["POST api.cdp.coinbase.com/platform/v2/x402/verify"]

    @pytest.mark.asyncio
    async def test_verify_true_on_facilitator_valid(self, monkeypatch):
        """verify_payment returns True when the facilitator reports isValid."""
        import base64
        import json

        from vigil_mcp.payments import x402

        async def fake_post(endpoint, body):
            assert endpoint == "/verify"
            assert body["paymentRequirements"]["scheme"] == "exact"
            return {"isValid": True, "payer": "0xabc"}

        monkeypatch.setattr(x402, "_post", fake_post)
        header = base64.b64encode(json.dumps({"x402Version": 1}).encode()).decode()
        assert await x402.verify_payment(header, "vigil_scan_token", 0.005) is True

    @pytest.mark.asyncio
    async def test_settle_success_returns_tx(self, monkeypatch):
        import base64
        import json

        from vigil_mcp.payments import x402

        async def fake_post(endpoint, body):
            assert endpoint == "/settle"
            return {"success": True, "transaction": "0xdead", "network": "base", "payer": "0xabc"}

        monkeypatch.setattr(x402, "_post", fake_post)
        header = base64.b64encode(json.dumps({"x402Version": 1}).encode()).decode()
        result = await x402.settle_payment(header, "vigil_scan_token", 0.005)
        assert result["transaction"] == "0xdead"

        # Settlement response header round-trips the tx hash.
        hdr = x402.settlement_response_header(result)
        decoded = json.loads(base64.b64decode(hdr))
        assert decoded["transaction"] == "0xdead"
        assert decoded["success"] is True

    @pytest.mark.asyncio
    async def test_settle_failure_returns_none(self, monkeypatch):
        import base64
        import json

        from vigil_mcp.payments import x402

        async def fake_post(endpoint, body):
            return {"success": False, "errorReason": "insufficient_funds", "errorMessage": "nope"}

        monkeypatch.setattr(x402, "_post", fake_post)
        header = base64.b64encode(json.dumps({"x402Version": 1}).encode()).decode()
        assert await x402.settle_payment(header, "vigil_scan_token", 0.005) is None


# ─── Approvals enrichment (token_symbol, spender_name) ─────


class TestApprovalEnrichment:
    """token_symbol/spender_name should come from the registry + GoPlus."""

    @pytest.fixture(autouse=True)
    def _bound_lookback(self, monkeypatch):
        monkeypatch.setenv("VIGIL_APPROVAL_LOOKBACK_BLOCKS", "100")
        monkeypatch.setenv("VIGIL_APPROVAL_LOG_CHUNK", "100")

    @pytest.mark.asyncio
    async def test_blue_chip_token_uses_registry_symbol(self, httpx_mock, monkeypatch):
        """USDC on Base should be labelled 'USDC' / 'USD Coin', not '0xabc...'."""
        from vigil_mcp.scanners.goplus import GoPlusResult, GoPlusScanner

        async def _unavailable(self, token, chain):
            return GoPlusResult(available=False, note="stubbed")

        monkeypatch.setattr(GoPlusScanner, "token_security", _unavailable)

        scanner = ApprovalScanner()
        usdc = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
        # head + getLogs
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": "0x100"})
        log = {
            "address": usdc,
            "topics": [
                "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
                "0x" + WALLET[2:].lower().zfill(64),
                "0x" + list(SAFE_SPENDERS)[0][2:].lower().zfill(64),
            ],
            "data": "0x" + hex(10**18)[2:].zfill(64),
        }
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": [log]})

        result = await scanner._scan_via_rpc(WALLET, "base", None)
        assert result.total == 1
        a = result.approvals[0]
        # Registry resolves the token.
        assert a.token_symbol == "USDC"
        assert a.token_name == "USD Coin"
        # Spender label from SAFE_SPENDER_NAMES (the first SAFE_SPENDERS entry).
        assert a.spender_name is not None
        assert "Uniswap" in a.spender_name or "1inch" in a.spender_name or "0x" in a.spender_name

    @pytest.mark.asyncio
    async def test_unknown_token_uses_goplus_symbol(self, httpx_mock, monkeypatch):
        """A non-blue-chip token gets its symbol from GoPlus."""
        from vigil_mcp.scanners.goplus import GoPlusResult, GoPlusScanner

        async def _gp(self, token, chain):
            return GoPlusResult(
                available=True,
                token_name="DemoToken",
                token_symbol="DEMO",
            )

        monkeypatch.setattr(GoPlusScanner, "token_security", _gp)

        scanner = ApprovalScanner()
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": "0x100"})
        log = {
            "address": TOKEN,
            "topics": [
                "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
                "0x" + WALLET[2:].lower().zfill(64),
                "0x" + SPENDER[2:].lower().zfill(64),
            ],
            "data": "0x" + hex(10**18)[2:].zfill(64),
        }
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": [log]})

        result = await scanner._scan_via_rpc(WALLET, "base", None)
        assert result.total == 1
        assert result.approvals[0].token_symbol == "DEMO"
        assert result.approvals[0].token_name == "DemoToken"


# ─── LiquidityLockScanner ──────────────────────────────────


class TestLiquidityLockClassify:
    """Pure-function classification rules (no I/O, no fixtures)."""

    def _scanner(self):
        from vigil_mcp.scanners.liquidity_lock import LiquidityLockScanner

        return LiquidityLockScanner()

    def test_decode_uint256_full_word(self):
        s = self._scanner()
        # 1 in 32-byte uint256
        assert s._decode_uint256("0x" + "0" * 63 + "1") == 1
        # large value
        assert s._decode_uint256("0x" + "f" * 64) == (1 << 256) - 1

    def test_decode_uint256_short_or_empty(self):
        s = self._scanner()
        assert s._decode_uint256("0x") is None
        assert s._decode_uint256("0x123") is None
        assert s._decode_uint256(None) is None
        # extra trailing bytes are tolerated — we read only the first word
        assert s._decode_uint256("0x" + "0" * 63 + "5" + "ab" * 8) == 5


class TestLiquidityLockScanner:
    """Integration tests with mocked HTTP responses."""

    LP = "0x" + "b" * 40
    LOCKER = "0xc4e637d37113192f4f1f060daebd7758de7f4131"  # UNCX V2 on Base
    BURN = "0x000000000000000000000000000000000000dead"

    def _word(self, value: int) -> str:
        return "0x" + format(value, "064x")

    @pytest.fixture
    def scanner(self):
        from vigil_mcp.scanners.liquidity_lock import LiquidityLockScanner

        return LiquidityLockScanner()

    @staticmethod
    def _mock_dexscreener(httpx_mock, pair_address):
        # MarketScanner calls DexScreener first; mock the deepest pair on Base.
        httpx_mock.add_response(
            url=lambda u: "dexscreener" in str(u),  # match any dexscreener URL
            json={
                "pairs": [
                    {
                        "chainId": "base",
                        "pairAddress": pair_address,
                        "baseToken": {"address": TOKEN},
                        "liquidity": {"usd": 100_000},
                    }
                ]
            },
        )

    @pytest.mark.asyncio
    async def test_unsupported_chain(self, scanner):
        result = await scanner.scan(TOKEN, "solana")
        assert result.available is False
        assert result.determined is False
        assert result.lock_status == "unknown"
        assert "not supported" in result.notes[0].lower()

    @pytest.mark.asyncio
    async def test_no_pair_found(self, scanner, httpx_mock):
        # DexScreener returns empty.
        httpx_mock.add_response(json={"pairs": []})
        result = await scanner.scan(TOKEN, "base")
        assert result.lock_status == "unknown"
        assert result.determined is False
        assert "no DEX pair" in result.notes[0].lower() or "no dex pair" in result.notes[0].lower()

    @pytest.mark.asyncio
    async def test_locked_via_uncx(self, scanner, httpx_mock):
        # 1) DexScreener returns a pair (LP token == pair address).
        httpx_mock.add_response(
            json={
                "pairs": [
                    {
                        "chainId": "base",
                        "pairAddress": self.LP,
                        "baseToken": {"address": TOKEN},
                        "liquidity": {"usd": 100_000},
                    }
                ]
            }
        )
        # 2) totalSupply = 1000
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": self._word(1000)})
        # 3) balanceOf(burn 0x0...0) = 0
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": self._word(0)})
        # 4) balanceOf(burn 0x...dEaD) = 0
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": self._word(0)})
        # 5) balanceOf(UNCX V2) = 850 ⇒ 85% locked
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": self._word(850)})

        result = await scanner.scan(TOKEN, "base")
        assert result.lock_status == "locked"
        assert result.determined is True
        assert result.locked_fraction == 0.85
        assert result.locker_name == "UNCX Network Locker V2"

    @pytest.mark.asyncio
    async def test_burned(self, scanner, httpx_mock):
        httpx_mock.add_response(
            json={
                "pairs": [
                    {
                        "chainId": "base",
                        "pairAddress": self.LP,
                        "baseToken": {"address": TOKEN},
                        "liquidity": {"usd": 100_000},
                    }
                ]
            }
        )
        # totalSupply = 1000
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": self._word(1000)})
        # burn 0x0...0 = 0
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": self._word(0)})
        # burn 0x...dEaD = 950 ⇒ 95% burned
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": self._word(950)})
        # UNCX = 0
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": self._word(0)})

        result = await scanner.scan(TOKEN, "base")
        assert result.lock_status == "burned"
        assert result.determined is True
        assert result.locked_fraction == 0.95

    @pytest.mark.asyncio
    async def test_unlocked(self, scanner, httpx_mock):
        httpx_mock.add_response(
            json={
                "pairs": [
                    {
                        "chainId": "base",
                        "pairAddress": self.LP,
                        "baseToken": {"address": TOKEN},
                        "liquidity": {"usd": 100_000},
                    }
                ]
            }
        )
        # totalSupply = 1000, all balances 0 ⇒ 0% locked = unlocked
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": self._word(1000)})
        for _ in range(3):  # 2 burn addrs + 1 locker
            httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": self._word(0)})

        result = await scanner.scan(TOKEN, "base")
        assert result.lock_status == "unlocked"
        assert result.determined is True
        assert result.locked_fraction == 0.0
        assert "WITHDRAWABLE" in result.notes[0]

    @pytest.mark.asyncio
    async def test_total_supply_zero_returns_unknown(self, scanner, httpx_mock):
        httpx_mock.add_response(
            json={
                "pairs": [
                    {
                        "chainId": "base",
                        "pairAddress": self.LP,
                        "baseToken": {"address": TOKEN},
                        "liquidity": {"usd": 100_000},
                    }
                ]
            }
        )
        # totalSupply = 0
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": self._word(0)})

        result = await scanner.scan(TOKEN, "base")
        assert result.lock_status == "unknown"
        assert result.determined is False

    @pytest.mark.asyncio
    async def test_total_supply_short_data_returns_unknown(self, scanner, httpx_mock):
        """V3 / NFT-LP positions have no totalSupply — must return unknown, not unlocked."""
        httpx_mock.add_response(
            json={
                "pairs": [
                    {
                        "chainId": "base",
                        "pairAddress": self.LP,
                        "baseToken": {"address": TOKEN},
                        "liquidity": {"usd": 100_000},
                    }
                ]
            }
        )
        # eth_call totalSupply returns "0x" — function does not exist
        httpx_mock.add_response(json={"jsonrpc": "2.0", "id": 1, "result": "0x"})

        result = await scanner.scan(TOKEN, "base")
        assert result.lock_status == "unknown"
        assert result.determined is False
        assert "V3" in result.notes[0] or "NFT" in result.notes[0]


# ─── FeedStore stats methods ──────────────────────────────


class TestFeedStoreStats:
    """Tests for the new FeedStore methods used by /stats."""

    def _store(self, tmp_path):
        from vigil_mcp.feed import FeedStore

        return FeedStore(db_path=str(tmp_path / "feed.db"))

    def test_tools_by_volume_orders_by_count_desc(self, tmp_path):
        store = self._store(tmp_path)
        for _ in range(3):
            store.record(TOKEN, "base", "vigil_safety_score", "safe", 90)
        for _ in range(2):
            store.record(TOKEN, "base", "vigil_consensus", "safe", None)
        store.record(TOKEN, "base", "vigil_check_scam", "clean", None)

        ranked = store.tools_by_volume(limit=5)
        assert ranked[0] == {"tool": "vigil_safety_score", "count": 3}
        assert ranked[1] == {"tool": "vigil_consensus", "count": 2}
        assert ranked[2] == {"tool": "vigil_check_scam", "count": 1}

    def test_tools_by_volume_empty_returns_empty_list(self, tmp_path):
        assert self._store(tmp_path).tools_by_volume(5) == []

    def test_recent_flagged_only_returns_high_critical_honeypot(self, tmp_path):
        store = self._store(tmp_path)
        store.record(TOKEN, "base", "vigil_safety_score", "safe", 90)
        store.record(TOKEN, "base", "vigil_safety_score", "low", 60)
        store.record(TOKEN, "base", "vigil_safety_score", "high", 30)
        store.record(TOKEN, "base", "vigil_detect_honeypot", "honeypot", None)
        store.record(TOKEN, "base", "vigil_consensus", "critical", None)

        flagged = store.recent_flagged(limit=10)
        verdicts = [r["verdict"] for r in flagged]
        # newest first; only the three flagged ones should appear
        assert verdicts == ["critical", "honeypot", "high"]

    def test_recent_flagged_empty_returns_empty_list(self, tmp_path):
        store = self._store(tmp_path)
        store.record(TOKEN, "base", "vigil_safety_score", "safe", 90)
        assert store.recent_flagged(limit=5) == []


# ─── CloneDetector ─────────────────────────────────────────


class TestCloneFingerprint:
    """Pure-function fingerprint + classify logic (no I/O)."""

    def _det(self, tmp_path):
        from vigil_mcp.scanners.clone_detector import CloneDetector, CloneFingerprintStore

        store = CloneFingerprintStore(db_path=str(tmp_path / "clone.db"))
        return CloneDetector(store=store)

    def test_normalize_rejects_tiny_code(self, tmp_path):
        det = self._det(tmp_path)
        # under _MIN_CODE_BYTES (200) -> None
        assert det._normalize_bytecode("0x" + "60" * 50) is None
        assert det._normalize_bytecode("0x") is None
        assert det._normalize_bytecode(None) is None

    def test_normalize_accepts_real_code(self, tmp_path):
        det = self._det(tmp_path)
        code = "0x" + "60" * 300  # 300 bytes
        norm = det._normalize_bytecode(code)
        assert norm is not None and len(norm) > 0

    def test_fingerprint_stable_and_distinct(self, tmp_path):
        det = self._det(tmp_path)
        a = det._normalize_bytecode("0x" + "ab" * 300)
        b = det._normalize_bytecode("0x" + "ab" * 300)
        c = det._normalize_bytecode("0x" + "cd" * 300)
        assert det._fingerprint(a) == det._fingerprint(b)  # stable
        assert det._fingerprint(a) != det._fingerprint(c)  # distinct

    def test_assess_clone_with_scam_sibling_is_dangerous(self, tmp_path):
        det = self._det(tmp_path)
        risk, notes = det._assess(clone_count=2, scam_siblings=["0xabc"])
        assert risk == "dangerous"

    def test_assess_large_cluster_is_suspicious(self, tmp_path):
        det = self._det(tmp_path)
        risk, _ = det._assess(clone_count=5, scam_siblings=[])
        assert risk == "suspicious"

    def test_assess_few_clones_is_safe_note(self, tmp_path):
        det = self._det(tmp_path)
        risk, _ = det._assess(clone_count=1, scam_siblings=[])
        assert risk == "safe"

    def test_assess_no_clones_is_safe(self, tmp_path):
        det = self._det(tmp_path)
        risk, _ = det._assess(clone_count=0, scam_siblings=[])
        assert risk == "safe"


class TestCloneFingerprintStore:
    def test_siblings_accumulate(self, tmp_path):
        from vigil_mcp.scanners.clone_detector import CloneFingerprintStore

        store = CloneFingerprintStore(db_path=str(tmp_path / "clone.db"))
        fp = "deadbeef" * 8
        store.record(fp, "base", "0x" + "1" * 40)
        store.record(fp, "base", "0x" + "2" * 40)
        store.record(fp, "base", "0x" + "3" * 40)
        # siblings of addr1 = addr2, addr3
        sibs = store.siblings(fp, "base", exclude="0x" + "1" * 40)
        assert len(sibs) == 2
        assert ("0x" + "2" * 40) in sibs

    def test_record_idempotent(self, tmp_path):
        from vigil_mcp.scanners.clone_detector import CloneFingerprintStore

        store = CloneFingerprintStore(db_path=str(tmp_path / "clone.db"))
        fp = "cafe" * 16
        addr = "0x" + "a" * 40
        store.record(fp, "base", addr)
        store.record(fp, "base", addr)  # same addr again
        # a different address shares the fp
        store.record(fp, "base", "0x" + "b" * 40)
        sibs = store.siblings(fp, "base", exclude=addr)
        assert sibs == ["0x" + "b" * 40]  # addr not double-counted


# ─── TaxScanner ────────────────────────────────────────────


class TestTaxScanner:
    """Tax-surface assessment logic (pure _assess over GoPlusResult)."""

    def _scanner(self):
        from vigil_mcp.scanners.tax_scanner import TaxScanner

        return TaxScanner()

    def _g(self, **kw):
        from vigil_mcp.scanners.goplus import GoPlusResult

        return GoPlusResult(available=True, **kw)

    def test_modifiable_tax_is_dangerous(self):
        s = self._scanner()
        risk, notes = s._assess(self._g(buy_tax=0.0, sell_tax=0.0, slippage_modifiable=True))
        assert risk == "dangerous"
        assert any("MODIFIABLE" in n for n in notes)

    def test_personal_modifiable_tax_is_dangerous(self):
        s = self._scanner()
        risk, _ = s._assess(self._g(buy_tax=0.0, sell_tax=0.0, personal_slippage_modifiable=True))
        assert risk == "dangerous"

    def test_severe_tax_is_dangerous(self):
        s = self._scanner()
        risk, _ = s._assess(self._g(buy_tax=0.0, sell_tax=0.6))
        assert risk == "dangerous"

    def test_high_tax_is_high(self):
        s = self._scanner()
        risk, _ = s._assess(self._g(buy_tax=0.12, sell_tax=0.12))
        assert risk == "high"

    def test_small_tax_is_caution(self):
        s = self._scanner()
        risk, _ = s._assess(self._g(buy_tax=0.03, sell_tax=0.03))
        assert risk == "caution"

    def test_zero_tax_is_safe(self):
        s = self._scanner()
        risk, _ = s._assess(self._g(buy_tax=0.0, sell_tax=0.0, transfer_tax=0.0))
        assert risk == "safe"

    def test_cooldown_only_is_caution(self):
        s = self._scanner()
        risk, _ = s._assess(self._g(buy_tax=0.0, sell_tax=0.0, trading_cooldown=True))
        assert risk == "caution"

    @pytest.mark.asyncio
    async def test_scan_unknown_when_goplus_unavailable(self, monkeypatch):
        from vigil_mcp.scanners import tax_scanner as tx
        from vigil_mcp.scanners.goplus import GoPlusResult

        async def fake_ts(self, token, chain):
            return GoPlusResult(available=False, note="no data")

        monkeypatch.setattr(tx.GoPlusScanner, "token_security", fake_ts)
        s = tx.TaxScanner()
        result = await s.scan("0x" + "9" * 40, "base")
        assert result.determined is False
        assert result.risk == "unknown"

    @pytest.mark.asyncio
    async def test_scan_unknown_when_no_tax_fields(self, monkeypatch):
        from vigil_mcp.scanners import tax_scanner as tx
        from vigil_mcp.scanners.goplus import GoPlusResult

        async def fake_ts(self, token, chain):
            # Available, but all tax fields are None.
            return GoPlusResult(available=True, token_symbol="X")

        monkeypatch.setattr(tx.GoPlusScanner, "token_security", fake_ts)
        s = tx.TaxScanner()
        result = await s.scan("0x" + "9" * 40, "base")
        assert result.determined is False
        assert result.risk == "unknown"

    @pytest.mark.asyncio
    async def test_scan_known_bluechip_is_safe(self, monkeypatch):
        from vigil_mcp.scanners import tax_scanner as tx

        # USDC on base is in the known-contracts registry.
        s = tx.TaxScanner()
        result = await s.scan("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "base")
        assert result.determined is True
        assert result.risk == "safe"
        assert result.buy_tax == 0.0
