"""Tests for the VIGIL Telegram bot — address parsing, dispatch, usage stats.

Network (Telegram + scanners) is stubbed; these tests lock in the pure logic:
address extraction, command routing, usage logging, and admin-gated /stats.
"""

import pytest

from vigil_mcp.autonomous.bot import UsageStore, VigilBot

USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"


class TestAddressExtraction:
    def test_extracts_from_scan_command(self):
        assert VigilBot._extract_addr(f"/scan {USDC}") == USDC

    def test_extracts_uppercase_lowercased(self):
        assert VigilBot._extract_addr("/scan " + USDC.upper()) == USDC

    def test_extracts_with_botname_and_extra_text(self):
        assert VigilBot._extract_addr(f"/scan@vigilcodesbot {USDC} please") == USDC

    def test_none_when_no_address(self):
        assert VigilBot._extract_addr("/scan not-an-address") is None

    def test_none_when_too_short(self):
        assert VigilBot._extract_addr("/scan 0x1234") is None


class TestUsageStore:
    def _store(self, tmp_path):
        return UsageStore(db_path=str(tmp_path / "usage.db"))

    def test_log_and_stats_counts(self, tmp_path):
        s = self._store(tmp_path)
        s.log(1, "/scan", USDC, "safe")
        s.log(2, "/scan", USDC, "safe")
        s.log(2, "/honeypot", "0x" + "a" * 40, "")
        stats = s.stats()
        assert stats["total_scans"] == 3       # rows with a target
        assert stats["unique_users"] == 2      # chat ids 1 and 2
        assert stats["top"][0][0] == USDC      # USDC most scanned
        assert stats["top"][0][1] == 2

    def test_help_command_not_counted_as_scan(self, tmp_path):
        s = self._store(tmp_path)
        s.log(1, "/help")  # no target
        stats = s.stats()
        assert stats["total_scans"] == 0
        assert stats["unique_users"] == 1

    def test_empty_store(self, tmp_path):
        s = self._store(tmp_path)
        stats = s.stats()
        assert stats["total_scans"] == 0
        assert stats["unique_users"] == 0
        assert stats["top"] == []


class TestDispatch:
    """Route commands without hitting Telegram or the scanners."""

    @pytest.fixture
    def bot(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VIGIL_TELEGRAM_BOT_TOKEN", "test-token")
        monkeypatch.setenv("VIGIL_TELEGRAM_CHAT_ID", "999")
        b = VigilBot()
        b.usage = UsageStore(db_path=str(tmp_path / "u.db"))
        # capture outgoing messages
        b.sent = []

        async def fake_send(client, chat_id, text):
            b.sent.append((chat_id, text))

        b._send = fake_send
        # stub scan handlers so dispatch is isolated
        calls = {"scan": 0, "honeypot": 0, "score": 0}
        b.calls = calls

        async def fake_scan(client, chat_id, addr):
            calls["scan"] += 1

        async def fake_hp(client, chat_id, addr):
            calls["honeypot"] += 1

        async def fake_score(client, chat_id, addr):
            calls["score"] += 1

        b._cmd_scan = fake_scan
        b._cmd_honeypot = fake_hp
        b._cmd_score = fake_score
        return b

    @pytest.mark.asyncio
    async def test_help_routes_to_help(self, bot):
        await bot._handle(None, {"chat": {"id": 1}, "text": "/start"})
        assert any("VIGIL" in t for _, t in bot.sent)

    @pytest.mark.asyncio
    async def test_scan_routes_and_logs(self, bot):
        await bot._handle(None, {"chat": {"id": 1}, "text": f"/scan {USDC}"})
        assert bot.calls["scan"] == 1
        assert bot.usage.stats()["total_scans"] == 1

    @pytest.mark.asyncio
    async def test_scan_without_address_prompts(self, bot):
        await bot._handle(None, {"chat": {"id": 1}, "text": "/scan foo"})
        assert bot.calls["scan"] == 0
        assert any("token address" in t for _, t in bot.sent)

    @pytest.mark.asyncio
    async def test_stats_admin_only(self, bot):
        # non-admin chat gets a generic reply, not stats
        await bot._handle(None, {"chat": {"id": 1}, "text": "/stats"})
        assert not any("bot stats" in t.lower() for _, t in bot.sent)

    @pytest.mark.asyncio
    async def test_stats_for_admin(self, bot):
        await bot._handle(None, {"chat": {"id": 999}, "text": "/stats"})
        assert any("bot stats" in t.lower() for _, t in bot.sent)
