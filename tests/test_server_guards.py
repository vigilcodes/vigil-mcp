"""Tests for server-side guards added for accuracy + agent reliability.

Covers:
- address validation that rejects malformed input instead of returning a
  fabricated verdict (false-signal guard)
- the /health tool count matching the advertised /tools/list (no double-count
  from prefixed + alias keys)
"""

import pytest

from vigil_mcp import server


class TestAddressValidation:
    def test_valid_address_passes_and_lowercases(self):
        addr = "0x833589FCD6EDB6E08F4C7C32D4F71B54BDA02913"
        assert server._validate_address(addr, "contract") == addr.lower()

    @pytest.mark.parametrize(
        "bad",
        [
            "0xNOTANADDRESS",
            "0x1234",  # too short
            "0x" + "g" * 40,  # non-hex
            "833589fcd6edb6e08f4c7c32d4f71b54bda02913",  # missing 0x
            "0x'; rm -rf /",  # injection attempt
            "",
        ],
    )
    def test_invalid_addresses_raise(self, bad):
        with pytest.raises(server.InvalidAddressError):
            server._validate_address(bad, "contract")

    def test_validate_tool_arguments_checks_single_keys(self):
        with pytest.raises(server.InvalidAddressError):
            server._validate_tool_arguments({"contract": "0xbad", "chain": "base"})

    def test_validate_tool_arguments_accepts_good(self):
        # Should not raise
        server._validate_tool_arguments({"wallet": "0x" + "a" * 40, "chain": "base"})

    def test_batch_tokens_validated(self):
        good = "0x" + "a" * 40
        with pytest.raises(server.InvalidAddressError):
            server._validate_tool_arguments({"tokens": [good, "0xbad"]})

    def test_batch_empty_tokens_rejected(self):
        with pytest.raises(server.InvalidAddressError):
            server._validate_tool_arguments({"tokens": []})

    def test_missing_address_keys_is_noop(self):
        # sentinel_status takes no address args — must not raise
        server._validate_tool_arguments({})


class TestHealthToolCount:
    def test_health_counts_only_prefixed_tools(self):
        # /health counts canonical vigil_* tools; TOOL_MAP also holds unprefixed
        # aliases, so the prefixed count must match /tools/list, not len(TOOL_MAP).
        prefixed = [k for k in server.TOOL_MAP if k.startswith("vigil_")]
        assert len(prefixed) == 13
        # Aliases exist too, so the raw map is larger.
        assert len(server.TOOL_MAP) > len(prefixed)


class TestEndpointRoutingDefault:
    """Setting BANKR_API_KEY alone must not route to the dead hosted API."""

    def test_scanners_default_empty_api_base(self, monkeypatch):
        monkeypatch.delenv("VIGIL_API", raising=False)
        from vigil_mcp.scanners.approvals import ApprovalScanner
        from vigil_mcp.scanners.honeypot import HoneypotDetector
        from vigil_mcp.scanners.safety_score import SafetyScorer
        from vigil_mcp.scanners.token_scanner import TokenScanner

        assert SafetyScorer().api_base == ""
        assert HoneypotDetector().api_base == ""
        assert ApprovalScanner().api_base == ""
        assert TokenScanner().api_base == ""
