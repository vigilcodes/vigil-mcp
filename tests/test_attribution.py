"""Tests for onchain attribution reporting (vigil_mcp.payments.attribution)."""

from vigil_mcp.payments import attribution as attr


def _cbor_map(d: dict) -> bytes:
    """Build a minimal CBOR text-key/text-value map for testing the decoder."""
    out = bytearray([0xA0 | len(d)])  # map, n entries (n < 24)
    for k, v in d.items():
        kb = k.encode()
        out += bytes([0x60 | len(kb)]) + kb  # text string key
        vb = v.encode()
        out += bytes([0x60 | len(vb)]) + vb  # text string value
    return bytes(out)


def test_cbor_decode_app_and_wallet():
    b = _cbor_map({"a": "bc_kz42eeiy", "w": "cdp_facil1"})
    codes = attr._cbor_decode_codes(b)
    assert codes == {"a": "bc_kz42eeiy", "w": "cdp_facil1"}


def test_cbor_decode_wallet_only():
    b = _cbor_map({"w": "cdp_facil1"})
    assert attr._cbor_decode_codes(b) == {"w": "cdp_facil1"}


def test_cbor_decode_garbage_is_empty():
    assert attr._cbor_decode_codes(b"") == {}
    assert attr._cbor_decode_codes(b"\xff\x00") == {}


def test_report_no_payto(monkeypatch):
    monkeypatch.delenv("VIGIL_X402_PAY_TO", raising=False)
    r = attr.build_attribution_report()
    assert r["total_count"] == 0
    assert "not configured" in r["note"]


def test_report_explorer_down(monkeypatch):
    monkeypatch.setenv("VIGIL_X402_PAY_TO", "0x" + "1" * 40)
    monkeypatch.setenv("VIGIL_X402_APP_CODE", "bc_kz42eeiy")
    monkeypatch.setattr(attr, "_incoming_usdc", lambda addr: None)
    r = attr.build_attribution_report()
    assert r["total_count"] == 0
    assert "explorer unavailable" in r["note"]


def test_report_counts_attributed(monkeypatch):
    monkeypatch.setenv("VIGIL_X402_PAY_TO", "0x" + "1" * 40)
    monkeypatch.setenv("VIGIL_X402_APP_CODE", "bc_kz42eeiy")

    monkeypatch.setattr(
        attr,
        "_incoming_usdc",
        lambda addr: [
            {"tx": "0xAAA", "value_usdc": 0.005, "timestamp": "t1"},
            {"tx": "0xBBB", "value_usdc": 0.005, "timestamp": "t2"},
        ],
    )

    def fake_decode(tx):
        return {"a": "bc_kz42eeiy", "w": "cdp_facil1"} if tx == "0xAAA" else {"w": "cdp_facil1"}

    monkeypatch.setattr(attr, "_decode_attribution", fake_decode)

    r = attr.build_attribution_report()
    assert r["total_count"] == 2
    assert r["attributed_count"] == 1
    assert r["settlements"][0]["attributed"] is True
    assert r["settlements"][1]["attributed"] is False


def test_report_resilient_to_decode_error(monkeypatch):
    monkeypatch.setenv("VIGIL_X402_PAY_TO", "0x" + "1" * 40)
    monkeypatch.setenv("VIGIL_X402_APP_CODE", "bc_kz42eeiy")
    monkeypatch.setattr(attr, "_incoming_usdc", lambda addr: [{"tx": "0xAAA", "value_usdc": 0.005, "timestamp": "t"}])

    def boom(tx):
        raise RuntimeError("rpc down")

    monkeypatch.setattr(attr, "_decode_attribution", boom)
    # A per-tx decode failure must not sink the whole report.
    r = attr.build_attribution_report()
    assert r["total_count"] == 1
    assert r["attributed_count"] == 0
    assert r["settlements"][0]["builder_codes"] == {}
