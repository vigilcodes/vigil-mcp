"""Tests for the holder concentration / whale-risk scanner."""

import pytest

from vigil_mcp.scanners.holder_concentration import HolderConcentrationScanner

TOKEN = "0x1111111111111111111111111111111111111111"


def _h(addr, pct, tag="", is_contract=0, is_locked=0):
    return {"address": addr, "percent": str(pct), "tag": tag, "is_contract": is_contract, "is_locked": is_locked}


def _scanner():
    return HolderConcentrationScanner()


def test_single_whale_over_50_is_dangerous():
    s = _scanner()
    holders = [_h("0x" + "a" * 40, 0.60), _h("0x" + "b" * 40, 0.05)]
    dumpable, excluded = s._dumpable_holders(holders, TOKEN)
    risk, _ = s._assess(dumpable, excluded, 1000)
    assert risk == "dangerous"


def test_top5_over_75_is_dangerous():
    s = _scanner()
    holders = [_h("0x" + f"{i + 1:040x}", 0.16) for i in range(5)] + [_h("0x" + "f" * 40, 0.02)]
    dumpable, excluded = s._dumpable_holders(holders, TOKEN)
    risk, _ = s._assess(dumpable, excluded, 1000)
    assert risk == "dangerous"  # top5 = 0.80


def test_largest_25_to_50_is_high():
    s = _scanner()
    holders = [_h("0x" + "a" * 40, 0.30), _h("0x" + "b" * 40, 0.05)]
    dumpable, excluded = s._dumpable_holders(holders, TOKEN)
    risk, _ = s._assess(dumpable, excluded, 1000)
    assert risk == "high"


def test_moderate_is_caution():
    s = _scanner()
    holders = [_h("0x" + "a" * 40, 0.15), _h("0x" + "b" * 40, 0.05)]
    dumpable, excluded = s._dumpable_holders(holders, TOKEN)
    risk, _ = s._assess(dumpable, excluded, 1000)
    assert risk == "caution"


def test_distributed_is_safe():
    s = _scanner()
    holders = [_h("0x" + f"{i + 1:040x}", 0.03) for i in range(10)]
    dumpable, excluded = s._dumpable_holders(holders, TOKEN)
    risk, _ = s._assess(dumpable, excluded, 50000)
    assert risk == "safe"


def test_pool_and_burn_excluded_from_concentration():
    s = _scanner()
    holders = [
        _h("0x" + "c" * 40, 0.90, tag="Uniswap V2 pool"),  # liquidity, excluded
        _h("0x000000000000000000000000000000000000dead", 0.05),  # burn, excluded
        _h("0x" + "a" * 40, 0.04),  # the only dumpable wallet
    ]
    dumpable, excluded = s._dumpable_holders(holders, TOKEN)
    assert len(dumpable) == 1
    assert dumpable[0]["pct"] == 0.04
    assert len(excluded) == 2
    risk, _ = s._assess(dumpable, excluded, 1000)
    assert risk == "safe"  # 90% pool is liquidity, not a dump risk


def test_locked_holder_excluded():
    s = _scanner()
    holders = [_h("0x" + "a" * 40, 0.60, is_locked=1), _h("0x" + "b" * 40, 0.05)]
    dumpable, excluded = s._dumpable_holders(holders, TOKEN)
    assert all(h["pct"] != 0.60 for h in dumpable)
    assert any("locked" in e for e in excluded)


def test_token_contract_itself_excluded():
    s = _scanner()
    holders = [_h(TOKEN, 0.70), _h("0x" + "b" * 40, 0.05)]
    dumpable, _ = s._dumpable_holders(holders, TOKEN)
    assert all(h["address"] != TOKEN for h in dumpable)


@pytest.mark.asyncio
async def test_scan_unknown_when_unavailable(monkeypatch):
    from vigil_mcp.scanners import holder_concentration as hc
    from vigil_mcp.scanners.goplus import GoPlusResult

    async def fake_ts(self, token, chain):
        return GoPlusResult(available=False, note="no data")

    monkeypatch.setattr(hc.GoPlusScanner, "token_security", fake_ts)
    result = await hc.HolderConcentrationScanner().scan("0x" + "9" * 40, "base")
    assert result.determined is False
    assert result.risk == "unknown"


@pytest.mark.asyncio
async def test_scan_unknown_when_no_holders(monkeypatch):
    from vigil_mcp.scanners import holder_concentration as hc
    from vigil_mcp.scanners.goplus import GoPlusResult

    async def fake_ts(self, token, chain):
        return GoPlusResult(available=True, token_symbol="X", holders=[])

    monkeypatch.setattr(hc.GoPlusScanner, "token_security", fake_ts)
    result = await hc.HolderConcentrationScanner().scan("0x" + "9" * 40, "base")
    assert result.determined is False
    assert result.risk == "unknown"


@pytest.mark.asyncio
async def test_scan_known_bluechip_is_safe():
    from vigil_mcp.scanners import holder_concentration as hc

    result = await hc.HolderConcentrationScanner().scan("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "base")
    assert result.determined is True
    assert result.risk == "safe"
