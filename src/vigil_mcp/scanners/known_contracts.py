"""Known-good contract registry — whitelists for blue-chip tokens and protocols."""

from typing import Optional


class KnownContract:
    name: str
    symbol: str
    safety_score: int
    risk_level: str
    notes: str

    def __init__(self, name: str, symbol: str, safety_score: int, risk_level: str, notes: str):
        self.name = name
        self.symbol = symbol
        self.safety_score = safety_score
        self.risk_level = risk_level
        self.notes = notes


# Verified blue-chip contracts across chains
# Key: (chain, address_lower) — IMPORTANT: addresses MUST be lowercase
KNOWN_GOOD: dict[tuple[str, str], KnownContract] = {
    # ─────────── Base ───────────
    # Stablecoins
    ("base", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"): KnownContract(
        "USD Coin", "USDC", 92, "safe", "Circle USDC on Base — fully backed stablecoin"
    ),
    ("base", "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca"): KnownContract(
        "USD Base Coin", "USDbC", 88, "safe", "Bridged USDC on Base"
    ),
    ("base", "0x50c5725949a6f0c72e6c4a641f24049a917db0cb"): KnownContract(
        "Dai Stablecoin", "DAI", 90, "safe", "MakerDAO DAI on Base"
    ),
    # WETH / wstETH / cbETH
    ("base", "0x4200000000000000000000000000000000000006"): KnownContract(
        "Wrapped Ether", "WETH", 90, "safe", "Canonical WETH on Base"
    ),
    ("base", "0x211cc4dd073734da055fbf44a2b4667d5e5fe5d2"): KnownContract(
        "Wrapped stETH", "wstETH", 88, "safe", "Lido wrapped stETH on Base"
    ),
    ("base", "0x2ae3f1ec7f1f5012cfeab0185bfc7aa3cf0dec22"): KnownContract(
        "Coinbase Wrapped Staked ETH", "cbETH", 88, "safe", "Coinbase staked ETH wrapper"
    ),
    # Aerodrome
    ("base", "0x940181a94a35a4569e4529a3cdfb74e38fd98631"): KnownContract(
        "Aerodrome", "AERO", 78, "safe", "Aerodrome Finance governance token — emissions via mint are by design"
    ),
    ("base", "0xcf77a3ba9a5ca399b7c97c74d54e5b1beb874e43"): KnownContract(
        "Aerodrome Router", "AERO-R", 82, "safe", "Aerodrome v1 Router"
    ),
    # Uniswap on Base
    ("base", "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad"): KnownContract(
        "Uniswap Universal Router", "UNI-UR", 85, "safe", "Uniswap Universal Router on Base"
    ),
    ("base", "0x2626664c2603336e57b271c5c0b26f421741e481"): KnownContract(
        "Uniswap V3 Router", "UNI-V3", 85, "safe", "Uniswap V3 SwapRouter on Base"
    ),
    ("base", "0x6ff5693b99212da76ad316178a184ab56d299b43"): KnownContract(
        "Uniswap Universal Router v2", "UNI-UR2", 85, "safe", "Uniswap Universal Router v1.2 on Base"
    ),
    # ─────────── Ethereum (kept for reference / multichain wallets) ───────────
    ("ethereum", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"): KnownContract(
        "USD Coin", "USDC", 92, "safe", "Circle USDC on Ethereum"
    ),
    ("ethereum", "0xdac17f958d2ee523a2206206994597c13d831ec7"): KnownContract(
        "Tether USD", "USDT", 85, "safe", "Tether USDT — centralized stablecoin with freeze capability"
    ),
    ("ethereum", "0x6b175474e89094c44da98b954eedeac495271d0f"): KnownContract(
        "Dai Stablecoin", "DAI", 90, "safe", "MakerDAO DAI"
    ),
    ("ethereum", "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"): KnownContract(
        "Wrapped Ether", "WETH", 92, "safe", "Canonical WETH"
    ),
    ("ethereum", "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"): KnownContract(
        "Wrapped BTC", "WBTC", 85, "safe", "BitGo custodied WBTC"
    ),
}


def lookup_known_contract(chain: str, address: str) -> Optional[KnownContract]:
    """Look up a contract in the known-good registry."""
    key = (chain.lower(), address.lower())
    return KNOWN_GOOD.get(key)
