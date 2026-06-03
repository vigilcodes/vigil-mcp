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
# Key: (chain, address_lower)
KNOWN_GOOD: dict[tuple[str, str], KnownContract] = {
    # Base
    ("base", "0x833588f63916024ffc580c12724940f2b8d47b5b"): KnownContract(
        "USD Coin", "USDC", 92, "safe", "Circle USDC on Base — fully backed stablecoin"
    ),
    ("base", "0x4200000000000000000000000000000000000006"): KnownContract(
        "Wrapped Ether", "WETH", 90, "safe", "Canonical WETH on Base"
    ),
    ("base", "0x50c5725949a6f0c72e6c4a641f24049a917db0cb"): KnownContract(
        "Dai Stablecoin", "DAI", 90, "safe", "MakerDAO DAI on Base"
    ),
    ("base", "0x211Cc4DD073734dA055fbF44a2B4667d5E5fE5d2"): KnownContract(
        "Wrapped stETH", "wstETH", 88, "safe", "Lido wrapped stETH on Base"
    ),
    ("base", "0x940181a94a35a4569e4529a3cdfb74e38fd98631"): KnownContract(
        "AERO", "AERO", 82, "safe", "Aerodrome Finance governance token"
    ),
    # Ethereum
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
    # Uniswap on Base
    ("base", "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"): KnownContract(
        "Uniswap Universal Router", "UNI-UR", 80, "safe", "Uniswap Universal Router"
    ),
    ("base", "0x2626664c2603336e57b271c5c0b26f421741e481"): KnownContract(
        "Uniswap V3 Router", "UNI-V3", 80, "safe", "Uniswap V3 Router on Base"
    ),
}


def lookup_known_contract(chain: str, address: str) -> Optional[KnownContract]:
    """Look up a contract in the known-good registry."""
    key = (chain.lower(), address.lower())
    return KNOWN_GOOD.get(key)
