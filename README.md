# VIGIL MCP Server

Onchain security scanner for DeFi traders on Base. Protect against rugpulls, honeypots, and dangerous token approvals.

Live MCP endpoint: **https://mcp.vigil.codes**
Site: **https://vigil.codes**

## Network

VIGIL ships Base-first. The scanners (approvals, token, honeypot, safety score) target Base mainnet (`chainid=8453`); a small set of Ethereum stablecoins are kept in the verified registry so multichain wallets get correct labels when they show up.

| Chain    | Approvals | Token Scan | Honeypot | Revoke |
|----------|-----------|------------|----------|--------|
| Base     | Yes       | Yes        | Yes      | Yes    |
| Ethereum | Read-only registry lookup only | — | — | — |

## Features

- **Approval Scanner** — list all ERC-20/ERC-721 approvals, flag unlimited approvals, identify risky spenders
- **Token Scanner** — analyze contracts for rugpull indicators: hidden mint, proxy patterns, tax manipulation, blacklist functions
- **Honeypot Detector** — simulate buy/sell to detect tokens that block selling
- **Safety Score** — 0-100 rating based on bytecode analysis, ownership, registry match, complexity
- **Wallet Report** — full security posture assessment
- **Wallet Monitor** — alerts for new approvals, risky interactions, and balance changes
- **Token Market** — price, liquidity, 24h volume, and pool age via DexScreener (no API key)
- **Deployer Check** — contract verification, name, and deployer reputation via Basescan
- **Batch Scan** — score multiple tokens in one call, ranked by risk
- **Approval Revoker** *(separate, BANKR_API_KEY required)* — revoke dangerous approvals via Bankr transaction signing

## Install

```bash
pip install -e .

# With dev dependencies
pip install -e ".[dev]"
```

## Run

```bash
# Stdio transport (default)
make run

# SSE transport on port 3100
make run-sse
```

## Configuration

Set environment variables:

```bash
export BANKR_API_KEY=bk_your_key_here   # Optional — only for revoke (write) actions
export BASE_RPC=https://mainnet.base.org       # Custom RPC (optional)
```

## MCP Client Config

### Claude Desktop

```json
{
  "mcpServers": {
    "vigil": {
      "command": "python3",
      "args": ["-m", "vigil_mcp.server"],
      "cwd": "/path/to/vigil/src",
      "env": {
        "BANKR_API_KEY": "bk_YOUR_KEY_HERE"
      }
    }
  }
}
```

### Cursor

Same format — see `config/cursor.json`.

## CLI Scripts

```bash
# Scan approvals
./scripts/vigil-approvals.sh <wallet> [chain]

# Scan token safety
./scripts/vigil-token.sh <token> [chain]

# Detect honeypot
./scripts/vigil-honeypot.sh <token> [chain]

# Get safety score
./scripts/vigil-score.sh <contract> [chain]

# Revoke approval (requires BANKR_API_KEY)
./scripts/vigil-revoke.sh <token> <spender> [chain]

# Full wallet report
./scripts/vigil-report.sh <wallet> [chain]

# Batch revoke
./scripts/vigil-batch-revoke.sh <wallet> [chain] [--risk-level critical|high|all]

# Report scam
./scripts/vigil-report-scam.sh <token> <type> <description> [chain]
```

## Development

```bash
make test    # Run tests
make lint    # Check code style
make format  # Auto-format code
```

## License

MIT
