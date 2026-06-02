# VIGIL MCP Server

Onchain security scanner for DeFi traders. Protect against rugpulls, honeypots, and dangerous token approvals.

## Supported Chains

| Chain | Approvals | Token Scan | Revoke |
|-------|-----------|------------|--------|
| Base | Yes | Yes | Yes |
| Ethereum | Yes | Yes | Yes |
| Polygon | Yes | Yes | Yes |
| Arbitrum | Yes | Yes | Yes |
| Solana | Yes (SPL) | Yes | Yes |

## Features

- **Approval Scanner** — List all ERC-20/ERC-721 approvals, flag unlimited approvals, identify risky spenders
- **Token Scanner** — Analyze contracts for rugpull indicators: hidden mint, proxy patterns, tax manipulation, blacklist functions
- **Honeypot Detector** — Simulate buy/sell to detect tokens that block selling
- **Safety Score** — 0-100 rating based on code analysis, ownership, liquidity, holder distribution
- **Approval Revoker** — Revoke dangerous approvals via Bankr transaction signing
- **Wallet Report** — Full security posture assessment

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
export BANKR_API_KEY=bk_your_key_here   # Required for revocations
export VIGIL_API=https://api.bankr.bot/vigil  # API endpoint
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
