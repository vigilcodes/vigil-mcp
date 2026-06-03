# VIGIL: Onchain Security Meets Autonomous Agents

**How an MCP security scanner on Base is joining 5 major AI agent platforms to protect DeFi traders — before they sign.**

---

## The Problem

Every day, DeFi users lose funds to rugpulls, honeypots, and forgotten token approvals. The pattern is always the same:

1. You approve a token contract months ago
2. That contract gets exploited (or was malicious from the start)
3. Your balance disappears

Most wallets have **unlimited approvals** to contracts they forgot about. One exploit = your entire balance gone. And most people have no idea how many tokens can drain their wallet right now.

The tools that exist today are reactive — they tell you what happened *after* you lose your money. We wanted something that works *before* you sign.

## Enter VIGIL

VIGIL is an onchain security agent on Base, built as an MCP (Model Context Protocol) server. It provides seven security tools that any AI client can use:

### 1. Approval Scanner
Lists every ERC-20 and ERC-721 approval on your wallet. Flags unlimited (`type(uint256).max`) allowances. Identifies unverified or malicious spender contracts.

### 2. Token Analyzer
Deep contract analysis for rugpull signatures — hidden mint functions, proxy upgrade patterns, adjustable tax rates, and owner-controlled blacklists.

### 3. Honeypot Detector
Simulates full buy-sell cycles on-chain. Detects tokens that block selling, apply extreme sell taxes, or trap liquidity through contract logic.

### 4. Safety Score
A 0–100 composite rating derived from bytecode analysis, ownership status, liquidity depth, holder distribution, and contract verification state.

### 5. Approval Revoker
Revoke dangerous token approvals with signed transactions through Bankr. Supports single and batch revocation by risk level.

### 6. Wallet Report
Full-spectrum security posture assessment. Aggregates all findings into a single report with severity ratings and remediation steps.

### 7. Wallet Monitor (NEW)
Real-time alerts for suspicious wallet activity. Detects new approvals, unlimited allowances, risky contract interactions, and balance changes. Returns alerts with severity levels and actionable recommendations.

## Why MCP?

MCP (Model Context Protocol) is the standard for connecting AI agents to external tools. By building VIGIL as an MCP server, we get integration with every compliant client for free:

- **Claude Desktop** — plug and play
- **Cursor** — same config
- **Aeon** — autonomous agent framework
- **OpenClaw** — personal AI assistant
- **Cline** — VS Code AI agent
- **Any MCP-compatible agent** — no custom code needed

This means any AI assistant can become a blockchain security expert. No glue code. No custom API. Just standard protocol.

## 5 Platform Integrations

We submitted VIGIL to every major AI agent platform:

### 1. Aeon Framework
PR: [aaronjmars/aeon#323](https://github.com/aaronjmars/aeon/pull/323)

Aeon is the most autonomous agent framework — runs unattended, self-heals, monitors its own output. VIGIL as an Aeon skill means:

- **Scheduled security scans** — run every 6 hours on your wallet
- **Autonomous alerting** — get notified when new risky approvals appear
- **Chain with other skills** — combine `token-movers` + `vigil` to automatically check security on trending tokens

The ecosystem listing is already merged ([PR #326](https://github.com/aaronjmars/aeon/pull/326)). Skill integration pending endpoint verification.

### 2. Bankr Skills
PR: [BankrBot/skills#438](https://github.com/BankrBot/skills/pull/438)

Bankr provides the transaction signing infrastructure that makes the Approval Revoker work. When VIGIL detects a dangerous approval, Bankr handles the secure signing and submission of the revocation transaction. This is the bridge between *detection* and *action*.

### 3. Claude Code (Anthropic)
PR: [anthropics/skills#1257](https://github.com/anthropics/skills/pull/1257)

Submitted to Anthropic's official skills repository. Once merged, any Claude Code user can use VIGIL for onchain security scanning.

### 4. OpenClaw
PR: [openclaw/openclaw#89873](https://github.com/openclaw/openclaw/pull/89873)

OpenClaw is the largest AI agent platform with 376k+ stars and 5400+ skills. VIGIL submitted as a new skill for DeFi security.

### 5. Cline MCP Marketplace
Issue: [cline/mcp-marketplace#1717](https://github.com/cline/mcp-marketplace/issues/1717)

Cline has 62k+ stars and 8M+ developers. Submitted to their MCP Marketplace for one-click installation.

## $VIGIL Token

$VIGIL is live on Base — the first token for onchain security.

| Property | Value |
|----------|-------|
| Contract | `0xC751afAdD6fde251Ac624A279ECB9ac85AA27bA3` |
| Chain | Base |
| DEX | Uniswap V4 |
| Creator Fees | 57% |

Trading fees fund autonomous security operations. The token launched on BankrBot with fair launch mechanics.

## Built for Base

VIGIL is purpose-built for the Base L2 ecosystem. Not multi-chain generic — every tool is optimized for Base's contract patterns, RPC infrastructure, and block explorer APIs.

This focus lets us go deeper than generic multi-chain scanners:

- Native Base RPC integration
- Optimized for Base's gas patterns
- Direct contract calls on Base mainnet
- Real-time scanning with Base's fast block times

## Live Endpoint

The MCP server is live and publicly accessible:

```
GET  https://mcp.vigil.codes/health        → {"status":"ok","tools":12}
POST https://mcp.vigil.codes/tools/call     → JSON-RPC 2.0
GET  https://mcp.vigil.codes/tools/list     → Available tools
```

No API key required for read-only tools. Any AI client can connect and start scanning immediately.

## Open Source

VIGIL is fully open source under the MIT license:

- **MCP Server**: [github.com/vigilcodes/vigil-mcp](https://github.com/vigilcodes/vigil-mcp)
- **Website**: [vigil.codes](https://vigil.codes)
- **Live MCP Endpoint**: [mcp.vigil.codes](https://mcp.vigil.codes)

## What's Next

1. **Multi-chain expansion** — Ethereum, Polygon, Arbitrum after Base is solid
2. **Community scam database** — crowdsource threat intelligence
3. **Staking tiers** — Scout, Guardian, Sentinel, Archon (stake-to-unlock)
4. **Governance** — $VIGIL holders vote on protocol parameters
5. **Enterprise API** — premium scans, historical data, deployer tracking

## Try It Now

```bash
# Scan a token
curl -X POST https://mcp.vigil.codes/tools/call \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vigil_scan_token","arguments":{"token":"0x833588f63916024ffc580c12724940f2b8d47b5b","chain":"base"}}}'

# Monitor a wallet
curl -X POST https://mcp.vigil.codes/tools/call \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vigil_monitor_wallet","arguments":{"wallet":"0xYourWallet","chain":"base"}}}'
```

## Acknowledgments

Thanks to [@aaronjmars](https://x.com/aaronjmars) for the detailed code review on the Aeon PR — the feedback on capabilities labeling and MCP wiring made the integration much more robust. And to the [@BankrBot](https://x.com/bankrbot) team for building the skills infrastructure that makes agent-tool interoperability possible.

---

*Stay vigilant.* 👁️

**Links:**
- Website: [vigil.codes](https://vigil.codes)
- GitHub: [vigilcodes/vigil-mcp](https://github.com/vigilcodes/vigil-mcp)
- X: [@vigilcodes](https://x.com/vigilcodes)
- Token: [0xC751afAdD6fde251Ac624A279ECB9ac85AA27bA3](https://basescan.org/token/0xC751afAdD6fde251Ac624A279ECB9ac85AA27bA3)
- Aeon PR: [aaronjmars/aeon#323](https://github.com/aaronjmars/aeon/pull/323)
- Bankr Skills PR: [BankrBot/skills#438](https://github.com/BankrBot/skills/pull/438)
- Claude Code PR: [anthropics/skills#1257](https://github.com/anthropics/skills/pull/1257)
- OpenClaw PR: [openclaw/openclaw#89873](https://github.com/openclaw/openclaw/pull/89873)
- Cline Issue: [cline/mcp-marketplace#1717](https://github.com/cline/mcp-marketplace/issues/1717)
