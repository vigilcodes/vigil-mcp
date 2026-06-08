# VIGIL: Onchain Security Meets Autonomous Agents

**How an MCP security scanner on Base is joining the Bankr and Aeon ecosystems to protect DeFi traders — before they sign.**

---

## The Problem

Every day, DeFi users lose funds to rugpulls, honeypots, and forgotten token approvals. The pattern is always the same:

1. You approve a token contract months ago
2. That contract gets exploited (or was malicious from the start)
3. Your balance disappears

Most wallets have **unlimited approvals** to contracts they forgot about. One exploit = your entire balance gone. And most people have no idea how many tokens can drain their wallet right now.

The tools that exist today are reactive — they tell you what happened *after* you lose your money. We wanted something that works *before* you sign.

## Enter VIGIL

VIGIL is an onchain security agent on Base, built as an MCP (Model Context Protocol) server. It provides six security tools that any AI client can use:

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

## Why MCP?

MCP (Model Context Protocol) is the standard for connecting AI agents to external tools. By building VIGIL as an MCP server, we get integration with every compliant client for free:

- **Claude Desktop** — plug and play
- **Cursor** — same config
- **Aeon** — autonomous agent framework
- **Any MCP-compatible agent** — no custom code needed

This means any AI assistant can become a blockchain security expert. No glue code. No custom API. Just standard protocol.

## Joining the Ecosystems

### BankrBot/skills

We submitted a PR to [BankrBot/skills](https://github.com/BankrBot/skills/pull/438) — the marketplace of plug-and-play tools for Bankr agents. Once merged, any Bankr user can install VIGIL with:

```
> install the vigil skill from https://github.com/BankrBot/skills/tree/main/vigil
```

Bankr provides the transaction signing infrastructure that makes the Approval Revoker work. When VIGIL detects a dangerous approval, Bankr handles the secure signing and submission of the revocation transaction. This is the bridge between *detection* and *action*.

### Aeon Framework

We also submitted a PR to [aaronjmars/aeon](https://github.com/aaronjmars/aeon/pull/323) — the most autonomous agent framework. Aeon runs unattended on GitHub Actions, self-heals when skills fail, and monitors its own output quality.

VIGIL as an Aeon skill means:

- **Scheduled security scans** — run every 6 hours on your wallet
- **Autonomous alerting** — get notified when new risky approvals appear
- **Chain with other skills** — combine `token-movers` + `vigil` to automatically check security on trending tokens

```yaml
# aeon.yml
skills:
  vigil:
    enabled: true
    schedule: "0 */6 * * *"
    var: "0xYourWalletAddress"
```

The integration with Aeon was particularly interesting from a design perspective. Aeon runs autonomously — "no approval loops, no babysitting." This meant we had to be careful about what VIGIL exposes as a skill:

- **Read-only scanning** (approvals, token analysis, honeypot detection, safety scoring) — safe for autonomous execution
- **Write actions** (approval revocation) — intentionally excluded from the autonomous skill, requires explicit user confirmation through Bankr

This separation is critical. You want an agent that *detects* problems running 24/7. You don't want an agent that *changes onchain state* without your explicit approval.

## Built for Base

VIGIL is purpose-built for the Base L2 ecosystem. Not multi-chain generic — every tool is optimized for Base's contract patterns, RPC infrastructure, and block explorer APIs.

This focus lets us go deeper than generic multi-chain scanners:

- Native Base RPC integration
- Optimized for Base's gas patterns
- Direct contract calls on Base mainnet
- Real-time scanning with Base's fast block times

## Open Source

VIGIL is fully open source under the MIT license:

- **MCP Server**: [github.com/vigilcodes/vigil-mcp](https://github.com/vigilcodes/vigil-mcp)
- **Website**: [vigil.codes](https://vigil.codes)
- **Live MCP Endpoint**: [mcp.vigil.codes](https://mcp.vigil.codes)

The MCP server runs on SSE transport and is publicly accessible. Any AI client can connect and start scanning immediately.

## What's Next

1. **$VIGIL Token** — governance and utility token on Base (coming soon)
2. **Premium scans** — deep analysis, historical data, deployer tracking
3. **Multi-chain expansion** — Ethereum, Polygon, Arbitrum after Base is solid
4. **Community scam database** — crowdsource threat intelligence
5. **Real-time monitoring** — websocket alerts for new approvals on watched wallets

## Try It Now

```bash
# Install
pip install -e .

# Run MCP server
make run-sse

# Or call the hosted endpoint directly (no install, no API key):
# POST https://mcp.vigil.codes/tools/call
#   {"jsonrpc":"2.0","id":1,"method":"tools/call",
#    "params":{"name":"vigil_safety_score",
#              "arguments":{"contract":"0x...","chain":"base"}}}
# List tools: GET https://mcp.vigil.codes/tools/list
```

## Acknowledgments

Thanks to [@aaronjmars](https://x.com/aaronjmars) for the detailed code review on the Aeon PR — the feedback on capabilities labeling and MCP wiring made the integration much more robust. And to the [@BankrBot](https://x.com/bankrbot) team for building the skills infrastructure that makes agent-tool interoperability possible.

---

*Stay vigilant.* 👁️

**Links:**
- Website: [vigil.codes](https://vigil.codes)
- GitHub: [vigilcodes/vigil-mcp](https://github.com/vigilcodes/vigil-mcp)
- X: [@vigilcodes](https://x.com/vigilcodes)
- Aeon PR: [aaronjmars/aeon#323](https://github.com/aaronjmars/aeon/pull/323)
- Bankr Skills PR: [BankrBot/skills#438](https://github.com/BankrBot/skills/pull/438)
