VIGIL: the onchain security agent that's actually right


What is VIGIL?

VIGIL is an onchain security agent on Base, built as an MCP server. Plug it into any AI client — Claude, Cursor, @aeonframework, or any MCP-compatible agent — and it becomes a blockchain security expert.

It does the checks most people skip before they sign:

Approval Scanner lists every ERC-20/721 approval on your wallet and flags unlimited allowances.

Token Analyzer scans contracts for rugpull signatures: hidden mint, proxy patterns, adjustable tax, and blacklists.

Honeypot Detector simulates buy and sell so you catch tokens that trap you before you ape.

Safety Score rates any contract 0 to 100 from bytecode, ownership, liquidity, and holders.

Approval Revoker kills dangerous approvals through @BankrBot transaction signing.

Wallet Report gives you full security posture in one call.

Wallet Monitor sends real-time alerts for new approvals, risky interactions, and balance changes.

Detection through @BankrBot, autonomous scheduled scans through @aeonframework. Detection plus action, no babysitting.


Why it matters

A security scanner is only useful if it's right. If it calls USDC a honeypot, nobody should trust it. So today's work was about exactly that: making the verdicts correct, and adding real-time monitoring on top.

Wallet Monitor is live. VIGIL's 7th tool watches a Base wallet for new approvals, unlimited allowances, risky contract interactions, and balance changes. Every alert ships with a severity rating and a recommended action.

We killed the false positives. The honeypot detector was wrongly flagging blue-chips like USDC and WETH. Two root causes: a wrong canonical USDC Base address in our registry, and logic that treated a valid zero balance as a broken contract. Both fixed, plus a fast-path that trusts verified blue-chip contracts instead of re-simulating them.

Bytecode analysis got smarter. The old selfdestruct check looked for the byte ff anywhere in the code, which flagged almost every contract. It now does a PUSH-aware opcode walk that skips PUSH1 through PUSH32 immediates, so it only flags a real SELFDESTRUCT opcode. Less noise, real signal.

Verified live on mcp.vigil.codes after restart:

USDC Base scored 92 and safe.
WETH Base scored 90 and safe.
AERO Base scored 78 and safe.
A no-code address scored 0 and critical.
USDC honeypot check returned is_honeypot false.

44 of 44 tests pass. Lint clean.

This round of cleanup came straight out of the @aeonframework PR review. The feedback from @aaronjmars on capabilities labeling and live-call correctness pushed VIGIL to be the kind of scanner an autonomous agent can run unattended, every 6 hours, with no babysitting.

The point of a security agent is to be right. Today VIGIL got more right.


$VIGIL

Ticker: $VIGIL
CA: 0xC751afAdD6fde251Ac624A279ECB9ac85AA27bA3
Chain: Base

7 tools. Base-native. Open source.

Website: vigil.codes
GitHub: github.com/vigilcodes/vigil-mcp

Stay vigilant.
