# Shipped This Weekend: VIGIL

*A build log. Everything here is live on Base at mcp.vigil.codes — verify it yourself.*

---

The thesis hasn't changed since day one: **scan before you sign.** Most security tools tell you what happened after you lose money. VIGIL tells you before.

This weekend that thesis grew from 12 tools to 15, got public stats, became discoverable by any x402 agent, and survived a production server migration. Here's the log.

---

## 1. Approval Simulator — the question nobody else answers

Every onchain security tool audits **the past**: approvals you already gave, contracts already deployed. None of them answer the one question that actually matters at signing time:

> *"If I approve this spender right now, what could it do?"*

`vigil_simulate_approval` answers it. Pass a spender + token, and VIGIL profiles the spender **before you sign**:

- Is it a contract or a plain wallet (EOA)? An EOA asking for an approval is a red flag.
- Is it a known-safe router (Uniswap, 1inch, 0x)?
- Does its bytecode contain `transferFrom` — i.e., can it actually move your tokens?
- Is it flagged by GoPlus or the community scam DB?
- Is the amount unlimited?

It returns `safe` / `suspicious` / `dangerous` with reasons and a plain recommendation.

```
Uniswap Router  -> safe       (known router, unlimited is standard)
random 0xdead.. -> dangerous  (EOA + unlimited = DO NOT APPROVE)
```

This is the literal fulfillment of "scan before you sign." Free, no API key.

## 2. Token Clone Detector — same code, new name

Scam operators don't write new code. They deploy the **same contract** dozens of times with different names. `vigil_detect_clone` catches that.

It fingerprints a token's bytecode (normalizing away the Solidity metadata that changes per-compile), then checks whether that exact fingerprint has appeared at other addresses VIGIL has seen — and cross-references those siblings against the community scam database.

The classification is deliberately careful:

- A clone sibling that's a **reported scam** -> `dangerous`
- The same bytecode at **3+ addresses** -> `suspicious` (possible clone farm)
- 1-2 matches (common for tokens from the same factory) -> `safe`, just a note

Because legitimate tokens reuse templates all the time, sharing bytecode is never *proof* of a scam — so a cluster alone never reaches `dangerous`. The fingerprint database grows with every scan, so the detector gets sharper the more it's used.

## 3. Agent discovery — VIGIL on the x402 map

The x402 protocol joined the Linux Foundation this spring, with Coinbase, Visa, Stripe, Cloudflare, and AWS as founding members. It's becoming the standard rail for agents paying for services. So VIGIL got on the map.

Two standard files now live on the server:

- **`/llms.txt`** — a machine-readable catalog: all 15 tools, which are free vs x402-paid (with prices), and how to call them. Generated live from the code, so it never drifts from reality.
- **`/.well-known/x402`** — the x402 service manifest advertising VIGIL's payable resources.

Plus per-tool resource paths (`/x402/<tool>`) that return a clean `402 Payment Required` for paid tools — exactly what directories and the CDP Bazaar probe for.

VIGIL is now **listed live on agent-tools.cloud** (both as an x402 service and an MCP server) and submitted to x402-list.com. An autonomous agent can discover VIGIL, read its catalog, and pay for a scan — no human, no hardcoded integration. That's the same loop @aeonframework has been describing: every skill becomes a product that pays for its own compute.

## 4. Public stats — proof, not hype

`mcp.vigil.codes/stats` is now public. Every number is derived live from the scan feed: total scans, flagged tokens, last 24h, unique tokens, top tools, recent flagged scans.

No projections. No hand-edited numbers. If the data isn't there, the page shows zeros — not placeholders. A security tool that asks for trust should be checkable.

## The unglamorous part: a production migration mid-stream

Saturday morning, `mcp.vigil.codes` was timing out for the public. Not a code bug — a server move. The VPS had been restored from a snapshot to a new droplet, but the DNS record still pointed at the old, now-dead IP.

The fix was a single DNS update, but the diagnosis is the lesson: the healthy server was right there, serving 15 tools with a valid cert — the traffic just wasn't reaching it. SSL, auto-renew, services-on-boot, and the full scan history all came across in the snapshot. Once DNS propagated, everything — including the paid Pre-Trade Report endpoint running on @bankrbot x402 Cloud that proxies through `mcp.vigil.codes` — came back online automatically.

Downtime is part of building in public too. Worth logging.

## Where VIGIL stands

**15 tools, live on Base, keyless for core checks:**

- Approval scanner, token scanner, honeypot detector, safety score
- Wallet report, wallet monitor, token market, deployer check
- Batch scan, scam check, sentinel status
- 6-source consensus (the false-positive guard)
- Liquidity lock detector
- **Approval simulator** (new)
- **Clone detector** (new)

Free to scan. Open source. Pay-per-call on x402 for the premium bundle. Discoverable by any agent. Integrated with the @aeonframework ecosystem — thanks to @aaronjmars for the early code review that made the integration solid.

The same principle runs through all of it: **a security tool is only useful if it's right, and only trustworthy if you can check it.** Missing data is never reported as safe. A single noisy source can't trigger a false alarm. Every number on the stats page is real.

**Scan before you sign.**

---

*VIGIL — onchain security scanner for Base. vigil.codes · mcp.vigil.codes · github.com/vigilcodes/vigil-mcp. Not financial advice.*
