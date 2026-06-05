# x402 monetization — setup checklist

VIGIL's x402 pay-per-call code is already in the repo
(`src/vigil_mcp/payments/x402.py`) and wired into `/tools/call`. It's gated
behind `VIGIL_X402_ENABLED=1`, so the public endpoint stays free until we
explicitly flip it on.

To go live, three things are needed.


## 1. Receiver wallet (USDC on Base)

Where collected fees land. Recommended:

- A wallet you control directly (Bankr / Coinbase / cold wallet on Base).
- NOT the deployer wallet of $VIGIL itself — keep responsibilities separate.
- It must be able to receive native USDC on Base
  (`0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`).

Once decided, set in `/root/vigil/.env`:

```
VIGIL_X402_PAY_TO=0xYourReceiverWalletOnBase
```


## 2. Coinbase CDP facilitator credentials

Per Coinbase's official docs, the CDP facilitator runs at:

```
https://api.cdp.coinbase.com/platform/v2/x402
```

It supports Base, Polygon, Arbitrum, World, Solana. **1,000 transactions per
month free**, then $0.001/tx. Includes KYT (Know-Your-Transaction) compliance
screening — it will decline payments from sanctioned addresses, which is good
for VIGIL's brand as a security tool.

To use it, you need CDP API keys (NOT just a URL):

1. Sign up at https://cdp.coinbase.com/
2. Create a new project
3. Generate API credentials (API Key ID + Secret)

Then set in `.env`:

```
CDP_API_KEY_ID=your-cdp-api-key-id
CDP_API_KEY_SECRET=your-cdp-api-key-secret
```

The code auto-detects these and uses the CDP facilitator. No need to set
`VIGIL_X402_FACILITATOR` unless you want to override (e.g. a self-hosted one).


## 3. Pricing (defaults already tuned)

The default in code is now **$0.005 per scan** (above the $0.001 facilitator
fee, so there's real margin even after the free quota runs out). Defensive
tools stay free on purpose.

| Tool                     | Default price | Notes                                       |
|--------------------------|---------------|---------------------------------------------|
| `vigil_safety_score`     | $0.005        | Most-asked verdict per AxiomBot             |
| `vigil_detect_honeypot`  | $0.005        | Same                                         |
| `vigil_scan_token`       | $0.005        | Same                                         |
| `vigil_token_market`     | $0.003        | Lighter call (DexScreener)                   |
| `vigil_deployer_check`   | $0.005        | External Basescan dependency                |
| `vigil_batch_scan`       | $0.025 (5x)   | Heavy: scans many tokens                    |
| `vigil_wallet_report`    | $0.010 (2x)   | Aggregates several scans                    |
| `vigil_check_scam`       | **free**      | Encourage reads — keeps community DB sticky |
| `vigil_scan_approvals`   | **free**      | Defensive use — keep barrier-free            |
| `vigil_monitor_wallet`   | **free**      | Sentinel users will hit this often          |
| `vigil_sentinel_status`  | **free**      | Lightweight read                            |

Override the global default with `VIGIL_X402_PRICE_USD=0.005` (or whatever).
Per-tool prices live in `_default_prices()` in `payments/x402.py`.


## 4. Activation (when 1–3 are filled)

Add to `/root/vigil/.env`:

```
VIGIL_X402_ENABLED=1
VIGIL_X402_PAY_TO=0xYourReceiverWalletOnBase
CDP_API_KEY_ID=...
CDP_API_KEY_SECRET=...
# optional — already defaults to $0.005:
# VIGIL_X402_PRICE_USD=0.005
```

Then:

```
systemctl restart vigil-mcp
```

Verify (priced tool unpaid → 402 with payment requirements):

```bash
curl -i -X POST https://mcp.vigil.codes/tools/call \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"vigil_safety_score",
                 "arguments":{"contract":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                              "chain":"base"}}}'
# expected: HTTP/1.1 402 Payment Required
# body: { "x402Version":1, "accepts":[{"scheme":"exact","network":"eip155:8453",
#                                      "maxAmountRequired":"5000", ... }] }
```

Free tool stays 200:

```bash
curl -i -X POST https://mcp.vigil.codes/tools/call \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"vigil_check_scam",
                 "arguments":{"token":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                              "chain":"base"}}}'
# expected: HTTP/1.1 200 OK
```


## 5. Announce + reply to AxiomBot

Once verified live, the launch tweet (drafted style):

```
VIGIL is now pay-per-scan over x402 👁️

Any agent on Base can call us and pay a few cents in USDC — no key, no account.

→ scan_token / detect_honeypot / safety_score: $0.005
→ batch_scan: $0.025
→ check_scam / scan_approvals / monitor_wallet: still free

Powered by @CoinbaseDev x402.

vigil.codes
```

Reply to @AxiomBot:

```
Live now 🤝

scan_token / detect_honeypot / safety_score → $0.005 in USDC on Base, x402 native.
batch_scan → $0.025 (5x).

Pre-DCA wallet analysis is exactly what we sized batch_scan for.
```


## Notes & gotchas

- First 1,000 transactions per month settle free on the CDP facilitator, so
  early traffic is pure margin.
- Network must be in CAIP-2 format (`eip155:8453` for Base mainnet). The code
  auto-resolves `"base"` → `"eip155:8453"`. Don't hand-edit to plain `"base"`.
- Pricing reads env at request time — tweak `VIGIL_X402_PRICE_USD` and the
  next request reflects it (no redeploy required).
- If the CDP facilitator hits an outage, priced tools fail closed (return 402).
  Free tools keep working. That's the safe failure mode.
- `vigil_check_scam` and `vigil_scan_approvals` should stay free. The cost of
  losing user goodwill on defensive tools is higher than micro-revenue.
