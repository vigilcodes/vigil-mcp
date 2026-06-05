# x402 monetization — setup checklist

VIGIL's x402 pay-per-call code is already in the repo (`src/vigil_mcp/payments/x402.py`)
and wired into `/tools/call`. It's gated behind `VIGIL_X402_ENABLED=1`, so the
public endpoint stays free until we explicitly flip it on.

To go live, three things are needed.


## 1. Receiver wallet (USDC on Base)

Where collected fees land. Recommended:

- A wallet you control directly (e.g. a Bankr/Coinbase/cold wallet on Base).
- NOT the deployer wallet of $VIGIL itself — keep responsibilities separate.
- Make sure it can hold native USDC on Base (`0x833589fc...02913`).

Once decided, set in `.env`:

```
VIGIL_X402_PAY_TO=0xYourReceiverWalletOnBase
```


## 2. Facilitator URL

The facilitator verifies signed payments and settles them onchain so the server
never holds funds. Coinbase's CDP facilitator is the recommended choice:

- 1,000 transactions per month free
- $0.001 per tx after that
- Supports Base, Polygon, Arbitrum, World, Solana
- Includes KYT (Know-Your-Transaction) compliance screening

Sign up: https://docs.cdp.coinbase.com/x402/quickstart-for-sellers
The signup flow gives you a facilitator base URL.

Then set in `.env`:

```
VIGIL_X402_FACILITATOR=https://<your-facilitator-url>
```


## 3. Pricing decision

Default in code is `$0.001 per scan`, but at the CDP facilitator's $0.001/tx
post-quota fee that's break-even. Recommended pricing for actual margin:

| Tool                    | Price (suggested) | Notes                                       |
|-------------------------|-------------------|---------------------------------------------|
| `vigil_safety_score`    | $0.005            | The most-asked verdict per AxiomBot         |
| `vigil_detect_honeypot` | $0.005            | Same                                         |
| `vigil_scan_token`      | $0.005            | Same                                         |
| `vigil_token_market`    | $0.003            | Lighter call (DexScreener)                   |
| `vigil_deployer_check`  | $0.005            | Hits Basescan — a real external dependency  |
| `vigil_batch_scan`      | $0.025 (5x base)  | Heavy: scans many tokens                    |
| `vigil_wallet_report`   | $0.010 (2x base)  | Aggregates several scans                    |
| `vigil_check_scam`      | free              | Encourage reads — keep community DB sticky  |
| `vigil_scan_approvals`  | free              | Defensive use — keep barrier-free            |
| `vigil_monitor_wallet`  | free or $0.005    | Decision: free for goodwill, paid for scale  |

Override per-tool by editing `_default_prices()` in `payments/x402.py`, or set
the global default with:

```
VIGIL_X402_PRICE_USD=0.005
```


## 4. Activation (when 1–3 are filled)

```
# in /root/vigil/.env
VIGIL_X402_ENABLED=1
VIGIL_X402_PAY_TO=0x...
VIGIL_X402_FACILITATOR=https://...
VIGIL_X402_PRICE_USD=0.005

# then
systemctl restart vigil-mcp
```

Verify:

```
# Priced tool unpaid -> 402 with payment requirements
curl -i -X POST https://mcp.vigil.codes/tools/call \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"vigil_safety_score",
                 "arguments":{"contract":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                              "chain":"base"}}}'
# expect: HTTP/2 402   plus the payment requirements JSON

# Free tool stays 200
curl -i -X POST https://mcp.vigil.codes/tools/call \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"vigil_check_scam",
                 "arguments":{"token":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                              "chain":"base"}}}'
# expect: HTTP/2 200
```


## 5. Announce + reply to AxiomBot

Once verified live, the launch tweet (already drafted near
`articles/vigil-tweet-drafts.md` style):

```
VIGIL is now pay-per-scan over x402 👁️

Any agent on Base can call us and pay a few cents in USDC — no key, no account.

→ scan_token / detect_honeypot / safety_score: $0.005
→ batch_scan: $0.025
→ check_scam: still free

Powered by @CoinbaseDev x402.

vigil.codes
```

And reply to @AxiomBot ([this thread](https://x.com/AxiomBot)):

```
Live now 🤝

scan_token / detect_honeypot / safety_score → $0.005 in USDC on Base, x402 native.
batch_scan → $0.025 (5x).

Pre-DCA wallet analysis is exactly what we sized batch_scan for.
```


## Notes & gotchas

- The first 1,000 transactions per month settle free on the CDP facilitator,
  so early traffic is pure margin.
- Pricing can be tweaked any time without redeploying — it reads env at request
  time.
- If a facilitator outage happens, priced tools will fail closed (return 402);
  free tools keep working. That's the safe failure mode.
- Keep `vigil_check_scam` and `vigil_scan_approvals` free — the cost of
  losing user goodwill on defensive tools is higher than micro-revenue.
