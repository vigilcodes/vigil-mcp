# VIGIL × Bankr x402 Cloud

Paid, agent-discoverable VIGIL services deployed on [Bankr x402 Cloud](https://docs.bankr.bot/x402-cloud/overview).

These are **composite products** — they call VIGIL's free scanners at
`mcp.vigil.codes` and aggregate the results. They do not re-host VIGIL's own
x402-paid tools (e.g. `vigil_consensus`), which would create a double-paywall.

## Services

### `vigil-pretrade` — Full Pre-Trade Report
- **URL:** `https://x402.bankr.bot/0x9f6697155bbfc4c87fe9499ceb233a3dda4ce708/vigil-pretrade`
- **Price:** $0.01 USDC/req (Base)
- **What it does:** one call runs `vigil_safety_score`, `vigil_detect_honeypot`,
  and `vigil_check_scam` in parallel, then returns one aggregated verdict
  (`safe` → `critical`) + recommendation.
- **Bias:** any hard risk signal dominates; missing data lowers completeness but
  never fabricates a `safe`.

#### Future
When `vigil_liquidity_lock` (PR #2) ships to production at `mcp.vigil.codes`,
add it as a fourth source in `x402/vigil-pretrade/index.ts` and redeploy.

## Deploy / manage

```bash
bankr login --api-key <bankr-api-key>   # auth (key is your account's)
bankr x402 deploy vigil-pretrade        # deploy / redeploy
bankr x402 list                         # status + request count
bankr x402 revenue                      # earnings
bankr x402 schema <url>                 # inspect schema
bankr x402 call <url> -X POST -d '{"token":"0x...","chain":"base"}'  # test (paid)
```

The deployed handler runs in Bankr's TypeScript/serverless runtime (256 MB,
30 s timeout). It only relays read-only public scan data — no VIGIL secrets are
used or exposed.
