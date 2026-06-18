# Public Stats — Requirements

## Introduction

Public, transparent stats endpoint + landing page for VIGIL. The goal is
**proof, not hype**: anyone can see exactly how many scans VIGIL has run, how
many tokens it has flagged, and how recently. This makes the project's traction
verifiable to agents, integrators, and curious users.

VIGIL already records every feed-worthy scan to `FeedStore` (SQLite). The
existing `/feed` endpoint exposes `totals` (total / flagged / last_24h /
unique_tokens) and `recent` scans. This spec extends that into a richer stats
surface — but adds **no new data collection**, **no PII**, and **no inflated
numbers**. Anything the page claims must be derivable from the live feed DB.

## Glossary

- **Stats_Endpoint**: New `GET /stats` JSON endpoint on `mcp.vigil.codes`.
- **Stats_Page**: New static HTML page (served at `/stats` on the same host or
  hosted alongside vigil.codes) that fetches and renders the endpoint.
- **Feed_Worthy_Scan**: A successful tool call whose result was recorded by
  `FeedStore` (current set: safety_score, detect_honeypot, scan_token,
  consensus, check_scam, plus liquidity_lock once added).
- **Flagged_Token**: A scan whose verdict is `high`, `critical`, or `honeypot`.

## Requirements

### R1 — Honest, derivable stats

1. Every number on Stats_Page SHALL be derivable from the live feed DB at
   request time. No hand-edited numbers, no projections, no inflated counts.
2. WHEN the feed DB is empty, the endpoint SHALL return zeros, not placeholders.
3. The endpoint SHALL NOT include any user identifier, IP, or wallet address
   beyond the publicly-scanned token addresses already present in the feed.

### R2 — Stats_Endpoint shape

`GET /stats` returns JSON with:

| field | type | meaning |
|---|---|---|
| `totals.total_scans` | int | All-time count of feed-worthy scans |
| `totals.flagged` | int | Scans whose verdict was high / critical / honeypot |
| `totals.last_24h` | int | Scans in the last 24 hours |
| `totals.unique_tokens` | int | Distinct tokens scanned all-time |
| `tools_live` | int | Number of canonical `vigil_*` tools currently registered |
| `tools_by_volume` | array | `[{tool, count}]` top 5 tools by all-time call count |
| `recent_flagged` | array | `[{token, chain, tool, verdict, score, at}]` last 5 flagged scans (high/critical/honeypot) |
| `service` | string | `"vigil-mcp"` |
| `as_of` | int | Server unix timestamp at response time |

### R3 — Caching to protect the DB

1. The Stats_Endpoint SHALL be safe to call frequently (target: page can poll
   every minute without DB strain).
2. Results MAY be cached in-process for up to 60 seconds. Cache key is global
   (one shared snapshot).
3. The endpoint SHALL include an `as_of` timestamp so callers know how fresh
   the snapshot is.

### R4 — Stats_Page rendering

1. Single static HTML page, no JS framework, no build step.
2. Renders the four headline numbers (total_scans, flagged, last_24h,
   unique_tokens) prominently.
3. Lists `tools_by_volume` and `recent_flagged` below the headline.
4. Footer: link to `vigil.codes`, GitHub source, and a note "All numbers
   derived from the live feed DB at <as_of UTC>."

### R5 — No regressions

1. Adding the endpoint and page SHALL NOT change behavior of any existing
   tool, the existing `/feed` endpoint, `/health`, or the home page.
2. Lint and full test suite SHALL pass.

### R6 — Failure mode

1. IF the feed DB read fails, the endpoint SHALL return HTTP 500 with a
   minimal JSON error body (`{"error":"stats unavailable"}`) — never a stale
   number presented as fresh.
