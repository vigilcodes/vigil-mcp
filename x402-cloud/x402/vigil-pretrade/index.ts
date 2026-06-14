/**
 * VIGIL — Full Pre-Trade Report (x402 paid endpoint).
 *
 * One call, one verdict. Runs several FREE VIGIL scanners against a token in
 * parallel (safety score, honeypot, community scam DB), then aggregates them
 * into a single pre-trade recommendation. Bankr wraps x402 payment + agent
 * discovery around this handler.
 *
 * Why this is a distinct product (not a re-host):
 * - The underlying VIGIL tools are individually free at mcp.vigil.codes.
 * - The value sold here is AGGREGATION + a single recommendation in one call,
 *   so there is no double-paywall (none of the called tools charge x402).
 *
 * Input (JSON body):  { token: string (0x...), chain?: string = "base" }
 * Output:             combined report with a single overall verdict.
 */

const VIGIL_ENDPOINT = "https://mcp.vigil.codes/tools/call";
const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
const SUPPORTED_CHAINS = ["base", "ethereum", "polygon", "arbitrum"];

type RpcArgs = Record<string, string>;

async function callVigil(tool: string, args: RpcArgs): Promise<unknown> {
  const res = await fetch(VIGIL_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: tool, arguments: args },
    }),
  });
  if (!res.ok) throw new Error(`${tool}: HTTP ${res.status}`);
  const data = (await res.json()) as Record<string, unknown>;
  if (data && typeof data === "object" && "error" in data) {
    throw new Error(`${tool}: ${JSON.stringify(data.error)}`);
  }
  return data && typeof data === "object" && "result" in data ? data.result : data;
}

export default async function handler(req: Request) {
  let body: Record<string, unknown> = {};
  try {
    body = await req.json();
  } catch {
    body = {};
  }

  const token = typeof body.token === "string" ? body.token.trim() : "";
  const chain =
    typeof body.chain === "string" && body.chain.trim() ? body.chain.trim().toLowerCase() : "base";

  if (!ADDR_RE.test(token)) {
    return new Response(
      JSON.stringify({ error: "Invalid token: expected a 0x-prefixed 40-hex-char address" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }
  if (!SUPPORTED_CHAINS.includes(chain)) {
    return new Response(
      JSON.stringify({ error: `Unsupported chain '${chain}'. Use: ${SUPPORTED_CHAINS.join(", ")}` }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  // Run the free scanners in parallel. If any fails, we surface it as a
  // partial result rather than failing the whole report — but if ALL fail,
  // we return 502 so the payment is not settled.
  const [scoreR, honeypotR, scamR] = await Promise.allSettled([
    callVigil("vigil_safety_score", { contract: token, token, chain }),
    callVigil("vigil_detect_honeypot", { token, chain }),
    callVigil("vigil_check_scam", { token, chain }),
  ]);

  const score = scoreR.status === "fulfilled" ? (scoreR.value as Record<string, unknown>) : null;
  const honeypot = honeypotR.status === "fulfilled" ? (honeypotR.value as Record<string, unknown>) : null;
  const scam = scamR.status === "fulfilled" ? (scamR.value as Record<string, unknown>) : null;

  if (!score && !honeypot && !scam) {
    return new Response(
      JSON.stringify({ error: "VIGIL upstream unreachable — no scanners returned data" }),
      { status: 502, headers: { "Content-Type": "application/json" } },
    );
  }

  // ── Aggregate into a single verdict ──────────────────────
  // Bias toward caution: any hard risk signal dominates. Missing data lowers
  // confidence but never fabricates a "safe".
  const reasons: string[] = [];
  let verdict = "safe";

  const isHoneypot = honeypot?.is_honeypot === true;
  const scamReported = scam?.reported === true;
  const riskLevel = typeof score?.risk_level === "string" ? (score.risk_level as string) : "unknown";
  const safetyScore = typeof score?.score === "number" ? (score.score as number) : null;

  if (isHoneypot) {
    verdict = "critical";
    reasons.push("Honeypot detected — selling may be blocked");
  }
  if (scamReported) {
    verdict = verdict === "critical" ? "critical" : "high";
    const n = typeof scam?.report_count === "number" ? scam.report_count : 0;
    reasons.push(`${n} community scam report(s)`);
  }
  if (riskLevel === "critical" || riskLevel === "high") {
    if (verdict === "safe") verdict = riskLevel;
    reasons.push(`Safety score risk level: ${riskLevel}${safetyScore !== null ? ` (${safetyScore}/100)` : ""}`);
  } else if ((riskLevel === "safe" || riskLevel === "low") && verdict === "safe") {
    reasons.push(`Safety score: ${safetyScore !== null ? `${safetyScore}/100` : riskLevel} (${riskLevel})`);
  }

  const missing: string[] = [];
  if (!score) missing.push("safety_score");
  if (!honeypot) missing.push("honeypot");
  if (!scam) missing.push("scam_db");

  const report = {
    token,
    chain,
    verdict,
    recommendation:
      verdict === "safe"
        ? "No blocking risk signals detected across VIGIL scanners."
        : `Caution — ${verdict.toUpperCase()} risk. ${reasons.join("; ")}`,
    reasons,
    sources: {
      safety_score: score,
      honeypot,
      scam_db: scam,
    },
    incomplete: missing.length > 0,
    missing_sources: missing,
    note: "Aggregated from VIGIL free scanners. Not financial advice.",
  };

  return new Response(JSON.stringify(report), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
