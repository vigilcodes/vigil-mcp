#!/usr/bin/env python3
"""Product demo video — VIGIL x402 pay-per-scan + onchain Builder Code attribution.

1920x1080 @ 60fps, with large easy-to-read subtitles narrating each step. Uses
REAL data from the live mainnet settlement:
  - tool:        vigil_scan_token (USDC, $0.005)
  - verdict:     92/100 SAFE
  - settlement:  0xce74cc8d…472c
  - attribution: { a: "bc_kz42eeiy", w: "cdp_facil1" }

Renders SVG frames -> PNG (rsvg-convert) -> H.264 mp4 (ffmpeg). Static holds are
produced by copying the last PNG so 60fps stays cheap.

Run:  python3 scripts/make_demo_x402.py
"""

import html
import os
import shutil
import subprocess

W, H = 1280, 720
RENDER_W, RENDER_H = 1920, 1080
FPS = 60
OUT_DIR = "/root/vigil/.demo_x402_frames"
FINAL = "/root/vigil/website/assets/vigil-x402-demo-1920x1080.mp4"

# Brand palette (matches the scan-page demo).
BG = "#080808"
ELEV = "#0e0e0e"
SUBTLE = "#141414"
GOLD = "#c8a961"
TEXT = "#d4d0c8"
DIM = "#6b6860"
BORDER = "#1e1e1c"
GREEN = "#6bbd6b"
BLUE = "#7fa8d4"

MONO = "DejaVu Sans Mono, monospace"
SERIF = "DejaVu Serif, Georgia, serif"

os.makedirs(OUT_DIR, exist_ok=True)
_idx = 0


def esc(s):
    return html.escape(str(s), quote=True)


def _write(svg):
    global _idx
    sp = os.path.join(OUT_DIR, f"f_{_idx:05d}.svg")
    pp = os.path.join(OUT_DIR, f"f_{_idx:05d}.png")
    with open(sp, "w") as fh:
        fh.write(svg)
    subprocess.run(["rsvg-convert", "-w", str(RENDER_W), "-h", str(RENDER_H), sp, "-o", pp], check=True)
    _idx += 1


def hold(n):
    """Repeat the previous frame n times by copying its PNG (cheap 60fps holds)."""
    global _idx
    if _idx == 0:
        return
    last = os.path.join(OUT_DIR, f"f_{_idx - 1:05d}.png")
    for _ in range(n):
        shutil.copyfile(last, os.path.join(OUT_DIR, f"f_{_idx:05d}.png"))
        _idx += 1


def chrome(subtitle, sub_alpha=1.0, progress=0.0):
    """Persistent UI chrome: header bar + bottom subtitle band + progress line."""
    # Subtitle band — large, high-contrast, easy to read.
    sub = ""
    if subtitle:
        sub = f'''
        <rect x="0" y="{H - 96}" width="{W}" height="96" fill="#000000" opacity="{0.82 * sub_alpha:.3f}"/>
        <rect x="0" y="{H - 96}" width="{W}" height="3" fill="{GOLD}" opacity="{sub_alpha:.3f}"/>
        <text x="{W // 2}" y="{H - 50}" text-anchor="middle" fill="{TEXT}"
              font-family="{SERIF}" font-size="27" opacity="{sub_alpha:.3f}">{esc(subtitle)}</text>'''
    prog = ""
    if progress > 0:
        prog = f'<rect x="0" y="{H - 96}" width="{int(W * min(progress, 1.0))}" height="3" fill="{GOLD}"/>'
    return f'''
  <rect width="{W}" height="{H}" fill="{BG}"/>
  <circle cx="62" cy="52" r="13" fill="none" stroke="{GOLD}" stroke-width="1.5"/>
  <circle cx="62" cy="52" r="5" fill="{GOLD}"/>
  <text x="88" y="58" fill="{GOLD}" font-family="{MONO}" font-size="15" letter-spacing="6">VIGIL</text>
  <text x="{W - 60}" y="58" text-anchor="end" fill="{DIM}" font-family="{MONO}" font-size="13"
        letter-spacing="2">onchain security · Base</text>
  <line x1="60" y1="78" x2="{W - 60}" y2="78" stroke="{BORDER}"/>
  {sub}
  {prog}'''


def svg(body, subtitle, sub_alpha=1.0, progress=0.0):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" fill="none">'
        + chrome(subtitle, sub_alpha, progress)
        + body
        + "</svg>"
    )


def fade_in(make_body, subtitle, frames=10, progress=0.0):
    """Render a short ease-in ramp of a scene body + subtitle."""
    for i in range(frames):
        a = (i + 1) / frames
        a = 1 - (1 - a) * (1 - a)  # ease-out
        _write(svg(make_body(a), subtitle, sub_alpha=a, progress=progress))


# ─────────────────────────────────────────────────────────────
# Scene bodies
# ─────────────────────────────────────────────────────────────

CONSOLE_X, CONSOLE_Y, CONSOLE_W = 140, 150, 1000


def title_body(a=1.0):
    return f'''
    <g opacity="{a:.3f}">
      <text x="{W // 2}" y="300" text-anchor="middle" fill="{GOLD}" font-family="{MONO}"
            font-size="18" letter-spacing="10" opacity="0.7">VIGIL · MCP</text>
      <text x="{W // 2}" y="380" text-anchor="middle" fill="{TEXT}" font-family="{SERIF}"
            font-size="64">Scan before you sign.</text>
      <text x="{W // 2}" y="436" text-anchor="middle" fill="{DIM}" font-family="{MONO}"
            font-size="18">rugpulls · honeypots · dangerous approvals — caught on Base</text>
    </g>'''


def console_body(lines, alphas, caret=False):
    """Render a terminal panel with progressively revealed lines."""
    rows = ""
    y = CONSOLE_Y + 70
    for (who, text, color), al in zip(lines, alphas):
        tag_color = {"agent": BLUE, "vigil": GOLD, "cdp": GREEN}.get(who, DIM)
        rows += (
            f'<text x="{CONSOLE_X + 30}" y="{y}" fill="{tag_color}" font-family="{MONO}" '
            f'font-size="19" opacity="{al:.3f}">{esc(who):<6}</text>'
            f'<text x="{CONSOLE_X + 120}" y="{y}" fill="{color}" font-family="{MONO}" '
            f'font-size="19" opacity="{al:.3f}">{esc(text)}</text>'
        )
        y += 52
    car = ""
    if caret:
        car = f'<rect x="{CONSOLE_X + 120}" y="{y - 18}" width="11" height="22" fill="{GOLD}" opacity="0.85"/>'
    return f'''
    <rect x="{CONSOLE_X}" y="{CONSOLE_Y}" width="{CONSOLE_W}" height="430" rx="14"
          fill="{ELEV}" stroke="{BORDER}"/>
    <circle cx="{CONSOLE_X + 26}" cy="{CONSOLE_Y + 26}" r="6" fill="#3a3a38"/>
    <circle cx="{CONSOLE_X + 48}" cy="{CONSOLE_Y + 26}" r="6" fill="#3a3a38"/>
    <circle cx="{CONSOLE_X + 70}" cy="{CONSOLE_Y + 26}" r="6" fill="#3a3a38"/>
    <text x="{CONSOLE_X + CONSOLE_W - 24}" y="{CONSOLE_Y + 31}" text-anchor="end" fill="{DIM}"
          font-family="{MONO}" font-size="13">agent ⇄ mcp.vigil.codes</text>
    <line x1="{CONSOLE_X}" y1="{CONSOLE_Y + 48}" x2="{CONSOLE_X + CONSOLE_W}" y2="{CONSOLE_Y + 48}"
          stroke="{BORDER}"/>
    {rows}{car}'''


def verdict_body(a=1.0):
    return f'''
    <g opacity="{a:.3f}">
      <text x="{W // 2}" y="150" text-anchor="middle" fill="{GOLD}" font-family="{MONO}"
            font-size="14" letter-spacing="4" opacity="0.7">VERDICT · vigil_scan_token</text>
      <rect x="290" y="180" width="700" height="150" rx="14" fill="{ELEV}" stroke="{BORDER}"/>
      <text x="360" y="285" fill="{GREEN}" font-family="{SERIF}" font-size="78">92<tspan
            font-size="26" fill="{DIM}">/100</tspan></text>
      <text x="540" y="232" fill="{GOLD}" font-family="{MONO}" font-size="13"
            letter-spacing="3" opacity="0.6">SAFETY SCORE</text>
      <text x="540" y="270" fill="{GREEN}" font-family="{MONO}" font-size="26" letter-spacing="2">SAFE</text>
      <text x="540" y="304" fill="{DIM}" font-family="{MONO}" font-size="15">USD Coin (USDC) · verified</text>
      <g font-family="{MONO}">
        <rect x="290" y="346" width="222" height="86" rx="10" fill="{ELEV}" stroke="{BORDER}"/>
        <text x="312" y="378" fill="{DIM}" font-size="11" letter-spacing="2">HONEYPOT</text>
        <text x="312" y="408" fill="{GREEN}" font-size="17">Not a honeypot</text>
        <rect x="528" y="346" width="222" height="86" rx="10" fill="{ELEV}" stroke="{BORDER}"/>
        <text x="550" y="378" fill="{DIM}" font-size="11" letter-spacing="2">BUY / SELL TAX</text>
        <text x="550" y="408" fill="{TEXT}" font-size="17">0% / 0%</text>
        <rect x="766" y="346" width="224" height="86" rx="10" fill="{ELEV}" stroke="{BORDER}"/>
        <text x="788" y="378" fill="{DIM}" font-size="11" letter-spacing="2">OWNERSHIP</text>
        <text x="788" y="408" fill="{GREEN}" font-size="17">Renounced</text>
      </g>
    </g>'''


def attribution_body(a=1.0, highlight=False):
    hl = GOLD if highlight else TEXT
    glow = f'filter="drop-shadow(0 0 6px {GOLD})"' if highlight else ""
    return f'''
    <g opacity="{a:.3f}">
      <text x="{W // 2}" y="150" text-anchor="middle" fill="{GOLD}" font-family="{MONO}"
            font-size="14" letter-spacing="4" opacity="0.7">ONCHAIN ATTRIBUTION · ERC-8021</text>
      <rect x="240" y="180" width="800" height="120" rx="12" fill="{ELEV}" stroke="{BORDER}"/>
      <text x="270" y="222" fill="{DIM}" font-family="{MONO}" font-size="13"
            letter-spacing="2">SETTLEMENT TX · BASE MAINNET</text>
      <text x="270" y="262" fill="{BLUE}" font-family="{MONO}" font-size="19">0xce74cc8d…8488472c</text>
      <text x="270" y="290" fill="{GREEN}" font-family="{MONO}" font-size="14">0.005 USDC settled · success</text>
      <rect x="240" y="320" width="800" height="150" rx="12" fill="{ELEV}" stroke="{BORDER}"/>
      <text x="270" y="362" fill="{DIM}" font-family="{MONO}" font-size="13"
            letter-spacing="2">BUILDER CODE SUFFIX (decoded)</text>
      <text x="270" y="416" fill="{DIM}" font-family="{MONO}" font-size="26">{{ </text>
      <text x="312" y="416" fill="{hl}" font-family="{MONO}" font-size="26" {glow}>a: "bc_kz42eeiy"</text>
      <text x="600" y="416" fill="{DIM}" font-family="{MONO}" font-size="26">, w: "cdp_facil1" }}</text>
      <text x="270" y="452" fill="{GOLD}" font-family="{MONO}" font-size="15"
            opacity="{1.0 if highlight else 0.0:.1f}">↑ VIGIL credited onchain — counts on the Base leaderboard</text>
    </g>'''


def closing_body(a=1.0):
    return f'''
    <g opacity="{a:.3f}">
      <text x="{W // 2}" y="300" text-anchor="middle" fill="{TEXT}" font-family="{SERIF}"
            font-size="54">Security scanning</text>
      <text x="{W // 2}" y="362" text-anchor="middle" fill="{TEXT}" font-family="{SERIF}"
            font-size="54">your agents can <tspan fill="{GOLD}">pay for.</tspan></text>
      <text x="{W // 2}" y="430" text-anchor="middle" fill="{DIM}" font-family="{MONO}"
            font-size="17" letter-spacing="2">x402 · USDC on Base · no API key · no account</text>
      <text x="{W // 2}" y="478" text-anchor="middle" fill="{GOLD}" font-family="{MONO}"
            font-size="20" letter-spacing="3">vigil.codes</text>
    </g>'''


# ─────────────────────────────────────────────────────────────
# Timeline
# ─────────────────────────────────────────────────────────────

CONSOLE_LINES = [
    ("agent", "▸ scan token  0x8335…2913", TEXT),
    ("vigil", "◂ 402  pay $0.005 USDC to scan", TEXT),
    ("agent", "▸ sign gasless USDC payment (EIP-3009)", TEXT),
    ("agent", "▸ attach Builder Code  a=bc_kz42eeiy", GOLD),
    ("cdp", "◂ verify OK   settle onchain OK", GREEN),
]
CONSOLE_SUBS = [
    "An AI agent asks VIGIL to scan a token",
    "VIGIL replies: pay $0.005 USDC to scan — no account, no API key",
    "The agent signs a gasless USDC payment (EIP-3009)",
    "…and tags the payment with VIGIL's Builder Code",
    "Coinbase's facilitator verifies and settles it onchain",
]


def reveal_console():
    n = len(CONSOLE_LINES)
    for step in range(n):
        sub = CONSOLE_SUBS[step]
        prog = 0.12 + 0.40 * (step + 1) / n
        # fade in the newly revealed line
        for i in range(9):
            a = (i + 1) / 9
            alphas = [1.0] * step + [a] + [0.0] * (n - step - 1)
            _write(
                svg(
                    console_body(CONSOLE_LINES[: step + 1], alphas[: step + 1]),
                    sub,
                    sub_alpha=min(1.0, a + 0.2),
                    progress=prog,
                )
            )
        hold(78)


def main():
    # 1 — Title
    fade_in(title_body, "VIGIL — onchain security scanning on Base", frames=14, progress=0.06)
    hold(120)
    for i in range(8):  # fade title out
        a = 1 - (i + 1) / 8
        _write(svg(title_body(a), "VIGIL — onchain security scanning on Base", sub_alpha=a, progress=0.06))

    # 2 — The x402 pay-per-scan flow (console)
    reveal_console()
    # hold full console a beat longer with a summarizing subtitle
    full = [1.0] * len(CONSOLE_LINES)
    _write(
        svg(console_body(CONSOLE_LINES, full), "One call: pay a few cents, get a real security verdict", progress=0.54)
    )
    hold(96)

    # 3 — Verdict card
    fade_in(verdict_body, "The scan runs — here's the verdict", frames=12, progress=0.66)
    hold(150)

    # 4 — Onchain attribution
    fade_in(
        lambda a: attribution_body(a, highlight=False),
        "Every payment is attributed onchain (ERC-8021)",
        frames=12,
        progress=0.82,
    )
    hold(90)
    # highlight the app code
    for i in range(10):
        a = (i + 1) / 10
        _write(
            svg(
                attribution_body(1.0, highlight=True),
                "Your Builder Code lands onchain — not just the facilitator's",
                sub_alpha=min(1.0, 0.4 + a),
                progress=0.9,
            )
        )
    hold(168)

    # 5 — Closing CTA
    for i in range(8):  # fade attribution out
        a = 1 - (i + 1) / 8
        _write(svg(attribution_body(a, highlight=True), "", sub_alpha=0.0, progress=0.95))
    fade_in(closing_body, "Security scanning your agents can pay for.", frames=14, progress=1.0)
    hold(168)

    print(f"rendered {_idx} frames (~{_idx / FPS:.1f}s @ {FPS}fps)")
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-framerate",
            str(FPS),
            "-i",
            os.path.join(OUT_DIR, "f_%05d.png"),
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            "-crf",
            "18",
            "-vf",
            f"scale={RENDER_W}:{RENDER_H}:flags=lanczos",
            "-movflags",
            "+faststart",
            FINAL,
        ],
        check=True,
    )
    print(f"wrote {FINAL}")


if __name__ == "__main__":
    main()
