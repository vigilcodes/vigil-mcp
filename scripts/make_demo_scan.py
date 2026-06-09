#!/usr/bin/env python3
"""Demo video of the vigil.codes/scan page scanning $VIGIL — 1920x1080 @ 60fps.

Mirrors the live scan page UI: type a token address into the input, hit scan,
results render (safety verdict + honeypot + tax + scam). Data is the real live
$VIGIL verdict (93/safe, not honeypot, 0% tax, 0 reports).
"""
import html
import os
import subprocess

# Layout uses a 1280x720 canvas; rendered at 1920x1080 (SVG scales cleanly) for
# crisp 1080p HD output.
W, H = 1280, 720
RENDER_W, RENDER_H = 1920, 1080
FPS = 60
OUT_DIR = "/root/vigil/.demo_scan_frames"
FINAL = "/root/vigil/website/assets/vigil-scan-demo-1920x1080.mp4"

BG = "#080808"
ELEV = "#0e0e0e"
SUBTLE = "#141414"
GOLD = "#c8a961"
TEXT = "#d4d0c8"
DIM = "#6b6860"
BORDER = "#1e1e1c"
GREEN = "#6bbd6b"

ADDR = "0xc751afadd6fde251ac624a279ecb9ac85aa27ba3"
CHAR_W = 13.0

os.makedirs(OUT_DIR, exist_ok=True)


def esc(s):
    return html.escape(s, quote=True)


def page(typed, cursor, show_scanning, show_result, result_alpha=1.0):
    # input box content
    input_txt = typed if typed else ""
    placeholder = "" if typed else "0x… token address on Base"
    input_fill = TEXT if typed else DIM
    cur = ""
    if cursor and not show_result and not show_scanning:
        cx = 150 + int(len(input_txt) * CHAR_W) + 4
        cur = f'<rect x="{cx}" y="226" width="10" height="22" fill="{GOLD}" opacity="0.85"/>'

    body = ""
    if show_scanning:
        body = f'<text x="150" y="330" fill="{DIM}" font-family="monospace" font-size="16">▮ scanning {ADDR[:10]}… </text>'
    elif show_result:
        a = result_alpha
        body = f'''
        <g opacity="{a:.2f}">
          <!-- token identity -->
          <text x="150" y="294" fill="{GOLD}" font-family="monospace" font-size="13" letter-spacing="3" opacity="0.7">vigilcodes · $VIGIL</text>
          <!-- verdict -->
          <rect x="150" y="306" width="980" height="120" rx="12" fill="{ELEV}" stroke="{BORDER}"/>
          <text x="186" y="390" fill="{GREEN}" font-family="Georgia, serif" font-size="58">93<tspan font-size="22" fill="{DIM}">/100</tspan></text>
          <text x="320" y="352" fill="{GOLD}" font-family="monospace" font-size="12" letter-spacing="3" opacity="0.6">SAFETY VERDICT</text>
          <text x="320" y="390" fill="{GREEN}" font-family="monospace" font-size="20" letter-spacing="2">SAFE</text>
          <!-- cards -->
          <g font-family="monospace">
            <rect x="150" y="442" width="316" height="92" rx="10" fill="{ELEV}" stroke="{BORDER}"/>
            <text x="178" y="476" fill="{DIM}" font-size="11" letter-spacing="2">HONEYPOT</text>
            <text x="178" y="506" fill="{GREEN}" font-size="18">Not a honeypot</text>

            <rect x="482" y="442" width="316" height="92" rx="10" fill="{ELEV}" stroke="{BORDER}"/>
            <text x="510" y="476" fill="{DIM}" font-size="11" letter-spacing="2">BUY / SELL TAX</text>
            <text x="510" y="506" fill="{TEXT}" font-size="18">0% / 0%</text>

            <rect x="814" y="442" width="316" height="92" rx="10" fill="{ELEV}" stroke="{BORDER}"/>
            <text x="842" y="476" fill="{DIM}" font-size="11" letter-spacing="2">SCAM REPORTS</text>
            <text x="842" y="506" fill="{GREEN}" font-size="18">None</text>
          </g>
          <text x="150" y="566" fill="{DIM}" font-family="monospace" font-size="13">Score: 93/100 — verified safe. Risk level: safe.</text>
          <text x="150" y="590" fill="{DIM}" font-family="monospace" font-size="12">$VIGIL · chain base · via mcp.vigil.codes</text>
        </g>'''

    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" fill="none">
  <rect width="{W}" height="{H}" fill="{BG}"/>
  <!-- header -->
  <circle cx="166" cy="74" r="15" fill="none" stroke="{GOLD}" stroke-width="1.5"/>
  <text x="150" y="80" fill="{GOLD}" font-family="monospace" font-size="11"></text>
  <text x="196" y="80" fill="{GOLD}" font-family="monospace" font-size="13" letter-spacing="6">VIGIL</text>
  <text x="{W-150}" y="80" text-anchor="end" fill="{DIM}" font-family="monospace" font-size="12" letter-spacing="2">vigil.codes/scan</text>
  <line x1="150" y1="100" x2="{W-150}" y2="100" stroke="{BORDER}"/>

  <text x="150" y="150" fill="{GOLD}" font-family="monospace" font-size="11" letter-spacing="4" opacity="0.6">LIVE SCAN · BASE · NO API KEY</text>
  <text x="150" y="196" fill="{TEXT}" font-family="Georgia, serif" font-size="40">Scan before you sign.</text>

  <!-- input -->
  <rect x="150" y="210" width="840" height="52" rx="10" fill="{SUBTLE}" stroke="{GOLD if (typed and not show_result) else BORDER}"/>
  <text x="170" y="244" fill="{input_fill}" font-family="monospace" font-size="15">{esc(input_txt) if typed else esc(placeholder)}</text>
  {cur}
  <rect x="1004" y="210" width="126" height="52" rx="10" fill="{GOLD}"/>
  <text x="1067" y="243" text-anchor="middle" fill="{BG}" font-family="monospace" font-size="13" letter-spacing="1" font-weight="bold">SCAN</text>

  {body}

  <text x="150" y="{H-40}" fill="{DIM}" font-family="monospace" font-size="12">powered by the live VIGIL MCP endpoint · open source</text>
</svg>'''


def main():
    idx = 0

    def emit(svg):
        nonlocal idx
        sp = os.path.join(OUT_DIR, f"f_{idx:05d}.svg")
        pp = os.path.join(OUT_DIR, f"f_{idx:05d}.png")
        with open(sp, "w") as fh:
            fh.write(svg)
        subprocess.run(
            ["rsvg-convert", "-w", str(RENDER_W), "-h", str(RENDER_H), sp, "-o", pp],
            check=True,
        )
        idx += 1

    # 1. empty input, blinking cursor (hold)
    for f in range(40):
        emit(page("", (f // 20) % 2 == 0, False, False))
    # 2. type the address — slower (2 frames/char) for a smooth, readable feel
    for ci in range(1, len(ADDR) + 1):
        for _ in range(2):
            emit(page(ADDR[:ci], True, False, False))
    # 3. full address typed, hold with cursor
    for f in range(40):
        emit(page(ADDR, (f // 20) % 2 == 0, False, False))
    # 4. scanning state
    for f in range(60):
        emit(page(ADDR, False, True, False))
    # 5. result fades in
    for f in range(16):
        emit(page(ADDR, False, False, True, min(1.0, (f + 1) / 16)))
    # 6. hold result (long, for loop/read)
    for f in range(180):
        emit(page(ADDR, False, False, True, 1.0))

    print(f"rendered {idx} frames")
    subprocess.run([
        "ffmpeg", "-y", "-framerate", str(FPS),
        "-i", os.path.join(OUT_DIR, "f_%05d.png"),
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "18",
        "-vf", f"scale={RENDER_W}:{RENDER_H}:flags=lanczos", "-movflags", "+faststart", FINAL,
    ], check=True)
    print(f"wrote {FINAL}")


if __name__ == "__main__":
    main()
