#!/usr/bin/env python3
"""Telegram-bot demo video — scanning $VIGIL via @vigilcodesbot. 1920x1080 @ 60fps.

Mimics a Telegram chat: the user types a /scan command (typewriter), it sends
as a chat bubble, then the bot replies with the verdict card. Real live data
($VIGIL: 93/safe, not honeypot, 0% tax, 0 reports, name vigilcodes / $Vigil).
"""
import html
import os
import subprocess

W, H = 1280, 720
RENDER_W, RENDER_H = 1920, 1080
FPS = 60
OUT_DIR = "/root/vigil/.demo_bot_frames"
FINAL = "/root/vigil/website/assets/vigil-bot-demo-1920x1080.mp4"

# Telegram-ish dark palette
BG = "#17212b"          # chat background
BUBBLE_OUT = "#2b5278"  # user (outgoing) bubble
BUBBLE_IN = "#182533"   # bot (incoming) bubble
TEXT = "#ffffff"
DIM = "#7d8e9e"
GOLD = "#c8a961"
GREEN = "#6bbd6b"
MONO_DIM = "#8fa6bd"

ADDR = "0xc751afadd6fde251ac624a279ecb9ac85aa27ba3"
ADDR_SHORT = "0xc751…27ba3"
CHAR_W = 12.0

# Embed the real VIGIL logo as the bot profile picture (base64).
with open("/root/vigil/.pfp_b64.txt") as _f:
    PFP_B64 = _f.read().strip()

os.makedirs(OUT_DIR, exist_ok=True)


def esc(s):
    return html.escape(s, quote=True)


def frame(typed, cursor, show_user_bubble, show_bot, bot_alpha=1.0):
    parts = []

    # header bar with real VIGIL logo as profile pic
    parts.append(f'<rect x="0" y="0" width="{W}" height="64" fill="#1f2c3a"/>')
    parts.append('<defs><clipPath id="pfpclip"><circle cx="44" cy="32" r="20"/></clipPath></defs>')
    parts.append(f'<image x="24" y="12" width="40" height="40" clip-path="url(#pfpclip)" '
                 f'href="data:image/png;base64,{PFP_B64}" preserveAspectRatio="xMidYMid slice"/>')
    parts.append(f'<circle cx="44" cy="32" r="20" fill="none" stroke="{GOLD}" stroke-width="1" opacity="0.4"/>')
    parts.append(f'<text x="78" y="29" fill="{TEXT}" font-family="Inter, sans-serif" font-size="17" font-weight="600">VIGIL</text>')
    parts.append(f'<text x="78" y="48" fill="{DIM}" font-family="Inter, sans-serif" font-size="12">@vigilcodesbot · bot</text>')

    # user outgoing bubble (the command)
    if show_user_bubble:
        cmd = "/scan " + ADDR
        w = 150 + int(len(cmd) * CHAR_W)
        x = W - 60 - w
        parts.append(f'<rect x="{x}" y="100" width="{w}" height="56" rx="14" fill="{BUBBLE_OUT}"/>')
        parts.append(f'<text x="{x+24}" y="135" fill="{TEXT}" font-family="monospace" font-size="18"><tspan fill="#cfe0f0">/scan</tspan> {esc(ADDR)}</text>')
        parts.append(f'<text x="{W-76}" y="150" text-anchor="end" fill="#9bbbe0" font-family="Inter, sans-serif" font-size="11">4:06 PM ✓✓</text>')

    # the typing input (before send)
    if not show_user_bubble:
        parts.append(f'<rect x="60" y="640" width="{W-120}" height="56" rx="16" fill="#232f3d"/>')
        shown = "/scan " + typed
        parts.append(f'<text x="86" y="675" fill="{TEXT}" font-family="monospace" font-size="18"><tspan fill="{GOLD}">/scan</tspan> {esc(typed)}</text>')
        if cursor:
            cx = 86 + int(len("/scan " + typed) * CHAR_W) + 4
            parts.append(f'<rect x="{cx}" y="657" width="9" height="22" fill="{GOLD}" opacity="0.85"/>')

    # bot incoming reply (verdict card)
    if show_bot:
        a = bot_alpha
        bx, by = 60, 190
        parts.append(f'<g opacity="{a:.2f}">')
        parts.append(f'<rect x="{bx}" y="{by}" width="720" height="300" rx="16" fill="{BUBBLE_IN}"/>')
        # header row with logo
        parts.append(f'<defs><clipPath id="bclip"><circle cx="{bx+40}" cy="{by+36}" r="16"/></clipPath></defs>')
        parts.append(f'<image x="{bx+24}" y="{by+20}" width="32" height="32" clip-path="url(#bclip)" '
                     f'href="data:image/png;base64,{PFP_B64}" preserveAspectRatio="xMidYMid slice"/>')
        parts.append(f'<text x="{bx+68}" y="{by+44}" fill="{TEXT}" font-family="Inter, sans-serif" font-size="18" font-weight="600">VIGIL scan · vigilcodes ($Vigil)</text>')
        parts.append(f'<text x="{bx+28}" y="{by+78}" fill="{MONO_DIM}" font-family="monospace" font-size="14">{ADDR_SHORT} · base</text>')
        parts.append(f'<line x1="{bx+28}" y1="{by+98}" x2="{bx+692}" y2="{by+98}" stroke="#2a3a4a"/>')
        # verdict lines
        parts.append(f'<text x="{bx+28}" y="{by+142}" font-family="Inter, sans-serif" font-size="22">✅ <tspan fill="{GREEN}" font-weight="700">93/100</tspan> <tspan fill="{TEXT}">— SAFE</tspan></text>')
        parts.append(f'<text x="{bx+28}" y="{by+182}" fill="{TEXT}" font-family="Inter, sans-serif" font-size="18">Honeypot: ✅ not a honeypot</text>')
        parts.append(f'<text x="{bx+28}" y="{by+216}" fill="{TEXT}" font-family="Inter, sans-serif" font-size="18">Buy/Sell tax: 0% / 0%</text>')
        parts.append(f'<text x="{bx+28}" y="{by+250}" fill="{TEXT}" font-family="Inter, sans-serif" font-size="18">Scam reports: ✅ none</text>')
        parts.append(f'<text x="{bx+28}" y="{by+286}" fill="{GOLD}" font-family="monospace" font-size="14">🔗 vigil.codes/scan</text>')
        parts.append('</g>')

    body = "".join(parts)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" fill="none">
  <rect width="{W}" height="{H}" fill="{BG}"/>
  {body}
</svg>'''


def main():
    idx = 0

    def emit(svg):
        nonlocal idx
        sp = os.path.join(OUT_DIR, f"f_{idx:05d}.svg")
        pp = os.path.join(OUT_DIR, f"f_{idx:05d}.png")
        with open(sp, "w") as fh:
            fh.write(svg)
        subprocess.run(["rsvg-convert", "-w", str(RENDER_W), "-h", str(RENDER_H), sp, "-o", pp], check=True)
        idx += 1

    # 1. empty, blink
    for f in range(30):
        emit(frame("", (f // 20) % 2 == 0, False, False))
    # 2. type the address (2 frames/char)
    for ci in range(1, len(ADDR) + 1):
        for _ in range(2):
            emit(frame(ADDR[:ci], True, False, False))
    # 3. full typed, hold
    for f in range(24):
        emit(frame(ADDR, (f // 20) % 2 == 0, False, False))
    # 4. message sent — show user bubble, no bot yet (bot "typing")
    for f in range(50):
        emit(frame(ADDR, False, True, False))
    # 5. bot reply fades in
    for f in range(16):
        emit(frame(ADDR, False, True, True, min(1.0, (f + 1) / 16)))
    # 6. hold result
    for f in range(170):
        emit(frame(ADDR, False, True, True, 1.0))

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
