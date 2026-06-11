#!/usr/bin/env python3
"""Scan-feed demo video — mimics vigil.codes/feed. 1920x1080 @ 60fps.

Rows appear one by one (live feel) under a stat header, mixing safe verdicts
and a flagged one, to show "security as a public good" in motion.
"""
import html
import os
import subprocess

W, H = 1280, 720
RW, RH = 1920, 1080
FPS = 60
OUT_DIR = "/root/vigil/.demo_feed_frames"
FINAL = "/root/vigil/website/assets/vigil-feed-demo-1920x1080.mp4"

BG = "#080808"; ELEV = "#0e0e0e"; GOLD = "#c8a961"; TEXT = "#d4d0c8"
DIM = "#6b6860"; BORDER = "#1e1e1c"; GREEN = "#6bbd6b"; RED = "#bd6b6b"; AMBER = "#d89b5b"

os.makedirs(OUT_DIR, exist_ok=True)

# (short token, tool, verdict label, color)
ROWS = [
    ("0x8335…2913", "safety score · base", "92 · safe", GREEN),
    ("0x4200…0006", "honeypot · base", "clear", GREEN),
    ("0x9401…8631", "safety score · base", "78 · safe", GREEN),
    ("0x1f3a…9b21", "scan token · base", "34 · high", RED),
    ("0xc751…7ba3", "consensus · base", "93 · safe", GREEN),
    ("0xaa01…ddef", "honeypot · base", "honeypot", RED),
]

# counters animate up to these
TOTALS = [("TOTAL SCANS", 128), ("FLAGGED", 19), ("LAST 24H", 41), ("TOKENS", 73)]


def esc(s): return html.escape(s, quote=True)


def page(rows_shown, counter_frac, new_alpha):
    parts = []
    parts.append(f'<text x="80" y="64" fill="{GOLD}" font-family="monospace" font-size="12" letter-spacing="4" opacity="0.55">VIGIL . LIVE SCAN FEED . BASE</text>')
    parts.append(f'<text x="80" y="112" fill="{TEXT}" font-family="Georgia, serif" font-size="38">The scan feed.</text>')
    parts.append(f'<text x="80" y="142" fill="{DIM}" font-family="Georgia, serif" font-size="17" font-style="italic">what VIGIL is checking on Base, in real time · anonymized</text>')

    # stat cards
    cx = 80
    for k, target in TOTALS:
        val = int(target * counter_frac)
        parts.append(f'<rect x="{cx}" y="166" width="266" height="92" rx="10" fill="{ELEV}" stroke="{BORDER}"/>')
        parts.append(f'<text x="{cx+22}" y="198" fill="{DIM}" font-family="monospace" font-size="11" letter-spacing="2">{k}</text>')
        parts.append(f'<text x="{cx+22}" y="240" fill="{GOLD}" font-family="Georgia, serif" font-size="36">{val}</text>')
        cx += 282

    # feed rows
    y = 290
    for i in range(rows_shown):
        tok, tool, verdict, color = ROWS[i]
        alpha = new_alpha if i == rows_shown - 1 else 1.0
        parts.append(f'<g opacity="{alpha:.2f}">')
        parts.append(f'<rect x="80" y="{y}" width="1120" height="58" rx="10" fill="{ELEV}" stroke="{BORDER}"/>')
        parts.append(f'<circle cx="108" cy="{y+29}" r="6" fill="{color}"/>')
        parts.append(f'<text x="132" y="{y+26}" fill="{TEXT}" font-family="monospace" font-size="16">{esc(tok)}</text>')
        parts.append(f'<text x="132" y="{y+46}" fill="{DIM}" font-family="monospace" font-size="12">{esc(tool)}</text>')
        parts.append(f'<text x="1176" y="{y+35}" text-anchor="end" fill="{color}" font-family="monospace" font-size="15" letter-spacing="1">{esc(verdict.upper())}</text>')
        parts.append('</g>')
        y += 66

    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" fill="none">
  <rect width="{W}" height="{H}" fill="{BG}"/>
  {''.join(parts)}
  <text x="80" y="{H-28}" fill="{DIM}" font-family="monospace" font-size="13">security as a public good</text>
  <text x="1200" y="{H-28}" text-anchor="end" fill="{GOLD}" font-family="monospace" font-size="13" opacity="0.7">vigil.codes/feed</text>
</svg>'''


def main():
    idx = 0
    def emit(svg):
        nonlocal idx
        sp = os.path.join(OUT_DIR, f"f_{idx:05d}.svg"); pp = os.path.join(OUT_DIR, f"f_{idx:05d}.png")
        open(sp, "w").write(svg)
        subprocess.run(["rsvg-convert", "-w", str(RW), "-h", str(RH), sp, "-o", pp], check=True)
        idx += 1

    # counters tick up while first rows already visible
    for f in range(50):
        emit(page(1, min(1.0, (f+1)/50), 1.0))
    # reveal rows one by one with fade
    for n in range(2, len(ROWS) + 1):
        for f in range(14):
            emit(page(n, 1.0, min(1.0, (f+1)/14)))
        for f in range(16):
            emit(page(n, 1.0, 1.0))
    # hold full feed
    for f in range(220):
        emit(page(len(ROWS), 1.0, 1.0))

    print(f"rendered {idx} frames")
    subprocess.run([
        "ffmpeg", "-y", "-framerate", str(FPS), "-i", os.path.join(OUT_DIR, "f_%05d.png"),
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "18",
        "-vf", f"scale={RW}:{RH}:flags=lanczos", "-movflags", "+faststart", FINAL,
    ], check=True)
    print(f"wrote {FINAL}")


if __name__ == "__main__":
    main()
