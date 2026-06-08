#!/usr/bin/env python3
"""Aeon-integration demo video for VIGIL (Twitter, 1280x720, smooth).

Narrative: an autonomous Aeon agent is about to sign -> VIGIL intercepts inside
the agent loop -> 5-source consensus -> safe to proceed, no human in the loop.

Frames rendered as SVG -> PNG (rsvg-convert), stitched with ffmpeg. Uses a
fade-in alpha ramp per line for a smooth (non-jittery) reveal.
"""
import html
import os
import subprocess

W, H = 1280, 720
FPS = 30
OUT_DIR = "/root/vigil/.demo_aeon_frames"
FINAL = "/root/vigil/website/assets/vigil-aeon-demo-1280x720.mp4"

GOLD = "#c8a961"
GREEN = "#6bbd6b"
RED = "#bd6b6b"
DIM = "#6b6860"
TEXT = "#d4d0c8"
BG = "#080808"
PANEL = "#0c0c0c"

os.makedirs(OUT_DIR, exist_ok=True)

LINES = [
    ("aeon agent :: autonomous loop running", GOLD),
    ("next action -> approve(spender, unlimited)", DIM),
    ("", TEXT),
    ("vigil :: scan before sign  [in-loop]", GOLD),
    ("  goplus      ........  ok", GREEN),
    ("  onchain     ........  ok", GREEN),
    ("  market      ........  ok", GREEN),
    ("  deployer    ........  ok", GREEN),
    ("  scam db     ........  ok", GREEN),
    ("", TEXT),
    ("consensus: 5/5 agree  ->  SAFE", GREEN),
    ("agent proceeds. no human in the loop.", DIM),
]

# (lines_visible, hold_frames)
SCHEDULE = [
    (1, 20),
    (2, 16),
    (4, 18),
    (5, 9),
    (6, 9),
    (7, 9),
    (8, 9),
    (9, 9),
    (11, 26),
    (12, 70),
]

CHAR_W = 13.2
LINE_Y0 = 172
LINE_DY = 40


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def frame_svg(n_visible: int, new_alpha: float, cursor: bool) -> str:
    rows = []
    y = LINE_Y0
    for i, (text, color) in enumerate(LINES[:n_visible]):
        alpha = new_alpha if i == n_visible - 1 else 1.0
        if text:
            rows.append(
                f'<text x="72" y="{y}" fill="{color}" opacity="{alpha:.2f}" '
                f'font-family="\'Courier New\', monospace" font-size="22">{esc(text)}</text>'
            )
        y += LINE_DY
    cur = ""
    if cursor:
        cy = LINE_Y0 + (n_visible - 1) * LINE_DY
        last_len = len(LINES[n_visible - 1][0]) if n_visible >= 1 else 0
        cx = 72 + int(last_len * CHAR_W) + 6
        cur = f'<rect x="{cx}" y="{cy-20}" width="11" height="24" fill="{GOLD}" opacity="0.85"/>'
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" fill="none">
  <rect width="{W}" height="{H}" fill="{BG}"/>
  <text x="72" y="76" fill="{GOLD}" font-family="'Courier New', monospace" font-size="13" letter-spacing="4" opacity="0.55">VIGIL x AEON . SECURITY IN THE AGENT LOOP</text>
  <rect x="60" y="102" width="{W-120}" height="{H-184}" rx="14" fill="{PANEL}" stroke="{GOLD}" stroke-width="1" opacity="0.96"/>
  <circle cx="92" cy="134" r="7" fill="{RED}"/>
  <circle cx="116" cy="134" r="7" fill="{GOLD}"/>
  <circle cx="140" cy="134" r="7" fill="{GREEN}"/>
  <text x="{W//2}" y="140" text-anchor="middle" fill="{DIM}" font-family="'Courier New', monospace" font-size="14">aeon agent runtime -> mcp.vigil.codes</text>
  <line x1="60" y1="156" x2="{W-60}" y2="156" stroke="#1e1e1c" stroke-width="1"/>
  {''.join(rows)}
  {cur}
  <text x="72" y="{H-38}" fill="{DIM}" font-family="'Courier New', monospace" font-size="14">merged into the Aeon agent stack</text>
  <text x="{W-70}" y="{H-38}" text-anchor="end" fill="{GOLD}" font-family="'Courier New', monospace" font-size="14" opacity="0.7">vigil.codes</text>
</svg>'''


def main() -> None:
    idx = 0
    for n_visible, hold in SCHEDULE:
        for f in range(hold):
            # fade-in ramp over first 6 frames of each new line
            new_alpha = min(1.0, (f + 1) / 6.0)
            cursor = (f // 8) % 2 == 0
            svg = frame_svg(n_visible, new_alpha, cursor)
            svg_path = os.path.join(OUT_DIR, f"f_{idx:04d}.svg")
            png_path = os.path.join(OUT_DIR, f"f_{idx:04d}.png")
            with open(svg_path, "w") as fh:
                fh.write(svg)
            subprocess.run(
                ["rsvg-convert", "-w", str(W), "-h", str(H), svg_path, "-o", png_path],
                check=True,
            )
            idx += 1
    print(f"rendered {idx} frames")

    subprocess.run(
        [
            "ffmpeg", "-y", "-framerate", str(FPS),
            "-i", os.path.join(OUT_DIR, "f_%04d.png"),
            "-c:v", "libx264", "-pix_fmt", "yuv420p",
            "-vf", "scale=1280:720:flags=lanczos",
            "-movflags", "+faststart",
            FINAL,
        ],
        check=True,
    )
    print(f"wrote {FINAL}")


if __name__ == "__main__":
    main()
