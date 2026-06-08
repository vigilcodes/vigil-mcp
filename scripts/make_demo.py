#!/usr/bin/env python3
"""Generate a smooth terminal-style demo video for VIGIL (Twitter, 1280x720).

Builds frames as SVG -> PNG (via rsvg-convert), then ffmpeg stitches them into
an MP4. The narrative mirrors the origin-story tweet:
  agent wants to approve  ->  VIGIL pauses  ->  scans 5 sources  ->  verdict.

A scene = (list of terminal lines already typed, hold_frames). Lines appear one
at a time, then the scene holds, producing a clean typewriter feel without
per-character jitter.
"""
import html
import os
import subprocess

W, H = 1280, 720
FPS = 30
OUT_DIR = "/root/vigil/.demo_frames"
FINAL = "/root/vigil/website/assets/vigil-demo-1280x720.mp4"

GOLD = "#c8a961"
GREEN = "#6bbd6b"
RED = "#bd6b6b"
DIM = "#6b6860"
TEXT = "#d4d0c8"
BG = "#080808"
PANEL = "#0c0c0c"

os.makedirs(OUT_DIR, exist_ok=True)

# Each line: (text, color). Scenes reveal lines progressively.
LINES = [
    ("$ agent: approve(spender, unlimited)", DIM),
    ("", TEXT),
    ("vigil :: intercept before signature", GOLD),
    ("scanning 5 independent sources...", TEXT),
    ("", TEXT),
    ("  goplus      ........  ok", GREEN),
    ("  onchain     ........  ok", GREEN),
    ("  market      ........  ok", GREEN),
    ("  deployer    ........  ok", GREEN),
    ("  scam db     ........  ok", GREEN),
    ("", TEXT),
    ("verdict: 5/5 sources agree  ->  SAFE", GREEN),
    ("confidence: 1.00   false-positive guard: on", DIM),
]

# Reveal schedule: (lines_visible, hold_frames)
SCHEDULE = [
    (1, 18),
    (3, 14),
    (4, 16),
    (5, 6),
    (6, 8),
    (7, 8),
    (8, 8),
    (9, 8),
    (10, 8),
    (11, 6),
    (12, 22),
    (13, 60),
]


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def frame_svg(n_visible: int, cursor: bool) -> str:
    rows = []
    y = 168
    for i, (text, color) in enumerate(LINES[:n_visible]):
        if text:
            rows.append(
                f'<text x="70" y="{y}" fill="{color}" '
                f'font-family="\'Courier New\', monospace" font-size="22">{esc(text)}</text>'
            )
        y += 38
    # blinking cursor on the last revealed line
    cur = ""
    if cursor and n_visible <= len(LINES):
        cy = 168 + (n_visible - 1) * 38
        last_len = len(LINES[n_visible - 1][0]) if n_visible >= 1 else 0
        cx = 70 + int(last_len * 13.2) + 6
        cur = f'<rect x="{cx}" y="{cy-20}" width="11" height="24" fill="{GOLD}" opacity="0.8"/>'
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" fill="none">
  <rect width="{W}" height="{H}" fill="{BG}"/>
  <text x="70" y="74" fill="{GOLD}" font-family="'Courier New', monospace" font-size="13" letter-spacing="4" opacity="0.55">VIGIL . SCAN BEFORE YOU SIGN . BASE</text>
  <rect x="60" y="100" width="{W-120}" height="{H-180}" rx="14" fill="{PANEL}" stroke="{GOLD}" stroke-width="1" opacity="0.96"/>
  <circle cx="92" cy="132" r="7" fill="{RED}"/>
  <circle cx="116" cy="132" r="7" fill="{GOLD}"/>
  <circle cx="140" cy="132" r="7" fill="{GREEN}"/>
  <text x="{W//2}" y="138" text-anchor="middle" fill="{DIM}" font-family="'Courier New', monospace" font-size="14">mcp.vigil.codes / tools/call</text>
  <line x1="60" y1="152" x2="{W-60}" y2="152" stroke="#1e1e1c" stroke-width="1"/>
  {''.join(rows)}
  {cur}
  <text x="{W-70}" y="{H-40}" text-anchor="end" fill="{GOLD}" font-family="'Courier New', monospace" font-size="14" opacity="0.7">vigil.codes</text>
</svg>'''


def main() -> None:
    idx = 0
    for n_visible, hold in SCHEDULE:
        for f in range(hold):
            cursor = (f // 8) % 2 == 0  # blink ~ every 8 frames
            svg = frame_svg(n_visible, cursor)
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
