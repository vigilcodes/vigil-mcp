#!/usr/bin/env python3
"""Aeon-integration demo video for VIGIL — typewriter terminal, 1280x720 @ 60fps.

Narrative: an autonomous Aeon agent is about to sign -> VIGIL intercepts in-loop
-> 5-source consensus -> safe to proceed, no human in the loop.

Animation model (a small timeline of events appended frame by frame):
  - TYPE  line: revealed character-by-character (typewriter), blinking cursor
  - PRINT line: appears instantly (program output), brief fade-in
  - HOLD       : keep current screen for N frames
Frames: SVG -> PNG (rsvg-convert) -> MP4 (ffmpeg).
"""
import html
import os
import subprocess

W, H = 1280, 720
FPS = 60
OUT_DIR = "/root/vigil/.demo_aeon_frames"
FINAL = "/root/vigil/website/assets/vigil-aeon-demo-1280x720.mp4"

GOLD = "#c8a961"
GREEN = "#6bbd6b"
RED = "#bd6b6b"
DIM = "#6b6860"
TEXT = "#d4d0c8"
BG = "#080808"
PANEL = "#0c0c0c"

CHAR_W = 13.2
LINE_Y0 = 160
LINE_DY = 33

os.makedirs(OUT_DIR, exist_ok=True)

# Script: each entry is (kind, text, color, opt)
#   kind "type"  -> typed char by char, opt = frames per char
#   kind "print" -> printed instantly with fade, opt = fade frames
#   kind "blank" -> empty spacer line
#   kind "hold"  -> hold current screen, opt = frames
SCRIPT = [
    ("type",  "aeon agent :: autonomous loop running", GOLD, 2),
    ("hold",  "", None, 14),
    ("type",  "next action -> swap into $NEWTOKEN", DIM, 2),
    ("hold",  "", None, 20),
    ("blank", "", None, 0),
    ("type",  "vigil :: scan before sign  [in-loop]", GOLD, 2),
    ("hold",  "", None, 16),
    ("print", "  honeypot     ........  can sell", GREEN, 8),
    ("hold",  "", None, 8),
    ("print", "  tax          ........  OWNER-MODIFIABLE", RED, 8),
    ("hold",  "", None, 10),
    ("print", "  ownership    ........  mint + pause live", RED, 8),
    ("hold",  "", None, 10),
    ("print", "  clone        ........  matches scam DB", RED, 8),
    ("hold",  "", None, 10),
    ("print", "  liquidity    ........  unlocked", RED, 8),
    ("hold",  "", None, 18),
    ("blank", "", None, 0),
    ("print", "consensus  ->  DANGEROUS", RED, 10),
    ("hold",  "", None, 30),
    ("print", "agent aborts the swap. funds safe.", GREEN, 10),
    ("hold",  "", None, 24),
    ("print", "no human in the loop.", DIM, 10),
    ("hold",  "", None, 150),
]


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def render_lines(committed, active=None, cursor=True):
    """committed: list of (text,color,alpha). active: (text,color,shown_chars)."""
    rows = []
    y = LINE_Y0
    cur_x = cur_y = None
    for text, color, alpha in committed:
        if text:
            rows.append(
                f'<text x="72" y="{y}" fill="{color}" opacity="{alpha:.2f}" '
                f'font-family="\'Courier New\', monospace" font-size="22">{esc(text)}</text>'
            )
        cur_x = 72 + int(len(text) * CHAR_W) + 6
        cur_y = y
        y += LINE_DY
    if active is not None:
        text, color, shown = active
        shown_text = text[:shown]
        rows.append(
            f'<text x="72" y="{y}" fill="{color}" '
            f'font-family="\'Courier New\', monospace" font-size="22">{esc(shown_text)}</text>'
        )
        cur_x = 72 + int(len(shown_text) * CHAR_W) + 6
        cur_y = y
    cur = ""
    if cursor and cur_x is not None:
        cur = f'<rect x="{cur_x}" y="{cur_y-20}" width="11" height="24" fill="{GOLD}" opacity="0.85"/>'
    return "".join(rows), cur


def frame_svg(body, cursor):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" fill="none">
  <rect width="{W}" height="{H}" fill="{BG}"/>
  <text x="72" y="76" fill="{GOLD}" font-family="'Courier New', monospace" font-size="13" letter-spacing="4" opacity="0.55">VIGIL x AEON . SECURITY IN THE AGENT LOOP</text>
  <rect x="60" y="102" width="{W-120}" height="{H-184}" rx="14" fill="{PANEL}" stroke="{GOLD}" stroke-width="1" opacity="0.96"/>
  <circle cx="92" cy="134" r="7" fill="{RED}"/>
  <circle cx="116" cy="134" r="7" fill="{GOLD}"/>
  <circle cx="140" cy="134" r="7" fill="{GREEN}"/>
  <text x="{W//2}" y="140" text-anchor="middle" fill="{DIM}" font-family="'Courier New', monospace" font-size="14">aeon agent runtime -> mcp.vigil.codes</text>
  <line x1="60" y1="156" x2="{W-60}" y2="156" stroke="#1e1e1c" stroke-width="1"/>
  {body}
  {cursor}
  <text x="72" y="{H-38}" fill="{DIM}" font-family="'Courier New', monospace" font-size="14">drop-in Aeon skill . read-only . 17 tools</text>
  <text x="{W-70}" y="{H-38}" text-anchor="end" fill="{GOLD}" font-family="'Courier New', monospace" font-size="14" opacity="0.7">vigil.codes</text>
</svg>'''


def main() -> None:
    idx = 0
    committed = []  # list of [text, color, alpha]

    def emit(body, cur):
        nonlocal idx
        svg = frame_svg(body, cur)
        sp = os.path.join(OUT_DIR, f"f_{idx:05d}.svg")
        pp = os.path.join(OUT_DIR, f"f_{idx:05d}.png")
        with open(sp, "w") as fh:
            fh.write(svg)
        subprocess.run(["rsvg-convert", "-w", str(W), "-h", str(H), sp, "-o", pp], check=True)
        idx += 1

    def blink(f):
        return (f // 18) % 2 == 0

    for kind, text, color, opt in SCRIPT:
        if kind == "blank":
            committed.append(["", color or TEXT, 1.0])
            continue
        if kind == "hold":
            for f in range(opt):
                body, cur = render_lines(committed, cursor=blink(f))
                emit(body, cur)
            continue
        if kind == "type":
            for ci in range(1, len(text) + 1):
                for _ in range(opt):
                    body, cur = render_lines(committed, active=(text, color, ci), cursor=True)
                    emit(body, cur)
            committed.append([text, color, 1.0])
            continue
        if kind == "print":
            for f in range(opt):
                a = min(1.0, (f + 1) / opt)
                tmp = committed + [[text, color, a]]
                body, cur = render_lines(tmp, cursor=blink(f))
                emit(body, cur)
            committed.append([text, color, 1.0])
            continue

    print(f"rendered {idx} frames")
    subprocess.run(
        [
            "ffmpeg", "-y", "-framerate", str(FPS),
            "-i", os.path.join(OUT_DIR, "f_%05d.png"),
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
