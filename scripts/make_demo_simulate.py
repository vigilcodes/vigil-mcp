#!/usr/bin/env python3
"""Approval Simulator demo — clean scene-based terminal, 1280x720 @ 60fps.

Two scenes, each cleared before the next so nothing overflows the panel:
  Scene 1: simulate a malicious spender  -> DANGEROUS verdict
  Scene 2: simulate Uniswap router       -> SAFE verdict

Design goals: smooth, aligned, never crowded. Each scene fits the panel
with room to spare; a fade transition separates them.

Frames: SVG -> PNG (rsvg-convert) -> MP4 (ffmpeg).
"""
import html
import os
import subprocess

W, H = 1280, 720
FPS = 60
OUT_DIR = "/root/vigil/.demo_simulate_frames"
FINAL = "/root/vigil/website/assets/vigil-simulate-demo-1280x720.mp4"

GOLD = "#c8a961"
GREEN = "#6bbd6b"
RED = "#bd6b6b"
AMBER = "#d89b5b"
DIM = "#6b6860"
TEXT = "#d4d0c8"
BG = "#080808"
PANEL = "#0c0c0c"

# Layout — generous spacing, panel interior is ~y176..y560 (≈11 lines max).
CHAR_W = 13.2
LINE_Y0 = 210
LINE_DY = 38
PANEL_X, PANEL_Y, PANEL_W, PANEL_H = 60, 102, W - 120, H - 184


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def dot_leader(label: str, value: str, width: int = 30) -> str:
    """Align 'label .......... value' on a fixed column for a clean look."""
    pad = max(2, width - len(label))
    return f"{label} {'.' * pad} {value}"


# Each scene is a list of steps. Steps render into a FRESH panel (cleared).
#   ("type", text, color, fpc)   typed char-by-char
#   ("line", text, color, fade)  printed instantly with short fade
#   ("gap",  "",   None, n)      blank spacer line
#   ("hold", "",   None, n)      hold current screen n frames
SCENE_1 = {
    "title": ("ATTEMPTING APPROVAL", AMBER),
    "subtitle": "approve( 0xdead…beef , USDC , unlimited )",
    "steps": [
        ("hold", "", None, 18),
        ("line", "vigil simulating spender…", DIM, 10),
        ("hold", "", None, 14),
        ("line", "  " + dot_leader("is a contract", "NO  — plain wallet"), RED, 9),
        ("hold", "", None, 7),
        ("line", "  " + dot_leader("known safe", "NO"), RED, 9),
        ("hold", "", None, 7),
        ("line", "  " + dot_leader("scam reports", "none yet"), DIM, 9),
        ("hold", "", None, 7),
        ("line", "  " + dot_leader("approval amount", "UNLIMITED"), RED, 9),
        ("hold", "", None, 22),
        ("gap", "", None, 0),
        ("verdict", "DANGEROUS  —  DO NOT APPROVE", RED, 12),
        ("hold", "", None, 95),
    ],
}

SCENE_2 = {
    "title": ("ATTEMPTING APPROVAL", AMBER),
    "subtitle": "approve( Uniswap Router , USDC , unlimited )",
    "steps": [
        ("hold", "", None, 18),
        ("line", "vigil simulating spender…", DIM, 10),
        ("hold", "", None, 14),
        ("line", "  " + dot_leader("is a contract", "YES — 12.4 KB"), GREEN, 9),
        ("hold", "", None, 7),
        ("line", "  " + dot_leader("known safe", "Uniswap Router"), GREEN, 9),
        ("hold", "", None, 7),
        ("line", "  " + dot_leader("approval amount", "unlimited (standard)"), GREEN, 9),
        ("hold", "", None, 22),
        ("gap", "", None, 0),
        ("verdict", "SAFE  —  recognized protocol", GREEN, 12),
        ("hold", "", None, 120),
    ],
}

os.makedirs(OUT_DIR, exist_ok=True)


def render_body(title, subtitle, committed, active=None, cursor=True, panel_alpha=1.0):
    """Render the panel header (title+subtitle) and the committed/active lines."""
    rows = []
    t_text, t_color = title
    # Scene title + typed subtitle live at the top of the panel.
    rows.append(
        f'<text x="72" y="186" fill="{t_color}" opacity="{panel_alpha:.2f}" '
        f'font-family="\'Courier New\', monospace" font-size="13" letter-spacing="3">{esc(t_text)}</text>'
    )
    if subtitle is not None:
        rows.append(
            f'<text x="72" y="214" fill="{TEXT}" opacity="{panel_alpha:.2f}" '
            f'font-family="Georgia, serif" font-size="22">{esc(subtitle)}</text>'
        )

    y = LINE_Y0 + 40  # body starts below the subtitle
    cur_x = cur_y = None
    for text, color, alpha in committed:
        a = alpha * panel_alpha
        if text:
            rows.append(
                f'<text x="80" y="{y}" fill="{color}" opacity="{a:.2f}" '
                f'font-family="\'Courier New\', monospace" font-size="21">{esc(text)}</text>'
            )
        cur_x = 80 + int(len(text) * CHAR_W) + 6
        cur_y = y
        y += LINE_DY
    if active is not None:
        text, color, shown = active
        shown_text = text[:shown]
        rows.append(
            f'<text x="80" y="{y}" fill="{color}" opacity="{panel_alpha:.2f}" '
            f'font-family="\'Courier New\', monospace" font-size="21">{esc(shown_text)}</text>'
        )
        cur_x = 80 + int(len(shown_text) * CHAR_W) + 6
        cur_y = y
    cur = ""
    if cursor and cur_x is not None and panel_alpha > 0.8:
        cur = f'<rect x="{cur_x}" y="{cur_y-19}" width="11" height="23" fill="{GOLD}" opacity="0.85"/>'
    return "".join(rows), cur


def verdict_box(text, color, alpha):
    """A highlighted verdict bar near the bottom of the panel."""
    y = 500
    return (
        f'<rect x="80" y="{y}" width="{PANEL_W - 40}" height="50" rx="8" '
        f'fill="{color}" opacity="{0.10 * alpha:.2f}" stroke="{color}" stroke-width="1.5" '
        f'stroke-opacity="{0.6 * alpha:.2f}"/>'
        f'<text x="104" y="{y + 33}" fill="{color}" opacity="{alpha:.2f}" '
        f'font-family="\'Courier New\', monospace" font-size="22" font-weight="600">{esc(text)}</text>'
    )


def frame_svg(inner):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" fill="none">
  <rect width="{W}" height="{H}" fill="{BG}"/>
  <text x="72" y="76" fill="{GOLD}" font-family="'Courier New', monospace" font-size="13" letter-spacing="4" opacity="0.55">VIGIL . APPROVAL SIMULATOR . SCAN BEFORE YOU SIGN</text>
  <rect x="{PANEL_X}" y="{PANEL_Y}" width="{PANEL_W}" height="{PANEL_H}" rx="14" fill="{PANEL}" stroke="{GOLD}" stroke-width="1" opacity="0.96"/>
  <circle cx="92" cy="134" r="7" fill="{RED}"/>
  <circle cx="116" cy="134" r="7" fill="{GOLD}"/>
  <circle cx="140" cy="134" r="7" fill="{GREEN}"/>
  <text x="{W//2}" y="140" text-anchor="middle" fill="{DIM}" font-family="'Courier New', monospace" font-size="14">vigil_simulate_approval -> mcp.vigil.codes</text>
  <line x1="{PANEL_X}" y1="156" x2="{PANEL_X + PANEL_W}" y2="156" stroke="#1e1e1c" stroke-width="1"/>
  {inner}
  <text x="72" y="{H-38}" fill="{DIM}" font-family="'Courier New', monospace" font-size="14">see what a spender can do BEFORE you sign</text>
  <text x="{W-70}" y="{H-38}" text-anchor="end" fill="{GOLD}" font-family="'Courier New', monospace" font-size="14" opacity="0.7">vigil.codes</text>
</svg>'''


class Renderer:
    def __init__(self):
        self.idx = 0

    def emit(self, inner):
        svg = frame_svg(inner)
        sp = os.path.join(OUT_DIR, f"f_{self.idx:05d}.svg")
        pp = os.path.join(OUT_DIR, f"f_{self.idx:05d}.png")
        with open(sp, "w") as fh:
            fh.write(svg)
        subprocess.run(["rsvg-convert", "-w", str(W), "-h", str(H), sp, "-o", pp], check=True)
        self.idx += 1

    @staticmethod
    def blink(f):
        return (f // 18) % 2 == 0

    def play_scene(self, scene):
        title = scene["title"]
        subtitle_full = scene["subtitle"]
        committed = []
        verdict = None  # (text, color)

        def compose(active=None, cursor=True, alpha=1.0):
            body, cur = render_body(title, subtitle_full, committed, active, cursor, alpha)
            vb = verdict_box(verdict[0], verdict[1], alpha) if verdict else ""
            return body + cur + vb

        # 1. Type the subtitle in (header animates first).
        for ci in range(1, len(subtitle_full) + 1):
            for _ in range(1):
                body, cur = render_body(title, subtitle_full[:ci], committed, None, True, 1.0)
                self.emit(body + cur)

        # 2. Steps.
        for kind, text, color, opt in scene["steps"]:
            if kind == "gap":
                committed.append(["", TEXT, 1.0])
            elif kind == "hold":
                for f in range(opt):
                    self.emit(compose(cursor=self.blink(f)))
            elif kind == "line":
                for f in range(opt):
                    a = min(1.0, (f + 1) / opt)
                    tmp = committed + [[text, color, a]]
                    body, cur = render_body(title, subtitle_full, tmp, None, self.blink(f), 1.0)
                    self.emit(body + cur + (verdict_box(verdict[0], verdict[1], 1.0) if verdict else ""))
                committed.append([text, color, 1.0])
            elif kind == "verdict":
                for f in range(opt):
                    a = min(1.0, (f + 1) / opt)
                    body, cur = render_body(title, subtitle_full, committed, None, False, 1.0)
                    self.emit(body + verdict_box(text, color, a))
                verdict = (text, color)

        # 3. Fade scene out (smooth transition to next).
        for f in range(14):
            a = max(0.0, 1.0 - (f + 1) / 14)
            self.emit(compose(cursor=False, alpha=a))

    def finish_with_cta(self):
        # Closing CTA card.
        for f in range(70):
            a = min(1.0, (f + 1) / 20)
            inner = (
                f'<text x="{W//2}" y="320" text-anchor="middle" fill="{TEXT}" opacity="{a:.2f}" '
                f'font-family="Georgia, serif" font-size="40">scan before you sign.</text>'
                f'<text x="{W//2}" y="380" text-anchor="middle" fill="{GOLD}" opacity="{a:.2f}" '
                f'font-family="\'Courier New\', monospace" font-size="18" letter-spacing="2">'
                f'vigil_simulate_approval . 14 tools live</text>'
            )
            self.emit(frame_svg(inner))


def main() -> None:
    r = Renderer()
    r.play_scene(SCENE_1)
    r.play_scene(SCENE_2)
    r.finish_with_cta()
    print(f"rendered {r.idx} frames")
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
