#!/usr/bin/env python3
"""Agent Discovery demo — clean scene-based terminal, 1280x720 @ 60fps.

Narrative: an agent discovers VIGIL on its own via the x402 standard files,
reads the catalog, and calls a tool — no human, no hardcoded integration.

  Scene 1: agent scans /.well-known/x402  -> finds VIGIL
  Scene 2: agent reads /llms.txt           -> sees 14 tools
  Scene 3: agent calls + pays              -> verdict returned
  CTA

Frames: SVG -> PNG (rsvg-convert) -> MP4 (ffmpeg).
"""
import html
import os
import subprocess

W, H = 1280, 720
FPS = 60
OUT_DIR = "/root/vigil/.demo_discovery_frames"
FINAL = "/root/vigil/website/assets/vigil-discovery-demo-1280x720.mp4"

GOLD = "#c8a961"
GREEN = "#6bbd6b"
RED = "#bd6b6b"
AMBER = "#d89b5b"
DIM = "#6b6860"
TEXT = "#d4d0c8"
BG = "#080808"
PANEL = "#0c0c0c"

CHAR_W = 13.2
LINE_Y0 = 210
LINE_DY = 38
PANEL_X, PANEL_Y, PANEL_W, PANEL_H = 60, 102, W - 120, H - 184

os.makedirs(OUT_DIR, exist_ok=True)


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def dot(label, value, width=26):
    pad = max(2, width - len(label))
    return f"{label} {'.' * pad} {value}"


SCENES = [
    {
        "title": ("STEP 1 — AGENT DISCOVERS", AMBER),
        "subtitle": "GET mcp.vigil.codes/.well-known/x402",
        "steps": [
            ("hold", "", None, 16),
            ("line", "scanning x402 manifest…", DIM, 10),
            ("hold", "", None, 12),
            ("line", "  " + dot("service", "vigil-mcp"), GREEN, 9),
            ("hold", "", None, 6),
            ("line", "  " + dot("network", "base (eip155:8453)"), GREEN, 9),
            ("hold", "", None, 6),
            ("line", "  " + dot("payable resources", "6 found"), GREEN, 9),
            ("hold", "", None, 22),
            ("verdict", "DISCOVERED — no config, no API key", GREEN, 12),
            ("hold", "", None, 70),
        ],
    },
    {
        "title": ("STEP 2 — AGENT READS CATALOG", AMBER),
        "subtitle": "GET mcp.vigil.codes/llms.txt",
        "steps": [
            ("hold", "", None, 16),
            ("line", "reading tool catalog…", DIM, 10),
            ("hold", "", None, 12),
            ("line", "  " + dot("total tools", "14"), GREEN, 9),
            ("hold", "", None, 6),
            ("line", "  " + dot("free checks", "honeypot, lock, score…"), GREEN, 9),
            ("hold", "", None, 6),
            ("line", "  " + dot("paid (x402)", "consensus, scan_token…"), GOLD, 9),
            ("hold", "", None, 22),
            ("verdict", "CATALOG PARSED — machine-readable", GREEN, 12),
            ("hold", "", None, 70),
        ],
    },
    {
        "title": ("STEP 3 — AGENT CALLS + PAYS", AMBER),
        "subtitle": "vigil_consensus( 0xToken , base )",
        "steps": [
            ("hold", "", None, 16),
            ("line", "paid $0.0075 USDC on base…", DIM, 10),
            ("hold", "", None, 14),
            ("line", "  " + dot("6 sources", "voted"), GREEN, 9),
            ("hold", "", None, 6),
            ("line", "  " + dot("verdict", "SAFE"), GREEN, 9),
            ("hold", "", None, 22),
            ("verdict", "DONE — agent scanned before it signed", GREEN, 12),
            ("hold", "", None, 110),
        ],
    },
]


def render_body(title, subtitle, committed, active=None, cursor=True, alpha=1.0):
    rows = []
    t_text, t_color = title
    rows.append(
        f'<text x="72" y="186" fill="{t_color}" opacity="{alpha:.2f}" '
        f'font-family="\'Courier New\', monospace" font-size="13" letter-spacing="3">{esc(t_text)}</text>'
    )
    if subtitle is not None:
        rows.append(
            f'<text x="72" y="214" fill="{TEXT}" opacity="{alpha:.2f}" '
            f'font-family="Georgia, serif" font-size="22">{esc(subtitle)}</text>'
        )
    y = LINE_Y0 + 40
    cur_x = cur_y = None
    for text, color, a in committed:
        aa = a * alpha
        if text:
            rows.append(
                f'<text x="80" y="{y}" fill="{color}" opacity="{aa:.2f}" '
                f'font-family="\'Courier New\', monospace" font-size="21">{esc(text)}</text>'
            )
        cur_x = 80 + int(len(text) * CHAR_W) + 6
        cur_y = y
        y += LINE_DY
    if active is not None:
        text, color, shown = active
        st = text[:shown]
        rows.append(
            f'<text x="80" y="{y}" fill="{color}" opacity="{alpha:.2f}" '
            f'font-family="\'Courier New\', monospace" font-size="21">{esc(st)}</text>'
        )
        cur_x = 80 + int(len(st) * CHAR_W) + 6
        cur_y = y
    cur = ""
    if cursor and cur_x is not None and alpha > 0.8:
        cur = f'<rect x="{cur_x}" y="{cur_y-19}" width="11" height="23" fill="{GOLD}" opacity="0.85"/>'
    return "".join(rows), cur


def verdict_box(text, color, alpha):
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
  <text x="72" y="76" fill="{GOLD}" font-family="'Courier New', monospace" font-size="13" letter-spacing="4" opacity="0.55">VIGIL . AGENT-DISCOVERABLE . x402 STANDARD</text>
  <rect x="{PANEL_X}" y="{PANEL_Y}" width="{PANEL_W}" height="{PANEL_H}" rx="14" fill="{PANEL}" stroke="{GOLD}" stroke-width="1" opacity="0.96"/>
  <circle cx="92" cy="134" r="7" fill="{RED}"/>
  <circle cx="116" cy="134" r="7" fill="{GOLD}"/>
  <circle cx="140" cy="134" r="7" fill="{GREEN}"/>
  <text x="{W//2}" y="140" text-anchor="middle" fill="{DIM}" font-family="'Courier New', monospace" font-size="14">autonomous agent -> mcp.vigil.codes</text>
  <line x1="{PANEL_X}" y1="156" x2="{PANEL_X + PANEL_W}" y2="156" stroke="#1e1e1c" stroke-width="1"/>
  {inner}
  <text x="72" y="{H-38}" fill="{DIM}" font-family="'Courier New', monospace" font-size="14">agents find VIGIL on their own</text>
  <text x="{W-70}" y="{H-38}" text-anchor="end" fill="{GOLD}" font-family="'Courier New', monospace" font-size="14" opacity="0.7">vigil.codes</text>
</svg>'''


class R:
    def __init__(self):
        self.idx = 0

    def emit(self, inner):
        sp = os.path.join(OUT_DIR, f"f_{self.idx:05d}.svg")
        pp = os.path.join(OUT_DIR, f"f_{self.idx:05d}.png")
        with open(sp, "w") as fh:
            fh.write(frame_svg(inner))
        subprocess.run(["rsvg-convert", "-w", str(W), "-h", str(H), sp, "-o", pp], check=True)
        self.idx += 1

    @staticmethod
    def blink(f):
        return (f // 18) % 2 == 0

    def scene(self, sc):
        title = sc["title"]
        sub = sc["subtitle"]
        committed = []
        verdict = None

        for ci in range(1, len(sub) + 1):
            body, cur = render_body(title, sub[:ci], committed, None, True, 1.0)
            self.emit(body + cur)

        for kind, text, color, opt in sc["steps"]:
            if kind == "hold":
                for f in range(opt):
                    body, cur = render_body(title, sub, committed, None, self.blink(f), 1.0)
                    vb = verdict_box(verdict[0], verdict[1], 1.0) if verdict else ""
                    self.emit(body + cur + vb)
            elif kind == "line":
                for f in range(opt):
                    a = min(1.0, (f + 1) / opt)
                    tmp = committed + [[text, color, a]]
                    body, cur = render_body(title, sub, tmp, None, self.blink(f), 1.0)
                    vb = verdict_box(verdict[0], verdict[1], 1.0) if verdict else ""
                    self.emit(body + cur + vb)
                committed.append([text, color, 1.0])
            elif kind == "verdict":
                for f in range(opt):
                    a = min(1.0, (f + 1) / opt)
                    body, _ = render_body(title, sub, committed, None, False, 1.0)
                    self.emit(body + verdict_box(text, color, a))
                verdict = (text, color)

        for f in range(12):
            a = max(0.0, 1.0 - (f + 1) / 12)
            body, _ = render_body(title, sub, committed, None, False, a)
            vb = verdict_box(verdict[0], verdict[1], a) if verdict else ""
            self.emit(body + vb)

    def cta(self):
        for f in range(75):
            a = min(1.0, (f + 1) / 20)
            inner = (
                f'<text x="{W//2}" y="310" text-anchor="middle" fill="{TEXT}" opacity="{a:.2f}" '
                f'font-family="Georgia, serif" font-size="38">agents find VIGIL on their own.</text>'
                f'<text x="{W//2}" y="372" text-anchor="middle" fill="{GOLD}" opacity="{a:.2f}" '
                f'font-family="\'Courier New\', monospace" font-size="17" letter-spacing="2">'
                f'/llms.txt . /.well-known/x402 . 14 tools live</text>'
            )
            self.emit(frame_svg(inner))


def main():
    r = R()
    for sc in SCENES:
        r.scene(sc)
    r.cta()
    print(f"rendered {r.idx} frames")
    subprocess.run(
        ["ffmpeg", "-y", "-framerate", str(FPS), "-i", os.path.join(OUT_DIR, "f_%05d.png"),
         "-c:v", "libx264", "-pix_fmt", "yuv420p", "-vf", "scale=1280:720:flags=lanczos",
         "-movflags", "+faststart", FINAL],
        check=True,
    )
    print(f"wrote {FINAL}")


if __name__ == "__main__":
    main()
