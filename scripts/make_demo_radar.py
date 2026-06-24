#!/usr/bin/env python3
"""VIGIL × Aeon radar-sweep demo — 1280x720 @ 60fps.

Visual language mirrors the vigil.codes hero radar (gold sweep, concentric
rings, blinking blips) so the clip is unmistakably VIGIL. Narrative:

  an aeon agent is about to sign -> VIGIL radar sweeps the target ->
  threat blips light up as the sweep passes them (tax, mint, clone, LP) ->
  verdict locks to DANGEROUS -> agent aborts. no human in the loop.

Frames: SVG -> PNG (rsvg-convert) -> MP4 (ffmpeg).
"""
import math
import os
import subprocess

W, H = 1280, 720
FPS = 60
OUT_DIR = "/root/vigil/.demo_radar_frames"
FINAL = "/root/vigil/website/assets/vigil-aeon-radar-1280x720.mp4"

GOLD = "#c8a961"
GOLD_SOFT = "#e8d5a3"
GREEN = "#6bbd6b"
RED = "#d4564a"
DIM = "#6b6860"
TEXT = "#d4d0c8"
BG = "#080808"

# Radar geometry (left-of-center so the verdict panel sits on the right)
CX, CY = 430, 380
R = 250

os.makedirs(OUT_DIR, exist_ok=True)

# Threat blips: angle (deg, 0=east, clockwise positive downward), radius frac, label
# These are the signals VIGIL's new scanners surface.
BLIPS = [
    (35, 0.62, "tax: modifiable"),
    (105, 0.48, "owner: mint+pause"),
    (170, 0.70, "clone: scam match"),
    (250, 0.55, "LP: unlocked"),
    (320, 0.40, "honeypot: ok"),  # the one safe signal
]
SAFE_INDEX = 4  # last blip is the green "ok" one


def blip_xy(angle_deg, rfrac):
    a = math.radians(angle_deg)
    return CX + math.cos(a) * R * rfrac, CY + math.sin(a) * R * rfrac


def norm_angle(d):
    return d % 360


def sweep_passed(blip_angle, sweep_angle, prev_sweep):
    """True once the sweep line has rotated past the blip's angle."""
    b = norm_angle(blip_angle)
    s = norm_angle(sweep_angle)
    p = norm_angle(prev_sweep)
    if p <= s:
        return p <= b <= s
    # wrapped past 360
    return b >= p or b <= s


def header_footer():
    return (
        f'<text x="64" y="70" fill="{GOLD}" font-family="\'Courier New\', monospace" '
        f'font-size="13" letter-spacing="5" opacity="0.6">VIGIL . SCAN BEFORE SIGN . BASE</text>'
        f'<text x="64" y="{H-40}" fill="{DIM}" font-family="\'Courier New\', monospace" '
        f'font-size="14">drop-in aeon skill . read-only . 17 tools</text>'
        f'<text x="{W-64}" y="{H-40}" text-anchor="end" fill="{GOLD}" '
        f'font-family="\'Courier New\', monospace" font-size="14" opacity="0.75">vigil.codes</text>'
    )


def radar_base():
    parts = [f'<circle cx="{CX}" cy="{CY}" r="{R}" fill="none" stroke="#1e1e1c" stroke-width="1.5"/>']
    for frac in (0.75, 0.5, 0.25):
        parts.append(f'<circle cx="{CX}" cy="{CY}" r="{R*frac:.0f}" fill="none" stroke="#1e1e1c" stroke-width="1"/>')
    parts.append(f'<line x1="{CX-R}" y1="{CY}" x2="{CX+R}" y2="{CY}" stroke="#1e1e1c" stroke-width="1"/>')
    parts.append(f'<line x1="{CX}" y1="{CY-R}" x2="{CX}" y2="{CY+R}" stroke="#1e1e1c" stroke-width="1"/>')
    parts.append(f'<circle cx="{CX}" cy="{CY}" r="6" fill="{GOLD}"/>')
    return "".join(parts)


def sweep_svg(angle_deg):
    a = math.radians(angle_deg)
    ex = CX + math.cos(a) * R
    ey = CY + math.sin(a) * R
    # trailing wedge (conic-like) approximated by a filled arc behind the line
    trail = 46  # degrees of glow trail
    a2 = math.radians(angle_deg - trail)
    tx = CX + math.cos(a2) * R
    ty = CY + math.sin(a2) * R
    large = 0
    wedge = (
        f'<path d="M{CX},{CY} L{tx:.1f},{ty:.1f} A{R},{R} 0 {large},1 {ex:.1f},{ey:.1f} Z" '
        f'fill="{GOLD}" opacity="0.07"/>'
    )
    line = f'<line x1="{CX}" y1="{CY}" x2="{ex:.1f}" y2="{ey:.1f}" stroke="{GOLD}" stroke-width="2.5" opacity="0.85"/>'
    return wedge + line


def blip_svg(i, revealed, pulse):
    angle, rfrac, label = BLIPS[i]
    x, y = blip_xy(angle, rfrac)
    if not revealed:
        # faint, undetected
        return f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{DIM}" opacity="0.3"/>'
    color = GREEN if i == SAFE_INDEX else RED
    rad = 6 + pulse * 3
    glow = f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{rad+8:.1f}" fill="{color}" opacity="0.10"/>'
    dot = f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{rad:.1f}" fill="{color}"/>'
    # label tag
    tag = (
        f'<text x="{x+14:.1f}" y="{y+5:.1f}" fill="{color}" '
        f'font-family="\'Courier New\', monospace" font-size="15">{label}</text>'
    )
    return glow + dot + tag


PANEL_X = 760


def panel_svg(detected, verdict_state, agent_line):
    """Right-side status panel. verdict_state: None|'scan'|'danger'."""
    parts = [
        f'<text x="{PANEL_X}" y="170" fill="{DIM}" font-family="\'Courier New\', monospace" '
        f'font-size="15">aeon agent :: autonomous</text>',
        f'<text x="{PANEL_X}" y="205" fill="{TEXT}" font-family="\'Courier New\', monospace" '
        f'font-size="17">{agent_line}</text>',
        f'<line x1="{PANEL_X}" y1="235" x2="{W-64}" y2="235" stroke="#1e1e1c" stroke-width="1"/>',
    ]
    y = 285
    labels = ["honeypot", "tax", "ownership", "clone", "liquidity"]
    # map detected booleans to display rows in a stable order
    rows = [
        ("honeypot", "ok", GREEN),
        ("tax", "modifiable", RED),
        ("ownership", "mint + pause", RED),
        ("clone", "scam match", RED),
        ("liquidity", "unlocked", RED),
    ]
    for i, (name, val, color) in enumerate(rows):
        if detected[i]:
            parts.append(
                f'<text x="{PANEL_X}" y="{y}" fill="{DIM}" font-family="\'Courier New\', monospace" font-size="16">{name}</text>'
            )
            parts.append(
                f'<text x="{PANEL_X+210}" y="{y}" fill="{color}" font-family="\'Courier New\', monospace" font-size="16">{val}</text>'
            )
        y += 38
    if verdict_state == "danger":
        parts.append(
            f'<rect x="{PANEL_X}" y="520" width="300" height="60" rx="10" fill="none" stroke="{RED}" stroke-width="2.5"/>'
        )
        parts.append(
            f'<text x="{PANEL_X+24}" y="560" fill="{RED}" font-family="\'Courier New\', monospace" '
            f'font-size="34" font-weight="bold">DANGEROUS</text>'
        )
    return "".join(parts)


def frame_svg(inner):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" fill="none">'
        f'<rect width="{W}" height="{H}" fill="{BG}"/>'
        f'{header_footer()}{inner}</svg>'
    )


def emit(idx, inner):
    svg = frame_svg(inner)
    sp = os.path.join(OUT_DIR, f"f_{idx:05d}.svg")
    pp = os.path.join(OUT_DIR, f"f_{idx:05d}.png")
    with open(sp, "w") as fh:
        fh.write(svg)
    subprocess.run(["rsvg-convert", "-w", str(W), "-h", str(H), sp, "-o", pp], check=True)


def main():
    idx = 0
    revealed = [False] * len(BLIPS)
    detected_rows = [False] * 5  # honeypot, tax, ownership, clone, liquidity

    # blip angle -> detected_rows index
    blip_to_row = {0: 1, 1: 2, 2: 3, 3: 4, 4: 0}  # tax, ownership, clone, LP, honeypot

    # Phase 1: intro hold (agent about to sign)
    for f in range(36):
        inner = radar_base() + sweep_svg(-90) + panel_svg([False] * 5, None, "next -> swap $NEWTOKEN")
        emit(idx, inner)
        idx += 1

    # Phase 2: two full sweeps revealing blips as the line passes them
    sweep_start = -90.0
    total_sweep_frames = 240  # 4s, two rotations
    prev_angle = sweep_start
    for f in range(total_sweep_frames):
        angle = sweep_start + (f / total_sweep_frames) * 720  # two full turns
        for i, (b_angle, _, _) in enumerate(BLIPS):
            if not revealed[i] and sweep_passed(b_angle, angle, prev_angle):
                revealed[i] = True
                detected_rows[blip_to_row[i]] = True
        prev_angle = angle
        pulse = (math.sin(f * 0.4) + 1) / 2
        blips = "".join(blip_svg(i, revealed[i], pulse) for i in range(len(BLIPS)))
        inner = (
            radar_base()
            + sweep_svg(angle)
            + blips
            + panel_svg(detected_rows, "scan", "scanning before sign...")
        )
        emit(idx, inner)
        idx += 1

    # Phase 3: verdict lock — DANGEROUS
    for f in range(60):
        pulse = (math.sin(f * 0.5) + 1) / 2
        blips = "".join(blip_svg(i, revealed[i], pulse) for i in range(len(BLIPS)))
        inner = radar_base() + sweep_svg(-90 + 720) + blips + panel_svg(detected_rows, "danger", "scanning before sign...")
        emit(idx, inner)
        idx += 1

    # Phase 4: agent aborts
    for f in range(120):
        pulse = (math.sin(f * 0.5) + 1) / 2
        blips = "".join(blip_svg(i, revealed[i], pulse) for i in range(len(BLIPS)))
        inner = (
            radar_base()
            + blips
            + panel_svg(detected_rows, "danger", "agent aborts. funds safe.")
            + f'<text x="{PANEL_X}" y="620" fill="{DIM}" font-family="\'Courier New\', monospace" '
            f'font-size="16">no human in the loop.</text>'
        )
        emit(idx, inner)
        idx += 1

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
