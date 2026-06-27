#!/usr/bin/env python3
"""VIGIL holder-concentration demo — animated donut, 1280x720 @ 30fps.

Teaches the tool's core insight visually:
  a whale that LOOKS like "only 30% of supply" is actually 75% of the float
  that can ACTUALLY be sold, once you exclude the LP pool, burns, and locks.

Story:
  1. donut builds segment-by-segment: pool 55%, whale 30%, burn 5%, others 10%
  2. "naive read: whale = 30%"
  3. VIGIL greys out pool + burn (not dumpable float)
  4. donut recomputes over dumpable float only -> whale = 75%
  5. verdict: DANGEROUS — one wallet controls 75% of what can sell

Frames: SVG -> PNG (rsvg-convert) -> MP4 (ffmpeg).
"""
import math
import os
import subprocess

W, H = 1280, 720
FPS = 30
OUT_DIR = "/root/vigil/.demo_holders_frames"
FINAL = "/root/vigil/website/assets/vigil-holders-1280x720.mp4"

GOLD = "#c8a961"
GOLD_SOFT = "#e8d5a3"
RED = "#d4564a"
GREEN = "#6bbd6b"
DIM = "#3a3830"
GREY = "#4a4742"
TEXT = "#d4d0c8"
TEXT_DIM = "#8a857a"
BG = "#080808"

CX, CY = 410, 380   # donut center
R_OUT, R_IN = 200, 120

os.makedirs(OUT_DIR, exist_ok=True)


def ring_segment(a0, a1, r_out=R_OUT, r_in=R_IN, cx=CX, cy=CY):
    """SVG path for a donut ring segment between angles a0..a1 (degrees, clockwise from top)."""
    # convert: 0deg = top (12 o'clock), clockwise positive
    def pt(r, a):
        rad = math.radians(a - 90)
        return cx + r * math.cos(rad), cy + r * math.sin(rad)
    large = 1 if (a1 - a0) % 360 > 180 else 0
    x0o, y0o = pt(r_out, a0)
    x1o, y1o = pt(r_out, a1)
    x1i, y1i = pt(r_in, a1)
    x0i, y0i = pt(r_in, a0)
    return (
        f"M{x0o:.2f},{y0o:.2f} "
        f"A{r_out},{r_out} 0 {large},1 {x1o:.2f},{y1o:.2f} "
        f"L{x1i:.2f},{y1i:.2f} "
        f"A{r_in},{r_in} 0 {large},0 {x0i:.2f},{y0i:.2f} Z"
    )


# Segments: (label, fraction, color, dumpable)
SEGMENTS = [
    ("Liquidity pool", 0.55, GOLD, False),
    ("Whale wallet", 0.30, RED, True),
    ("Burned", 0.05, GREY, False),
    ("Other holders", 0.10, GOLD_SOFT, True),
]


def header():
    return (
        f'<text x="64" y="70" fill="{GOLD}" font-family="\'Courier New\', monospace" '
        f'font-size="13" letter-spacing="5" opacity="0.6">VIGIL . HOLDER CONCENTRATION . tool #18</text>'
        f'<text x="64" y="{H-38}" fill="{TEXT_DIM}" font-family="\'Courier New\', monospace" '
        f'font-size="14">could a few wallets dump on you?</text>'
        f'<text x="{W-64}" y="{H-38}" text-anchor="end" fill="{GOLD}" '
        f'font-family="\'Courier New\', monospace" font-size="14" opacity="0.75">mcp.vigil.codes</text>'
    )


def donut(fractions_colors, sweep=1.0, center_label="", center_sub=""):
    """Draw donut. fractions_colors: list of (frac, color, alpha). sweep 0..1 reveals progressively."""
    parts = []
    total_shown = sweep * sum(f for f, _, _ in fractions_colors)
    acc = 0.0
    angle = 0.0
    for frac, color, alpha in fractions_colors:
        seg = frac
        if acc + seg <= total_shown:
            draw = seg
        elif acc < total_shown:
            draw = total_shown - acc
        else:
            draw = 0
        if draw > 0.0005:
            a0 = angle
            a1 = angle + draw * 360
            parts.append(f'<path d="{ring_segment(a0, a1)}" fill="{color}" opacity="{alpha:.2f}"/>')
        angle += seg * 360
        acc += seg
    inner = "".join(parts)
    cl = ""
    if center_label:
        cl = (
            f'<text x="{CX}" y="{CY-6}" text-anchor="middle" fill="{TEXT}" '
            f'font-family="\'Courier New\', monospace" font-size="40" font-weight="bold">{center_label}</text>'
        )
    cs = ""
    if center_sub:
        cs = (
            f'<text x="{CX}" y="{CY+28}" text-anchor="middle" fill="{TEXT_DIM}" '
            f'font-family="\'Courier New\', monospace" font-size="17">{center_sub}</text>'
        )
    return inner + cl + cs


LX = 700  # legend x


def legend(rows, title=""):
    """rows: list of (label, pct_text, color, struck)."""
    parts = []
    y = 210
    if title:
        parts.append(
            f'<text x="{LX}" y="{y}" fill="{TEXT_DIM}" font-family="\'Courier New\', monospace" font-size="20">{title}</text>'
        )
        y += 48
    for label, pct, color, struck in rows:
        parts.append(f'<rect x="{LX}" y="{y-18}" width="22" height="22" rx="4" fill="{color}"/>')
        tcol = GREY if struck else TEXT
        deco = ' text-decoration="line-through"' if struck else ""
        parts.append(
            f'<text x="{LX+34}" y="{y}" fill="{tcol}" font-family="\'Courier New\', monospace" font-size="22"{deco}>{label}</text>'
        )
        parts.append(
            f'<text x="{LX+430}" y="{y}" text-anchor="end" fill="{tcol}" '
            f'font-family="\'Courier New\', monospace" font-size="22"{deco}>{pct}</text>'
        )
        y += 46
    return "".join(parts)


def frame(inner):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" fill="none">'
        f'<rect width="{W}" height="{H}" fill="{BG}"/>{header()}{inner}</svg>'
    )


def emit(idx, inner):
    sp = os.path.join(OUT_DIR, f"f_{idx:05d}.svg")
    pp = os.path.join(OUT_DIR, f"f_{idx:05d}.png")
    with open(sp, "w") as fh:
        fh.write(frame(inner))
    subprocess.run(["rsvg-convert", "-w", str(W), "-h", str(H), sp, "-o", pp], check=True)


FULL = [(f, c, 1.0) for _, f, c, _ in SEGMENTS]


def main():
    idx = 0

    def title(t, sub):
        return (
            f'<text x="{LX}" y="150" fill="{GOLD}" font-family="\'Courier New\', monospace" '
            f'font-size="34" font-weight="bold">{t}</text>'
            f'<text x="{LX}" y="186" fill="{TEXT_DIM}" font-family="\'Courier New\', monospace" font-size="18">{sub}</text>'
        )

    # Scene 1: build the donut segment by segment (reveal sweep 0 -> 1)
    build_frames = 60
    for f in range(build_frames + 1):
        sweep = f / build_frames
        rows = []
        shown_total = sweep * 1.0
        acc = 0.0
        for label, frac, color, dump in SEGMENTS:
            visible = acc < shown_total
            rows.append((label, f"{frac*100:.0f}%", color, False) if visible else (label, "", DIM, False))
            acc += frac
        inner = title("Holder breakdown", "$NEWTOKEN — top wallets by share") + donut(FULL, sweep) + legend(rows)
        emit(idx, inner); idx += 1

    # hold full donut
    for _ in range(30):
        rows = [(lbl, f"{fr*100:.0f}%", col, False) for lbl, fr, col, _ in SEGMENTS]
        emit(idx, title("Holder breakdown", "$NEWTOKEN — top wallets by share") + donut(FULL, 1.0) + legend(rows)); idx += 1

    # Scene 2: naive read
    for _ in range(45):
        rows = [(lbl, f"{fr*100:.0f}%", col, False) for lbl, fr, col, _ in SEGMENTS]
        naive = (
            f'<text x="{LX}" y="500" fill="{TEXT}" font-family="\'Courier New\', monospace" font-size="22">naive read: whale = 30%</text>'
            f'<text x="{LX}" y="532" fill="{TEXT_DIM}" font-family="\'Courier New\', monospace" font-size="18">looks fine, right?</text>'
        )
        emit(idx, title("Holder breakdown", "$NEWTOKEN — top wallets by share") + donut(FULL, 1.0) + legend(rows) + naive); idx += 1

    # Scene 3: VIGIL excludes pool + burn (fade those segments to grey, strike legend)
    fade_frames = 30
    for f in range(fade_frames + 1):
        t = f / fade_frames
        fc = []
        for _, frac, color, dump in SEGMENTS:
            if dump:
                fc.append((frac, color, 1.0))
            else:
                # fade colored -> dim
                fc.append((frac, GREY, 1.0 - 0.55 * t))
        rows = [(lbl, f"{fr*100:.0f}%", (col if dump else GREY), (not dump and t > 0.5)) for lbl, fr, col, dump in SEGMENTS]
        note = (
            f'<text x="{LX}" y="500" fill="{GOLD}" font-family="\'Courier New\', monospace" font-size="20">VIGIL excludes non-sellable float:</text>'
            f'<text x="{LX}" y="530" fill="{TEXT_DIM}" font-family="\'Courier New\', monospace" font-size="17">LP pool + burns can\'t dump on you</text>'
        )
        emit(idx, title("Exclude what can't sell", "pools, burns, locks aren\'t dump risk") + donut(fc, 1.0) + legend(rows) + note); idx += 1

    # Scene 4: recompute donut over DUMPABLE float only (whale 30/(30+10)=75%, others 25%)
    dump_total = 0.30 + 0.10
    whale_d = 0.30 / dump_total  # 0.75
    other_d = 0.10 / dump_total  # 0.25
    DUMP_FULL = [(whale_d, RED, 1.0), (other_d, GOLD_SOFT, 1.0)]
    recompute = 40
    for f in range(recompute + 1):
        sweep = f / recompute
        rows = [
            ("Whale wallet", f"{whale_d*100:.0f}%", RED, False),
            ("Other holders", f"{other_d*100:.0f}%", GOLD_SOFT, False),
        ]
        note = (
            f'<text x="{LX}" y="500" fill="{TEXT}" font-family="\'Courier New\', monospace" font-size="22">of the SELLABLE float...</text>'
        )
        emit(idx, title("Concentration of dumpable float", "what can actually hit the market") +
             donut(DUMP_FULL, sweep, center_label=f"{whale_d*100:.0f}%" if sweep > 0.6 else "", center_sub="one wallet" if sweep > 0.6 else "") +
             legend(rows, title="dumpable float only") + note); idx += 1

    # Scene 5: verdict DANGEROUS
    for f in range(90):
        pulse = (math.sin(f * 0.35) + 1) / 2
        rows = [
            ("Whale wallet", "75%", RED, False),
            ("Other holders", "25%", GOLD_SOFT, False),
        ]
        box = (
            f'<rect x="{LX}" y="476" width="380" height="64" rx="12" fill="none" stroke="{RED}" stroke-width="{2+pulse*1.5:.1f}"/>'
            f'<text x="{LX+24}" y="518" fill="{RED}" font-family="\'Courier New\', monospace" font-size="34" font-weight="bold">DANGEROUS</text>'
            f'<text x="{LX}" y="585" fill="{TEXT_DIM}" font-family="\'Courier New\', monospace" font-size="18">one wallet controls 75% of what can sell.</text>'
        )
        emit(idx, title("Verdict", "clean contract \u2260 safe distribution") +
             donut(DUMP_FULL, 1.0, center_label="75%", center_sub="one wallet") +
             legend(rows, title="dumpable float only") + box); idx += 1

    print(f"rendered {idx} frames")
    subprocess.run(
        ["ffmpeg", "-y", "-framerate", str(FPS), "-i", os.path.join(OUT_DIR, "f_%05d.png"),
         "-c:v", "libx264", "-pix_fmt", "yuv420p", "-vf", "scale=1280:720:flags=lanczos",
         "-movflags", "+faststart", FINAL], check=True)
    print(f"wrote {FINAL}")


if __name__ == "__main__":
    main()
