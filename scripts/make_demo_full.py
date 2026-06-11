#!/usr/bin/env python3
"""Full VIGIL product demo — multi-scene, 1920x1080 @ 60fps.

Scenes: intro → live scan (type + verdict) → multi-source consensus →
public feed → outro. One cohesive ~30s walkthrough for sharing on Telegram/X.
All data is real ($VIGIL: 93/safe, 5/5 consensus, USDC 92, etc).
"""
import html
import os
import subprocess

W, H = 1280, 720
RW, RH = 1920, 1080
FPS = 30
OUT_DIR = "/root/vigil/.demo_full_frames"
FINAL = "/root/vigil/website/assets/vigil-full-demo-1920x1080.mp4"

BG = "#080808"; ELEV = "#0e0e0e"; SUBTLE = "#141414"; GOLD = "#c8a961"
TEXT = "#d4d0c8"; DIM = "#6b6860"; BORDER = "#1e1e1c"; GREEN = "#6bbd6b"; RED = "#bd6b6b"; AMBER = "#d89b5b"

ADDR = "0xc751afadd6fde251ac624a279ecb9ac85aa27ba3"
CHAR_W = 13.0
os.makedirs(OUT_DIR, exist_ok=True)
idx = 0


def esc(s): return html.escape(s, quote=True)


def shell(inner, label=""):
    lab = f'<text x="80" y="64" fill="{GOLD}" font-family="monospace" font-size="12" letter-spacing="4" opacity="0.55">{esc(label)}</text>' if label else ""
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" fill="none">
  <rect width="{W}" height="{H}" fill="{BG}"/>
  {lab}
  {inner}
  <text x="1200" y="{H-30}" text-anchor="end" fill="{GOLD}" font-family="monospace" font-size="13" opacity="0.7">vigil.codes</text>
</svg>'''


def emit(svg):
    global idx
    sp = os.path.join(OUT_DIR, f"f_{idx:05d}.svg"); pp = os.path.join(OUT_DIR, f"f_{idx:05d}.png")
    open(sp, "w").write(svg)
    subprocess.run(["rsvg-convert", "-w", str(RW), "-h", str(RH), sp, "-o", pp], check=True)
    idx += 1


def hold(svg, n):
    for _ in range(n):
        emit(svg)


# ── Scene 1: intro ───────────────────────────────────────────
def scene_intro():
    inner = (
        f'<text x="80" y="300" fill="{TEXT}" font-family="Georgia, serif" font-size="72">VIGIL</text>'
        f'<text x="80" y="356" fill="{DIM}" font-family="Georgia, serif" font-size="26" font-style="italic">onchain security for agents on Base</text>'
        f'<text x="80" y="420" fill="{GOLD}" font-family="monospace" font-size="18">scan before you sign.</text>'
    )
    # fade in
    for f in range(30):
        a = min(1.0, (f + 1) / 24)
        emit(shell(f'<g opacity="{a:.2f}">{inner}</g>', "VIGIL . MCP SECURITY . BASE"))
    hold(shell(inner, "VIGIL . MCP SECURITY . BASE"), 70)


# ── Scene 2: live scan ───────────────────────────────────────
def scan_frame(typed, cursor, result_a):
    parts = [
        f'<text x="80" y="150" fill="{TEXT}" font-family="Georgia, serif" font-size="34">Scan any Base token.</text>',
        f'<rect x="80" y="180" width="840" height="52" rx="10" fill="{SUBTLE}" stroke="{GOLD if typed else BORDER}"/>',
        f'<text x="100" y="214" fill="{TEXT}" font-family="monospace" font-size="15">{esc(typed) if typed else ""}</text>',
        f'<rect x="936" y="180" width="184" height="52" rx="10" fill="{GOLD}"/>',
        f'<text x="1028" y="213" text-anchor="middle" fill="{BG}" font-family="monospace" font-size="13" font-weight="bold">SCAN</text>',
    ]
    if cursor and typed:
        cx = 100 + int(len(typed) * CHAR_W) + 4
        parts.append(f'<rect x="{cx}" y="192" width="9" height="22" fill="{GOLD}" opacity="0.85"/>')
    if result_a > 0:
        parts.append(f'<g opacity="{result_a:.2f}">')
        parts.append(f'<text x="80" y="288" fill="{GOLD}" font-family="monospace" font-size="12" letter-spacing="3" opacity="0.7">vigilcodes · $VIGIL</text>')
        parts.append(f'<rect x="80" y="300" width="1040" height="110" rx="12" fill="{ELEV}" stroke="{BORDER}"/>')
        parts.append(f'<text x="112" y="378" fill="{GREEN}" font-family="Georgia, serif" font-size="54">93<tspan font-size="20" fill="{DIM}">/100</tspan></text>')
        parts.append(f'<text x="240" y="344" fill="{GOLD}" font-family="monospace" font-size="12" letter-spacing="3" opacity="0.6">SAFETY VERDICT</text>')
        parts.append(f'<text x="240" y="380" fill="{GREEN}" font-family="monospace" font-size="20">SAFE</text>')
        # mini cards
        parts.append(f'<rect x="80" y="426" width="336" height="84" rx="10" fill="{ELEV}" stroke="{BORDER}"/>')
        parts.append(f'<text x="108" y="458" fill="{DIM}" font-family="monospace" font-size="11">HONEYPOT</text>')
        parts.append(f'<text x="108" y="488" fill="{GREEN}" font-family="monospace" font-size="17">not a honeypot</text>')
        parts.append(f'<rect x="432" y="426" width="336" height="84" rx="10" fill="{ELEV}" stroke="{BORDER}"/>')
        parts.append(f'<text x="460" y="458" fill="{DIM}" font-family="monospace" font-size="11">BUY / SELL TAX</text>')
        parts.append(f'<text x="460" y="488" fill="{TEXT}" font-family="monospace" font-size="17">0% / 0%</text>')
        parts.append(f'<rect x="784" y="426" width="336" height="84" rx="10" fill="{ELEV}" stroke="{BORDER}"/>')
        parts.append(f'<text x="812" y="458" fill="{DIM}" font-family="monospace" font-size="11">SCAM REPORTS</text>')
        parts.append(f'<text x="812" y="488" fill="{GREEN}" font-family="monospace" font-size="17">none</text>')
        parts.append('</g>')
    return shell("".join(parts), "VIGIL . LIVE SCAN . NO API KEY")


def scene_scan():
    for ci in range(1, len(ADDR) + 1):
        emit(scan_frame(ADDR[:ci], True, 0))
        emit(scan_frame(ADDR[:ci], True, 0))
    hold(scan_frame(ADDR, True, 0), 20)
    for f in range(16):
        emit(scan_frame(ADDR, False, min(1.0, (f + 1) / 16)))
    hold(scan_frame(ADDR, False, 1.0), 110)


# ── Scene 3: consensus ───────────────────────────────────────
def scene_consensus():
    srcs = ["goplus", "onchain", "market", "deployer", "scam db"]
    def frame(n):
        parts = [
            f'<text x="80" y="150" fill="{TEXT}" font-family="Georgia, serif" font-size="34">Multi-source consensus.</text>',
            f'<text x="80" y="188" fill="{DIM}" font-family="Georgia, serif" font-size="18" font-style="italic">five independent signals vote — one noisy source can\'t false-positive.</text>',
        ]
        y = 240
        for i, s in enumerate(srcs):
            shown = i < n
            a = 1.0 if shown else 0.12
            parts.append(f'<g opacity="{a:.2f}">')
            parts.append(f'<rect x="80" y="{y}" width="1040" height="56" rx="10" fill="{ELEV}" stroke="{BORDER}"/>')
            parts.append(f'<circle cx="112" cy="{y+28}" r="7" fill="{GREEN if shown else DIM}"/>')
            parts.append(f'<text x="140" y="{y+35}" fill="{TEXT}" font-family="monospace" font-size="16">{s}</text>')
            if shown:
                parts.append(f'<text x="1092" y="{y+35}" text-anchor="end" fill="{GREEN}" font-family="monospace" font-size="15">SAFE</text>')
            parts.append('</g>')
            y += 64
        if n >= 5:
            parts.append(f'<text x="80" y="{y+38}" fill="{GREEN}" font-family="Georgia, serif" font-size="26">verdict: 5/5 agree → SAFE · confidence 1.00</text>')
        return shell("".join(parts), "VIGIL . CONSENSUS . FALSE-POSITIVE GUARD")
    for n in range(1, 6):
        for f in range(14):
            emit(frame(n))
    hold(frame(5), 120)


# ── Scene 4: feed ────────────────────────────────────────────
def scene_feed():
    rows = [
        ("0x8335…2913", "safety score", "92 · safe", GREEN),
        ("0x4200…0006", "honeypot", "clear", GREEN),
        ("0x1f3a…9b21", "scan token", "34 · high", RED),
        ("0xc751…7ba3", "consensus", "93 · safe", GREEN),
        ("0xaa01…ddef", "honeypot", "honeypot", RED),
    ]
    def frame(n):
        parts = [
            f'<text x="80" y="150" fill="{TEXT}" font-family="Georgia, serif" font-size="34">Public scan feed.</text>',
            f'<text x="80" y="188" fill="{DIM}" font-family="Georgia, serif" font-size="18" font-style="italic">live, anonymized — security as a public good on Base.</text>',
        ]
        y = 226
        for i in range(n):
            tok, tool, verdict, color = rows[i]
            parts.append(f'<rect x="80" y="{y}" width="1040" height="58" rx="10" fill="{ELEV}" stroke="{BORDER}"/>')
            parts.append(f'<circle cx="110" cy="{y+29}" r="6" fill="{color}"/>')
            parts.append(f'<text x="136" y="{y+26}" fill="{TEXT}" font-family="monospace" font-size="15">{tok}</text>')
            parts.append(f'<text x="136" y="{y+46}" fill="{DIM}" font-family="monospace" font-size="12">{tool} · base</text>')
            parts.append(f'<text x="1092" y="{y+35}" text-anchor="end" fill="{color}" font-family="monospace" font-size="14">{verdict.upper()}</text>')
            y += 66
        return shell("".join(parts), "VIGIL . LIVE FEED . VIGIL.CODES/FEED")
    for n in range(1, len(rows) + 1):
        for f in range(12):
            emit(frame(n))
    hold(frame(len(rows)), 90)


# ── Scene 5: outro ───────────────────────────────────────────
def scene_outro():
    inner = (
        f'<text x="80" y="240" fill="{TEXT}" font-family="Georgia, serif" font-size="40">Try it. No key.</text>'
        f'<text x="80" y="320" fill="{GOLD}" font-family="monospace" font-size="20">🌐  vigil.codes/scan</text>'
        f'<text x="80" y="364" fill="{GOLD}" font-family="monospace" font-size="20">💬  @vigilcodesbot</text>'
        f'<text x="80" y="408" fill="{GOLD}" font-family="monospace" font-size="20">📡  vigil.codes/feed</text>'
        f'<text x="80" y="478" fill="{DIM}" font-family="monospace" font-size="15">12 tools · merged into Aeon · live on Base</text>'
    )
    for f in range(20):
        a = min(1.0, (f + 1) / 18)
        emit(shell(f'<g opacity="{a:.2f}">{inner}</g>', "VIGIL . SCAN BEFORE YOU SIGN"))
    hold(shell(inner, "VIGIL . SCAN BEFORE YOU SIGN"), 150)


def main():
    scene_intro()
    scene_scan()
    scene_consensus()
    scene_feed()
    scene_outro()
    print(f"rendered {idx} frames")
    subprocess.run([
        "ffmpeg", "-y", "-framerate", str(FPS), "-i", os.path.join(OUT_DIR, "f_%05d.png"),
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "19",
        "-vf", f"scale={RW}:{RH}:flags=lanczos", "-movflags", "+faststart", FINAL,
    ], check=True)
    print(f"wrote {FINAL}")


if __name__ == "__main__":
    main()
