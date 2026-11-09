"""
Builds Gandalf's acquisition flow: the three collectors, how each reaches a host,
what it takes there in order of volatility, how locked files are read, and how
the archive gets to Elrond. One self-contained HTML page (inline SVG, logos
embedded).

    python3 scripts/docs/architecture/build_gandalf_flow.py [out.html]

Writes src/web/frontend/public/architecture/gandalf-acquisition.html by default.
"""
import base64
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
ASSETS = HERE / "assets"
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "src" / "web" / "frontend" / "public" / "architecture" / "gandalf-acquisition.html"

RED, INK, SOFT, BOX = "#8f2d2d", "#1f2328", "#57606a", "#f3dede"
W, H = 1700, 1040


def png(name):
    return "data:image/png;base64," + base64.b64encode((ASSETS / name).read_bytes()).decode()


svg = []


def text(x, y, lines, size=17, weight=600, colour=INK, anchor="middle"):
    for i, line in enumerate(lines):
        svg.append(f'<text x="{x}" y="{y + i * (size + 5)}" font-size="{size}" font-weight="{weight if i == 0 else 400}" '
                   f'fill="{colour if i == 0 else SOFT}" text-anchor="{anchor}">{line}</text>')


def arrow(d, label=None, lx=0, ly=0):
    svg.append(f'<path d="{d}" fill="none" stroke="{RED}" stroke-width="2.4" stroke-dasharray="9 7" '
               f'marker-end="url(#head)"/>')
    if label:
        w = len(label) * 8.6 + 18
        svg.append(f'<rect x="{lx - w / 2}" y="{ly - 15}" width="{w}" height="24" rx="4" fill="#ffffff"/>')
        svg.append(f'<text x="{lx}" y="{ly + 2}" font-size="15" fill="{INK}" text-anchor="middle">{label}</text>')


def image(href, x, y, w, h):
    svg.append(f'<image href="{href}" x="{x - w / 2}" y="{y - h / 2}" width="{w}" height="{h}" '
               f'preserveAspectRatio="xMidYMid meet"/>')


# ---- icons ----
def lock_icon(cx, cy):
    svg.append(f'<g transform="translate({cx},{cy})">'
               f'<path d="M -26 -10 L -26 -30 Q -26 -56 0 -56 Q 26 -56 26 -30 L 26 -10" fill="none" stroke="#6e7781" '
               f'stroke-width="10"/>'
               f'<rect x="-44" y="-14" width="88" height="68" rx="12" fill="#f5a524"/>'
               f'<circle cx="0" cy="14" r="10" fill="#7a4b00"/><rect x="-4" y="16" width="8" height="22" rx="3" fill="#7a4b00"/>'
               f'</g>')


def chip_icon(cx, cy):
    pins = "".join(
        f'<rect x="{-34 + i * 17}" y="-56" width="7" height="14" rx="2" fill="#2f9e44"/>'
        f'<rect x="{-34 + i * 17}" y="42" width="7" height="14" rx="2" fill="#2f9e44"/>'
        f'<rect x="-56" y="{-34 + i * 17}" width="14" height="7" rx="2" fill="#2f9e44"/>'
        f'<rect x="42" y="{-34 + i * 17}" width="14" height="7" rx="2" fill="#2f9e44"/>' for i in range(5))
    svg.append(f'<g transform="translate({cx},{cy})">{pins}'
               f'<rect x="-44" y="-44" width="88" height="88" rx="10" fill="#40c057"/>'
               f'<rect x="-26" y="-26" width="52" height="52" rx="6" fill="#2b8a3e"/>'
               f'<text x="0" y="8" font-size="20" font-weight="700" fill="#ffffff" text-anchor="middle">RAM</text></g>')


def manifest_icon(cx, cy):
    svg.append(f'<g transform="translate({cx},{cy})">'
               f'<path d="M -34 -46 L 18 -46 L 38 -26 L 38 46 L -34 46 Z" fill="#ffffff" stroke="#6e40c9" stroke-width="5" '
               f'stroke-linejoin="round"/><path d="M 18 -46 L 18 -26 L 38 -26" fill="none" stroke="#6e40c9" stroke-width="5"/>'
               + "".join(f'<rect x="-22" y="{-18 + i * 14}" width="{44 if i % 2 else 34}" height="6" rx="3" fill="#a371f7"/>'
                         for i in range(4))
               + '<circle cx="30" cy="40" r="17" fill="#1a7f37"/>'
               '<path d="M 22 40 L 28 46 L 39 33" fill="none" stroke="#ffffff" stroke-width="5" stroke-linecap="round" '
               'stroke-linejoin="round"/></g>')


# ---- the collectors ----
GX, GY = 760, 470  # Gandalf
image(png("flow-bash.png"), 250, 140, 130, 130)
text(250, 232, ["gandalf.sh", "Linux and macOS · bash 3.2+", "Local, or Remote over SSH + scp"])
image(png("flow-powershell.png"), 760, 135, 140, 140)
text(760, 232, ["Invoke-Gandalf.ps1", "Windows · PowerShell 5.1+, as admin", "Local, or Remote over PSRemoting (WinRM)"])
image(png("flow-python.png"), 1210, 140, 120, 120)
text(1210, 232, ["gandalf.py", "Linux and macOS · Python 3", "Local, or Remote over SSH (paramiko)"])

arrow(f"M 300 300 C 420 320, 560 350, {GX - 110} {GY - 70}")
arrow(f"M {GX} 312 L {GX} {GY - 112}")
arrow(f"M 1150 300 C 1080 330, 960 360, {GX + 110} {GY - 70}")

# ---- Gandalf ----
svg.append(f'<circle cx="{GX}" cy="{GY}" r="92" fill="#e9f2ea" stroke="#2f6b3a" stroke-width="3"/>')
svg.append(f'<clipPath id="gclip"><circle cx="{GX}" cy="{GY}" r="89"/></clipPath>')
# head and shoulders from the project's own Gandalf (public/images/gandalf.png), filling the circle
svg.append(f'<image href="{png("flow-gandalf.png")}" x="{GX - 92}" y="{GY - 92}" width="184" height="184" '
           f'clip-path="url(#gclip)" preserveAspectRatio="xMidYMid slice"/>')
text(GX, GY + 122, ["Gandalf", "live acquisition"], size=19)

# ---- targets ----
for (img, w, h, label, sub), y in zip(
        (("flow-windows.png", 70, 70, "Windows", "8.1 to 11, Server 2012 R2+"),
         ("flow-linux.png", 62, 74, "Linux", "Ubuntu, Debian, RHEL, Rocky..."),
         ("flow-apple.png", 52, 62, "macOS", "Big Sur onwards")), (410, 515, 620)):
    image(png(img), 90, y, w * 0.85, h * 0.85)
    text(150, y - 4, [label, sub], size=16, anchor="start")
arrow(f"M {GX - 100} {GY + 45} L 425 {GY + 45}", "live, as admin or root", 545, GY + 44)
svg.append(f'<path d="M 410 410 L 410 620" stroke="{RED}" stroke-width="2.4" stroke-dasharray="9 7"/>')
arrow("M 410 410 L 392 410")
arrow("M 410 620 L 392 620")

# ---- memory ----
chip_icon(1180, 470)
text(1180, 560, ["Memory (-M)", "DumpIt · AVML · osxpmem"])
arrow(f"M {GX + 100} {GY} L 1110 {GY}", "first, after live state", 975, GY - 1)

# ---- on the host ----
bx, by, bw, bh = 15, 700, 1350, 300
svg.append(f'<rect x="{bx}" y="{by}" width="{bw}" height="{bh}" rx="16" fill="{BOX}" stroke="{RED}" stroke-width="2.4" '
           f'stroke-dasharray="11 7"/>')
arrow(f"M {GX} {GY + 172} L {GX} {by - 4}")


def pills(y, title, items, numbered=False):
    text(bx + bw / 2, y, [title], size=18)
    widths = [len(t) * 7.9 + (50 if numbered else 30) for t in items]
    gap = 10
    total = sum(widths) + gap * (len(items) - 1)
    x = bx + (bw - total) / 2
    trunk = y + 18
    svg.append(f'<path d="M {bx + bw / 2} {y + 8} L {bx + bw / 2} {trunk}" stroke="{RED}" stroke-width="2.4"/>')
    svg.append(f'<path d="M {x + widths[0] / 2} {trunk + 14} L {x + widths[0] / 2} {trunk} '
               f'L {x + total - widths[-1] / 2} {trunk} L {x + total - widths[-1] / 2} {trunk + 14}" '
               f'fill="none" stroke="{RED}" stroke-width="2.4"/>')
    for i, (item, w) in enumerate(zip(items, widths)):
        if 0 < i < len(items) - 1:
            svg.append(f'<path d="M {x + w / 2} {trunk} L {x + w / 2} {trunk + 14}" stroke="{RED}" stroke-width="2.4"/>')
        svg.append(f'<rect x="{x}" y="{trunk + 14}" width="{w}" height="40" rx="9" fill="#ffffff"/>')
        if numbered:
            svg.append(f'<circle cx="{x + 20}" cy="{trunk + 34}" r="12" fill="{RED}"/>'
                       f'<text x="{x + 20}" y="{trunk + 39}" font-size="14" font-weight="700" fill="#ffffff" '
                       f'text-anchor="middle">{i + 1}</text>')
        svg.append(f'<text x="{x + 34 + (w - 34) / 2 if numbered else x + w / 2}" y="{trunk + 40}" font-size="15.5" fill="{INK}" '
                   f'text-anchor="middle">{item}</text>')
        x += w + gap


pills(by + 38, "On the host, in order of volatility: copied locally first, hashed afterwards", [
    "Connections, processes", "Memory", "$LogFile, $J, page files, $MFT", "Temp dirs",
    "Event logs, /var/log", "Prefetch, registry", "Users, files"], numbered=True)
pills(by + 178, "How a locked or in-use file is read", [
    "Gandalf's raw NTFS reader", "RawCopy (disk_tools.zip)", "temporary VSS snapshot", "reg save + hive logs",
    "plain copy", "log show export (macOS)"])

# ---- archive, manifest, Elrond ----
manifest_icon(1530, 810)
text(1530, 892, ["log.meta", "SHA-256 of every file, after copying", "log.audit: when each was taken"])
arrow(f"M {bx + bw + 4} 830 C 1400 828, 1440 820, 1472 812")
lock_icon(1530, 480)
text(1530, 568, ["Encrypted archive", "None · Password · Key", "key: &lt;host&gt;.shadowfax.key"])
arrow("M 1530 752 L 1530 640", "archived", 1530, 700)
# the ledger-keeper (public/images/elrond.png), trimmed to the figure
image(png("flow-elrond.png"), 1530, 150, 110, 166)
text(1530, 254, ["Elrond", "decrypts, re-hashes every file", "gandalf_integrity.jsonl"])
arrow("M 1530 416 L 1530 322", "scp · PSRemoting · copy", 1530, 372)

page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gandalf acquisition flow</title>
<style>
html,body{{margin:0;background:#ffffff}}
svg{{display:block;width:100%;max-width:{W}px;height:auto;margin:0 auto;
  font-family:"Avenir Next","Segoe UI","Helvetica Neue",Arial,sans-serif}}
</style>
</head>
<body>
<svg viewBox="0 0 {W} {H}" role="img" aria-label="Gandalf's acquisition flow: three collectors, the hosts they reach, what they take in order of volatility, and the archive's path to Elrond">
<defs><marker id="head" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
<path d="M 0 0 L 10 5 L 0 10 Z" fill="{RED}"/></marker></defs>
{chr(10).join(svg)}
</svg>
</body>
</html>
"""
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(page)
print(f"{OUT} {len(page) // 1024} KB")
