"""
Builds Rivendell's architecture map: a self-contained HTML page (fonts and images
embedded) in the style of a map of Middle-earth. Page 1 is the realm (Gandalf, the
web UI, the worker, Elrond, Eru, Aragorn, Mordor); page 2 is Elrond's directed graph,
branching by evidence type and operating system.

    python3 scripts/docs/architecture/build_map.py [out.html]

Writes src/web/frontend/public/architecture/rivendell-architecture.html by default,
where the web app's About page links to it. Edit the text here, not the HTML.
"""
import base64
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
ASSETS = HERE / "assets"
FONTS = REPO / "src" / "web" / "frontend" / "public" / "fonts"
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "src" / "web" / "frontend" / "public" / "architecture" / "rivendell-architecture.html"


def b64(path):
    return base64.b64encode(Path(path).read_bytes()).decode()


# ---- palette (Rivendell UI) ----
NAVY, NAVY2, NAVY3 = "#0f0f23", "#1a1a2e", "#2a2a5a"
PARCH, PARCH_DIM = "#f0dba5", "#cdbb8a"
TEAL, GREEN, GREEN2 = "#66d9ef", "#a7db6c", "#8abf4d"
GOLD, RUST, CRIMSON, VIOLET = "#ffce54", "#d57a54", "#ed5565", "#b39ddb"
INK, INK_SOFT = "#4c3a1b", "rgba(76,58,27,0.55)"

W, H = 2560, 1440
# map panel and the image's 1024-px coordinates -> page coordinates
MX, MY, MW, MH = 430, 160, 1700, 1222
SCALE = MW / 1024
CROP = (1024 * SCALE - MH) * 0.38


def P(ix, iy):
    return round(MX + ix * SCALE), round(MY + iy * SCALE - CROP)


PLACES = {
    "shire": P(300, 330), "bree": P(372, 322), "rivendell": P(468, 326), "moria": P(492, 442),
    "isengard": P(446, 560), "minas": P(612, 640), "mordor": P(850, 612), "erebor": P(690, 112),
    "havens": P(192, 332),
}

parts = []
svg = []
overlay = []  # drawn above the cards (arrows inside the Elrond inset)


def box(x, y, w, h, title, body, colour=PARCH, kicker="", icons=(), border=None, dashed=False):
    border = border or colour
    icon_html = "".join(f'<img src="data:image/png;base64,{b64(ASSETS / (i + ".png"))}" alt="{i}" '
                        f'style="width:20px;height:20px;vertical-align:-4px;margin-left:6px">' for i in icons)
    kick = f'<div class="kicker" style="color:{colour}">{kicker}</div>' if kicker else ""
    parts.append(
        f'<div class="card" style="left:{x}px;top:{y}px;width:{w}px;height:{h}px;border-color:{border};'
        f'{"border-style:dashed;" if dashed else ""}">{kick}<div class="title" style="color:{colour}">{title}{icon_html}</div>'
        f'<div class="body">{body}</div></div>')


def place(key, label, dx=14, dy=-28):
    x, y = PLACES[key]
    parts.append(f'<div class="place" style="left:{x + dx}px;top:{y + dy}px">{label}</div>')
    svg.append(f'<g transform="translate({x},{y})"><circle r="9" fill="{NAVY}" stroke="{PARCH}" stroke-width="2.5"/>'
               f'<path d="M0 -6 L1.8 -1.8 L6 0 L1.8 1.8 L0 6 L-1.8 1.8 L-6 0 L-1.8 -1.8 Z" fill="{GOLD}"/></g>')


def region(x, y, text, size=46, rotate=0):
    parts.append(f'<div class="region" style="left:{x}px;top:{y}px;font-size:{size}px;transform:rotate({rotate}deg)">{text}</div>')


MARK = 0


def route(d, colour, width=3.5, dash="", label=None, lx=0, ly=0, arrow=True, lw=260, anchor="start", layer=None):
    global MARK
    layer = svg if layer is None else layer
    MARK += 1
    head = ""
    if arrow:
        head = (f'<marker id="m{MARK}" orient="auto" markerWidth="6" markerHeight="6" refX="3" refY="3" '
                f'markerUnits="strokeWidth"><path d="M0 0 L6 3 L0 6 Z" fill="{colour}"/></marker>')
    layer.append(f'<defs>{head}</defs><path d="{d}" fill="none" stroke="{NAVY}" stroke-width="{width + 3.5}" '
               f'stroke-linecap="round" opacity="0.35"/>'
               f'<path d="{d}" fill="none" stroke="{colour}" stroke-width="{width}" stroke-linecap="round" '
               f'stroke-linejoin="round" {f"stroke-dasharray={chr(34)}{dash}{chr(34)}" if dash else ""} '
               f'{f"marker-end={chr(34)}url(#m{MARK}){chr(34)}" if arrow else ""}/>')
    if label:
        parts.append(f'<div class="route-label" style="left:{lx}px;top:{ly}px;width:{lw}px;text-align:{anchor};'
                     f'border-color:{colour}">{label}</div>')


def c(*pts):
    """A smooth path through points (quadratic midpoints)."""
    d = f"M {pts[0][0]} {pts[0][1]}"
    for i in range(1, len(pts) - 1):
        mx, my = (pts[i][0] + pts[i + 1][0]) / 2, (pts[i][1] + pts[i + 1][1]) / 2
        d += f" Q {pts[i][0]} {pts[i][1]} {mx} {my}"
    d += f" L {pts[-1][0]} {pts[-1][1]}"
    return d


# ================= header =================
parts.append(f'<img src="data:image/png;base64,{b64(ASSETS / "rivendell.png")}" alt="Rivendell" '
             f'style="position:absolute;left:52px;top:26px;height:108px;border-radius:8px;border:1px solid {PARCH_DIM}">')
parts.append(f'<div style="position:absolute;left:{52 + 180}px;top:30px;width:720px">'
             f'<div class="h1">Rivendell</div>'
             f'<div class="h2">A map of the realm: how a case travels from Gandalf to Elrond to Eru</div></div>')

# Eru: beyond the circles of the world (top centre, above the map)
box(1020, 18, 640, 134, "Eru <span class='sub'>AI analyst · Ask Eru</span>",
    "Reads Elrond's cooked artefacts, IOCs and ATT&amp;CK tags; answers in plain language with a local model "
    "(<b>Ollama</b>, nothing leaves the host). Without Ollama it says why and answers a fixed set of questions "
    "straight from the case files.",
    VIOLET, kicker="Beyond the circles of the world")

# legend
lx, ly = 1700, 24
parts.append(f'<div class="legend" style="left:{lx}px;top:{ly}px;width:800px;height:116px"></div>')
legend = [(GREEN, "", "live acquisition (hosts, cloud)"), (GOLD, "10 7", "the Great East Road: Gandalf archives"),
          (TEAL, "", "web UI, jobs and queues"), (CRIMSON, "", "Mordor: attack datasets"),
          (VIOLET, "6 6", "Eru: AI, read-only"), ("#9aa3b5", "", "administration and the lab")]
for i, (col, dash, text) in enumerate(legend):
    x = lx + 24 + (i % 2) * 390
    y = ly + 20 + (i // 2) * 30
    svg.append(f'<path d="M {x} {y + 9} L {x + 52} {y + 9}" stroke="{col}" stroke-width="4" '
               f'{f"stroke-dasharray={chr(34)}{dash}{chr(34)}" if dash else ""} stroke-linecap="round"/>')
    parts.append(f'<div class="legend-text" style="left:{x + 66}px;top:{y}px">{text}</div>')

# ================= the map =================
parts.append(f'<div class="map" style="left:{MX}px;top:{MY}px;width:{MW}px;height:{MH}px;'
             f'background-size:{MW}px {round(1024 * SCALE)}px;background-position:0 -{round(CROP)}px"></div>')

region(MX + 400, MY + 770, "E R I A D O R", 40)
region(MX + 760, MY + 236, "R H O V A N I O N", 30, -2)
region(MX + 830, MY + 940, "G O N D O R", 40)
region(MX + 1400, MY + 925, "M O R D O R", 40)
region(MX + 30, MY + 1010, "B E L E G A E R", 30, -8)
region(MX + 60, MY + 1050, "<i style='font-size:18px;letter-spacing:0.12em'>the Great Sea</i>", 18, -8)

for key, label, dx, dy in (("shire", "The Shire", -40, 14), ("bree", "Bree", -20, 14),
                           ("rivendell", "Rivendell", -120, -30), ("moria", "Moria", -78, -10),
                           ("isengard", "Isengard", 14, -10), ("minas", "Minas Tirith", -70, 14),
                           ("mordor", "Barad-dûr", 14, -30), ("erebor", "Erebor", 14, -10),
                           ("havens", "Grey Havens", -60, -34)):
    place(key, label, dx, dy)

# compass rose (sea, bottom left)
cx, cy = MX + 120, MY + 1130
pts = []
for a in range(0, 360, 45):
    r = 64 if a % 90 == 0 else 36
    pts.append((a, r))
rose = "".join(
    f'<path d="M 0 0 L {round(math.sin(math.radians(a - 12)) * 14, 1)} {round(-math.cos(math.radians(a - 12)) * 14, 1)} '
    f'L {round(math.sin(math.radians(a)) * r, 1)} {round(-math.cos(math.radians(a)) * r, 1)} '
    f'L {round(math.sin(math.radians(a + 12)) * 14, 1)} {round(-math.cos(math.radians(a + 12)) * 14, 1)} Z" '
    f'fill="{INK if a % 90 == 0 else PARCH_DIM}" stroke="{INK}" stroke-width="1"/>' for a, r in pts)
svg.append(f'<g transform="translate({cx},{cy})" opacity="0.8"><circle r="46" fill="none" stroke="{INK}" stroke-width="1.5"/>'
           f'<circle r="52" fill="none" stroke="{INK}" stroke-width="0.8"/>{rose}'
           f'<text x="0" y="-74" text-anchor="middle" font-family="Cinzel" font-size="20" fill="{INK}">N</text></g>')

# ================= realms (cards on the map) =================
S, B, R, M, I, T, MO, E, GH = (PLACES[k] for k in ("shire", "bree", "rivendell", "moria", "isengard", "minas",
                                                   "mordor", "erebor", "havens"))

box(MX + 20, MY + 440, 330, 286, "Gandalf <span class='sub'>acquisition</span>",
    "<b>gandalf.sh</b> and <b>gandalf.py</b> (Linux, macOS; local or over SSH) and <b>Invoke-Gandalf.ps1</b> "
    "(Windows, as admin). Live state first, then files in order of volatility; locked ones straight off the "
    "NTFS volume. Once all is copied, every file is SHA-256 hashed into <code>log.meta</code>, which Elrond checks "
    "on arrival. The archive is encrypted; in Key mode the key rides home as <code>&lt;host&gt;.shadowfax.key</code>.",
    GREEN, kicker="Sets out from the Shire")

box(MX + 250, MY + 70, 360, 168, "Web UI and API <span class='sub'>:5687 · :5688</span>",
    "React front end and FastAPI back end: start jobs, upload or pick images, watch progress, read results, "
    "Ask Eru, Pippin (threat intelligence), shared findings. Admins also see Aragorn.",
    TEAL, kicker="The Prancing Pony, Bree")

box(MX + 400, MY + 530, 330, 196, "Elrond worker <span class='sub'>Celery</span>",
    "Jobs arrive through <b>Redis</b>. The worker runs Elrond, and Elrond runs its tools as separate processes: "
    "Volatility 3, Plaso, Artemis, RegRipper, YARA, The Sleuth Kit.",
    TEAL, kicker="Delving in Moria")

box(MX + 40, MY + 790, 330, 190, "SIEM <span class='sub'>Splunk · Elastic · Kibana</span>",
    "<code>--Splunk</code> and <code>--Elastic</code> index the cooked artefacts, with Rivendell's own Splunk app "
    "and Kibana dashboards. Local containers or remote servers.",
    RUST, kicker="The palantír of Orthanc")

box(MX + 760, MY + 1000, 420, 206, "Aragorn <span class='sub'>administration</span>",
    "<b>Andúril</b>: Rivendell's own containers (status, logs, restart; won't stop the worker mid-job). "
    "<b>The lab</b>: Linux targets, Tart and UTM VMs, test runs from the browser, Gandalf against seeded hosts, "
    "Mordor recordings.",
    "#c9cfdc", kicker="The King in Minas Tirith")

box(MX + 1250, MY + 990, 430, 206, "Mordor <span class='sub'>attack datasets</span>",
    "OTRF Security-Datasets (APT29 day 1 and 2, Atomic sets) and the lab's own recordings of Atomic Red Team "
    "tests. <code>--Mordor</code> ingests them as event logs, so detections and ATT&amp;CK tagging can be checked "
    "against known attacks.",
    CRIMSON, kicker="Where the shadows lie")

box(MX + 1270, MY + 70, 410, 170, "Case store <span class='sub'>the hoard</span>",
    "<b>Postgres</b>: users, jobs, history. Case directories on disk: <code>raw/</code>, <code>cooked/</code>, "
    "<code>analysis/</code>, <code>mitre_techniques.txt</code>, timelines, archives.",
    GOLD, kicker="Under the Lonely Mountain")

# Rivendell: Elrond's road, an inset
rx, ry, rw, rh = MX + 870, MY + 300, 812, 560
parts.append(f'<div class="inset" style="left:{rx}px;top:{ry}px;width:{rw}px;height:{rh}px"></div>')
parts.append(f'<div class="inset-title" style="left:{rx + 24}px;top:{ry + 14}px">'
             f'<span class="kicker" style="color:{PARCH}">The Last Homely House</span><br>'
             f'<span style="color:{PARCH};font-size:30px">Elrond</span> <span class="sub">analysis · a directed graph, '
             f'not a pipeline: it branches by OS, evidence type and cloud provider</span></div>')
steps = [
    ("01", "Identify and mount", "E01, VMDK, raw and dd images; memory; Gandalf archives (checked, extracted, "
     "laid out); Mordor datasets; cloud logs"),
    ("02", "Collect", "Per OS: hives, event logs, $MFT and journals; launchd, BTM, unified logs; cron, systemd, "
     "PAM, logins, containers. Shadow copies too."),
    ("03", "Process", "Parsers and tools turn raw artefacts into cooked CSV and JSON with a LastWriteTime column"),
    ("04", "Analyse", "Keywords, YARA, IOCs, threat intelligence, stacking across hosts, timestomping, ADS, masquerading"),
    ("05", "ATT&amp;CK", "Techniques tagged from artefacts and event-log rules; Navigator layer"),
    ("06", "Timeline", "Plaso super-timeline across every source"),
    ("07", "Export", "Splunk, Elastic, case archive with hashes"),
]
for i, (num, name, text) in enumerate(steps):
    col, row = i % 4, i // 4
    x = rx + 20 + col * 196
    y = ry + 104 + row * 226
    parts.append(f'<div class="step" style="left:{x}px;top:{y}px;width:182px;height:{210}px">'
                 f'<div class="num">{num}</div><div class="step-title">{name}</div>{text}</div>')
    if i < len(steps) - 1:
        if col < 3:
            route(f"M {x + 182} {y + 40} L {x + 194} {y + 40}", GOLD, 3, layer=overlay)
        else:
            route(f"M {x + 91} {y + 210} C {x + 91} {y + 218}, {rx + 111} {y + 214}, {rx + 111} {y + 224}", GOLD, 3,
                  layer=overlay)
parts.append(f'<div class="inset-note" style="left:{rx + 612}px;top:{ry + 340}px;width:184px">'
             f'Gandalf archives are mapped onto the same <code>raw/</code> layout a disk image gets, so every later '
             f'stage treats them alike.</div>')

# ================= the margins: lands of Men (inputs) and what returns (outputs) =================
parts.append(f'<div class="column-title" style="left:40px;top:172px;width:360px">The Lands of Men'
             f'<div class="column-sub">what Gandalf and Elrond read</div></div>')
inputs = [
    ("Windows hosts", "Event logs, registry and hives with logs, $MFT, $UsnJrnl, Prefetch, SRUM, Amcache, "
     "tasks, BITS, Search, Defender, browsers, memory", ["windows"], GREEN),
    ("Linux hosts", "Logs, journal, cron, systemd, PAM, sudoers, logins, histories, web roots, kernel modules, "
     "Docker and Kubernetes node state, memory (AVML)", ["linux"], GREEN),
    ("macOS hosts", "launchd and BTM items, unified-log export, TCC, KnowledgeC, quarantine, ExecPolicy, "
     "XProtect, Biome, browsers", ["macos"], GREEN),
    ("Cloud", "AWS, Azure and GCP: instances, disk snapshots, CloudTrail and activity logs; Kubernetes audit logs", ["aws", "azure"], GREEN),
    ("Disk and memory images", "E01, VMDK, raw and dd, VHD(X); memory dumps, hiberfil, pagefile. "
     "Straight to Elrond, no Gandalf needed.", [], TEAL),
]
ys = []
for i, (t, body, icons, col) in enumerate(inputs):
    y = 260 + i * 228
    ys.append(y)
    box(40, y, 360, 206, t, body, col, icons=icons)

parts.append(f'<div class="column-title" style="left:2160px;top:172px;width:360px">What Returns'
             f'<div class="column-sub">what the analyst gets</div></div>')
outputs = [
    ("Case directory", "raw/ as collected, cooked/ CSV and JSON per artefact, analysis/ (IOCs, threat intelligence matches), "
     "audit log of every step", GOLD),
    ("ATT&amp;CK Navigator", "A layer of every technique tagged in the case, served by the bundled Navigator", GOLD),
    ("Timeline", "One Plaso super-timeline of every source, also indexed into Splunk or Kibana", GOLD),
    ("Dashboards", "Splunk app and Kibana dashboards over the same cooked data", RUST),
    ("Answers and findings", "Eru: case summaries and suggestions with a model; exact answers from the files "
     "without one. Findings the team confirmed in the case browser, as a report and a layer",
     VIOLET),
]
oys = []
for i, (t, body, col) in enumerate(outputs):
    y = 260 + i * 228
    oys.append(y)
    box(2160, y, 360, 206, t, body, col)

# ================= roads =================
gx, gy = MX + 20 + 330, MY + 440 + 140
for i in range(3):
    route(c((400, ys[i] + 103), (415, ys[i] + 103), (MX + 6, gy - 30 + i * 30), (MX + 20, gy - 30 + i * 30)),
          GREEN, 3)
# cloud: Rivendell's cloud commands pull disks and logs for Elrond
route(c((400, ys[3] + 103), (MX - 10, ys[3] + 103), (MX + 360, MY + 700), (MX + 400, MY + 680)), GREEN, 3,
      dash="2 7", label="cloud: snapshots and logs", lx=MX + 210, ly=MY + 754, lw=170)
# disk images: straight to the web UI / Elrond
route(c((400, ys[4] + 103), (MX + 420, ys[4] + 90), (MX + 560, MY + 860), (MX + 580, MY + 726)),
      TEAL, 3, label="images go straight to Elrond", lx=MX + 400, ly=MY + 1004, lw=200)

# the Great East Road: Gandalf -> Shire -> Bree -> Rivendell
route(c((MX + 200, MY + 440), S, B, (R[0] - 40, R[1] + 10), R), GOLD, 5, dash="14 9", arrow=False)
route(c(R, (rx - 30, ry + 60), (rx, ry + 70)), GOLD, 5, dash="14 9",
      label="<b>The Great East Road</b>: encrypted per-host archives, <code>acquisitions/</code>, "
            "decrypted and checked on arrival", lx=MX + 390, ly=MY + 448, lw=300)

# Bree (web UI) -> Moria (worker) via Redis; Moria -> Rivendell
route(c((MX + 430, MY + 238), (MX + 520, MY + 400), (MX + 560, MY + 530)), TEAL, 3.5,
      label="jobs queued in Redis", lx=MX + 600, ly=MY + 300, lw=150)
route(c((MX + 730, MY + 620), (MX + 820, MY + 620), (rx, ry + 330)), TEAL, 3.5, label="runs Elrond", lx=MX + 740,
      ly=MY + 650, lw=110)

# Rivendell -> Isengard (SIEM)
route(c((rx + 300, ry + rh), (rx + 200, MY + 930), (MX + 380, MY + 900), (MX + 370, MY + 890)), RUST, 3.5,
      label="<code>--Splunk</code> · <code>--Elastic</code>", lx=MX + 520, ly=MY + 920, lw=200)
# Rivendell -> Erebor (case store)
route(c((rx + 560, ry), (rx + 600, MY + 250), (MX + 1400, MY + 240)), GOLD, 3.5,
      label="case output, job state", lx=rx + 610, ly=MY + 250, lw=180)
# Erebor -> Eru (read-only)
route(c((MX + 1500, MY + 70), (MX + 1450, MY + 20), (1500, 140)), VIOLET, 3, dash="6 6",
      label="Eru reads the case", lx=1660, ly=MY + 8, lw=170)
# Mordor -> Rivendell
route(c((MX + 1460, MY + 990), (MX + 1440, MY + 930), (rx + 560, ry + rh)), CRIMSON, 4,
      label="<code>--Mordor</code>: datasets as event logs", lx=MX + 1050, ly=MY + 900, lw=290)
# Aragorn's lab -> Mordor (recordings) and -> Gandalf (seeded targets)
route(c((MX + 1180, MY + 1100), (MX + 1215, MY + 1095), (MX + 1250, MY + 1090)), "#9aa3b5", 3,
      label="lab recordings", lx=MX + 1185, ly=MY + 1160, lw=130)
route(c((MX + 760, MY + 1150), (MX + 430, MY + 1150), (MX + 300, MY + 1040), (MX + 200, MY + 726)), "#9aa3b5", 3,
      dash="5 7", label="seeded lab targets test every collector", lx=MX + 470, ly=MY + 1160, lw=270)
# Rivendell -> outputs
for i, y in enumerate(oys):
    route(c((rx + rw, ry + 200 + i * 40), (rx + rw + 60, ry + 200 + i * 40), (2140, y + 103), (2160, y + 103)),
          GOLD if i < 3 else (RUST if i == 3 else VIOLET), 3, dash="6 6" if i == 4 else "")

parts.append(f'<div class="footer">Rivendell · Gandalf collects · Elrond analyses · Eru answers · '
             f'Aragorn keeps the realm · page 1 of 2 · generated from the codebase, October 2026</div>')


def page(anchor, label):
    """The current parts and roads as one page, then clear them for the next."""
    html = (f'<section class="page" id="{anchor}" aria-label="{label}">\n'
            + "\n".join(p for p in parts if 'class="map"' in p)
            + f'\n<svg class="roads" width="{W}" height="{H}" viewBox="0 0 {W} {H}">{"".join(svg)}</svg>\n'
            + "\n".join(p for p in parts if 'class="map"' not in p)
            + f'\n<svg class="roads" width="{W}" height="{H}" viewBox="0 0 {W} {H}">{"".join(overlay)}</svg>\n</section>')
    parts.clear(); svg.clear(); overlay.clear()
    return html


pages = [page("realm", "Rivendell, drawn as a map of Middle-earth")]

# ================= page 2: Elrond's roads =================
LANE_COLOURS = {"Windows": TEAL, "Linux": GOLD, "macOS": VIOLET}
MEM = RUST

parts.append(f'<img src="data:image/png;base64,{b64(ASSETS / "rivendell.png")}" alt="Rivendell" '
             f'style="position:absolute;left:52px;top:26px;height:108px;border-radius:8px;border:1px solid {PARCH_DIM}">')
parts.append(f'<div style="position:absolute;left:{52 + 180}px;top:30px;width:1100px">'
             f'<div class="h1">Elrond</div>'
             f'<div class="h2">The roads from Rivendell: one directed graph, branching by evidence type, operating '
             f'system and shadow copy</div></div>')

# legend
lx, ly = 1700, 24
parts.append(f'<div class="legend" style="left:{lx}px;top:{ly}px;width:820px;height:116px"></div>')
legend = [(GREEN, "", "evidence arriving"), (TEAL, "", "Windows branch"),
          (GOLD, "", "Linux branch"), (VIOLET, "", "macOS branch"),
          (MEM, "", "memory (Volatility 3)"), (PARCH, "10 7", "shared stages, every host")]
for i, (col, dash, text) in enumerate(legend):
    x = lx + 24 + (i % 2) * 400
    y = ly + 20 + (i // 2) * 30
    svg.append(f'<path d="M {x} {y + 9} L {x + 52} {y + 9}" stroke="{col}" stroke-width="4" '
               f'{f"stroke-dasharray={chr(34)}{dash}{chr(34)}" if dash else ""} stroke-linecap="round"/>')
    parts.append(f'<div class="legend-text" style="left:{x + 66}px;top:{y}px">{text}</div>')

# what arrives
parts.append(f'<div class="column-title" style="left:40px;top:172px;width:360px">What Arrives'
             f'<div class="column-sub">every kind of evidence Elrond takes</div></div>')
arrivals = [
    ("Disk images", "E01, VMDK, VHD(X), raw and dd; whole disks or single volumes.", ["windows", "linux", "macos"]),
    ("Memory images", "Raw dumps, AFF4, hiberfil.sys, pagefile.sys, MEMORY.DMP, a VM's .vmem.", []),
    ("Gandalf archives", "Per-host archives from all three collectors, encrypted or not.", []),
    ("Event datasets", "OTRF Security-Datasets (Mordor) and the lab's own recordings of Atomic tests.", []),
    ("Cloud", "Instances' disk snapshots, CloudTrail and activity logs from AWS, Azure and GCP; Kubernetes audit logs.", ["aws", "azure"]),
]
ay = []
for i, (t, body, icons) in enumerate(arrivals):
    y = 250 + i * 214
    ay.append(y)
    box(40, y, 360, 186, t, body, GREEN if t != "Memory images" else MEM, icons=icons)

# the ford: identify and mount
fx, fy, fw, fh = 450, 470, 290, 470
box(fx, fy, fw, fh, "Identify and mount",
    "Each image is mounted read-only: <b>ewfmount</b> for E01, <b>qemu-nbd</b> or <b>guestmount</b> for VMDK "
    "and VHD(X), <b>losetup</b> and <b>kpartx</b> for raw, <b>ntfs-3g</b>, HFS+ and APFS drivers for the file "
    "systems. The OS is read from what's on the volume. <b>vshadowmount</b> turns every shadow copy into a "
    "branch of its own. Memory images get their Volatility profile here and wait for processing.",
    PARCH, kicker="The Ford of Bruinen")

# the lanes on parchment
px, py, pw, ph = 770, 170, 1150, 1050
parts.append(f'<div class="map" style="left:{px}px;top:{py}px;width:{pw}px;height:{ph}px;'
             f'background-size:{pw * 1.5}px auto;background-position:-300px -120px"></div>')
lanes = [
    ("Windows", "The West-road", 200,
     ("Hives with their .LOG1/.LOG2, NTUSER and UsrClass, event logs, $MFT, $UsnJrnl, $LogFile, prefetch, SRUM, "
      "Amcache, jump lists, the WMI repository, tasks, recycle bin, browsers, Outlook, hiberfil and pagefile."),
     ("<b>Artemis</b> parses $MFT, $UsnJrnl, event logs, prefetch, SRUM, jump lists, shimcache and Outlook; registry "
      "extractions for system and user hives and USB; WMI subscriptions carved from OBJECTS.DATA; UAL, "
      "ActivitiesCache, ETL, LNK, Defender logs, PCA, WER."),
     "windows.pslist, psscan, cmdline, netscan, malfind, svcscan, dlllist, handles, registry.hivelist and "
     "userassist; hiberfil.sys and MEMORY.DMP read as memory."),
    ("Linux", "The North-way", 545,
     ("/etc (passwd, group, shadow, sudoers, PAM, preload, profile), /var/log and the journal, cron, systemd units and "
      "generators, utmp/wtmp/btmp, wtmpdb and lastlog2, udev, autostart, web roots, histories, Docker and Kubernetes."),
     ("Logs, services and groups to CSV; logins and failed logins; PAM, sudoers and preload flagged; udev, desktop "
      "and user units; kernel modules without a file; executables in /tmp and /dev/shm; web shells; bash, zsh and "
      "vim histories; containers flagged for what they can reach."),
     "linux.pslist, pstree, bash, lsof, malfind, lsmod, check_modules, check_syscall, check_idt, check_creds, "
     "tty_check."),
    ("macOS", "The Elven-path", 890,
     ("LaunchAgents, LaunchDaemons and StartupItems, BTM, a unified-log export, TCC, KnowledgeC, quarantine, "
      "ExecPolicy, XProtect, Biome, notifications, emond, periodic, logs, Safari and Chrome, Mail."),
     ("Plists to JSON with persistence tagged; BTM items and SFL lists decoded (NSKeyedArchiver, bookmarks); "
      "SQLite databases read with their WAL; emond and periodic scripts; unified-log events; .emlx mail; zsh "
      "history."),
     "mac.pslist, psaux, bash, lsof, netstat, malfind, lsmod, check_syscall, check_sysctl, check_trap_table, "
     "kauth_scopes, trustedbsd."),
]
CW, PW_, MW_ = 340, 400, 320
cx, prx, mx = px + 20, px + 20 + CW + 25, px + 20 + CW + 25 + PW_ + 25
lane_mid = {}
for name, kicker, y, collect, process, memory in lanes:
    col = LANE_COLOURS[name]
    parts.append(f'<div class="lane-title" style="left:{px + 20}px;top:{y - 14}px;color:{INK}">'
                 f'{kicker.upper()} · <span style="color:#1b3a4b">{name.upper()}</span></div>')
    box(cx, y + 30, CW, 270, "Collect", collect, col, kicker="disk images only")
    box(prx, y + 30, PW_, 270, "Process", process, col, kicker="raw/ to cooked/ CSV and JSON")
    box(mx, y + 30, MW_, 270, "Memory", memory, MEM, kicker="Volatility 3")
    route(f"M {cx + CW} {y + 165} L {prx - 4} {y + 165}", col, 3.5)

# ford -> lanes
for name, _, y, *_ in lanes:
    route(c((fx + fw, fy + fh / 2), (fx + fw + 20, fy + fh / 2), (cx - 30, y + 165), (cx - 4, y + 165)),
          LANE_COLOURS[name], 3.5)
# arrivals -> ford / straight on
route(c((400, ay[0] + 93), (430, ay[0] + 93), (fx + 60, fy - 40), (fx + 60, fy)), GREEN, 3)
route(c((400, ay[1] + 93), (425, ay[1] + 93), (fx - 10, fy + 120), (fx, fy + 120)), MEM, 3)
route(c((400, ay[4] + 93), (432, ay[4] + 93), (fx + 100, fy + fh + 60), (fx + 100, fy + fh)), GREEN, 3, dash="2 7",
      label="snapshots become disk images", lx=fx + 30, ly=fy + fh + 70, lw=230)
# memory images: the ford -> each lane's memory card
for name, _, y, *_ in lanes:
    route(c((fx + fw - 40, fy + fh), (fx + fw - 30, py + ph - 10), (mx + MW_ / 2, py + ph - 10), (mx + MW_ / 2, y + 300)),
          MEM, 2.5, dash="4 6", arrow=True) if name == "macOS" else None
route(f"M {mx + MW_ / 2} {lanes[2][2] + 30} L {mx + MW_ / 2} {lanes[1][2] + 300 + 4}", MEM, 2.5, dash="4 6")
route(f"M {mx + MW_ / 2} {lanes[1][2] + 30} L {mx + MW_ / 2} {lanes[0][2] + 300 + 4}", MEM, 2.5, dash="4 6")
parts.append(f'<div class="route-label" style="left:{mx + MW_ / 2 - 130}px;top:{py + ph + 18}px;width:260px;'
             f'text-align:center;border-color:{MEM}">memory images, by the profile they were given</div>')
# Gandalf archives skip collection: they join between Collect and Process
gx = cx + CW + 12
route(c((400, ay[2] + 98), (422, ay[2] + 98), (422, py + ph + 40), (gx, py + ph + 40), (gx, lanes[2][2] + 185)),
      GREEN, 3.5)
route(f"M {gx} {lanes[2][2] + 145} L {gx} {lanes[1][2] + 185}", GREEN, 3.5, arrow=False)
route(f"M {gx} {lanes[1][2] + 145} L {gx} {lanes[0][2] + 185}", GREEN, 3.5)
parts.append(f'<div class="route-label" style="left:{gx - 240}px;top:{py + ph + 56}px;width:470px;text-align:center;'
             f'border-color:{GREEN}"><b>Gandalf archives</b> are decrypted, checked against Gandalf\'s SHA-256 '
             f'manifest and laid out as <code>raw/</code>: already collected, they join at Process</div>')

# shared stages
sx, sw = 1960, 560
parts.append(f'<div class="column-title" style="left:{sx}px;top:172px;width:{sw}px">The Council'
             f'<div class="column-sub">every host, whichever road it came by</div></div>')
stages = [
    ("Analyse", "Keyword and YARA searches, IOC extraction, timestomping and alternate data streams in $MFT, "
     "masquerading and misplaced binaries, NSRL matching. <code>--threatIntel</code> matches the case and ranks "
     "groups by what matched; stacking ranks what few of the hosts have, with its reasons."),
    ("ATT&amp;CK", "Techniques tagged from artefacts, event-log rules and Mordor datasets into "
     "<code>mitre_techniques.txt</code>; a Navigator layer."),
    ("Timeline", "<b>Plaso</b> (psteal) builds one super-timeline across every source of a host."),
    ("Export", "<code>--Splunk</code>, <code>--Elastic</code> (Rivendell's app and dashboards), "
     "<code>--Navigator</code>, and the case archive with its audit log."),
]
sy = []
for i, (t, body) in enumerate(stages):
    y = 260 + i * 262
    sy.append(y)
    box(sx, y, sw, 230, t, body, GREEN if i < 3 else PARCH)
    if i:
        route(f"M {sx + sw / 2} {sy[i - 1] + 230} L {sx + sw / 2} {y - 4}", PARCH, 3.5, dash="10 7")
for name, _, y, *_ in lanes:
    route(c((prx + PW_, y + 140), (prx + PW_ + 14, y + 140), (mx - 12, y + 100), (mx - 12, y + 18),
            (px + pw + 10, y + 18), (sx - 30, sy[0] + 115), (sx - 4, sy[0] + 115)), LANE_COLOURS[name], 3)
    route(c((mx + MW_, y + 180), (px + pw + 10, y + 180), (sx - 30, sy[0] + 150), (sx - 4, sy[0] + 150)), MEM, 2.5)
# event datasets: cooked events straight to analysis
route(c((400, ay[3] + 98), (412, ay[3] + 98), (412, py + ph + 120), (sx - 40, py + ph + 120), (sx - 40, sy[1] + 115),
        (sx - 4, sy[1] + 115)), GREEN, 3, dash="2 7",
      label="event datasets: one host per computer, events into <code>cooked/evt/</code>", lx=1430,
      ly=py + ph + 104, lw=440)

parts.append(f'<div class="footer">Rivendell · Elrond · the same stages for every host, whatever road it took · '
             f'page 2 of 2 · generated from the codebase, October 2026</div>')
pages.append(page("elrond", "Elrond's directed graph, branching by evidence type and operating system"))

font_css = "".join(
    f"@font-face{{font-family:'Cinzel';font-weight:{wt};src:url(data:font/ttf;base64,{b64(FONTS / f)}) format('truetype')}}"
    for f, wt in (("Cinzel-Regular.ttf", 400), ("Cinzel-SemiBold.ttf", 600), ("Cinzel-Bold.ttf", 700)))

html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=2560">
<title>Rivendell — a map of the realm</title>
<style>
{font_css}
""" + f'''{font_css}
html,body{{margin:0;background:{NAVY}}}
.page{{position:relative;width:{W}px;height:{H}px;margin:0 auto;overflow:hidden;
  background:radial-gradient(ellipse at 50% 40%, {NAVY2} 0%, {NAVY} 75%);color:{PARCH};
  font-family:Georgia,'Garamond',serif}}
@page{{size:{W}px {H}px;margin:0}}
.page::before{{content:"";position:absolute;inset:10px;border:2px solid {PARCH_DIM};border-radius:6px;pointer-events:none}}
.page::after{{content:"";position:absolute;inset:18px;border:1px solid rgba(205,187,138,0.45);border-radius:4px;pointer-events:none}}
.h1{{font-family:Cinzel,serif;font-weight:700;font-size:54px;letter-spacing:0.12em;color:{PARCH};line-height:62px}}
.h2{{font-family:Cinzel,serif;font-size:16px;letter-spacing:0.04em;color:{PARCH_DIM};margin-top:6px}}
.map{{position:absolute;border:3px double {PARCH_DIM};border-radius:4px;
  box-shadow:0 0 0 8px rgba(15,15,35,0.6), inset 0 0 120px rgba(76,58,27,0.45)}}
.region{{position:absolute;font-family:Cinzel,serif;font-weight:600;color:{INK_SOFT};letter-spacing:0.3em;
  white-space:nowrap;transform-origin:left top}}
.place{{position:absolute;font-family:Cinzel,serif;font-weight:700;font-size:17px;color:{INK};
  text-shadow:0 0 4px #e9dcbc,0 0 8px #e9dcbc;white-space:nowrap}}
.card{{position:absolute;box-sizing:border-box;padding:14px 16px;background:rgba(15,15,35,0.93);
  border:1.5px solid;border-radius:8px;box-shadow:0 6px 18px rgba(0,0,0,0.45)}}
.card .title{{font-family:Cinzel,serif;font-weight:700;font-size:21px;line-height:27px;margin-bottom:6px}}
.card .body{{font-size:15px;line-height:21px;color:#e5e0d0}}
.kicker{{font-family:Cinzel,serif;font-size:12px;letter-spacing:0.16em;text-transform:uppercase;opacity:0.85;margin-bottom:2px}}
.sub{{font-family:Georgia,serif;font-size:14px;font-weight:normal;color:{PARCH_DIM};letter-spacing:0}}
code{{font-family:'JetBrains Mono',ui-monospace,Menlo,monospace;font-size:13px;color:{TEAL};
  background:rgba(102,217,239,0.08);padding:0 3px;border-radius:3px}}
.inset{{position:absolute;box-sizing:border-box;background:rgba(26,26,46,0.95);border:3px double {PARCH};
  border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,0.55)}}
.inset-title{{position:absolute;font-family:Cinzel,serif;font-weight:700;line-height:34px}}
.inset-note{{position:absolute;font-size:14px;line-height:20px;color:{PARCH_DIM};font-style:italic}}
.step{{position:absolute;box-sizing:border-box;padding:12px 14px;background:{NAVY3};border:1px solid rgba(240,219,165,0.35);
  border-radius:8px;font-size:14px;line-height:20px;color:#d9d3c2}}
.step .num{{font-family:Cinzel,serif;font-weight:700;font-size:16px;color:{GOLD}}}
.step .step-title{{font-family:Cinzel,serif;font-weight:700;font-size:18px;line-height:24px;color:{PARCH};margin:2px 0 8px}}
.route-label{{position:absolute;box-sizing:border-box;font-size:14px;line-height:19px;color:{PARCH};
  background:rgba(15,15,35,0.88);padding:5px 9px;border-left:3px solid;border-radius:3px}}
.column-title{{position:absolute;font-family:Cinzel,serif;font-weight:700;font-size:24px;letter-spacing:0.14em;
  color:{PARCH};text-align:center}}
.column-sub{{font-family:Georgia,serif;font-weight:normal;font-style:italic;font-size:15px;letter-spacing:0;color:{PARCH_DIM}}}
.legend{{position:absolute;box-sizing:border-box;border:1px solid rgba(205,187,138,0.5);border-radius:8px;background:rgba(15,15,35,0.7)}}
.legend-text{{position:absolute;font-size:15px;line-height:18px;color:#e5e0d0;white-space:nowrap}}
.footer{{position:absolute;left:0;right:0;bottom:24px;text-align:center;font-family:Cinzel,serif;font-size:14px;
  letter-spacing:0.18em;color:{PARCH_DIM}}}
svg.roads{{position:absolute;left:0;top:0;pointer-events:none}}
''' + f""".map{{background-image:url(data:image/jpeg;base64,{b64(ASSETS / "map.jpg")})}}
.lane-title{{position:absolute;font-family:Cinzel,serif;font-weight:700;font-size:20px;letter-spacing:0.22em;
  text-shadow:0 0 4px #e9dcbc,0 0 8px #e9dcbc;white-space:nowrap}}
.page + .page{{margin-top:40px}}
@media print{{.page{{page-break-after:always}} .page + .page{{margin-top:0}}}}
</style>
</head>
<body>
{chr(10).join(pages)}
</body>
</html>
"""
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(html)
print(f"{OUT} {len(html) // 1024} KB")
