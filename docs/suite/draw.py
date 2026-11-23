"""Draws the suite's two diagrams: how Ostraka, Rowanholt and Shikari work together.

    python3 docs/suite/draw.py

The same file is in all three repositories (docs/suite/); change it in all three and redraw. It writes
suite.svg (the three products and what passes between them) and suite-anatomy.svg (the whole workflow,
drawn as Shikari's shikari_workflow.svg is: inputs, each product's insides, what crosses between them,
the outputs and the shared foundation). Each product keeps its own colour: Ostraka's red ochre,
Rowanholt's leaf green and Shikari's gold; teal is the suite's own, for what they share.
Standard library only.
"""

from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

HERE = Path(__file__).resolve().parent

BG, CARD, LINE, DIM = "#0d1117", "#141d2b", "#2a4a5e", "#7a8fa6"
WHITE, TEAL, SOFT = "#ffffff", "#4ecdc4", "#a0b8c8"
OSTRAKA, ROWANHOLT, SHIKARI = "#e07a5f", "#a7db6c", "#f5c842"
OUTSIDE = "#66d9ef"
FONT = "'Segoe UI', 'SF Pro Display', -apple-system, sans-serif"


class Svg:
    def __init__(self, width: int, height: int, title: str, subtitle: str):
        self.w, self.h = width, height
        self.parts: list[str] = []
        self.colours: set[str] = set()
        self.rect(0, 0, width, height, BG, None, rx=8)
        self.text(60, 46, title, 26, WHITE, 700)
        self.text(60, 66, subtitle, 13, DIM)

    def rect(self, x, y, w, h, fill, stroke, *, rx=8, width=1.0, dashed=False):
        dash = ' stroke-dasharray="5 4"' if dashed else ""
        line = f' stroke="{stroke}" stroke-width="{width}"{dash}' if stroke else ""
        self.parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}"{line}/>')

    def text(self, x, y, words, size=10, fill=DIM, weight=400, *, anchor="start", spacing=0.0):
        extra = f' letter-spacing="{spacing}"' if spacing else ""
        self.parts.append(
            f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{fill}" '
            f'text-anchor="{anchor}"{extra}>{escape(words)}</text>'
        )

    def label(self, x, y, words, colour=TEAL):
        self.text(x, y, words.upper(), 11, colour, 600, spacing=1.5)

    def card(self, x, y, w, h, title, lines, colour=TEAL, *, accent="", strong=False, dashed=False):
        """A box in the example's manner: a coloured mark, a white title, muted lines, one accent line."""
        self.rect(x, y, w, h, CARD, colour if strong else LINE, width=1.5 if strong else 1, dashed=dashed)
        self.rect(x + 16, y + 16, 12, 12, "none", colour, rx=3, width=1.5)
        self.text(x + 36, y + 27, title, 13, WHITE, 600)
        for i, line in enumerate(lines):
            self.text(x + 16, y + 48 + i * 13, line)
        if accent:
            self.text(x + 16, y + 48 + len(lines) * 13 + 2, accent, 10, colour)

    def chip(self, x, y, w, words, colour):
        self.rect(x, y, w, 24, BG, colour, rx=5, width=0.75)
        self.text(x + w / 2, y + 16, words, 10, WHITE, 500, anchor="middle")

    def arrow(self, points, colour=TEAL, words="", *, at=None, dashed=False, both=False):
        self.colours.add(colour)
        path = " ".join(f"{'M' if i == 0 else 'L'}{x},{y}" for i, (x, y) in enumerate(points))
        dash = ' stroke-dasharray="5 4"' if dashed else ""
        mid = self._marker(colour)
        start = f' marker-start="url(#{mid}s)"' if both else ""
        self.parts.append(
            f'<path d="{path}" fill="none" stroke="{colour}" stroke-width="1.5"{dash}{start} '
            f'marker-end="url(#{mid})"/>'
        )
        if words:
            (x1, y1), (x2, y2) = at or (points[0], points[-1])
            self.text((x1 + x2) / 2, (y1 + y2) / 2 - 6, words, 10, SOFT, 500, anchor="middle")

    @staticmethod
    def _marker(colour: str) -> str:
        return "a" + colour.lstrip("#")

    def save(self, name: str) -> None:
        markers = "".join(
            f'<marker id="{self._marker(c)}" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">'
            f'<path d="M0,0 L8,3 L0,6" fill="{c}"/></marker>'
            f'<marker id="{self._marker(c)}s" markerWidth="8" markerHeight="6" refX="0" refY="3" orient="auto">'
            f'<path d="M8,0 L0,3 L8,6" fill="{c}"/></marker>'
            for c in sorted(self.colours)
        )
        body = "\n  ".join(self.parts)
        (HERE / name).write_text(
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" font-family="{FONT}">\n'
            f"  <defs>{markers}</defs>\n  {body}\n</svg>\n"
        )


def legend(s: Svg, x: int, y: int) -> None:
    items = [(OSTRAKA, "Ostraka"), (ROWANHOLT, "Rowanholt"), (SHIKARI, "Shikari"), (TEAL, "shared"), (OUTSIDE, "outside the suite")]
    for i, (colour, words) in enumerate(items):
        s.rect(x + i * 150, y - 10, 12, 12, "none", colour, rx=3, width=1.5)
        s.text(x + i * 150 + 20, y, words, 11, SOFT)


# ---- 1. The suite: three products and what passes between them ------------------------------------


def suite() -> None:
    s = Svg(1400, 820, "The suite — Ostraka, Rowanholt and Shikari", "Three products beside each other: evidence, detection and the record of the incident")

    s.label(60, 110, "Evidence and analysis", ROWANHOLT)
    s.card(60, 122, 340, 200, "Rowanholt", [
        "Acquisition (Gandalf) and analysis (Elrond)",
        "Parsed artefacts from Windows, Linux, macOS, cloud",
        "Findings that cite a row: host, artefact, row, SHA-256",
        "Smith, the AI analyst, read-only, row-cited",
        "Lead, confirmed or benign; an analyst confirms",
        "Webhooks: job.completed, finding.confirmed",
    ], ROWANHOLT, accent="paired: an ostraka-scope token and a webhook", strong=True)

    s.label(1000, 110, "Detection and hunting", SHIKARI)
    s.card(1000, 122, 340, 200, "Shikari", [
        "ATT&CK groups, CVEs and reports become detections",
        "Splunk, Defender XDR, Elasticsearch, SecOps",
        "Coverage: which techniques have a detection",
        "Hunts, correlation, emulation (VECTR)",
        "Detection library and the attack's anatomy",
        "Webhooks: run.completed, run.executed",
    ], SHIKARI, accent="paired: an ostraka-scope token and a webhook", strong=True)

    s.label(530, 110, "The record of the incident", OSTRAKA)
    s.card(530, 122, 340, 200, "Ostraka", [
        "Incidents and hunts: people, tasks, decisions",
        "Findings: leads until an analyst confirms",
        "Assessments, ACH, stakeholder updates, reports",
        "Regulator clocks, handovers, the attack flow",
        "Every change in a hash-chained activity log",
        "TLP guard: RED stays on the organisation's network",
    ], OSTRAKA, accent="pairs from a one-use link · Integrations", strong=True)

    # Ostraka and Rowanholt
    s.arrow([(530, 160), (400, 160)], ROWANHOLT, "pairs; starts a job")
    s.arrow([(530, 200), (400, 200)], ROWANHOLT, "reads cases and rows")
    s.arrow([(400, 240), (530, 240)], ROWANHOLT, "findings, as leads")
    s.arrow([(400, 280), (530, 280)], ROWANHOLT, "job.completed (signed)", dashed=True)
    # Ostraka and Shikari
    s.arrow([(870, 160), (1000, 160)], SHIKARI, "pairs; starts a hunt")
    s.arrow([(870, 200), (1000, 200)], SHIKARI, "is T1059.001 covered?")
    s.arrow([(1000, 240), (870, 240)], SHIKARI, "counts, never rows")
    s.arrow([(1000, 280), (870, 280)], SHIKARI, "run.executed (signed)", dashed=True)

    # What leaves the suite
    s.label(60, 380, "Out of the suite", OUTSIDE)
    outs = [
        (60, "SIEMs", ["Shikari deploys detections;", "Ostraka stores queries, never rows"]),
        (390, "Teams and Slack", ["team and incident channels,", "outbound webhooks, masked"]),
        (720, "MISP, STIX 2.1, Navigator", ["indicators and techniques,", "from the record"]),
        (1050, "Reports", ["PDF and Word, branded;", "Rowanholt's case reports too"]),
    ]
    for x, title, lines in outs:
        s.card(x, 392, 290, 84, title, lines, OUTSIDE)
    s.arrow([(1170, 322), (1170, 360), (205, 360), (205, 392)], SHIKARI)
    s.arrow([(700, 322), (700, 345), (535, 345), (535, 392)], OSTRAKA)
    s.arrow([(700, 345), (865, 345), (865, 392)], OSTRAKA)
    s.arrow([(780, 345), (1195, 345), (1195, 392)], OSTRAKA)

    # AI and MCP
    s.label(60, 530, "AI and agents", TEAL)
    s.card(60, 542, 410, 84, "MCP servers, one per product", ["Rowanholt's Smith, Shikari's, Ostraka's /mcp:", "each as its token's owner; restricted TLP stays out"], TEAL)
    s.card(495, 542, 410, 84, "Ollama or Anthropic", ["local models for TLP:RED and AMBER+STRICT;", "AI rephrases or answers, never confirms"], TEAL)
    s.card(930, 542, 410, 84, "The reporting standard", ["fixed rules, not AI: PHIA terms, verified", "confirmation, ACH arithmetic"], OSTRAKA)

    # Shared foundation
    s.label(60, 680, "Shared by all three", TEAL)
    shared = [
        ("samarkand", "licences, webhooks, STIX, MISP, SIEM"),
        ("Pairing", "a one-use link: a scoped token and a webhook"),
        ("Licensing", "Free, Pro, Services · Ed25519, offline"),
        ("install-suite", "one command installs all three"),
    ]
    for i, (title, line) in enumerate(shared):
        x = 60 + i * 325
        s.rect(x, 692, 305, 52, CARD, TEAL, width=1)
        s.text(x + 16, 714, title, 13, WHITE, 600)
        s.text(x + 16, 732, line)
    legend(s, 60, 790)
    s.save("suite.svg")


# ---- 2. The anatomy: the whole workflow, in Shikari's workflow manner ------------------------------


COL = 360  # a product's column; 100 between columns leaves room for the connectors and their words


def column(s: Svg, x: int, y: int, name: str, colour: str, stages: list[tuple[str, str]]) -> list[int]:
    """A product's insides, top to bottom; returns the middle of each stage, so connectors run level."""
    s.rect(x, y, COL, 40 + len(stages) * 56, CARD, colour, rx=10, width=1.5)
    s.text(x + 20, y + 26, name, 15, colour, 700)
    ys = []
    for i, (title, line) in enumerate(stages):
        top = y + 40 + i * 56
        s.rect(x + 16, top, COL - 32, 46, BG, LINE, rx=6, width=0.75)
        s.text(x + 30, top + 19, title, 12, WHITE, 600)
        s.text(x + 30, top + 35, line)
        ys.append(top + 23)
    return ys


def level(s: Svg, x1: int, x2: int, y: int, colour: str, words: str, *, dashed=False, below=False) -> None:
    """A level connector between two columns, its words above (or below) it."""
    s.arrow([(x1, y), (x2, y)], colour, dashed=dashed)
    s.text((x1 + x2) / 2, y + (14 if below else -6), words, 9, SOFT, 500, anchor="middle")


def anatomy() -> None:
    s = Svg(1400, 1230, "The suite — anatomy", "From the first alert to lessons learned: what each product does, and what crosses between them")
    rx, ox, sx = 60, 520, 980  # Rowanholt, Ostraka, Shikari

    s.label(60, 104, "Input sources", OUTSIDE)
    inputs = [
        ("Evidence", ["disk images, memory, triage", "collections, cloud logs"], "E01 · raw · VMDK · Gandalf"),
        ("Threat intelligence", ["ATT&CK groups and software,", "CVEs, reports, YARA"], "APT29 · Scattered Spider"),
        ("Alerts and SIEMs", ["Splunk, Defender XDR,", "Elasticsearch, Google SecOps"], "the alert that starts it"),
        ("People", ["responders, leads, commander,", "observers and stakeholders"], "invited, with TOTP"),
    ]
    for i, (title, lines, accent) in enumerate(inputs):
        s.card(60 + i * 325, 116, 305, 92, title, lines, OUTSIDE, accent=accent)
    s.arrow([(330, 208), (330, 274)], OUTSIDE)
    s.arrow([(537, 208), (537, 236), (1160, 236), (1160, 274)], OUTSIDE)
    s.arrow([(862, 208), (862, 274)], OUTSIDE)
    s.arrow([(1187, 208), (1187, 254), (640, 254), (640, 274)], OUTSIDE)

    s.label(60, 266, "The three products", TEAL)
    row = column(s, rx, 274, "Rowanholt", ROWANHOLT, [
        ("Acquire", "Gandalf collects; hashes recorded"),
        ("Parse and analyse", "30+ tools: timelines, IOCs, YARA, ATT&CK"),
        ("Findings", "Smith and analysts flag rows: lead first"),
        ("Rows", "each one cited: host, artefact, ref, SHA-256"),
        ("Confirmed or benign", "an analyst decides, never Smith"),
        ("Case report", "and a Navigator layer of the case"),
    ])
    ost = column(s, ox, 274, "Ostraka", OSTRAKA, [
        ("Declare", "incident or hunt, severity, TLP, code name"),
        ("Work", "tasks, playbooks on the anatomy, clocks"),
        ("Findings", "leads cite rows, observables, files"),
        ("Confirm", "an analyst, after a verification"),
        ("Assess", "PHIA terms, ACH, defensive writing"),
        ("Report and learn", "updates, reports, lessons into tasks"),
    ])
    shk = column(s, sx, 274, "Shikari", SHIKARI, [
        ("Hunt", "a group, a CVE or techniques"),
        ("Generate", "detections per technique, correlated"),
        ("Validate", "containerised SIEMs, precision and recall"),
        ("Coverage", "which techniques have a detection"),
        ("Execute", "runs a hunt's queries; keeps counts only"),
        ("Deploy", "to the SIEM; emulation through VECTR"),
    ])

    level(s, ox, rx + COL, row[0], ROWANHOLT, "starts or links a job")
    level(s, rx + COL, ox, row[2], ROWANHOLT, "leads, with citations")
    level(s, ox, rx + COL, row[3], ROWANHOLT, "reads the cited row", dashed=True)
    level(s, rx + COL, ox, row[5], ROWANHOLT, "job.completed, signed", dashed=True)
    level(s, ox + COL, sx, shk[0], SHIKARI, "starts a hunt run")
    level(s, sx, ox + COL, shk[1], SHIKARI, "run.completed, signed", dashed=True)
    level(s, ox + COL, sx, ost[3] - 7, SHIKARI, "covered?")
    level(s, sx, ox + COL, ost[3] + 7, SHIKARI, "a gap becomes a task", below=True)
    level(s, sx, ox + COL, shk[4], SHIKARI, "counts, never rows")

    s.label(60, 700, "Between them", TEAL)
    between = [
        (ROWANHOLT, "Ostraka ⇄ Rowanholt", ["paired: an ostraka-scope token, a signed webhook", "reads cases and rows; starts jobs on its evidence", "finding.confirmed arrives as a lead, once", "job.completed is noted on the record"]),
        (SHIKARI, "Ostraka ⇄ Shikari", ["paired: an ostraka-scope token, a signed webhook", "confirmed techniques without detections: gap tasks", "starts hunt runs; Shikari runs their queries", "a count per query comes back, never a row"]),
        (TEAL, "The TLP guard", ["TLP:RED and AMBER+STRICT records exchange", "only with servers on the organisation's network:", "private, Tailscale, .internal, .lan, .ts.net", "requests carry identifiers, never the record"]),
    ]
    for i, (colour, title, lines) in enumerate(between):
        s.card(60 + i * 433, 712, 413, 112, title, lines, colour)

    s.label(60, 872, "Output", OUTSIDE)
    outputs = [
        ("Reports", ["technical report and briefing,", "PDF and Word, branded"], OSTRAKA),
        ("Chat", ["Teams and Slack channels,", "team and incident, masked"], OSTRAKA),
        ("Intelligence", ["STIX 2.1, MISP push,", "ATT&CK Navigator layers"], OSTRAKA),
        ("Detections in the SIEM", ["validated, correlated,", "covering what the incident used"], SHIKARI),
    ]
    for i, (title, lines, colour) in enumerate(outputs):
        s.card(60 + i * 325, 884, 305, 84, title, lines, colour)

    s.label(60, 1022, "Shared foundation", TEAL)
    shared = [
        ("samarkand", ["licences, webhook signing and retries,", "STIX, MISP, Navigator, SIEM clients, netguard"]),
        ("One standard", ["invitation only, TOTP for everyone,", "one-use links, audited security log"]),
        ("One way to run", ["desktop apps or a team server, homelab", "behind Tailscale; install-suite for all three"]),
    ]
    for i, (title, lines) in enumerate(shared):
        s.card(60 + i * 433, 1034, 413, 84, title, lines, TEAL)
    legend(s, 60, 1180)
    s.save("suite-anatomy.svg")


if __name__ == "__main__":
    suite()
    anatomy()
