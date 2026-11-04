#!/usr/bin/env python3
"""Extract per-test and per-stage timings from Rowanholt test output.

Reads rowanholt_audit.log from each test output directory, joins it with the
TestCase definitions in run_test.py and the image sizes, and writes JSON, CSV
and Markdown summaries.

Usage:
    python tests/scripts/test_timings.py [--output-root DIR] [--images-root DIR]
                                         [--json FILE] [--csv FILE] [--markdown FILE]
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent))
import run_test  # noqa: E402

_RECORD_START = re.compile(r"\s*(?=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?,)")

AUDIT_LOG = "rowanholt_audit.log"


FOLDED_STAGE_PREFIXES = ("indexing", "potential script obfuscation")
VOLATILITY_PREFIXES = ("extracted windows.", "extracted linux.", "extracted mac.", "no evidence of")


def normalise_stage(stage: str) -> str:
    """Fold per-artefact stage names (e.g. 'indexing SAM.json for X') into one stage."""
    stage = stage.split(" (line #")[0]
    if stage.startswith(VOLATILITY_PREFIXES):
        return "volatility plugins"
    for prefix in FOLDED_STAGE_PREFIXES:
        if stage.startswith(prefix):
            return prefix
    # SIEM entries name each file and image: 'indexed SAM.json for X', 'completed indexing for X'
    if " for " in stage:
        return stage.split(" ")[0]
    return stage


def _parse_ts(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def parse_audit_log(path: Path) -> Dict:
    """Return overall start/end and ordered per-stage timing from one audit log.

    Elrond writes an entry when work finishes, so each stage is charged the gap
    since the previous entry; stage minutes therefore sum to the total duration.
    """
    stages: "OrderedDict[str, Dict]" = OrderedDict()
    first: Optional[datetime] = None
    last: Optional[datetime] = None
    completed = False

    # Split on timestamps rather than newlines: some writers (analysis/iocs.py)
    # omit the trailing newline, gluing thousands of entries onto one line.
    text = path.read_text(errors="replace")
    records = _RECORD_START.split(text.split("\n", 1)[1] if "\n" in text else "")
    for line in records:
        parts = line.strip().split(",", 3)
        if len(parts) < 3:
            continue
        ts = _parse_ts(parts[0])
        if ts is None:
            continue
        stage = normalise_stage(parts[2])
        entry = parts[3] if len(parts) > 3 else ""
        gap = (ts - last).total_seconds() if last else 0.0
        first = first or ts
        last = ts
        s = stages.setdefault(stage, {"seconds": 0.0, "entries": 0})
        s["seconds"] += gap
        s["entries"] += 1
        if stage == "elrond_stage" and "completed" in entry.lower():
            completed = True

    return {
        "start": first,
        "end": last,
        "finished": completed,
        "stages": stages,
    }


def image_sizes(images: List[str], images_root: Path) -> List[float]:
    """Return each image size in GB (0 when the image is not present)."""
    sizes = []
    for img in images:
        p = Path(img) if os.path.isabs(img) else images_root / img
        sizes.append(round(p.stat().st_size / 1e9, 2) if p.exists() else 0.0)
    return sizes


def collect(output_root: Path, images_root: Path) -> List[Dict]:
    """Build one timing record per test output directory with an audit log."""
    cases = {t.name: t for t in run_test.ALL_TESTS}
    rows = []
    for test_dir in sorted(output_root.iterdir()):
        log = test_dir / AUDIT_LOG
        if not log.is_file():
            continue
        parsed = parse_audit_log(log)
        if parsed["start"] is None:
            continue
        case = cases.get(test_dir.name)
        images = case.images if case else []
        sizes = image_sizes(images, images_root)
        total_min = (parsed["end"] - parsed["start"]).total_seconds() / 60
        rows.append({
            "test": test_dir.name,
            "options": sorted(k for k, v in (case.options if case else {}).items() if v),
            "images": images,
            "image_size_gb": sizes,
            "total_image_gb": round(sum(sizes), 2),
            "started": parsed["start"].isoformat(timespec="seconds"),
            "ended": parsed["end"].isoformat(timespec="seconds"),
            "duration_min": round(total_min, 1),
            "estimated_min": case.estimated_duration_minutes if case else None,
            "stages": {
                name: {
                    "duration_min": round(s["seconds"] / 60, 1),
                    "entries": s["entries"],
                }
                for name, s in parsed["stages"].items()
            },
        })
    return rows


def write_markdown(rows: List[Dict], path: Path) -> None:
    """Write a Markdown table of test durations and their slowest stages."""
    lines = [
        "| Test | Options | Image(s) | Size (GB) | Duration (min) | Estimate (min) | Slowest stages |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in sorted(rows, key=lambda r: r["duration_min"], reverse=True):
        slow = sorted(r["stages"].items(), key=lambda kv: kv[1]["duration_min"], reverse=True)[:3]
        slow_txt = ", ".join(f"{k} {v['duration_min']}m ({v['entries']})" for k, v in slow)
        lines.append(
            f"| {r['test']} | {', '.join(r['options']) or '—'} | {', '.join(r['images'])} "
            f"| {r['total_image_gb']} | {r['duration_min']} | {r['estimated_min']} | {slow_txt} |"
        )
    path.write_text("\n".join(lines) + "\n")


def write_csv(rows: List[Dict], path: Path) -> None:
    """Write one CSV row per test, stages flattened as 'stage=min(entries)'."""
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["test", "options", "images", "total_image_gb", "duration_min",
                    "estimated_min", "started", "ended", "stages"])
        for r in rows:
            w.writerow([
                r["test"], ";".join(r["options"]), ";".join(r["images"]), r["total_image_gb"],
                r["duration_min"], r["estimated_min"], r["started"], r["ended"],
                "; ".join(f"{k}={v['duration_min']}m({v['entries']})" for k, v in r["stages"].items()),
            ])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output-root", default=run_test.TEST_OUTPUT_PATH)
    parser.add_argument("--images-root", default=run_test.TEST_IMAGES_PATH)
    parser.add_argument("--json")
    parser.add_argument("--csv")
    parser.add_argument("--markdown")
    args = parser.parse_args()

    rows = collect(Path(args.output_root), Path(args.images_root))
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2))
    if args.csv:
        write_csv(rows, Path(args.csv))
    if args.markdown:
        write_markdown(rows, Path(args.markdown))
    if not (args.json or args.csv or args.markdown):
        json.dump(rows, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
