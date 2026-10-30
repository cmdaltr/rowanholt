#!/usr/bin/env python3
"""
Score a case's stacking.csv against the values the lab planted, and record the result.

    lab/lib/stacking_eval.py <elrond output dir> <acquisitions dir> [--readme lab/README.md] [--label TEXT]

The plants are the "stacking" values in each target's expected.json (a substring of a row's
Value or Example, as precision_at_k matches them). Prints precision at 4, 8 and 20 and where
each plant ranked, and with --readme appends a row to the table between the stacking-eval
markers there. Exits 1 when a plant isn't in stacking.csv at all.
"""
import argparse
import csv
import importlib.util
import json
import sys
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional

REPO = Path(__file__).resolve().parents[2]
STACKING = REPO / "src" / "analysis" / "rivendell" / "analysis" / "stacking.py"
KS = (4, 8, 20)
TABLE_END = "<!-- stacking-eval: rows above -->"


def precision_at_k():
    """stacking.precision_at_k, loaded by path: the analysis package isn't installed on the host."""
    spec = importlib.util.spec_from_file_location("stacking", STACKING)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.precision_at_k


def plants(acquisitions: Path) -> Dict[str, List[str]]:
    """Each target's planted values, from its expected.json."""
    found = {}
    for expected in sorted(acquisitions.glob("*/expected.json")):
        try:
            values = json.loads(expected.read_text()).get("stacking", [])
        except (OSError, ValueError):
            continue
        if values:
            found[expected.parent.name] = [v.lower() for v in values]
    return found


def ranks(stacking_csv: Path, needles: List[str]) -> Dict[str, Optional[int]]:
    """The first rank at which each planted value appears, or None."""
    with open(stacking_csv, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    first = {}
    for needle in needles:
        first[needle] = next((int(r["Rank"]) for r in rows
                              if needle in r["Value"] or needle in r["Example"].lower()), None)
    return first


def append_row(readme: Path, row: str) -> None:
    text = readme.read_text()
    if TABLE_END not in text:
        raise SystemExit(f"{readme} has no '{TABLE_END}' marker to add the result above")
    readme.write_text(text.replace(TABLE_END, f"{row}\n{TABLE_END}", 1))


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    cli.add_argument("output", type=Path, help="Elrond's destination for the case")
    cli.add_argument("acquisitions", type=Path, help="the acquisitions folder, a folder per target")
    cli.add_argument("--readme", type=Path, help="append the result to this file's stacking-eval table")
    cli.add_argument("--label", default="", help="what was stacked, for the table (default: the hosts)")
    options = cli.parse_args()

    found = sorted(options.output.rglob("stacking.csv"))
    if not found:
        print(f"No stacking.csv under {options.output}: Elrond needs --Analysis and two or more hosts.")
        return 1
    stacking_csv = found[0]
    planted = plants(options.acquisitions)
    if not planted:
        print(f"No \"stacking\" values in the expected.json files under {options.acquisitions}.")
        return 1
    needles = sorted({n for values in planted.values() for n in values})
    with open(stacking_csv, newline="", encoding="utf-8") as fh:
        total = sum(1 for _ in csv.DictReader(fh))
    score = precision_at_k()
    precisions = {k: score(str(stacking_csv), needles, k) for k in KS}
    where = ranks(stacking_csv, needles)

    print(f"{stacking_csv}: {total} rows; plants on {', '.join(planted)}")
    for k in KS:
        print(f"  precision@{k}: {precisions[k]:.2f}")
    for needle, rank in where.items():
        print(f"  {needle}: {'rank ' + str(rank) if rank else 'NOT FOUND'}")

    if options.readme:
        hosts = sorted(p.name for p in options.acquisitions.iterdir() if p.is_dir())
        placed = ", ".join(str(r) if r else "missing" for r in sorted(where.values(), key=lambda r: r or 10 ** 9))
        append_row(options.readme, f"| {date.today().isoformat()} | {options.label or ', '.join(hosts)} | {total} | "
                                   + " | ".join(f"{precisions[k]:.2f}" for k in KS) + f" | {placed} |")
        print(f"Added to {options.readme}")
    return 0 if all(where.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
