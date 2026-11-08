#!/usr/bin/env python3
"""Elrond's processing of one collected file, printed: a quick loop for parser work on real data.

    python3 process_one.py <case>/<host>/artefacts/raw/<path> [--os Windows|Linux|macOS] [--rows N] [--keep DIR]

The file goes through process_artefacts, the dispatcher a full run uses, into a scratch case whose raw/
is a link to the real one (so parsers that read a sibling, such as shadow beside passwd, still find it).
Nothing is written beside the evidence. `rowanholt elrond process-one` runs this in a throwaway worker
container with the checkout's source, so a parser edit is tested without rebuilding the worker.
"""

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import List

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from rowanholt.core.records import RecordsError, is_table, read_records  # noqa: E402
from rowanholt.process.process import process_artefacts  # noqa: E402

RAW = re.compile(r"^(?P<root>.*?)/(?P<host>[^/]+)/artefacts/raw/(?P<rel>.+)$")


def guess_os(rel: str) -> str:
    """The platform Elrond would have identified, from where the file sits in raw/."""
    top = rel.split("/")[0]
    if top in ("macos", "tcc", "fseventsd", "unified_log_store", "spotlight") or rel.endswith(".asl"):
        return "macOS"
    if top in ("linux", "cron", "cron_jobs", "at_jobs", "conf", "journal") or rel in ("passwd", "crontab"):
        return "Linux"
    return "Windows"


def show(path: Path, limit: int) -> None:
    """A cooked file's row count and its first rows, one field per line."""
    print(f"\n== {path.name}")
    if not is_table(path):
        text = path.read_text(encoding="utf-8", errors="replace")
        print(f"   {len(text)} characters" + ("; the start" if len(text) > 1200 else ""))
        print("   " + text[:1200].replace("\n", "\n   "))
        return
    try:
        rows: List[dict] = [record for _, record in read_records(path)]
    except RecordsError as exc:
        print(f"   unreadable: {exc}")
        return
    print(f"   {len(rows)} rows" + (f"; the first {limit}" if len(rows) > limit else ""))
    for n, row in enumerate(rows[:limit], 1):
        print(f"   [{n}]")
        for key, value in row.items():
            if value not in (None, "", [], {}):
                shown = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
                print(f"       {key}: {shown[:200]}")


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    cli.add_argument("artefact", help="a file under <case>/<host>/artefacts/raw/")
    cli.add_argument("--os", choices=("Windows", "Linux", "macOS"), help="the host's platform (default: guessed)")
    cli.add_argument("--rows", type=int, default=5, help="rows to print from each cooked file (default 5)")
    cli.add_argument("--keep", help="copy the scratch case's cooked/ here instead of deleting it")
    options = cli.parse_args()

    source = Path(options.artefact).absolute()
    match = RAW.match(str(source))
    if not match or not source.is_file():
        print(f"Not a file under <case>/<host>/artefacts/raw/: {source}")
        return 2
    host, rel = match["host"], match["rel"]
    platform = options.os or guess_os(rel)

    work = Path(tempfile.mkdtemp(prefix="process-one-"))
    try:
        artefacts = work / host / "artefacts"
        artefacts.mkdir(parents=True)
        (artefacts / "raw").symlink_to(Path(match["root"]) / host / "artefacts" / "raw")
        output_directory, img = str(work) + "/", f"{host}::{platform}"
        print(f"{rel} as {img}")
        os.chdir(HERE)  # tool paths are relative to Elrond's folder, as in a full run
        process_artefacts(output_directory, "", "3", output_directory, "processing", [(output_directory, img)], img,
                          f"'{host}'", "/", str(artefacts / "raw" / rel), "", "", "", False)

        cooked = [p for p in sorted((artefacts / "cooked").rglob("*")) if p.is_file()]
        if not cooked:
            print("\nNothing cooked: no processor took this file, or it failed (see above).")
        for path in cooked:
            show(path, options.rows)
        techniques = work / "mitre_techniques.txt"
        if techniques.exists():
            print("\n== ATT&CK techniques recorded\n   " + " ".join(sorted(set(techniques.read_text().split()))))
        if options.keep and cooked:
            shutil.copytree(artefacts / "cooked", Path(options.keep) / host, dirs_exist_ok=True)
            print(f"\nCooked files copied to {Path(options.keep) / host}")
        return 0 if cooked else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
