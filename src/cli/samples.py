#!/usr/bin/env python3
"""
rowanholt samples: public forensic images as ready cases (src/analysis/rowanholt/samples).

Usage:
    rowanholt samples list
    rowanholt samples fetch <id> [<id> ...] | --all     download, check each file's hash, unpack
    rowanholt samples import <id> [<id> ...] | --all [--force]   start each as an Elrond job

The samples folder is ROWANHOLT_SAMPLES_DIR (or --dir; default /tmp/rowanholt/samples): a path
the worker can read, as the jobs it starts read the images where they are. Import uses
Rowanholt's API: ROWANHOLT_API (default http://localhost:5688) and, on a team server,
ROWANHOLT_TOKEN.
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import List

# In place of this folder, whose rowanholt.py would shadow Elrond's rowanholt package
sys.path[0] = str(Path(__file__).resolve().parents[1] / "analysis")

from rowanholt.samples import samples  # noqa: E402

logger = logging.getLogger("rowanholt.samples")


def _size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _chosen(ids: List[str], everything: bool) -> List[dict]:
    if everything:
        return samples.catalogue()
    if not ids:
        raise samples.SampleError("Name the samples (rowanholt samples list), or --all")
    return [samples.sample(i) for i in ids]


def cmd_list(root: Path) -> int:
    """The catalogue, with what's here."""
    logger.info("Samples folder: %s\n", root)
    for s in samples.catalogue():
        st = samples.status(s, root)
        state = "ready" if st["images"] else ", ".join(f"{f['name']}: {f['state']}" for f in st["files"])
        logger.info("%-22s %s\n%22s %s; %s\n%22s %s\n", s["id"], s["title"], "", s["os"], " + ".join(s["covers"]),
                    "", state)
    return 0


def _progress():
    last = {}

    def report(name: str, done: int, total: int) -> None:
        step = done // (512 << 20)
        if last.get(name) != step:
            last[name] = step
            logger.info("  %s: %s%s", name, _size(done), f" of {_size(total)}" if total else "")
    return report


def cmd_fetch(root: Path, chosen: List[dict]) -> int:
    """Download, check and unpack each sample."""
    failed = 0
    for s in chosen:
        try:
            for entry in s["files"]:
                samples.fetch_file(s, entry, root, _progress())
            found = samples.unpack(s, root)
            logger.info("%s: ready (%s)", s["id"], ", ".join(p.name for p in found))
        except (samples.SampleError, OSError) as exc:
            logger.error("%s: %s", s["id"], exc)
            failed += 1
    return 1 if failed else 0


def cmd_import(root: Path, chosen: List[dict], force: bool) -> int:
    """Start each fetched sample as a job."""
    api = os.environ.get("ROWANHOLT_API", "http://localhost:5688")
    token = os.environ.get("ROWANHOLT_TOKEN")
    failed = 0
    for s in chosen:
        try:
            found = samples.images(s, root)
            if not found:
                raise samples.SampleError(f"not fetched yet: rowanholt samples fetch {s['id']}")
            job = samples.create_job(samples.job_request(s, found, force), api, token)
            logger.info("%s: job %s started as case %s (%s)", s["id"], job.get("id"), job.get("case_number"),
                        job.get("destination_path"))
        except (samples.SampleError, OSError) as exc:
            logger.error("%s: %s", s["id"], exc)
            failed += 1
    return 1 if failed else 0


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(prog="rowanholt samples", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dir", help="the samples folder (default: ROWANHOLT_SAMPLES_DIR, else /tmp/rowanholt/samples)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="the catalogue, with what's here")
    for name, text in (("fetch", "download, check and unpack"), ("import", "start as Elrond jobs")):
        p = sub.add_parser(name, help=text)
        p.add_argument("ids", nargs="*")
        p.add_argument("--all", action="store_true")
        if name == "import":
            p.add_argument("--force", action="store_true", help="replace a case folder that's already there")
    args = parser.parse_args()
    root = samples.samples_dir(args.dir)
    try:
        if args.command == "list":
            return cmd_list(root)
        chosen = _chosen(args.ids, args.all)
        if args.command == "fetch":
            return cmd_fetch(root, chosen)
        return cmd_import(root, chosen, args.force)
    except samples.SampleError as exc:
        logger.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
