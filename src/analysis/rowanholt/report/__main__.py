"""``python3 -m rowanholt.report CASE_FOLDER``: the uncurated report of a case Elrond has processed,
without processing it again (run from src/analysis)."""

import argparse
import logging
import sys
from typing import List, Optional

from .build import FORMATS, write_reports

logger = logging.getLogger("rowanholt.report")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m rowanholt.report",
                                     description="Write a case's report (Markdown and DOCX) from its case folder.")
    parser.add_argument("case_folder", help="the case's folder: the one holding its host folders")
    parser.add_argument("--case", default="", help="the case number (default: the one Elrond recorded, or the folder's name)")
    parser.add_argument("--out", default="", help="where to write the report (default: the case folder)")
    parser.add_argument("--format", nargs="+", choices=FORMATS, default=list(FORMATS), help="markdown, docx or both")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="  %(message)s")
    try:
        written = write_reports(args.case_folder, args.out or None, args.format, args.case,
                                progress=lambda message: logger.info(message))
    except (FileNotFoundError, NotADirectoryError, PermissionError) as exc:
        logger.error(f"Error: {exc}")
        return 1
    for path in written:
        logger.info(f"Report: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
