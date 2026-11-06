"""Reading a case's output for the case browser: hosts, their cooked artefacts and analysis files,
and rows from them, paged and filtered.

Read-only by construction: nothing here opens a file for writing, and only artefacts/cooked/,
analysis/ and the case's own top-level tables are reachable; raw/ never is. A path from a request
is resolved and must stay under one of those folders.

Tables are JSON Lines (rowanholt/core/records.py, loaded from Elrond's source tree); cases
processed before that are CSV and JSON arrays, read the same way.
"""

import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple


def _load_tables():
    """rowanholt/core/records.py, loaded by path: putting Elrond's source tree on sys.path would let
    its own config and main shadow the backend's."""
    for src in (os.environ.get("ROWANHOLT_ELROND_SRC", "/opt/elrond-src"), Path(__file__).resolve().parents[2] / "analysis"):
        path = Path(src, "rowanholt", "core", "records.py")
        if path.is_file():
            spec = importlib.util.spec_from_file_location("rowanholt_records", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise ImportError("rowanholt/core/records.py not found: is Elrond's source mounted at ROWANHOLT_ELROND_SRC?")


tables = _load_tables()

ROW_FILES = tables.TABLE_SUFFIXES
MAX_JSON_BYTES = 64 << 20  # an old case's JSON array is read whole
MAX_SCAN = 500_000  # rows scanned for a filter before the count stops being exact
MAX_CELL = 2000
CASE_HOST = "(case)"  # the case's top-level tables, such as threat_groups

csv.field_size_limit(16 << 20)


class CaseFileError(ValueError):
    """A path outside the readable folders, or a file that isn't a table."""


def case_root(destination: str, case_number: str) -> Optional[Path]:
    """The folder holding a job's host folders: the destination itself, or the case's folder in it."""
    if not destination:
        return None
    root = Path(destination)
    for candidate in (root, root / case_number):
        if candidate.is_dir() and (_is_host(candidate) or any(_is_host(p) for p in candidate.iterdir() if p.is_dir())):
            return candidate
    return None


def _is_host(path: Path) -> bool:
    return (path / "artefacts").is_dir() or (path / "analysis").is_dir()


def hosts(root: Path) -> List[Path]:
    if _is_host(root):
        return [root]
    return sorted(p for p in root.iterdir() if p.is_dir() and _is_host(p))


def _readable(host_dir: Path) -> List[Path]:
    return [host_dir / "artefacts" / "cooked", host_dir / "analysis"]


def listing(root: Path) -> Dict:
    """Every host with its readable tables, and the case's own."""
    out = []
    for host_dir in hosts(root):
        files = []
        for folder in _readable(host_dir):
            if not folder.is_dir():
                continue
            for path in sorted(folder.rglob("*")):
                if path.is_file() and path.suffix.lower() in ROW_FILES:
                    files.append({"path": str(path.relative_to(host_dir)), "size": path.stat().st_size})
        out.append({"host": host_dir.name, "files": files})
    case_files = [{"path": p.name, "size": p.stat().st_size} for p in sorted(root.iterdir())
                  if p.is_file() and p.suffix.lower() in ROW_FILES]
    return {"hosts": out, "case_files": case_files}


def resolve(root: Path, host: str, relative: str) -> Path:
    """The file a request names, refused unless it's a table in a readable folder."""
    if host == CASE_HOST:
        allowed, base = [root], root
    else:
        matches = [h for h in hosts(root) if h.name == host]
        if not matches:
            raise CaseFileError(f"No host {host!r} in this case")
        base = matches[0]
        allowed = _readable(base)
    path = (base / relative).resolve()
    if path.suffix.lower() not in ROW_FILES or not path.is_file():
        raise CaseFileError(f"{relative}: not a table in this case")
    for folder in allowed:
        folder = folder.resolve()
        if host == CASE_HOST and path.parent == folder:
            return path
        if host != CASE_HOST and folder in path.parents:
            return path
    raise CaseFileError(f"{relative}: outside the case's cooked and analysis folders")


def csv_row(row: Dict) -> Dict[str, str]:
    """A csv.DictReader row as records() yields it (and row_hash() hashes it)."""
    return {k or "": v if isinstance(v, str) else json.dumps(v) for k, v in row.items()}


def json_row(record) -> Dict[str, str]:
    """A JSON record as records() yields it (and row_hash() hashes it)."""
    if not isinstance(record, dict):
        return {"value": json.dumps(record) if not isinstance(record, str) else record}
    return {str(k): v if isinstance(v, str) else json.dumps(v, default=str) for k, v in record.items()}


def records_with_values(path: Path) -> Iterator[Tuple[str, Dict, Dict[str, str]]]:
    """(row reference, record as written, row as records() gives it) for each row."""
    convert = csv_row if path.suffix.lower() == ".csv" else json_row
    try:
        for ref, record in tables.read_records(path, max_json_bytes=MAX_JSON_BYTES):
            yield ref, record, convert(record)
    except tables.RecordsError as exc:
        raise CaseFileError(f"{exc}: open it from the case folder, or re-run its processing") from None


def records(path: Path) -> Iterator[Tuple[str, Dict[str, str]]]:
    """(row reference, row) for each row: the line number in JSON Lines and CSV (a CSV's header
    is line 1), #index in an old case's JSON array. Values are text, nested ones as JSON."""
    for ref, _, row in records_with_values(path):
        yield ref, row


def row_hash(row: Dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(row, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def page(path: Path, query: str = "", offset: int = 0, limit: int = 100) -> Dict:
    """Rows offset..offset+limit of those containing `query` (case-insensitive, any field)."""
    needle = query.lower()
    rows, columns, total, scanned, exact = [], [], 0, 0, True
    for ref, row in records(path):
        scanned += 1
        if not columns:
            columns = list(row)
        if needle and not any(needle in (v or "").lower() for v in row.values()):
            if scanned >= MAX_SCAN:
                exact = False
                break
            continue
        if offset <= total < offset + limit:
            rows.append({"ref": ref, "hash": row_hash(row),
                         "cells": {k: (v or "")[:MAX_CELL] for k, v in row.items()}})
        total += 1
        if scanned >= MAX_SCAN or (not needle and total >= offset + limit and scanned >= 10_000):
            # Without a filter, stop once the page is full; the total is then a lower bound
            exact = False
            break
    for row in rows:
        for key in row["cells"]:
            if key not in columns:
                columns.append(key)
    return {"columns": columns, "rows": rows, "total": total, "exact": exact}


def find_row(path: Path, ref: str) -> Optional[Dict[str, str]]:
    for current, row in records(path):
        if current == ref:
            return row
    return None


SPREADSHEET_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def _cell(value: str) -> str:
    """A spreadsheet runs a cell that starts with = + - or @ as a formula: an evidential value such
    as =HYPERLINK(...) or a command line is prefixed with ' so it opens as text."""
    return "'" + value if value.startswith(SPREADSHEET_FORMULA) and value != "-" else value


def csv_export(path: Path, query: str = "") -> Iterator[str]:
    """The table as CSV, rows matching `query` as page() matches them: a header of every field any
    record has (a JSON Lines table's records needn't share them), nested values as JSON text, the
    row reference first. Read twice, for the header and then the rows."""
    needle = query.lower()

    def matching() -> Iterator[Tuple[str, Dict[str, str]]]:
        for ref, row in records(path):
            if not needle or any(needle in (v or "").lower() for v in row.values()):
                yield ref, row

    columns: Dict[str, None] = {}
    for _, row in matching():
        columns.update(dict.fromkeys(row))
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["row", *columns])
    for count, (ref, row) in enumerate(matching(), 1):
        writer.writerow([ref, *(_cell(row.get(c) or "") for c in columns)])
        if count % 1000 == 0:
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate()
    yield buffer.getvalue()
