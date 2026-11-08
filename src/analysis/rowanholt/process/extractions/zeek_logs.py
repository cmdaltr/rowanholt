"""Zeek's logs as rows: the TSV format (``#separator``/``#fields``/``#types`` headers) and the JSON
one (``LogAscii::use_json=T``, one object per line), plain or gzipped as Zeek rotates them.

Both formats come out the same: Zeek's dotted names with underscores (``id.orig_h`` ->
``id_orig_h``: Elastic would make ``id`` an object and refuse a table with a plain ``id``), sets
and vectors as lists, counts and ports as numbers, unset and empty fields as "" (lists as []),
and ``ts`` as ISO 8601 UTC. Stdlib only.
"""

import gzip
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

# Zeek's own bookkeeping, not traffic
HOUSEKEEPING = {"packet_filter", "loaded_scripts", "stats", "capture_loss", "telemetry", "broker", "cluster",
                "print", "reporter", "config"}
TIME_FIELDS = ("ts",)  # other Zeek time fields stay as Zeek wrote them (epoch seconds)
NUMERIC = ("count", "int", "port", "double", "interval")
LOG_NAME = re.compile(r"^([a-z0-9_]+?)(?:\.\d{2}:\d{2}:\d{2}-\d{2}:\d{2}:\d{2})?(?:\.log)?(?:\.gz)?$", re.I)


class ZeekLogError(ValueError):
    """A file that looked like a Zeek log and isn't one."""


def _open(path: Path):
    with open(path, "rb") as probe:
        gzipped = probe.read(2) == b"\x1f\x8b"
    if gzipped:
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def _first_line(path: Path) -> str:
    try:
        with _open(path) as fh:
            return fh.readline(65536)
    except (OSError, EOFError, gzip.BadGzipFile):
        return ""


def log_format(path: Path) -> str:
    """"tsv", "json" or "" (not a Zeek log), from the file's first line."""
    first = _first_line(Path(path))
    if first.startswith("#separator"):
        return "tsv"
    if first.lstrip().startswith("{"):
        try:
            record = json.loads(first)
        except ValueError:
            return ""
        # Zeek's JSON lines carry ts, and a uid (connections) or fuid (files) or _path when streamed
        if isinstance(record, dict) and "ts" in record and ({"uid", "fuid", "_path", "id.orig_h"} & set(record)):
            return "json"
    return ""


def log_name(path: Path) -> str:
    """The log a file holds from its name: conn.log, conn.09:00:00-10:00:00.log.gz -> conn."""
    match = LOG_NAME.match(Path(path).name)
    return match.group(1).lower() if match else Path(path).name.split(".")[0].lower()


def zeek_time(value: Any) -> str:
    """A Zeek time (epoch seconds, or ISO 8601 when JSON timestamps were set so) as ISO 8601 UTC."""
    if value in (None, "", "-"):
        return ""
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return str(value)
    try:
        moment = datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return str(value)
    text = moment.strftime("%Y-%m-%dT%H:%M:%S")
    if moment.microsecond:
        text += f".{moment.microsecond:06d}".rstrip("0")
    return text + "Z"


def _key(name: str) -> str:
    return name.replace(".", "_")


def _number(value: str, kind: str) -> Any:
    try:
        return float(value) if kind in ("double", "interval") else int(value)
    except ValueError:
        return value


def _unescape(value: str) -> str:
    """Zeek's \\xNN escapes (non-printing bytes and the separator itself) back to characters."""
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), value) if "\\x" in value else value


def _tsv_rows(fh, first: str) -> Iterator[Dict[str, Any]]:
    separator = "\t"
    if first.startswith("#separator"):
        raw = first.split(" ", 1)[1].strip() if " " in first else "\\x09"
        separator = _unescape(raw) or "\t"
    set_separator, empty, unset = ",", "(empty)", "-"
    fields: List[str] = []
    types: List[str] = []
    for line in fh:
        line = line.rstrip("\n").rstrip("\r")
        if not line:
            continue
        if line.startswith("#"):
            directive, _, rest = line.partition(separator)
            if directive == "#set_separator":
                set_separator = _unescape(rest)
            elif directive == "#empty_field":
                empty = rest
            elif directive == "#unset_field":
                unset = rest
            elif directive == "#fields":
                fields = rest.split(separator)
            elif directive == "#types":
                types = rest.split(separator)
            continue
        if not fields:
            raise ZeekLogError("data before the #fields line")
        values = line.split(separator)
        row: Dict[str, Any] = {}
        for index, name in enumerate(fields):
            value = values[index] if index < len(values) else unset
            kind = types[index] if index < len(types) else "string"
            container = kind.startswith(("set[", "vector["))
            if value == unset or value == empty:
                row[_key(name)] = [] if container else ""
                continue
            if container:
                inner = kind[kind.index("[") + 1:-1]
                items = [_unescape(v) for v in value.split(set_separator)]
                row[_key(name)] = [_number(v, inner) if inner in NUMERIC else v for v in items]
            elif kind in NUMERIC:
                row[_key(name)] = _number(value, kind)
            elif kind == "bool":
                row[_key(name)] = value == "T"
            else:
                row[_key(name)] = _unescape(value)
        yield row


def _chain(first: str, fh) -> Iterator[str]:
    """The first line (already read: gzip streams don't seek cheaply) and the rest."""
    yield first
    yield from fh


def _json_rows(fh) -> Iterator[Dict[str, Any]]:
    for line in fh:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            yield {_key(k): v for k, v in record.items()}


def _json_path(path: Path) -> Optional[str]:
    """The _path a streamed JSON log's first line carries, or None."""
    try:
        record = json.loads(_first_line(path))
    except ValueError:
        return None
    return str(record["_path"]).lower() if isinstance(record, dict) and record.get("_path") else None


def log_kind(path: Path) -> Tuple[str, str]:
    """(format, log name) for a file, or ("", "") when it isn't a Zeek log. The log's own name for
    itself (TSV's #path, a streamed JSON line's _path) wins over the file's."""
    path = Path(path)
    kind = log_format(path)
    if not kind:
        return "", ""
    own = tsv_path(path) if kind == "tsv" else _json_path(path)
    return kind, (own or log_name(path)).lower()


def iter_log(path: Path) -> Iterator[Dict[str, Any]]:
    """One Zeek log's rows, streamed, ``ts`` as ISO 8601; ZeekLogError if it isn't one."""
    path = Path(path)
    kind = log_format(path)
    if not kind:
        raise ZeekLogError(f"{path.name} isn't a Zeek log")
    with _open(path) as fh:
        first = fh.readline()
        rows = _tsv_rows(fh, first) if kind == "tsv" else _json_rows(_chain(first, fh))
        for row in rows:
            row.pop("_path", None)
            for field in TIME_FIELDS:
                if field in row:
                    row[field] = zeek_time(row[field])
            yield row


def read_log(path: Path) -> Tuple[str, List[Dict[str, Any]]]:
    """(log name, rows) for one Zeek log file, read whole (tests and small logs)."""
    return log_kind(path)[1], list(iter_log(path))


def tsv_path(path: Path) -> Optional[str]:
    """The #path a TSV log declares (its log name when the file was renamed), or None."""
    try:
        with _open(Path(path)) as fh:
            for _, line in zip(range(12), fh):
                if line.startswith("#path"):
                    return line.rstrip("\n").split(None, 1)[1].strip() if len(line.split()) > 1 else None
    except (OSError, EOFError, gzip.BadGzipFile):
        return None
    return None
