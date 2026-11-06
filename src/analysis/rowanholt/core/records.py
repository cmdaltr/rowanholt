"""Rowanholt's one output format: JSON Lines, every record carrying the same envelope.

Every table Elrond writes (cooked artefacts, analysis, the case's own tables) is a ``.jsonl``
file, one JSON object per line: the envelope fields first, then the artefact's own fields under
their own names. Every reader goes through ``read_records``, which also reads the CSV and JSON
arrays of cases processed before the change (docs/OUTPUT_FORMAT.md).

Stdlib only: the web backend loads this module from Elrond's source tree too.
"""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Union

ENVELOPE = ("host", "artefact", "source_path", "timestamp", "techniques")
SUFFIX = ".jsonl"
TABLE_SUFFIXES = (".jsonl", ".json", ".csv")  # this format first, then the old ones

csv.field_size_limit(16 << 20)

_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%Y/%m/%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%a %b %d %H:%M:%S %Y",
    "%a %b %d %H:%M:%S %Y %z",
    "%b %d %Y %H:%M:%S",
    "%Y%m%d%H%M%S",
)
_EMPTY = {"", "-", "0", "none", "null", "n/a", "unknown", "0000-00-00t00:00:00", "0000-00-00 00:00:00",
          "1601-01-01t00:00:00", "1601-01-01 00:00:00", "1970-01-01t00:00:00", "1970-01-01 00:00:00"}
# Epoch values outside these years are counters or IDs, not times
_EARLIEST, _LATEST = datetime(1980, 1, 1, tzinfo=timezone.utc), datetime(2100, 1, 1, tzinfo=timezone.utc)

Techniques = Union[None, Sequence[str], Callable[[Dict[str, Any]], Iterable[str]]]


def _iso(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)  # times without a zone are recorded as UTC
    moment = moment.astimezone(timezone.utc)
    text = moment.strftime("%Y-%m-%dT%H:%M:%S")
    if moment.microsecond:
        text += f".{moment.microsecond:06d}".rstrip("0")
    return text + "Z"


def _from_epoch(number: float) -> Optional[str]:
    for divisor in (1, 1_000, 1_000_000):  # seconds, milliseconds, microseconds
        try:
            moment = datetime.fromtimestamp(number / divisor, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            continue
        if _EARLIEST <= moment < _LATEST:
            return _iso(moment)
    return None


def iso_timestamp(value: Any) -> Optional[str]:
    """``value`` as ISO 8601 UTC (``2026-10-29T14:03:11Z``), or None when it isn't a time."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        return _iso(value)
    if isinstance(value, (int, float)):
        return _from_epoch(value) if value > 0 else None
    if isinstance(value, dict):  # Artemis/evtx style: {"#attributes": {"SystemTime": ...}}
        inner = value.get("#attributes", value)
        return iso_timestamp(inner.get("SystemTime")) if isinstance(inner, dict) else None
    text = str(value).strip()
    if text.lower().rstrip("z") in _EMPTY:
        return None
    if text.isdigit() and len(text) not in (8, 14):
        return _from_epoch(int(text))
    candidate = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    if " UTC" in candidate:
        candidate = candidate.replace(" UTC", "+00:00")
    try:
        return _iso(datetime.fromisoformat(candidate))
    except ValueError:
        pass
    if "." in candidate:  # more than six fractional digits (NTFS's 100 ns)
        head, _, rest = candidate.partition(".")
        digits = "".join(c for c in rest if c.isdigit())
        zone = rest[len(digits):]
        try:
            return _iso(datetime.fromisoformat(f"{head}.{digits[:6].ljust(6, '0')}{zone}"))
        except ValueError:
            pass
    for fmt in _FORMATS:
        try:
            return _iso(datetime.strptime(text, fmt))
        except ValueError:
            continue
    return None


def _technique_list(row: Dict[str, Any], techniques: Techniques) -> List[str]:
    found = techniques(row) if callable(techniques) else (techniques or [])
    out: List[str] = []
    for item in found:
        for tid in str(item).replace(";", ",").replace("|", ",").split(","):
            tid = tid.strip().upper()
            if tid.startswith("T") and tid not in out:
                out.append(tid)
    return out


def envelope(row: Dict[str, Any], *, host: str, artefact: str, source_path: str = "",
             time_field: Optional[str] = None, techniques: Techniques = None) -> Dict[str, Any]:
    """``row`` with the envelope fields in front. A row field with an envelope name is kept as
    ``orig_<name>``, except a ``timestamp`` that is the row's own time."""
    if time_field is None and "timestamp" in row:
        time_field = "timestamp"
    record: Dict[str, Any] = {
        "host": host,
        "artefact": artefact,
        "source_path": source_path,
        "timestamp": iso_timestamp(row.get(time_field)) if time_field else None,
        "techniques": _technique_list(row, techniques),
    }
    for key, value in row.items():
        key = str(key)
        if key in record:
            if key == "timestamp" and time_field == "timestamp":
                continue
            key = f"orig_{key}"
        record[key] = value
    return record


def write_records(path: Union[str, Path], rows: Iterable[Dict[str, Any]], *, host: str, artefact: str,
                  source_path: str = "", time_field: Optional[str] = None,
                  techniques: Techniques = None) -> int:
    """Append ``rows`` to ``path`` as JSON Lines with the envelope; the number written.

    ``techniques`` is a list for every row, or a function giving each row its own.
    """
    path = Path(path)
    written = 0
    out = None
    try:
        for row in rows:
            if out is None:
                path.parent.mkdir(parents=True, exist_ok=True)
                out = open(path, "a", encoding="utf-8")
            record = envelope(row, host=host, artefact=artefact, source_path=source_path,
                              time_field=time_field, techniques=techniques)
            out.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            written += 1
    finally:
        if out is not None:
            out.close()
    return written


def table_path(folder: Union[str, Path], name: str) -> Path:
    """Where the table ``name`` is in ``folder``: this format's file if there is one, then an old
    case's ``.csv`` or ``.json``; this format's path if none exists yet."""
    folder = Path(folder)
    stem = name[: -len(Path(name).suffix)] if Path(name).suffix in TABLE_SUFFIXES else name
    for suffix in TABLE_SUFFIXES:
        candidate = folder / f"{stem}{suffix}"
        if candidate.is_file():
            return candidate
    return folder / f"{stem}{SUFFIX}"


def artefact_name(path: Union[str, Path], cooked: Union[str, Path]) -> str:
    """The artefact a file under ``cooked`` holds: its path there without the suffix."""
    relative = Path(path).relative_to(cooked)
    return str(relative.with_suffix("")).replace("\\", "/")


def is_table(path: Union[str, Path]) -> bool:
    return Path(path).suffix.lower() in TABLE_SUFFIXES


class RecordsError(ValueError):
    """A table that can't be read."""


def read_records(path: Union[str, Path], max_json_bytes: Optional[int] = None) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """(reference, record) for every record in a table.

    ``.jsonl``: the line number, streamed; a line that isn't JSON comes back as
    ``{"unparsed": line}`` rather than ending the read. ``.csv`` (old cases): the line number,
    the header being line 1. ``.json`` (old cases): ``#index`` in its array, read whole, so
    ``max_json_bytes`` can refuse a huge one.
    """
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        with open(path, encoding="utf-8", errors="replace") as fh:
            for number, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    record = {"unparsed": line.rstrip("\n")}
                yield str(number), record if isinstance(record, dict) else {"value": record}
        return
    if suffix == ".csv":
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            for number, row in enumerate(csv.DictReader(fh), start=2):
                yield str(number), {k or "": v for k, v in row.items()}
        return
    if max_json_bytes is not None and path.stat().st_size > max_json_bytes:
        raise RecordsError(f"{path.name} is over {max_json_bytes >> 20} MB")
    with open(path, encoding="utf-8", errors="replace") as fh:
        try:
            data = json.load(fh)
        except ValueError as whole:
            fh.seek(0)  # JSON Lines under a .json name (Artemis's own layout)
            try:
                data = [json.loads(line) for line in fh if line.strip()]
            except ValueError:
                raise RecordsError(f"{path.name} isn't valid JSON ({whole})") from None
    if isinstance(data, dict):
        data = data.get("items") or data.get("records") or [data]
    for number, record in enumerate(data):
        yield f"#{number}", record if isinstance(record, dict) else {"value": record}


def own_fields(record: Dict[str, Any]) -> Dict[str, Any]:
    """The artefact's own fields: ``record`` without the envelope."""
    return {k: v for k, v in record.items() if k not in ENVELOPE}


def check_file(path: Union[str, Path]) -> List[str]:
    """What's wrong with a ``.jsonl`` table: lines that aren't JSON objects or lack the envelope."""
    problems: List[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for number, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError as exc:
                problems.append(f"line {number}: not JSON ({exc})")
                continue
            if not isinstance(record, dict):
                problems.append(f"line {number}: not an object")
                continue
            missing = [k for k in ENVELOPE if k not in record]
            if missing:
                problems.append(f"line {number}: no {', '.join(missing)}")
            elif not isinstance(record["techniques"], list):
                problems.append(f"line {number}: techniques isn't a list")
    return problems
