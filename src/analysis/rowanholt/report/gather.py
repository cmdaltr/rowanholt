"""What a case report says, read from the case directory.

Read-only by construction: files are opened for reading only, and only a host's
``artefacts/cooked/`` and ``analysis/`` tables, its Gandalf files beside them (``gandalf_*``,
``artefacts/host.info``) and the case's own top-level files are read; ``raw/`` never is.

Every claim carries a ``Cite``: the host, the file relative to the host's folder (as the case
browser names it), the row reference (the line number in JSON Lines and CSV, ``#n`` in an old
case's JSON array) and the row's SHA-256 as the case browser and findings compute it.
"""

import csv
import hashlib
import importlib.util
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)


def _load_records():
    """rowanholt/core/records.py: imported in Elrond, loaded by path in the backend."""
    try:
        from rowanholt.core import records as module
        return module
    except ImportError:
        path = Path(__file__).resolve().parents[1] / "core" / "records.py"
        spec = importlib.util.spec_from_file_location("rowanholt_report_records", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


records = _load_records()

CASE_HOST = "(case)"
METHOD_FILE = "rowanholt_method.json"
AUDIT_LOG = "rowanholt_audit.log"
TECHNIQUES_FILE = "mitre_techniques.txt"
ATTACK_CSV = Path(__file__).resolve().parents[1] / "post" / "mitre" / "enterprise_attack.csv"
TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
ENVELOPE = tuple(records.ENVELOPE)
CITES_PER_FILE = 5  # rows cited per technique per file; the rest are counted
MAX_PROBLEMS = 50  # integrity rows other than verified, failures in the audit log
MAX_INDICATORS = 25  # per host and type
MAX_JSON_BYTES = 64 << 20  # an old case's JSON array is read whole, as the case browser reads it
EXCERPT = 300
# Record times outside these years are a FILETIME or epoch zero (1601, 1970), as records.py treats epochs
EARLIEST, LATEST = "1980", "2100"
# Group knowledge matched against the case, not evidence that a technique happened
NOT_TECHNIQUE_EVIDENCE = {"analysis/threat_intel_matches"}
TECHNIQUE_COLUMNS = ("Technique", "Techniques", "technique_id", "Technique ID", "mitre_technique_id",
                     "mitre_techniques")
NETWORK_TYPES = ("IPv4 address", "IPv6 address", "domain")
_TECHNIQUES_MARK = '"techniques": ['
_TIME_MARK = '"timestamp": '
_OWN_TIME_MARK = '"orig_timestamp": "'

csv.field_size_limit(16 << 20)


@dataclass
class Cite:
    """One row, as a reviewer finds it: host, file in the host's folder, row reference, row hash."""

    host: str
    file: str
    ref: str
    row_hash: str
    excerpt: str = ""
    time: str = ""
    source: str = ""  # the collected file the row was parsed from (the envelope's source_path)


@dataclass
class TechniqueFile:
    host: str
    file: str
    count: int = 0
    cites: List[Cite] = field(default_factory=list)


@dataclass
class Technique:
    tid: str
    name: str = ""
    tactics: str = ""
    recorded: bool = False  # in the case's mitre_techniques.txt
    files: Dict[Tuple[str, str], TechniqueFile] = field(default_factory=dict)

    @property
    def rows(self) -> int:
        return sum(f.count for f in self.files.values())

    @property
    def hosts(self) -> List[str]:
        return sorted({f.host for f in self.files.values()})


@dataclass
class Indicator:
    kind: str
    value: str
    count: int
    watchlist: bool
    cite: Cite


@dataclass
class Integrity:
    gandalf: bool = False  # the host came from a Gandalf archive
    checked: bool = False
    file: str = ""
    counts: Dict[str, int] = field(default_factory=dict)
    problems: List[Cite] = field(default_factory=list)
    archive: str = ""
    extracted: str = ""
    summary: str = ""  # what the extraction marker recorded
    phone: bool = False  # checked against the hashes taken when the phone's evidence was registered


@dataclass
class HostReport:
    name: str
    os: str = ""
    os_cite: str = ""
    tables: int = 0
    legacy_tables: int = 0  # CSV or JSON arrays, from before JSON Lines: no envelope, no per-row techniques
    records: int = 0
    timed: int = 0
    unreadable: List[Tuple[str, str]] = field(default_factory=list)
    earliest: Optional[Cite] = None
    latest: Optional[Cite] = None
    first_technique: Optional[Cite] = None
    last_technique: Optional[Cite] = None
    collected_from: str = ""
    collected_to: str = ""
    collected_entries: int = 0
    processed_from: str = ""
    processed_to: str = ""
    integrity: Integrity = field(default_factory=Integrity)
    ioc_file: str = ""
    ioc_rows: int = 0
    ioc_types: Dict[str, int] = field(default_factory=dict)
    indicators: Dict[str, List[Indicator]] = field(default_factory=dict)  # type -> most frequent first
    watchlisted: List[Indicator] = field(default_factory=list)
    intel_file: str = ""
    intel: List[Indicator] = field(default_factory=list)  # kind = the element's kind, value = element


@dataclass
class AuditEntry:
    line: int
    time: str
    host: str
    stage: str
    entry: str


@dataclass
class CaseReport:
    case: str
    root: str
    generated: str
    hosts: List[HostReport] = field(default_factory=list)
    techniques: Dict[str, Technique] = field(default_factory=dict)
    method: Optional[Dict] = None
    method_problem: str = ""
    audit_entries: int = 0
    stages: Dict[str, Dict[str, int]] = field(default_factory=dict)  # host -> stage -> count
    failures: List[AuditEntry] = field(default_factory=list)
    failure_count: int = 0
    threat_groups_file: str = ""
    threat_groups: List[Tuple[Dict[str, str], Cite]] = field(default_factory=list)

    @property
    def earliest(self) -> Optional[Cite]:
        return _extreme([h.earliest for h in self.hosts], min)

    @property
    def latest(self) -> Optional[Cite]:
        return _extreme([h.latest for h in self.hosts], max)


def _extreme(cites: List[Optional[Cite]], pick: Callable) -> Optional[Cite]:
    present = [c for c in cites if c and c.time]
    return pick(present, key=lambda c: _time_key(c.time)) if present else None


def _time_key(iso: str) -> str:
    """ISO times as records.iso_timestamp writes them compare as text once the Z is off
    (05.5Z would otherwise sort before 05Z)."""
    return iso[:-1] if iso.endswith("Z") else iso


# ---- rows as the case browser reads and hashes them ----

def _csv_row(row: Dict) -> Dict[str, str]:
    return {k or "": v if isinstance(v, str) else json.dumps(v) for k, v in row.items()}


def _json_row(record) -> Dict[str, str]:
    if not isinstance(record, dict):
        return {"value": json.dumps(record) if not isinstance(record, str) else record}
    return {str(k): v if isinstance(v, str) else json.dumps(v, default=str) for k, v in record.items()}


def row_hash(record, csv_table: bool = False) -> str:
    """The SHA-256 the case browser gives a row (case_files.row_hash over its records())."""
    row = _csv_row(record) if csv_table else _json_row(record)
    return hashlib.sha256(json.dumps(row, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _leaves(value, prefix: str = "") -> Iterator[Tuple[str, str]]:
    if isinstance(value, dict):
        for key, inner in value.items():
            yield from _leaves(inner, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(value, list):
        if all(not isinstance(v, (dict, list)) for v in value):
            if value:
                yield prefix, ", ".join(str(v) for v in value)
        else:
            for number, inner in enumerate(value):
                yield from _leaves(inner, f"{prefix}[{number}]")
    elif value not in (None, ""):
        yield prefix, str(value)


def excerpt(record: Dict) -> str:
    """The row's own fields as text, nested ones by their path, cut to EXCERPT characters."""
    own = {k: v for k, v in record.items() if k not in ENVELOPE} if isinstance(record, dict) else {"value": record}
    parts = []
    leaves = [(k, v) for k, v in _leaves(own) if "#attributes" not in k and not k.endswith("Guid")
              and k != "orig_timestamp"]  # the time is cited beside the excerpt
    # An event's own data says what happened; its System block is the same on every event
    leaves.sort(key=lambda kv: 0 if ("EventData" in kv[0] or "UserData" in kv[0]) else 1)
    for key, value in leaves:
        key = key.replace("data.Event.", "")
        parts.append(f"{key}: {' '.join(value.split())}")
        if sum(len(p) + 2 for p in parts) > EXCERPT:
            break
    text = "; ".join(parts)
    return text if len(text) <= EXCERPT else text[:EXCERPT - 1] + "…"


def techniques_of(record: Dict) -> List[str]:
    """Every ATT&CK ID a row names: the envelope's techniques, or (old cases) a technique column."""
    found: List[str] = []
    values = [record.get("techniques")] + [record.get(c) for c in TECHNIQUE_COLUMNS]
    for value in values:
        items = value if isinstance(value, list) else re.split(r"[,;|\s]+", value) if isinstance(value, str) else []
        for item in items:
            if isinstance(item, dict):
                item = item.get("mitre_technique_id") or item.get("technique_id") or ""
            tid = str(item).strip().upper()
            if TECHNIQUE.match(tid) and tid not in found:
                found.append(tid)
    return found


def record_time(record: Dict) -> str:
    """The envelope's time, or the artefact's own time kept beside it where the envelope has none."""
    if not isinstance(record, dict):
        return ""
    for key in ("timestamp", "orig_timestamp"):
        moment = records.iso_timestamp(record.get(key)) if record.get(key) else None
        if moment:
            return moment
    return ""


def _fast(line: str) -> Optional[Tuple[List[str], str]]:
    """(techniques, time) from a line write_records wrote, without decoding the whole record (a
    cooked MFT is millions of lines with no techniques); None when the line isn't one. The marks
    can't occur inside a JSON string, where their quotes would be escaped, and the envelope comes
    first, so the first of each is the envelope's."""
    if not line.startswith('{"host": '):
        return None
    start = line.find(_TECHNIQUES_MARK)
    at = line.find(_TIME_MARK)
    if start < 0 or at < 0:
        return None
    start += len(_TECHNIQUES_MARK)
    if line.startswith("]", start):
        techniques: List[str] = []
    else:
        end = line.find("]", start)
        try:
            techniques = [str(t).upper() for t in json.loads(line[start - 1:end + 1])]
        except ValueError:
            return None
    at += len(_TIME_MARK)
    moment = ""
    if line.startswith('"', at):
        moment = line[at + 1:line.find('"', at + 1)]
    else:
        own = line.find(_OWN_TIME_MARK)
        if own >= 0:
            own += len(_OWN_TIME_MARK)
            moment = records.iso_timestamp(line[own:line.find('"', own)]) or ""
    return techniques, moment


# ---- reading the case ----

def case_root(path: Path, case_number: str = "") -> Path:
    """The folder holding the host folders: ``path`` itself, or the case's folder in it."""
    for candidate in (path, path / case_number) if case_number else (path,):
        if candidate.is_dir() and (_is_host(candidate) or any(_is_host(p) for p in candidate.iterdir() if p.is_dir())):
            return candidate
    raise FileNotFoundError(f"{path}: no Elrond host folders (artefacts/ or analysis/) here")


def _is_host(path: Path) -> bool:
    return (path / "artefacts").is_dir() or (path / "analysis").is_dir()


def host_dirs(root: Path) -> List[Path]:
    if _is_host(root):
        return [root]
    return sorted(p for p in root.iterdir() if p.is_dir() and _is_host(p))


def _tables(host_dir: Path) -> Iterator[Path]:
    for folder in (host_dir / "artefacts" / "cooked", host_dir / "analysis"):
        if folder.is_dir():
            for path in sorted(folder.rglob("*")):
                if path.is_file() and path.suffix.lower() in records.TABLE_SUFFIXES:
                    yield path


def _table(folder: Path, name: str) -> Optional[Path]:
    path = records.table_path(folder, name)
    return path if path.is_file() else None


def _rows(path: Path) -> Iterator[Tuple[str, Dict]]:
    yield from records.read_records(path, max_json_bytes=MAX_JSON_BYTES)


def _cite(host: str, host_dir: Path, path: Path, ref: str, record: Dict, moment: str = "") -> Cite:
    csv_table = path.suffix.lower() == ".csv"
    return Cite(host=host, file=path.relative_to(host_dir).as_posix(), ref=ref,
                row_hash=row_hash(record, csv_table), excerpt=excerpt(record),
                time=moment or record_time(record),
                source=str(record.get("source_path") or "") if isinstance(record, dict) else "")


class _Scan:
    """One pass over a host's tables: counts, times and the rows behind each technique."""

    def __init__(self, report: CaseReport, host: HostReport, host_dir: Path):
        self.report, self.host, self.host_dir = report, host, host_dir
        # (time key, path, ref, line or record) for the earliest and latest rows, decoded at the end
        self.extremes: Dict[str, Optional[Tuple]] = {"earliest": None, "latest": None,
                                                     "first_technique": None, "last_technique": None}

    def _consider(self, which: Tuple[str, str], moment: str, path: Path, ref: str, row) -> None:
        key = _time_key(moment)
        if not EARLIEST <= key < LATEST:  # a FILETIME or epoch zero, not a time
            return
        low, high = which
        if self.extremes[low] is None or key < self.extremes[low][0]:
            self.extremes[low] = (key, path, ref, row, moment)
        if self.extremes[high] is None or key > self.extremes[high][0]:
            self.extremes[high] = (key, path, ref, row, moment)

    def _tag(self, techniques: List[str], path: Path, ref: str, record: Dict, moment: str) -> None:
        relative = path.relative_to(self.host_dir).as_posix()
        for tid in techniques:
            technique = self.report.techniques.setdefault(tid, Technique(tid))
            entry = technique.files.setdefault((self.host.name, relative), TechniqueFile(self.host.name, relative))
            entry.count += 1
            if len(entry.cites) < CITES_PER_FILE:
                entry.cites.append(_cite(self.host.name, self.host_dir, path, ref, record, moment))

    def table(self, path: Path) -> None:
        artefact = path.relative_to(self.host_dir).with_suffix("").as_posix()
        evidence = artefact not in NOT_TECHNIQUE_EVIDENCE
        self.host.tables += 1
        if path.suffix.lower() != ".jsonl":
            self.host.legacy_tables += 1
        try:
            if path.suffix.lower() == ".jsonl":
                self._jsonl(path, evidence)
            else:
                for ref, record in _rows(path):
                    self._record(path, ref, record, evidence)
        except (OSError, records.RecordsError, csv.Error, UnicodeError) as exc:
            self.host.unreadable.append((path.relative_to(self.host_dir).as_posix(), str(exc)))
            logger.debug(f"Couldn't read {path}: {exc}")

    def _jsonl(self, path: Path, evidence: bool) -> None:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for number, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                quick = _fast(line)
                if quick is None:
                    try:
                        record = json.loads(line)
                    except ValueError:
                        self.host.records += 1
                        continue
                    self._record(path, str(number), record if isinstance(record, dict) else {"value": record}, evidence)
                    continue
                techniques, moment = quick
                self.host.records += 1
                if moment:
                    self.host.timed += 1
                    self._consider(("earliest", "latest"), moment, path, str(number), line)
                if techniques and evidence:
                    record = json.loads(line)
                    self._tag([t for t in techniques if TECHNIQUE.match(t)], path, str(number), record, moment)
                    if moment:
                        self._consider(("first_technique", "last_technique"), moment, path, str(number), record)

    def _record(self, path: Path, ref: str, record: Dict, evidence: bool) -> None:
        self.host.records += 1
        moment = record_time(record) if "timestamp" in record or "orig_timestamp" in record else ""
        if moment:
            self.host.timed += 1
            self._consider(("earliest", "latest"), moment, path, ref, record)
        techniques = techniques_of(record) if evidence else []
        if techniques:
            self._tag(techniques, path, ref, record, moment)
            if moment:
                self._consider(("first_technique", "last_technique"), moment, path, ref, record)

    def finish(self) -> None:
        for which, found in self.extremes.items():
            if found is None:
                continue
            _, path, ref, row, moment = found
            record = json.loads(row) if isinstance(row, str) else row
            setattr(self.host, which, _cite(self.host.name, self.host_dir, path, ref, record, moment))


def _integrity(host: HostReport, host_dir: Path) -> None:
    integrity = host.integrity
    integrity.gandalf = (host_dir / "gandalf_log.meta").is_file() or (host_dir / "gandalf_extracted.json").is_file()
    marker = host_dir / "gandalf_extracted.json"
    if marker.is_file():
        try:
            data = json.loads(marker.read_text(encoding="utf-8", errors="replace"))
            integrity.archive = str(data.get("archive", ""))
            integrity.extracted = str(data.get("extracted", ""))
            integrity.summary = str(data.get("integrity", ""))
        except (OSError, ValueError, AttributeError):
            pass
    path = _table(host_dir, "gandalf_integrity") or _table(host_dir, "mobile_integrity")
    if not path:
        return
    integrity.phone = path.stem == "mobile_integrity"
    integrity.checked = True
    integrity.file = path.relative_to(host_dir).as_posix()
    try:
        for ref, record in _rows(path):
            status = str(record.get("status", "")) or "unknown"
            integrity.counts[status] = integrity.counts.get(status, 0) + 1
            if status != "verified" and len(integrity.problems) < MAX_PROBLEMS:
                integrity.problems.append(_cite(host.name, host_dir, path, ref, record))
    except (OSError, records.RecordsError, csv.Error) as exc:
        host.unreadable.append((integrity.file, str(exc)))


def _collection(host: HostReport, host_dir: Path) -> None:
    """When Gandalf collected: the first and last entries of its log.audit."""
    audit = host_dir / "gandalf_log.audit"
    if not audit.is_file():
        return
    try:
        with open(audit, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.reader(fh):  # the time is the first column (datetime, or LastWriteTime from Windows)
                moment = records.iso_timestamp(row[0].strip()) if row else None
                if not moment:
                    continue
                host.collected_entries += 1
                if not host.collected_from or _time_key(moment) < _time_key(host.collected_from):
                    host.collected_from = moment
                if not host.collected_to or _time_key(moment) > _time_key(host.collected_to):
                    host.collected_to = moment
    except (OSError, csv.Error) as exc:
        host.unreadable.append(("gandalf_log.audit", str(exc)))


def _host_os(host: HostReport, host_dir: Path) -> None:
    info = host_dir / "artefacts" / "host.info"
    if host.os or not info.is_file():
        return
    try:
        first = info.read_text(encoding="utf-8", errors="replace").splitlines()[0]
    except (OSError, IndexError):
        return
    if "::" in first:
        host.os, host.os_cite = first.split("::", 1)[1].strip(), "artefacts/host.info line 1"


def _iocs(host: HostReport, host_dir: Path) -> None:
    path = _table(host_dir / "analysis", "iocs")
    if not path:
        return
    host.ioc_file = path.relative_to(host_dir).as_posix()
    seen: Dict[Tuple[str, str], Indicator] = {}
    try:
        for ref, record in _rows(path):
            value, kind = str(record.get("ioc") or "").strip(), str(record.get("indicator_type") or "other")
            if not value:
                continue
            host.ioc_rows += 1
            key = (kind, value.lower())
            if key in seen:
                seen[key].count += 1
                continue
            host.ioc_types[kind] = host.ioc_types.get(kind, 0) + 1
            seen[key] = Indicator(kind, value, 1, bool(str(record.get("watchlist_match") or "").strip()),
                                  _cite(host.name, host_dir, path, ref, record))
    except (OSError, records.RecordsError, csv.Error) as exc:
        host.unreadable.append((host.ioc_file, str(exc)))
    ordered = sorted(seen.values(), key=lambda i: (-i.count, i.value.lower()))
    host.watchlisted = [i for i in ordered if i.watchlist]
    for indicator in ordered:
        listed = host.indicators.setdefault(indicator.kind, [])
        if len(listed) < MAX_INDICATORS:
            listed.append(indicator)


def _intel(host: HostReport, host_dir: Path) -> None:
    path = _table(host_dir / "analysis", "threat_intel_matches")
    if not path:
        return
    host.intel_file = path.relative_to(host_dir).as_posix()
    seen: Dict[str, Indicator] = {}
    try:
        for ref, record in _rows(path):
            element = str(record.get("Element") or "")
            if not element:
                continue
            if element in seen:
                seen[element].count += 1
                continue
            seen[element] = Indicator(str(record.get("Kind") or ""), element, 1, False,
                                      _cite(host.name, host_dir, path, ref, record))
    except (OSError, records.RecordsError, csv.Error) as exc:
        host.unreadable.append((host.intel_file, str(exc)))
    host.intel = sorted(seen.values(), key=lambda i: (-i.count, i.value.lower()))


def _audit(report: CaseReport, root: Path) -> None:
    """Elrond's audit log: which stages ran for each host, when, and what failed."""
    path = root / AUDIT_LOG
    if not path.is_file():
        return
    hosts = {h.name: h for h in report.hosts}
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        for number, row in enumerate(reader, start=1):
            if len(row) < 4 or row[0] == "LastWriteTime":
                continue
            moment, host_name, stage, entry = row[0], row[1], row[2], ",".join(row[3:])
            report.audit_entries += 1
            stages = report.stages.setdefault(host_name, {})
            stages[stage] = stages.get(stage, 0) + 1
            host = hosts.get(host_name)
            iso = records.iso_timestamp(moment) or ""
            if host and iso:
                if not host.processed_from or _time_key(iso) < _time_key(host.processed_from):
                    host.processed_from = iso
                if not host.processed_to or _time_key(iso) > _time_key(host.processed_to):
                    host.processed_to = iso
            if host and stage == "identified platform" and not host.os:
                host.os, host.os_cite = entry.strip(), f"{AUDIT_LOG} line {reader.line_num}"
            if "failed" in stage.lower() or "failed" in entry.lower():
                report.failure_count += 1
                if len(report.failures) < MAX_PROBLEMS:
                    report.failures.append(AuditEntry(reader.line_num, moment, host_name, stage, entry.strip()))


def _method(report: CaseReport, root: Path) -> None:
    path = root / METHOD_FILE
    if not path.is_file():
        report.method_problem = (f"Elrond didn't record its method in this case ({METHOD_FILE} is missing: the case "
                                 "was processed before Elrond recorded it)")
        return
    try:
        report.method = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError) as exc:
        report.method_problem = f"{METHOD_FILE} couldn't be read ({exc})"


def _threat_groups(report: CaseReport, root: Path) -> None:
    path = _table(root, "threat_groups")
    if not path:
        return
    report.threat_groups_file = path.name
    try:
        for ref, record in _rows(path):
            report.threat_groups.append((
                {k: str(v) for k, v in record.items() if k not in ENVELOPE},
                Cite(CASE_HOST, path.name, ref, row_hash(record, path.suffix.lower() == ".csv"), excerpt(record))))
    except (OSError, records.RecordsError, csv.Error) as exc:
        logger.warning(f"Couldn't read {path}: {exc}")


def _recorded_techniques(report: CaseReport, root: Path) -> None:
    path = root / TECHNIQUES_FILE
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        tid = line.strip().upper()
        if TECHNIQUE.match(tid):
            report.techniques.setdefault(tid, Technique(tid)).recorded = True


def attack_names(wanted: List[str]) -> Dict[str, Tuple[str, str]]:
    """(name, tactics) for each technique, from post/mitre/enterprise_attack.csv; a
    sub-technique's name is given with its parent's, as ATT&CK writes it."""
    ids = set(wanted) | {t.split(".")[0] for t in wanted}
    found: Dict[str, Tuple[str, str]] = {}
    if not ATTACK_CSV.is_file():
        return {}
    with open(ATTACK_CSV, newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            tid = row.get("technique_id", "")
            if tid in ids and tid not in found:
                found[tid] = (row.get("technique_name", ""), row.get("tactics", ""))
                if len(found) == len(ids):
                    break
    named = {}
    for tid in wanted:
        if tid not in found:
            continue
        name, tactics = found[tid]
        parent = found.get(tid.split(".")[0])
        if "." in tid and parent and not name.startswith(parent[0]):
            name = f"{parent[0]}: {name}"
        named[tid] = (name, tactics)
    return named


def gather(path, case_number: str = "", progress: Optional[Callable[[str], None]] = None) -> CaseReport:
    """Read a case for its report. ``path`` is the case's folder (the one holding its host
    folders) or the folder holding that; ``progress(message)`` hears about each host."""
    root = case_root(Path(path), case_number)
    report = CaseReport(case=case_number, root=str(root), generated=datetime.now().astimezone().isoformat(timespec="seconds"))
    _method(report, root)
    if not report.case:
        report.case = str((report.method or {}).get("case") or root.name)
    _recorded_techniques(report, root)
    for host_dir in host_dirs(root):
        host = HostReport(host_dir.name)
        report.hosts.append(host)
        if progress:
            progress(f"reading {host.name}")
        scan = _Scan(report, host, host_dir)
        for table in _tables(host_dir):
            scan.table(table)
        scan.finish()
        _integrity(host, host_dir)
        _collection(host, host_dir)
        _iocs(host, host_dir)
        _intel(host, host_dir)
    _audit(report, root)
    for host, host_dir in zip(report.hosts, host_dirs(root)):
        _host_os(host, host_dir)
    _threat_groups(report, root)
    for tid, (name, tactics) in attack_names(sorted(report.techniques)).items():
        report.techniques[tid].name, report.techniques[tid].tactics = name, tactics
    return report
