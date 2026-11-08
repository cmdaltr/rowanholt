"""Processing node for phones (--Mobile): iLEAPP or ALEAPP over the evidence, cooked like any artefact.

For each host core/mobile.py registered:

  1. an ADB backup is laid out as a file system first (process/extractions/android_backup.py);
  2. iLEAPP (iOS) or ALEAPP (Android) runs over the evidence as a subprocess, its report in
     <host>/mobile/<iLEAPP|ALEAPP>/ and its console output in <host>/mobile/<tool>.log;
  3. each of its TSV exports (_TSV Exports/<artefact>.tsv) becomes
     artefacts/cooked/<ileapp|aleapp>/<artefact>.jsonl, in parts below Elrond's IOC extraction's
     10 MB limit when it's large;
  4. configuration profiles and MDM (iOS), device administrators and owners (Android) are read by
     Elrond itself (extractions/mobile_config.py) into cooked/mobile_management.jsonl, with the
     ATT&CK Mobile techniques they evidence;
  5. every cooked record with a time goes, in time order, into artefacts/mobile_timeline.jsonl.

The backup password reaches iLEAPP on its standard input (its own password prompt, which reads
standard input when there's no terminal: the tool runs in a new session), never its command line.
"""

import csv
import importlib.util
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from rowanholt.audit import write_audit_log_entry
from rowanholt.core.mobile import (ANDROID, IOS, MobileEvidence, backup_password, is_mobile_image, load_evidence,
                                   manifest_files)
from rowanholt.core.records import SUFFIX, iso_timestamp, own_fields, read_records, write_records
from rowanholt.process.extractions import android_backup, mobile_config
from rowanholt.process.extractions.artemis import _record_techniques

logger = logging.getLogger(__name__)


def _tool_definitions() -> Dict:
    """MOBILE_TOOLS from src/analysis/tools/definitions.py, loaded by its path: the tools package's
    __init__ imports its YAML tool manager, which Elrond doesn't need for this."""
    path = Path(__file__).resolve().parents[2] / "tools" / "definitions.py"
    spec = importlib.util.spec_from_file_location("rowanholt_tool_definitions", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up while it loads
    spec.loader.exec_module(module)
    return module.MOBILE_TOOLS


MOBILE_TOOLS = _tool_definitions()

csv.field_size_limit(16 << 20)

WORK_DIR = "mobile"
MANAGEMENT_TABLE = "mobile_management"
TIMELINE = "mobile_timeline"
# Elrond's IOC extraction skips files of 10 MB or more (analysis.py): tables are written in parts below it
PART_BYTES = 9_000_000
BATCH = 1000
TIME_WORDS = re.compile(r"time|date|timestamp|created|modified|start|end|last ?(?:seen|used|visit)", re.I)
# Rows read to decide which column is a table's time
SAMPLE = 50
SUMMARY_FIELDS = 6
SUMMARY_CHARS = 300
MEMBER_BYTES = 8 << 20  # a configuration profile or device policy file is a few KB


class LeappError(RuntimeError):
    """The LEAPP tool couldn't be run (not installed)."""


def tool_path(tool: str) -> Optional[str]:
    """Where a LEAPP tool's launcher is, from its definition in tools/definitions.py."""
    definition = MOBILE_TOOLS[tool]
    found = shutil.which(definition.executable_name)
    if found:
        return found
    for folder in definition.common_paths.get("linux", []):
        candidate = Path(folder) / definition.executable_name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def leapp_command(executable: str, input_type: str, input_path: str, work: Path, report_name: str) -> List[str]:
    """The tool's command line. The password is never on it."""
    return [executable, "-t", input_type, "-i", str(input_path), "-o", str(work), "--custom_output_folder", report_name]


def run_leapp(tool: str, input_type: str, input_path: str, work: Path, password: Optional[str] = None,
              runner: Callable = subprocess.run) -> Tuple[Path, int]:
    """Run iLEAPP or ALEAPP over the evidence; (its report folder, its exit status).

    A password is written to the tool's standard input, and the tool runs in a session of its own
    so it has no terminal: its prompt for the password then reads standard input."""
    executable = tool_path(tool)
    if not executable:
        definition = MOBILE_TOOLS[tool]
        raise LeappError(f"{definition.name} isn't installed ({definition.install_methods.get('linux', '')})")
    name = MOBILE_TOOLS[tool].name
    work.mkdir(parents=True, exist_ok=True)
    report = work / name
    if report.exists():  # the tool refuses a report folder that's there already
        shutil.rmtree(report)
    command = leapp_command(executable, input_type, str(Path(input_path).resolve()), work.resolve(), name)
    with open(work / f"{tool}.log", "w", encoding="utf-8", errors="replace") as log:
        log.write("$ " + " ".join(command) + "\n")
        log.flush()
        kwargs = {"stdout": log, "stderr": subprocess.STDOUT, "start_new_session": True, "text": True}
        if password:
            kwargs["input"] = password + "\n"
        else:
            kwargs["stdin"] = subprocess.DEVNULL
        result = runner(command, **kwargs)
    return report, result.returncode


def slug(name: str) -> str:
    """A table name from a LEAPP artefact name ('SMS - Messages' -> 'sms_messages')."""
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "artefact"


def _header(cells: List[str]) -> List[str]:
    out: List[str] = []
    for number, cell in enumerate(cells, 1):
        name = cell.replace("﻿", "").strip() or f"column_{number}"
        base, n = name, 2
        while name in out:
            name, n = f"{base}_{n}", n + 1
        out.append(name)
    return out


def tsv_rows(path: Path) -> Tuple[List[str], Iterator[Dict[str, str]]]:
    """(header, rows) of a LEAPP TSV export. LEAPP appends to a TSV each time an artefact writes,
    header and all, so a repeat of the header is skipped."""
    fh = open(path, encoding="utf-8-sig", errors="replace", newline="")
    reader = csv.reader(fh, delimiter="\t")
    try:
        first = next(reader)
    except StopIteration:
        fh.close()
        return [], iter(())
    header = _header(first)

    def rows() -> Iterator[Dict[str, str]]:
        try:
            for cells in reader:
                if not any(c.strip() for c in cells) or [c.replace("﻿", "").strip() for c in cells] == \
                        [c.replace("﻿", "").strip() for c in first]:
                    continue
                row = dict(zip(header, cells))
                for extra, value in enumerate(cells[len(header):], len(header) + 1):
                    row[f"column_{extra}"] = value
                yield row
        finally:
            fh.close()

    return header, rows()


def time_field(header: List[str], sample: List[Dict[str, str]]) -> Optional[str]:
    """The table's time: the first time-like column whose values in the sample are mostly times."""
    for name in header:
        if not TIME_WORDS.search(name):
            continue
        values = [row.get(name, "") for row in sample if (row.get(name) or "").strip()]
        if values and sum(1 for v in values if iso_timestamp(v)) * 2 > len(values):
            return name
    return None


def write_parts(base: Path, rows: Iterable[Dict], *, host: str, artefact: str, source_path: str,
                time: Optional[str], techniques=None, part_bytes: int = PART_BYTES) -> Tuple[int, List[Path]]:
    """Write rows as <base>.jsonl, then <base>-0002.jsonl ... once a part reaches part_bytes;
    (rows written, the parts)."""
    parts: List[Path] = []
    written = 0
    batch: List[Dict] = []

    def flush() -> None:
        nonlocal written
        if not batch:
            return
        if not parts or parts[-1].stat().st_size >= part_bytes:
            number = len(parts) + 1
            parts.append(base.with_name(base.name + (SUFFIX if number == 1 else f"-{number:04d}{SUFFIX}")))
        written += write_records(parts[-1], batch, host=host, artefact=artefact, source_path=source_path,
                                 time_field=time, techniques=techniques)
        batch.clear()

    for row in rows:
        batch.append(row)
        if len(batch) >= BATCH:
            flush()
    flush()
    return written, parts


def cook_report(report: Path, cooked: Path, host_dir: Path, host: str, tool: str) -> Dict[str, int]:
    """Each TSV export of a LEAPP report as cooked/<tool>/<artefact>.jsonl; {table: rows}.
    LEAPP's own bookkeeping (names starting '_', such as its staged-file hashes) is left out."""
    counts: Dict[str, int] = {}
    for tsv in sorted(report.glob("_TSV Exports/*.tsv")):
        if tsv.name.startswith("_"):
            continue
        header, rows = tsv_rows(tsv)
        if not header:
            continue
        sample: List[Dict[str, str]] = []
        for row in rows:
            sample.append(row)
            if len(sample) >= SAMPLE:
                break
        when = time_field(header, sample)
        name = slug(tsv.stem)
        table = f"{tool}/{name}"

        def chained(first=sample, rest=rows) -> Iterator[Dict[str, str]]:
            yield from first
            yield from rest

        written, _ = write_parts(cooked / tool / name, chained(), host=host, artefact=table,
                                 source_path=str(tsv.relative_to(host_dir)), time=when)
        if written:
            counts[table] = counts.get(table, 0) + written
    return counts


# ---- device management (configuration profiles, MDM, device administrators) --------------

def _directory_members(root: Path, wanted: Callable[[str], bool]) -> Iterator[Tuple[str, bytes, str]]:
    for current, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            path = Path(current) / name
            rel = path.relative_to(root).as_posix()
            if wanted(rel):
                try:
                    if path.stat().st_size <= MEMBER_BYTES:
                        yield rel, path.read_bytes(), _mtime(path.stat().st_mtime)
                except OSError as e:
                    logger.warning("couldn't read %s: %s", path, e)


def _mtime(seconds: float) -> str:
    if not seconds or seconds <= 0:
        return ""
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _archive_members(path: Path, wanted: Callable[[str], bool]) -> Iterator[Tuple[str, bytes, str]]:
    if path.name.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as zipped:
            for info in zipped.infolist():
                if not info.is_dir() and wanted(info.filename) and info.file_size <= MEMBER_BYTES:
                    when = datetime(*info.date_time).isoformat() + "Z" if info.date_time[0] >= 1980 else ""
                    yield info.filename, zipped.read(info), when
        return
    with tarfile.open(path, "r|*") as tar:
        for member in tar:
            if member.isfile() and wanted(member.name) and member.size <= MEMBER_BYTES:
                handle = tar.extractfile(member)
                if handle is not None:
                    yield member.name, handle.read(), _mtime(member.mtime)


def management_files(evidence: MobileEvidence) -> Iterator[Tuple[str, bytes, str]]:
    """(path on the phone, contents, modified) of each configuration-profile or device-policy file
    in the evidence. An encrypted iTunes backup's files can't be read without decrypting it all,
    which is iLEAPP's job: none from it."""
    wanted = mobile_config.is_ios_config_file if evidence.platform == IOS else mobile_config.is_android_config_file
    path = Path(evidence.path)
    if evidence.kind == "itunes_backup":
        if evidence.encrypted:
            return
        for phone_path, on_disk in manifest_files(path, "%Library/ConfigurationProfiles/%"):
            if wanted(phone_path):
                yield phone_path, on_disk.read_bytes(), _mtime(on_disk.stat().st_mtime)
    elif evidence.kind in ("ios_filesystem", "android_filesystem"):
        yield from (_directory_members(path, wanted) if path.is_dir() else _archive_members(path, wanted))


def management_rows(evidence: MobileEvidence) -> List[Dict]:
    """The device-management rows for a phone's evidence."""
    rows: List[Dict] = []
    for phone_path, data, modified in management_files(evidence):
        if evidence.platform == IOS:
            rows.extend(mobile_config.ios_config_rows(phone_path, data, modified))
        else:
            rows.extend(mobile_config.android_config_rows(phone_path, data))
    return rows


MANAGEMENT_HEADER = ["Source", "Kind", "Name", "Identifier", "Organisation", "Package", "Component", "User",
                     "PayloadTypes", "Policies", "Server", "Installed", "Flag", "Technique"]


def write_management(cooked: Path, host: str, rows: List[Dict]) -> List[str]:
    """cooked/mobile_management.jsonl; the techniques it tagged."""
    techniques = sorted({r["Technique"] for r in rows if r.get("Technique")})
    if rows:
        write_records(cooked / f"{MANAGEMENT_TABLE}{SUFFIX}",
                      ({k: row.get(k, "") for k in MANAGEMENT_HEADER} for row in rows),
                      host=host, artefact=MANAGEMENT_TABLE, source_path="", time_field="Installed",
                      techniques=lambda row: [row.get("Technique") or ""])
    return techniques


# ---- the timeline -------------------------------------------------------------------------

def _summary(record: Dict) -> str:
    fields = [(k, v) for k, v in own_fields(record).items() if v not in (None, "") and not str(k).startswith("orig_")]
    text = "; ".join(f"{k}: {v}" for k, v in fields[:SUMMARY_FIELDS])
    return text if len(text) <= SUMMARY_CHARS else text[:SUMMARY_CHARS - 1] + "…"


def build_timeline(cooked: Path, artefacts: Path, host: str, scratch: Path) -> int:
    """Every record with a time under cooked/ (this host's phone tables), in time order, as
    artefacts/mobile_timeline.jsonl; how many. Sorted in SQLite on disk, not in memory."""
    scratch.mkdir(parents=True, exist_ok=True)
    db_path = scratch / "timeline.sqlite"
    if db_path.exists():
        db_path.unlink()
    con = sqlite3.connect(str(db_path))
    try:
        con.execute("CREATE TABLE events (ts TEXT, artefact TEXT, ref TEXT, event TEXT, techniques TEXT)")
        for table in sorted(cooked.rglob(f"*{SUFFIX}")):
            batch = []
            for ref, record in read_records(table):
                if record.get("timestamp"):
                    batch.append((record["timestamp"], record.get("artefact", ""), f"{table.name}:{ref}",
                                  _summary(record), json.dumps(record.get("techniques") or [])))
                if len(batch) >= BATCH:
                    con.executemany("INSERT INTO events VALUES (?,?,?,?,?)", batch)
                    batch.clear()
            con.executemany("INSERT INTO events VALUES (?,?,?,?,?)", batch)
        con.commit()
        out = artefacts / f"{TIMELINE}{SUFFIX}"
        if out.exists():
            out.unlink()
        cursor = con.execute("SELECT ts, artefact, ref, event, techniques FROM events ORDER BY ts, artefact, ref")
        rows = ({"Time": ts, "Artefact": artefact, "Row": ref, "Event": event, "Techniques": ";".join(json.loads(tech))}
                for ts, artefact, ref, event, tech in cursor)
        written = write_records(out, rows, host=host, artefact=TIMELINE, source_path="artefacts/cooked",
                                time_field="Time", techniques=lambda row: [row["Techniques"]])
    finally:
        con.close()
        db_path.unlink(missing_ok=True)
    return written


# ---- the password's absence from the case ------------------------------------------------

def password_in_report(report: Path, password: Optional[str]) -> List[str]:
    """LEAPP's own output files (not the phone's files it staged in data/ and media/) that contain
    the backup password; their paths relative to the report. The password is only looked for,
    never written."""
    if not password or len(password) < 4 or not report.is_dir():
        return []
    needle = password.encode("utf-8")
    found = []
    for current, dirs, files in os.walk(report):
        if Path(current) == report:
            dirs[:] = [d for d in dirs if d not in ("data", "media")]
        for name in files:
            path = Path(current) / name
            try:
                with open(path, "rb") as fh:
                    tail = b""
                    while True:
                        block = fh.read(1 << 20)
                        if not block:
                            break
                        if needle in tail + block:
                            found.append(str(path.relative_to(report)))
                            break
                        tail = block[-len(needle):]
            except OSError:
                continue
    return sorted(found)


# ---- one phone -----------------------------------------------------------------------------

def _audit(verbosity: str, output_directory: str, host: str, stage: str, text: str, prnt: str = "") -> None:
    write_audit_log_entry(verbosity, output_directory,
                          "{},{},{},{}\n".format(datetime.now().isoformat(), host, stage, text.replace(",", ";")),
                          prnt)


def clear_previous(host_dir: Path) -> None:
    """What an earlier run made for this phone: the writers append, so a second run would double it."""
    cooked = host_dir / "artefacts" / "cooked"
    for tool in ("ileapp", "aleapp"):
        shutil.rmtree(cooked / tool, ignore_errors=True)
    for path in (cooked / f"{MANAGEMENT_TABLE}{SUFFIX}", host_dir / "artefacts" / f"{TIMELINE}{SUFFIX}"):
        if path.exists():
            path.unlink()
    shutil.rmtree(host_dir / "analysis", ignore_errors=True)


def process_phone(verbosity: str, output_directory: str, img: str, stage: str = "processing",
                  runner: Callable = subprocess.run) -> Dict[str, object]:
    """Process one phone registered by core/mobile.py; a summary of what was made."""
    host = img.split("::")[0]
    host_dir = Path(output_directory) / host
    evidence = load_evidence(output_directory, host)
    summary: Dict[str, object] = {"host": host, "tables": {}, "techniques": [], "timeline": 0, "status": "done"}
    if evidence is None:
        print(f"    No {host}/mobile_evidence.json: '{host}' wasn't registered as a phone; skipping it")
        summary["status"] = "not registered"
        return summary
    print(f"    processing {evidence.kind.replace('_', ' ')} for '{host}'...", flush=True)
    clear_previous(host_dir)
    cooked = host_dir / "artefacts" / "cooked"
    cooked.mkdir(parents=True, exist_ok=True)
    work = host_dir / WORK_DIR
    password = backup_password() if evidence.encrypted else None
    if evidence.encrypted and not password:
        _audit(verbosity, output_directory, host, stage, f"{evidence.kind} is encrypted and no password was given; not processed",
               f" -> {datetime.now().isoformat().replace('T', ' ')} -> '{host}' is encrypted: give its password with "
               "--backupPasswordStdin (the job form's backup password); not processed")
        summary["status"] = "password needed"
        return summary

    input_type, input_path, tool_password = evidence.input_type, evidence.path, None
    if evidence.kind == "adb_backup":
        layout = work / "adb_filesystem"
        shutil.rmtree(layout, ignore_errors=True)
        try:
            counts = android_backup.extract_to_filesystem(Path(evidence.path), layout, password)
        except android_backup.AndroidBackupError as e:
            _audit(verbosity, output_directory, host, stage, f"ADB backup not opened: {e}",
                   f" -> {datetime.now().isoformat().replace('T', ' ')} -> couldn't open the ADB backup for '{host}': {e}")
            summary["status"] = str(e)
            return summary
        _audit(verbosity, output_directory, host, stage,
               f"ADB backup laid out as a file system: {counts['files']} files ({counts['skipped']} members left out)",
               f" -> {datetime.now().isoformat().replace('T', ' ')} -> laid out the ADB backup for '{host}': "
               f"{counts['files']} files in {layout}")
        input_type, input_path = "fs", str(layout)
    elif evidence.kind == "itunes_backup" and password:
        tool_password = password

    tables: Dict[str, int] = {}
    try:
        report, status = run_leapp(evidence.tool, input_type, input_path, work, tool_password, runner=runner)
        name = MOBILE_TOOLS[evidence.tool].name
        if status != 0:
            print(f"     {name} exited with status {status} for '{host}' (see {work / (evidence.tool + '.log')}); "
                  "cooking what it wrote")
        tables = cook_report(report, cooked, host_dir, host, evidence.tool)
        _audit(verbosity, output_directory, host, stage,
               f"{name} over {evidence.kind}: exit {status}; {len(tables)} tables; {sum(tables.values())} rows",
               f" -> {datetime.now().isoformat().replace('T', ' ')} -> {name} parsed '{host}': "
               f"{len(tables)} artefacts, {sum(tables.values()):,} rows")
        leaked = password_in_report(report, tool_password)
        if leaked:
            _audit(verbosity, output_directory, host, stage,
                   f"the backup password appears in {len(leaked)} of {name}'s output files: {'; '.join(leaked[:20])}",
                   f" -> WARNING: the backup password appears in {len(leaked)} of {name}'s output files for '{host}' "
                   f"(in {report}); check them before the case is shared")
    except LeappError as e:
        _audit(verbosity, output_directory, host, stage, str(e),
               f" -> {datetime.now().isoformat().replace('T', ' ')} -> {e}: '{host}' gets no {evidence.tool} tables")
        summary["status"] = str(e)

    management = management_rows(evidence)
    techniques = write_management(cooked, host, management)
    if management:
        tables[MANAGEMENT_TABLE] = len(management)
        _audit(verbosity, output_directory, host, stage,
               f"device management: {len(management)} entries; techniques {' '.join(techniques) or 'none'}",
               f" -> {datetime.now().isoformat().replace('T', ' ')} -> device management for '{host}': "
               f"{len(management)} entries" + (f", {', '.join(techniques)}" if techniques else ""))
    if techniques:
        _record_techniques(os.path.join(output_directory, "mitre_techniques.txt"), techniques)
    summary["timeline"] = build_timeline(cooked, host_dir / "artefacts", host, work)
    summary["tables"], summary["techniques"] = tables, techniques
    print(f"     '{host}': {len(tables)} tables, {summary['timeline']:,} timeline entries", flush=True)
    return summary


def process_mobile(verbosity: str, output_directory: str, imgs: Dict[str, str], stage: str = "processing") -> List[Dict]:
    """The phones among imgs, each processed (core.py's process phase routes them here)."""
    print("\n\n  -> \033[1;36mCommencing Processing Phase (phones)...\033[1;m\n  ----------------------------------------")
    done = []
    for _, img in sorted(imgs.items(), key=lambda x: x[1]):
        if not is_mobile_image(img):
            continue
        try:
            done.append(process_phone(verbosity, output_directory, img, stage))
        except Exception as e:  # one phone's failure mustn't stop the others
            logger.exception("processing %s failed", img)
            print(f"     ERROR processing '{img.split('::')[0]}': {e}", flush=True)
    print("  ----------------------------------------\n  -> Completed Processing Phase (phones).\n")
    return done
