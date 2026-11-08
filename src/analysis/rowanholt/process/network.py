"""Network evidence (elrond.py --Network): PCAP and PCAPNG captures, Zeek logs and NetFlow/IPFIX
text exports, cooked into a case like any host's artefacts.

Each source (a capture, a log, or a folder of them) becomes one folder in the case, named after it:

  <case>/<capture>/artefacts/zeek/<pcap>/   Zeek's own logs for each capture (JSON), kept for zeek-cut
  <case>/<capture>/artefacts/cooked/zeek/   conn, dns, http, ssl, files and Zeek's other protocol logs
  <case>/<capture>/artefacts/cooked/netflow.jsonl
  <case>/<capture>/artefacts/cooked/network_timeline.jsonl   one line per event, in time order
  <case>/<capture>/analysis/iocs.jsonl, network_matches.jsonl  (with --extractIocs)

PCAPs go through Zeek as a subprocess (never as a library: the boundary isolates the parser from
the evidence). Zeek logs supplied directly are read as they are, TSV or JSON, plain or gzipped.
Techniques come from process/extractions/network_rules.py and go to the case's
mitre_techniques.txt; the folder is recorded as platform "Network" in the audit log, so --Index
and the SIEM phase find it like any host.
"""

import hashlib
import heapq
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, Union

from rowanholt.audit import write_audit_log_entry
from rowanholt.core.records import SUFFIX, read_records, table_path, write_records
from rowanholt.process.extractions import netflow, network_rules, zeek_logs
from rowanholt.process.extractions.artemis import _record_techniques

logger = logging.getLogger(__name__)

PLATFORM = "Network"
MARKER = "network.info"  # artefacts/network.info: what the folder was made from
PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",  # pcap, ns pcap
              b"\x0a\x0d\x0d\x0a"}  # pcapng
ZEEK_PATHS = ("/opt/zeek/bin/zeek", "/usr/local/zeek/bin/zeek")
# Zeek's policy script that hashes every file it sees: the hashes join files.log to the hosts' files
ZEEK_SCRIPTS = ("frameworks/files/hash-all-files",)
# Disk and memory images (elrond.py's list) and Gandalf's archives
HOST_EVIDENCE = (".e01", ".vmdk", ".dd", ".raw", ".img", ".001", ".mem", ".vmem", ".lime", ".dmp", ".aff4",
                 ".tar.gz", ".tar.gz.enc", ".zip", ".zip.enc", "host.info")
TIMELINE_LOGS = ("conn", "dns", "http", "ssl", "files", "notice", "smb_files", "ftp", "smtp", "ssh")
TIMELINE_CHUNK = 100_000
MATCH_HEADER = ["Value", "Type", "Network Table", "Network Line", "Seen On Wire", "Host", "Host File", "Host Line",
                "Seen On Host"]


class NetworkEvidenceError(ValueError):
    """A source with no network evidence in it."""


class ZeekError(RuntimeError):
    """Zeek missing, or failing on a capture."""


def evidence_kind(path: Path) -> str:
    """"pcap", "zeek", "netflow" or "" for one file, from its content (names lie)."""
    path = Path(path)
    if path.name.startswith("._"):
        return ""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return ""
    if head in PCAP_MAGIC:
        return "pcap"
    if zeek_logs.log_format(path):
        return "zeek"
    if head[:2] != b"\x1f\x8b" and netflow.is_flow_export(path):
        return "netflow"
    return ""


def network_files(source: Path) -> Dict[str, List[Path]]:
    """The network evidence in a file or folder: {"pcap": [...], "zeek": [...], "netflow": [...]}."""
    source = Path(source)
    found: Dict[str, List[Path]] = {"pcap": [], "zeek": [], "netflow": []}
    candidates = [source] if source.is_file() else sorted(p for p in source.rglob("*") if p.is_file())
    for path in candidates:
        kind = evidence_kind(path)
        if kind:
            found[kind].append(path)
    return found


def is_network_source(source: str) -> bool:
    """Whether elrond.py's source is network evidence: a capture, log or export, or a folder holding
    them and no disk or memory image or Gandalf archive (a host's evidence with a capture beside it
    is still the host's)."""
    path = Path(source)
    if path.is_file():
        return bool(evidence_kind(path))
    if not path.is_dir():
        return False
    if any(p.name.lower().endswith(HOST_EVIDENCE) for p in path.rglob("*") if p.is_file()):
        return False
    return any(network_files(path).values())


def capture_name(source: Path, output_directory: str) -> str:
    """The case folder for a source: its name without the extension, or with -network added when
    a host already has that folder."""
    source = Path(source)
    stem = source.name if source.is_dir() else source.name.split(".")[0] or source.name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", stem).strip("._") or "network"
    folder = Path(output_directory) / name
    if folder.exists() and not (folder / "artefacts" / MARKER).exists():
        name += "-network"
    return name


def find_zeek() -> Optional[str]:
    """Zeek's executable: PATH, then where Zeek's packages (/opt/zeek) and images (/usr/local/zeek)
    put it, as tools/config.yaml defines it. Not through tools.manager: it imports elrond.utils,
    which resolves to elrond.py itself."""
    found = shutil.which("zeek")
    if found:
        return found
    return next((path for path in ZEEK_PATHS if os.access(path, os.X_OK)), None)


def run_zeek(pcap: Path, workdir: Path, zeek: Optional[str] = None) -> List[Path]:
    """Run Zeek over one capture, its logs (JSON) written into workdir; the logs it wrote."""
    zeek = zeek or find_zeek()
    if not zeek:
        raise ZeekError("Zeek isn't installed (the worker image has it; elsewhere see tools/config.yaml)")
    workdir = Path(workdir)
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)
    # -C: captures from hosts with checksum offloading have bad checksums Zeek would otherwise drop
    command = [zeek, "-C", "-r", str(Path(pcap).resolve()), *ZEEK_SCRIPTS, "LogAscii::use_json=T"]
    try:
        result = subprocess.run(command, cwd=str(workdir), capture_output=True, text=True)
    except OSError as error:
        raise ZeekError(f"Zeek wouldn't start: {error}") from error
    logs = sorted(p for p in workdir.glob("*.log") if p.is_file())
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()[-3:]
        raise ZeekError(f"Zeek failed on {Path(pcap).name} ({result.returncode}): {' | '.join(detail)}")
    return logs


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _audit(verbosity: str, output_directory: str, host: str, action: str, detail: str, prnt: str) -> None:
    clean = detail.replace(",", ";").replace("\n", " ")
    write_audit_log_entry(verbosity, output_directory, f"{datetime.now().isoformat()},{host},{action},{clean}\n",
                          f" -> {datetime.now().isoformat().replace('T', ' ')} -> {prnt}" if prnt else "")


def _keyed(paths: List[Path], reader) -> Iterator[Tuple[Tuple[int, int], Dict[str, Any]]]:
    for file_index, path in enumerate(paths):
        for row_index, row in enumerate(reader(path)):
            yield (file_index, row_index), row


def _judge(kind: str, paths: List[Path], reader) -> network_rules.Findings:
    """Every rule for this log over all its files (rotated logs judged together)."""
    return network_rules.merge(rule(_keyed(paths, reader)) for rule in network_rules.RULES.get(kind, ()))


def _join(value: Any) -> str:
    if isinstance(value, list):
        return ",".join(str(v) for v in value) or "-"
    return str(value) if value not in (None, "") else "-"


def timeline_message(kind: str, row: Dict[str, Any]) -> str:
    """One line saying what a record is, for the network timeline."""
    g = lambda field: _join(row.get(field))  # noqa: E731
    endpoints = f"{g('id_orig_h')}:{g('id_orig_p')} -> {g('id_resp_h')}:{g('id_resp_p')}"
    if kind == "conn":
        return (f"{g('proto')} {endpoints} {g('service')} {g('conn_state')}, sent {g('orig_bytes')} received "
                f"{g('resp_bytes')} bytes in {g('duration')}s")
    if kind == "dns":
        answer = g("answers") if row.get("answers") else g("rcode_name")
        return f"DNS {g('id_orig_h')} asked {g('id_resp_h')} {g('qtype_name')} {g('query')} -> {answer}"
    if kind == "http":
        return f"HTTP {endpoints} {g('method')} {g('host')}{g('uri')} {g('status_code')} {g('resp_mime_types')}"
    if kind == "ssl":
        return f"TLS {endpoints} server_name {g('server_name')} {g('version')} established {g('established')}"
    if kind == "files":
        return (f"File {g('mime_type')} {g('filename')} {g('seen_bytes')} bytes over {g('source')} "
                f"{endpoints if row.get('id_orig_h') else g('tx_hosts') + ' -> ' + g('rx_hosts')} sha1 {g('sha1')}")
    if kind == "notice":
        return f"Notice {g('note')}: {g('msg')} {g('src')} -> {g('dst')}"
    if kind == "netflow":
        return (f"Flow {g('Proto')} {g('SrcAddr')}:{g('SrcPort')} -> {g('DstAddr')}:{g('DstPort')}, {g('Bytes')} bytes "
                f"{g('Packets')} packets")
    return f"{kind} {endpoints}"


class _Timeline:
    """Timeline entries sorted on disk in chunks and merged, so a large capture isn't held whole."""

    def __init__(self, folder: Path) -> None:
        self.folder = Path(tempfile.mkdtemp(prefix=".network-timeline-", dir=str(folder)))
        self.buffer: List[Tuple[str, Dict[str, Any]]] = []
        self.chunks: List[Path] = []

    def add(self, time: str, entry: Dict[str, Any]) -> None:
        if not time:
            return  # as Plaso's timeline: an event without a time has no place in it
        self.buffer.append((time, entry))
        if len(self.buffer) >= TIMELINE_CHUNK:
            self._spill()

    def _spill(self) -> None:
        if not self.buffer:
            return
        self.buffer.sort(key=lambda item: item[0])
        chunk = self.folder / f"{len(self.chunks):05d}.jsonl"
        with open(chunk, "w", encoding="utf-8") as out:
            for time, entry in self.buffer:
                out.write(json.dumps([time, entry], ensure_ascii=False, default=str) + "\n")
        self.chunks.append(chunk)
        self.buffer = []

    def _read(self, chunk: Path) -> Iterator[Tuple[str, Dict[str, Any]]]:
        with open(chunk, encoding="utf-8") as fh:
            for line in fh:
                time, entry = json.loads(line)
                yield time, entry

    def write(self, path: Path, host: str) -> int:
        self._spill()
        try:
            merged = heapq.merge(*(self._read(c) for c in self.chunks), key=lambda item: item[0])
            return write_records(path, (entry for _, entry in merged), host=host, artefact="network_timeline",
                                 source_path="artefacts/cooked", time_field="Time")
        finally:
            shutil.rmtree(self.folder, ignore_errors=True)


def _cook(kind: str, artefact: str, paths: List[Path], reader, table: Path, host: str, host_dir: Path,
          timeline: _Timeline, techniques: set) -> int:
    """Judge and write one log's files into its cooked table; the records written."""
    findings = _judge(kind, paths, reader)
    line = 0
    for file_index, path in enumerate(paths):
        def rows() -> Iterator[Dict[str, Any]]:
            nonlocal line
            for row_index, row in enumerate(reader(path)):
                network_rules.apply(row, findings.get((file_index, row_index), []))
                if row["Techniques"]:
                    techniques.update(t.strip() for t in row["Techniques"].split(","))
                line += 1
                if kind in TIMELINE_LOGS or kind == "netflow":
                    timeline.add(str(row.get("ts") or row.get("Start") or ""), {
                        "Time": row.get("ts") or row.get("Start"), "Source": artefact,
                        "Message": timeline_message(kind, row), "Uid": row.get("uid", ""),
                        "Row": f"{artefact}:{line}", "Flag": row["Flag"], "Techniques": row["Techniques"]})
                yield row

        try:
            source_path = str(path.relative_to(host_dir))
        except ValueError:
            source_path = str(path)
        write_records(table, rows(), host=host, artefact=artefact, source_path=source_path,
                      time_field="ts" if kind != "netflow" else "Start",
                      techniques=lambda row: [row.get("Techniques") or ""])
    return line


def _netflow_rows(path: Path) -> Iterator[Dict[str, Any]]:
    for row in netflow.flow_rows(path):
        yield {k: v for k, v in row.items() if k in netflow.HEADER}


def process_network_source(source: Union[str, List[str]], output_directory: str, verbosity: str = "",
                           stage: str = "processing", extractiocs: bool = False,
                           watchlist_file: Optional[str] = None) -> Dict[str, Any]:
    """Cook one network source (a path, or the paths iter_sources grouped) into the case; what was
    done ({host, records, tables, techniques, pcaps, skipped}). NetworkEvidenceError when it holds
    no network evidence."""
    paths = [Path(p) for p in ([source] if isinstance(source, (str, Path)) else source)]
    files: Dict[str, List[Path]] = {"pcap": [], "zeek": [], "netflow": []}
    for path in paths:
        for kind, found in network_files(path).items():
            files[kind].extend(f for f in found if f not in files[kind])
    if not any(files.values()):
        raise NetworkEvidenceError(f"{', '.join(str(p) for p in paths)} holds no PCAP, Zeek log or NetFlow export")
    output_directory = os.path.join(output_directory, "")
    # One path names the folder after itself; files grouped from a folder, after the folder
    source_path = paths[0] if len(paths) == 1 else paths[0].parent
    host = capture_name(source_path, output_directory)
    host_dir = Path(output_directory) / host
    artefacts = host_dir / "artefacts"
    cooked = artefacts / "cooked"
    # A re-run replaces this folder's network tables rather than appending to them
    for stale in (cooked / "zeek", artefacts / "zeek"):
        shutil.rmtree(stale, ignore_errors=True)
    for stale in (cooked / f"netflow{SUFFIX}", cooked / f"network_timeline{SUFFIX}",
                  host_dir / "analysis" / f"network_matches{SUFFIX}", host_dir / "analysis" / f"iocs{SUFFIX}"):
        if stale.exists():
            stale.unlink()
    cooked.mkdir(parents=True, exist_ok=True)
    (artefacts / MARKER).write_text(json.dumps({"sources": [str(p.resolve()) for p in paths], "platform": PLATFORM,
                                                 "files": {k: [str(p) for p in v] for k, v in files.items()}}, indent=1))
    _audit(verbosity, output_directory, host, "identified platform", PLATFORM, "")
    for kind, paths in files.items():
        for path in paths:
            _audit(verbosity, output_directory, host, "network evidence", f"{kind} {path} sha256 {_sha256(path)}",
                   f"{kind} '{path.name}' read as network evidence for '{host}'")
    if files["pcap"] and files["zeek"]:
        logger.warning("%s holds captures and Zeek logs: if the logs came from these captures, their "
                       "records appear twice", host)

    summary: Dict[str, Any] = {"host": host, "records": 0, "tables": [], "techniques": [], "pcaps": 0, "skipped": []}
    logs = list(files["zeek"])
    for pcap in files["pcap"]:
        try:
            produced = run_zeek(pcap, artefacts / "zeek" / pcap.name)
        except ZeekError as error:
            summary["skipped"].append(f"{pcap.name}: {error}")
            _audit(verbosity, output_directory, host, "zeek failed", f"{pcap.name}: {error}",
                   f"Zeek couldn't read '{pcap.name}' for '{host}': {error}")
            continue
        summary["pcaps"] += 1
        logs.extend(produced)
        _audit(verbosity, output_directory, host, stage, f"zeek {pcap.name} ({len(produced)} logs)",
               f"{stage} '{pcap.name}' through Zeek for '{host}': {len(produced)} logs")

    by_log: Dict[str, List[Path]] = {}
    for path in logs:
        name = zeek_logs.log_kind(path)[1]
        if name and name not in zeek_logs.HOUSEKEEPING:
            by_log.setdefault(name, []).append(path)
    timeline = _Timeline(artefacts)
    techniques: set = set()
    for name, paths in sorted(by_log.items()):
        artefact = f"zeek/{name}"
        written = _cook(name, artefact, paths, zeek_logs.iter_log, cooked / "zeek" / f"{name}{SUFFIX}", host, host_dir,
                        timeline, techniques)
        if written:
            summary["records"] += written
            summary["tables"].append(artefact)
            _audit(verbosity, output_directory, host, stage, f"zeek {name} log ({written} records)",
                   f"{stage} Zeek {name} log for '{host}': {written} records")
    if files["netflow"]:
        written = _cook("netflow", "netflow", files["netflow"], _netflow_rows, cooked / f"netflow{SUFFIX}", host,
                        host_dir, timeline, techniques)
        if written:
            summary["records"] += written
            summary["tables"].append("netflow")
            _audit(verbosity, output_directory, host, stage, f"netflow ({written} flows)",
                   f"{stage} NetFlow export(s) for '{host}': {written} flows")
    events = timeline.write(cooked / f"network_timeline{SUFFIX}", host)
    if events:
        summary["tables"].append("network_timeline")
    techniques.discard("")
    summary["techniques"] = sorted(techniques)
    if techniques:
        _record_techniques(os.path.join(output_directory, "mitre_techniques.txt"), summary["techniques"])

    if extractiocs:
        from rowanholt.analysis.iocs import compare_iocs

        tables = sorted(str(p) for p in cooked.rglob(f"*{SUFFIX}") if p.name != f"network_timeline{SUFFIX}")
        (host_dir / "analysis").mkdir(parents=True, exist_ok=True)
        compare_iocs(output_directory, verbosity, f"{host}::{PLATFORM}", stage, f"'{host}'", tables, 0, 0.0,
                     watchlist_file=watchlist_file)
        summary["matches"] = match_host_iocs(output_directory, host)
    return summary


def _ioc_table(host_dir: Path) -> Optional[Path]:
    path = table_path(host_dir / "analysis", "iocs")
    return path if path.is_file() else None


def match_host_iocs(output_directory: str, host: str) -> int:
    """IOCs seen on the wire that the case's other hosts have too (their analysis/iocs): one row per
    value and host, written to <host>/analysis/network_matches.jsonl; the rows written."""
    output = Path(output_directory)
    mine = _ioc_table(output / host)
    if mine is None:
        return 0
    wire: Dict[str, Dict[str, Any]] = {}
    for _, record in read_records(mine):
        value = str(record.get("ioc") or "").lower()
        if not value:
            continue
        seen = wire.setdefault(value, {"type": record.get("indicator_type", ""), "file": record.get("Filename", ""),
                                       "line": record.get("line_number", ""), "count": 0})
        seen["count"] += 1
    rows: List[Dict[str, Any]] = []
    for other in sorted(p for p in output.iterdir() if p.is_dir() and p.name != host and not p.name.startswith(".")):
        table = _ioc_table(other)
        if table is None:
            continue
        on_host: Dict[str, Dict[str, Any]] = {}
        for _, record in read_records(table):
            value = str(record.get("ioc") or "").lower()
            if value in wire:
                hit = on_host.setdefault(value, {"file": record.get("Filename", ""), "line": record.get("line_number", ""),
                                                 "count": 0})
                hit["count"] += 1
        for value, hit in sorted(on_host.items()):
            seen = wire[value]
            network_table = Path(str(seen["file"]))
            rows.append({"Value": value, "Type": seen["type"],
                         "Network Table": _relative_table(network_table, output / host),
                         "Network Line": seen["line"], "Seen On Wire": seen["count"], "Host": other.name,
                         "Host File": hit["file"], "Host Line": hit["line"], "Seen On Host": hit["count"]})
    if rows:
        write_records(output / host / "analysis" / f"network_matches{SUFFIX}", rows, host=host,
                      artefact="network_matches")
    return len(rows)


def _relative_table(path: Path, host_dir: Path) -> str:
    try:
        return str(path.relative_to(host_dir / "artefacts" / "cooked").with_suffix(""))
    except ValueError:
        return str(path)


def network_hosts(output_directory: str) -> Dict[str, str]:
    """allimgs entries for the case's network folders ({<folder>/artefacts/raw: "<name>::Network"}),
    as the SIEM writers take hosts."""
    found: Dict[str, str] = {}
    root = Path(output_directory)
    if not root.is_dir():
        return found
    for folder in sorted(root.iterdir()):
        if (folder / "artefacts" / MARKER).is_file():
            found[str(folder / "artefacts" / "raw")] = f"{folder.name}::{PLATFORM}"
    return found


def iter_sources(sources: Iterable[str]) -> Tuple[List[List[str]], List[str]]:
    """(network sources, the rest) of elrond.py's sources. A folder or a capture is a source of its
    own; Zeek logs and NetFlow exports given one by one (as the web app's file browser gives them)
    are grouped by the folder they're in, so a sensor's conn.log and dns.log land in one folder."""
    network: List[List[str]] = []
    grouped: Dict[str, List[str]] = {}
    other: List[str] = []
    for source in sources:
        if not is_network_source(source):
            other.append(source)
        elif Path(source).is_file() and evidence_kind(Path(source)) != "pcap":
            folder = str(Path(source).resolve().parent)
            if folder not in grouped:
                grouped[folder] = []
                network.append(grouped[folder])
            grouped[folder].append(source)
        else:
            network.append([source])
    return network, other
