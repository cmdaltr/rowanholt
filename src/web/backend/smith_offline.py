"""
Smith without an LLM: questions answered straight from Elrond's case output.

Free-text questions need Ollama. When it isn't there, Ask Smith offers these
instead: each reads the case directory (<case>/<host>/artefacts/cooked/, <case>/<host>/analysis/,
<case>/mitre_techniques.txt, <case>/threat_groups) and summarises what
Elrond found, so the answers are exact rather than generated. Each line built from a row
carries that row (host, file, row reference, SHA-256: what a finding stores), so the answer can
be flagged from (answer_with_rows).
"""

import csv
import json
import logging
import os
import re
from collections import Counter
from contextvars import ContextVar
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

try:
    from . import case_files
except ImportError:  # main.py imports the routes as top-level modules too
    import case_files

logger = logging.getLogger(__name__)

MAX_ROWS = 15
# Set by main.py: case path -> the analysts' findings on it (case_routes.findings_for_case)
FINDINGS: Optional[Callable[[str], List[Dict]]] = None
SUSPICIOUS_COMMAND = re.compile(
    r"\b(?:wget|curl|nc|ncat|socat|base64|chmod\s+\+x|python[23]?\s+-c|perl\s+-e|bash\s+-i|/dev/tcp|"
    r"powershell|iex|invoke-|certutil|bitsadmin|mshta|rundll32|regsvr32|history\s+-c|unset\s+histfile)\b",
    re.I,
)
# Cooked tables whose Flag field marks a finding (Elrond's Windows, Linux and macOS processors)
FLAGGED_TABLES = ("pam", "sudoers", "autostart", "udev_rules", "preload", "shell_init",
                  "kernel_modules", "btm_items", "emond_rules", "periodic")
PERSISTENCE_LISTS = ("startup_items", "generators")
# stacking.py's PERSISTENCE (the backend doesn't import the analysis package; a test keeps them equal)
STACKING_PERSISTENCE = {"scheduled task", "wmi consumer", "service (Windows)", "autorun (Windows)", "service (systemd)",
                        "autorun (Linux)", "kernel module", "autorun (macOS)", "driver (Windows)"}
RARE_ROWS = 8
NETWORK_IOC_TYPES = ("IPv4 address", "IPv6 address", "domain")
# The rows the lines shown so far came from, while answer_with_rows() runs
_citing: ContextVar[Optional[List[Dict[str, str]]]] = ContextVar("smith_offline_citing", default=None)


class Cited(str):
    """A line of an answer, with the row it was built from (and, for a value on several hosts, theirs)."""
    cite: Optional[Dict[str, str]] = None
    more: List[Dict[str, str]] = []


def _cited(text: str, host: str, file: str, ref: str, normal: Dict[str, str]) -> Cited:
    line = Cited(text)
    line.cite = {"host": host, "file": file, "row_ref": ref, "hash": case_files.row_hash(normal), "line": text}
    return line


def _hosts(case_path: str) -> List[Path]:
    """Host folders in an Elrond case: the ones holding artefacts/."""
    root = Path(case_path)
    if (root / "artefacts").is_dir():
        return [root]
    return sorted(p for p in root.iterdir() if p.is_dir() and (p / "artefacts").is_dir())


def _numbered(path: Path) -> Iterator[Tuple[str, Dict, Dict[str, str]]]:
    """(row reference, row as written, row as hashed) for each row of a table, as case_files reads it;
    nothing for a table that isn't there."""
    if not path.is_file():
        return
    try:
        yield from case_files.records_with_values(path)
    except (OSError, ValueError, csv.Error, case_files.CaseFileError) as e:
        logger.debug(f"Couldn't read {path}: {e}")


def _rows(path: Path) -> List[Dict]:
    return [row for _, row, _ in _numbered(path)]


def _table(folder: Path, name: str) -> Path:
    """The table ``name`` in ``folder``, in this case's format."""
    return case_files.tables.table_path(folder, name)


def _where(host: Path, path: Path) -> Tuple[str, str]:
    """The (host, file) a citation names: the host folder and the path in it, or the case's own file."""
    try:
        return host.name, str(path.relative_to(host))
    except ValueError:
        return case_files.CASE_HOST, path.name


def _cooked(host: Path, pattern: str) -> List[Path]:
    """The cooked tables matching ``pattern`` (a name without its suffix, globbing allowed): one
    file per table, in this case's format."""
    found: Dict[Path, Path] = {}
    for path in (host / "artefacts" / "cooked").rglob(pattern + ".*"):
        suffix = path.suffix.lower()
        if suffix not in case_files.ROW_FILES or not path.is_file():
            continue
        stem = path.with_suffix("")
        held = found.get(stem)
        if held is None or case_files.ROW_FILES.index(suffix) < case_files.ROW_FILES.index(held.suffix.lower()):
            found[stem] = path
    return sorted(found.values())


def _bullets(lines: Iterable[str], limit: int = MAX_ROWS) -> str:
    lines = list(lines)
    citing = _citing.get()
    if citing is not None:
        for line in lines[:limit]:
            if getattr(line, "cite", None):
                citing.append(line.cite)
                citing.extend(getattr(line, "more", []))
    shown = "\n".join(f"• {line}" for line in lines[:limit])
    if len(lines) > limit:
        shown += f"\n• …and {len(lines) - limit} more"
    return shown


def _host_info(host: Path) -> str:
    info = host / "artefacts" / "host.info"
    try:
        first = info.read_text(errors="replace").splitlines()[0]
        return first.split("::", 1)[1] if "::" in first else first
    except (OSError, IndexError):
        return "unknown platform"


# ---- case questions -----------------------------------------------------------

def hosts(case_path: str) -> str:
    found = _hosts(case_path)
    if not found:
        return "No processed hosts in this case yet: Elrond writes one folder per host with an artefacts/ folder inside."
    lines = []
    for host in found:
        cooked = _cooked(host, "*")
        lines.append(f"**{host.name}**: {_host_info(host)}, {len(cooked)} processed artefact files")
    return "**Hosts in this case:**\n" + _bullets(lines, 50)


def techniques(case_path: str) -> str:
    ids = set()
    for path in [Path(case_path) / "mitre_techniques.txt"] + [h / "mitre_techniques.txt" for h in _hosts(case_path)]:
        if path.is_file():
            ids.update(t.strip() for t in path.read_text(errors="replace").split() if re.match(r"^T\d{4}(?:\.\d{3})?$", t.strip()))
    if not ids:
        return "No ATT&CK techniques were tagged for this case. Run Elrond with --Analysis (and --Navigator for a layer)."
    return (f"**{len(ids)} ATT&CK techniques were tagged:**\n" + ", ".join(sorted(ids)) +
            "\n\nEach was tagged by a processor or analysis rule from a specific artefact; "
            "the Navigator layer (--Navigator) shows them on the matrix.")


def persistence(case_path: str) -> str:
    sections = []
    for host in _hosts(case_path):
        lines = []
        for name in FLAGGED_TABLES:
            for path in _cooked(host, name):
                for ref, row, normal in _numbered(path):
                    flag = row.get("Flag") or ""
                    # out-of-tree and unsigned alone are DKMS and VM drivers; only an odd file location is a lead
                    if name == "kernel_modules" and not ("no module file" in flag or "outside" in flag):
                        continue
                    if flag:
                        what = row.get("Command") or row.get("Line") or row.get("Module") or row.get("Library") or \
                            row.get("Identifier") or row.get("Name") or row.get("Actions") or ""
                        text = f"{path.stem}: {row.get('Source') or row.get('Path') or ''} {what} — {row['Flag']}".strip()
                        lines.append(_cited(text, *_where(host, path), ref, normal))
        for name in PERSISTENCE_LISTS:
            for path in _cooked(host, name):
                for ref, row, normal in _numbered(path):
                    text = f"{path.stem}: {row.get('Path') or row.get('Source') or row.get('Name') or ''}"
                    lines.append(_cited(text, *_where(host, path), ref, normal))
        # WMI event subscriptions carved from the repository; Elrond notes the ones Windows makes itself
        for path in _cooked(host, "wbem"):
            for ref, sub, normal in _numbered(path):
                if not sub.get("note"):
                    values = sub.get("consumer_values") or []
                    action = "; ".join(str(v) for v in values) if isinstance(values, list) else str(values)
                    text = (f"WMI subscription: {sub.get('filter_name')} -> {sub.get('consumer_class')} "
                            f"'{sub.get('consumer_name')}'" + (f": {action}" if action else ""))
                    lines.append(_cited(text, *_where(host, path), ref, normal))
        # Run keys: RegRipper's run plugin over SOFTWARE and each NTUSER.DAT (Elrond tags them T1547.001)
        for path in _cooked(host, "registry/*"):
            for ref, record, normal in _numbered(path):
                if record.get("Plugin") == "run" and record.get("AppName"):
                    hive = record.get("RegistryHive") or path.stem
                    if record.get("AccountProfile"):
                        hive += f" ({record['AccountProfile']})"
                    text = f"Run key: {hive} {record.get('RegistryKey', '')}: {record['AppName']} -> {record.get('AppLocation', '')}"
                    lines.append(_cited(text, *_where(host, path), ref, normal))
        if lines:
            sections.append(f"**{host.name}**\n" + _bullets(lines))
    if not sections:
        return ("Nothing flagged as persistence. Elrond flags startup items, Run keys, WMI event subscriptions, "
                "launchd and BTM items, PAM, sudoers, udev, autostart, generators and kernel modules when it "
                "finds something unusual.")
    return "**Flagged persistence and privilege findings:**\n\n" + "\n\n".join(sections)


def logins(case_path: str) -> str:
    sections = []
    for host in _hosts(case_path):
        lines = []
        records = [r for p in _cooked(host, "login_records") for r in _rows(p)]
        users = Counter(r.get("User", "") for r in records if r.get("Type") == "USER_PROCESS" and r.get("User"))
        failed = Counter((r.get("Address") or r.get("Host") or "?") for r in records if r.get("Source", "").endswith("btmp"))
        if users:
            lines.append("logins: " + ", ".join(f"{u} ({n})" for u, n in users.most_common(10)))
        if failed:
            lines.append("failed logins by source: " + ", ".join(f"{s} ({n})" for s, n in failed.most_common(10)))
        for path in _cooked(host, "lastlog"):
            for ref, row, normal in list(_numbered(path))[:10]:
                text = f"last login {row.get('User') or row.get('UID')}: {row.get('LastWriteTime')} from {row.get('Host') or 'local'}"
                lines.append(_cited(text, *_where(host, path), ref, normal))
        if lines:
            sections.append(f"**{host.name}**\n" + _bullets(lines))
    if not sections:
        return "No login records were processed (wtmp, btmp, lastlog, wtmpdb on Linux; Windows logons come from the Security event log)."
    return "**Logins:**\n\n" + "\n\n".join(sections)


def iocs(case_path: str) -> str:
    sections = []
    for host in _hosts(case_path):
        rows = _rows(_table(host / "analysis", "iocs"))
        if not rows:
            continue
        kinds = Counter(r.get("indicator_type", "?") for r in rows)
        # analysis/iocs.py's types; it once read "ipv4", which Elrond never wrote, so no address was listed
        values = Counter(r.get("ioc", "") for r in rows if r.get("indicator_type") in NETWORK_IOC_TYPES)
        watched = {r.get("ioc", "") for r in rows if r.get("watchlist_match")}
        sections.append(f"**{host.name}**: {len(rows)} indicators (" + ", ".join(f"{k} {n}" for k, n in kinds.most_common()) +
                        ")\n" + _bullets(f"{v} (×{n}{', watchlist' if v in watched else ''})"
                                         for v, n in values.most_common(MAX_ROWS)))
    if not sections:
        return "No IOCs were extracted. Run Elrond with --extractIocs."
    return "**Extracted IOCs** (most frequent network indicators first; check before acting on them):\n\n" + "\n\n".join(sections)


def findings(case_path: str) -> str:
    """What analysts have confirmed in the case browser, then the leads still open."""
    flagged = FINDINGS(case_path) if FINDINGS else []
    if not flagged:
        return ("No findings yet. Open the case from its job (Browse case), and flag rows as leads; "
                "confirm them once they hold up.")
    def line(f: Dict) -> str:
        technique = f" ({f['technique']})" if f.get("technique") else ""
        return f"{f['title']}{technique}: {f['host']}, {Path(f['artefact']).name} row {f['row_ref']} ({f['author']})"
    confirmed = [f for f in flagged if f["status"] == "confirmed"]
    leads = [f for f in flagged if f["status"] == "lead"]
    parts = [f"**Confirmed** ({len(confirmed)})\n" + (_bullets(map(line, confirmed)) if confirmed else "• none yet")]
    if leads:
        parts.append(f"**Open leads** ({len(leads)})\n" + _bullets(map(line, leads)))
    benign = len(flagged) - len(confirmed) - len(leads)
    if benign:
        parts.append(f"{benign} more marked benign.")
    return "\n\n".join(parts)


def threat_intel(case_path: str) -> str:
    """What Elrond's threat intelligence phase found: the most specific elements per host, and the
    groups whose evidence turned up, with what each rank rests on."""
    sections = []
    for host in _hosts(case_path):
        path = _table(host / "analysis", "threat_intel_matches")
        seen: Dict[str, Tuple[str, Dict[str, str], Dict[str, str]]] = {}
        for ref, row, normal in _numbered(path):
            seen.setdefault(row.get("Element", ""), (ref, row, normal))
        if not seen:
            continue
        ordered = sorted(seen.values(), key=lambda m: (m[1].get("Common") == "yes", int(m[1].get("Groups Using") or 0)))
        sections.append(f"**{host.name}**\n" + _bullets(
            _cited(f"{r['Element']} in {Path(r.get('Artefact', '')).name}: {r.get('Groups') or r.get('Sources')}"
                   + (" (common: many groups use it)" if r.get("Common") == "yes" else ""), *_where(host, path), ref, normal)
            for ref, r, normal in ordered))
    groups_csv = _table(Path(case_path), "threat_groups")
    groups = list(_numbered(groups_csv))
    if groups:
        sections.append("**Whose tradecraft it resembles** (a lead, not attribution)\n" + _bullets(
            _cited(f"{g['Group']}: {g['Basis']}" + (f", {g['Techniques In Case']}" if g.get("Techniques In Case") else ""),
                   case_files.CASE_HOST, groups_csv.name, ref, normal)
            for ref, g, normal in groups[:8]))
    if not sections:
        return ("No threat intelligence matching was run on this case. Import indicators in Pippin (threat intelligence), "
                "then tick Threat intelligence on Elrond's page (or run Elrond with --threatIntel).")
    return "**Threat intelligence matches** (the most specific first):\n\n" + "\n\n".join(sections)


def commands(case_path: str) -> str:
    sections = []
    for host in _hosts(case_path):
        hits = []
        for pattern in ("*bash_history", "*zsh_history", "shell_histories", "*ConsoleHost_history*"):
            for path in _cooked(host, pattern):
                for ref, row, normal in _numbered(path):
                    command = str(row.get("Command") or next(iter(case_files.tables.own_fields(row).values()), "") or "")
                    if SUSPICIOUS_COMMAND.search(command):
                        hits.append(_cited(f"{path.stem}: {command.strip()[:200]}", *_where(host, path), ref, normal))
        if hits:
            sections.append(f"**{host.name}**\n" + _bullets(hits, 25))
    if not sections:
        return "No download, encoding, reverse-shell or history-clearing commands in the processed shell histories."
    return "**Commands worth a look** (download, decode, shell, history clearing):\n\n" + "\n\n".join(sections)


def staging(case_path: str) -> str:
    sections = []
    for host in _hosts(case_path):
        lines = [_cited(f"{r.get('Path')} ({r.get('Kind')}, {r.get('Size')} bytes, sha256 {(r.get('SHA256') or '')[:16]}…)",
                        *_where(host, p), ref, normal)
                 for p in _cooked(host, "tmp_executables") for ref, r, normal in _numbered(p)]
        if lines:
            sections.append(f"**{host.name}**\n" + _bullets(lines))
    if not sections:
        return "No executables were listed in /tmp, /var/tmp or /dev/shm (Linux, Gandalf collections)."
    return "**Executables in temporary directories:**\n\n" + "\n\n".join(sections)


def detections(case_path: str) -> str:
    sections = []
    for host in _hosts(case_path):
        lines = []
        for p in _cooked(host, "defender_detections"):
            lines += [_cited(f"Defender: {r.get('ThreatName') or r.get('Threat') or ''} {r.get('Path') or ''}".strip(),
                             *_where(host, p), ref, normal) for ref, r, normal in _numbered(p)]
        for p in _cooked(host, "webshells"):
            lines += [_cited(f"web shell: {r.get('Source')} ({r.get('Indicators')})", *_where(host, p), ref, normal)
                      for ref, r, normal in _numbered(p)]
        for p in _cooked(host, "xprotect_*"):
            shown = case_files.tables.own_fields
            lines += [_cited(f"XProtect ({p.stem}): {', '.join(f'{k}={v}' for k, v in list(shown(r).items())[:4])}",
                             *_where(host, p), ref, normal) for ref, r, normal in list(_numbered(p))[:10]]
        # Elrond's own scanners: ClamAV's rows in analysis, and one line per YARA rule and file
        clamav = _table(host / "analysis", "analysis")
        lines += [_cited(f"ClamAV: {r.get('analysis_value')} {r.get('Filename')}", *_where(host, clamav), ref, normal)
                  for ref, r, normal in _numbered(clamav) if r.get("analysis_type") == "ClamAV"]
        yara = _table(host / "analysis", "yara")
        seen = set()
        for ref, r, normal in _numbered(yara):
            key = (r.get("yara_rule"), r.get("path"), r.get("file"))
            if key not in seen:
                seen.add(key)
                lines.append(_cited(f"YARA {r.get('yara_rule')}: {r.get('path')}/{r.get('file')}", *_where(host, yara),
                                    ref, normal))
        if lines:
            sections.append(f"**{host.name}**\n" + _bullets(lines))
    if not sections:
        return "No Defender detections, XProtect events, web shells, ClamAV or YARA hits in the processed artefacts."
    return "**Detections:**\n\n" + "\n\n".join(sections)


def rare(case_path: str) -> str:
    """The top of Elrond's stacking across hosts (<case>/stacking): persistence, then programs."""
    stacking_csv = _table(Path(case_path), "stacking")
    rows = list(_numbered(stacking_csv))
    if not rows:
        return ("Nothing was stacked for this case. Stacking compares hosts, so it needs two or more, and runs with "
                "Elrond's analysis (--Analysis); something is called rare only among three or more hosts of an OS.")
    def text(r: Dict[str, str]) -> str:
        return (f"#{r.get('Rank')} {r.get('Value')} ({r.get('Family')}): on {r.get('Hosts With It')} of "
                f"{r.get('Hosts In Case')} hosts ({r.get('Hosts')}); {r.get('Reasons')}")
    persistence = [n for n in rows if (n[1].get("Family") or "").split(",")[0] in STACKING_PERSISTENCE]
    programs = [n for n in rows if n not in persistence]
    shown = persistence[:RARE_ROWS] + programs[:RARE_ROWS]
    host_rows = _host_rows(Path(case_path), [r for _, r, _ in shown])

    def lines(section: List[Tuple[str, Dict[str, str], Dict[str, str]]]) -> List[str]:
        out: List[str] = []
        for index, (ref, r, normal) in enumerate(section):
            if index >= RARE_ROWS:
                out.append(text(r))
                continue
            found = [s for s in _stacking_sources(r) if s in host_rows]
            if found:
                # The rows on the hosts the value was read from: that's what a finding should rest on
                line = _cited(text(r), *found[0], host_rows[found[0]])
                line.more = [_cited(text(r), *s, host_rows[s]).cite for s in found[1:]]
                out.append(line)
            else:
                out.append(_cited(text(r), case_files.CASE_HOST, stacking_csv.name, ref, normal))
        return out
    parts = []
    if persistence:
        parts.append(f"**Ways back in** ({len(persistence)})\n" + _bullets(lines(persistence), RARE_ROWS))
    if programs:
        parts.append(f"**Programs and process pairs** ({len(programs)})\n" + _bullets(lines(programs), RARE_ROWS))
    return ("**What's rare across the hosts** (stacking, highest score first):\n\n" + "\n\n".join(parts) +
            "\n\nEach row is a lead, not a verdict: rare can be an older build or a busier host. "
            "Flag one with ⚑: the flag goes on the host's own row the value was read from.")


RARE_SOURCES = 5  # host rows cited per stacking line


def _stacking_sources(row: Dict[str, str]) -> List[Tuple[str, str, str]]:
    """(host, artefact, row) for each host a stacking row's value was read on: Sources, or from a
    stacking table before it, Host and Row."""
    listed = row.get("Sources") or []
    try:
        listed = json.loads(listed) if isinstance(listed, str) else listed
        sources = [tuple(map(str, s)) for s in listed if len(s) == 3]
    except (TypeError, ValueError):
        sources = []
    if not sources and row.get("Host") and row.get("Row"):
        sources = [(row["Host"], row.get("Artefact") or "", row["Row"])]
    return [s for s in sources if all(s)][:RARE_SOURCES]


def _host_rows(root: Path, stacked: List[Dict[str, str]]) -> Dict[Tuple[str, str, str], Dict[str, str]]:
    """{(host, artefact, row reference): the row as case_files reads it} for the host rows these stacking rows
    name (_stacking_sources); each file read once, and only through case_files, so only what the case
    browser can open. A stacking table from before Host and Row names none: those stay unresolved."""
    wanted: Dict[Tuple[str, str], set] = {}
    for r in stacked:
        for host, artefact, ref in _stacking_sources(r):
            wanted.setdefault((host, artefact), set()).add(ref)
    found: Dict[Tuple[str, str, str], Dict[str, str]] = {}
    for (host, artefact), refs in wanted.items():
        try:
            for ref, row in case_files.records(case_files.resolve(root, host, artefact)):
                if ref in refs:
                    found[(host, artefact, ref)] = row
                    refs.discard(ref)
                    if not refs:
                        break
        except (case_files.CaseFileError, OSError, ValueError, csv.Error) as e:
            logger.debug(f"Couldn't read {host}: {artefact} for stacking's rows: {e}")
    return found


def analysis(case_path: str) -> str:
    sections = []
    for host in _hosts(case_path):
        path = _table(host / "analysis", "analysis")
        rows = list(_numbered(path))
        if rows:
            kinds = Counter(r.get("analysis_type", "?") for _, r, _ in rows)
            examples = [_cited(f"{r.get('analysis_type')}: {r.get('Filename')} {r.get('analysis_value', '')}".strip(),
                               *_where(host, path), ref, normal) for ref, r, normal in rows]
            sections.append(f"**{host.name}**: " + ", ".join(f"{k} ({n})" for k, n in kinds.most_common()) + "\n" + _bullets(examples, 10))
    if not sections:
        return "Elrond's analysis stage found nothing (or wasn't run: use --Analysis)."
    return "**What Elrond's analysis flagged** (timestomping, ADS, masquerading and the like):\n\n" + "\n\n".join(sections)


# ---- general questions (no case) ----------------------------------------------

GENERAL_ANSWERS = {
    "enable_llm": (
        "**Turning on Smith's free-text answers**\n\n"
        "Smith generates answers with a local model served by Ollama, so case data never leaves this machine.\n"
        "1. Install Ollama: `brew install ollama` on macOS, or see ollama.com for Linux and Windows.\n"
        "2. Start it: `ollama serve` (the macOS app starts it for you).\n"
        "3. Pull the model Rowanholt is set to use (ROWANHOLT_MODEL_NAME, default llama3.2:3b): `ollama pull llama3.2:3b`.\n"
        "4. Rowanholt's backend reaches it at OLLAMA_HOST (default http://host.docker.internal:11434 from Docker). "
        "Point that at another machine's Ollama if this one is short of memory.\n"
        "Reload Ask Smith once it's running: the LLM badge turns green."
    ),
    "windows_persistence": (
        "**Where Windows persistence lives, and where Rowanholt shows it**\n\n"
        "• Run/RunOnce keys and services: registry (SOFTWARE, SYSTEM, NTUSER.DAT), tagged T1547.001 / T1543.003\n"
        "• Scheduled tasks: System32\\Tasks (Artemis) and the TaskScheduler event log, T1053.005\n"
        "• Startup folders: startup_items, T1547.001\n"
        "• WMI subscriptions: the WMI repository (carved when Artemis can't parse it), T1546.003\n"
        "• BITS jobs: bits/qmgr, T1197\n"
        "Check the Navigator layer for what was actually tagged in a case."
    ),
    "linux_persistence": (
        "**Linux persistence checklist, as Rowanholt collects it**\n\n"
        "• cron and at: cron/, crontab, T1053.003\n"
        "• systemd units, user units and generators: services/, autostart, generators, T1543.002\n"
        "• shell start-up: /etc/profile(.d), bashrc, rc.local: shell_init, T1546.004 / T1037.004\n"
        "• loader: ld.so.preload: preload, T1574.006\n"
        "• PAM and sudoers: pam, sudoers, T1556.003 / T1548.003\n"
        "• udev, XDG autostart, SSH authorized_keys, kernel modules: udev_rules, autostart, kernel_modules"
    ),
    "macos_persistence": (
        "**macOS persistence checklist, as Rowanholt collects it**\n\n"
        "• LaunchAgents and LaunchDaemons (system, Apple's and per user): plists, T1543.001 / T1543.004\n"
        "• Login and background items as macOS 13+ tracks them: btm_items, T1547.015\n"
        "• emond rules: emond_rules, T1546.014\n"
        "• periodic scripts and *.local: periodic\n"
        "• kernel extensions: kextpolicy_*, T1547.006\n"
        "• TCC grants, quarantine events and the unified-log export show what ran and what it was allowed to touch."
    ),
    "gandalf": (
        "**Collecting with Gandalf**\n\n"
        "• Linux/macOS: `sudo ./gandalf.sh -E Key -A Local` (or gandalf.py), or Remote over SSH with a hosts list\n"
        "• Windows: `Invoke-Gandalf.ps1 -EncryptionObject Key -Acquisition Local` as admin; locked files come off the raw volume\n"
        "• Then give Elrond the acquisitions/ folder: `elrond.py <CASE> <dir>/acquisitions <dest> --Gandalf --Process --Analysis`"
    ),
}

CASE_QUESTIONS: Dict[str, Dict[str, object]] = {
    "hosts": {"question": "Which hosts are in this case?", "answer": hosts},
    "techniques": {"question": "Which ATT&CK techniques were tagged?", "answer": techniques},
    "persistence": {"question": "What persistence was flagged?", "answer": persistence},
    "logins": {"question": "Who logged in, and were there failed logins?", "answer": logins},
    "iocs": {"question": "What IOCs were extracted?", "answer": iocs},
    "commands": {"question": "Which shell commands look suspicious?", "answer": commands},
    "staging": {"question": "Were executables staged in temp directories?", "answer": staging},
    "detections": {"question": "Any malware detections or web shells?", "answer": detections},
    "analysis": {"question": "What did Elrond's analysis flag?", "answer": analysis},
    "rare": {"question": "What's rare in this case?", "answer": rare},
    "threat_intel": {"question": "Does anything match known threat intelligence?", "answer": threat_intel},
    "findings": {"question": "What have analysts confirmed?", "answer": findings},
}
GENERAL_QUESTIONS = {
    "enable_llm": "How do I turn on Smith's free-text answers?",
    "windows_persistence": "Where does Windows persistence live?",
    "linux_persistence": "What's the Linux persistence checklist?",
    "macos_persistence": "What's the macOS persistence checklist?",
    "gandalf": "How do I collect a host with Gandalf?",
}


def catalogue() -> List[Dict[str, object]]:
    """The offline questions, case ones first."""
    return ([{"id": k, "question": v["question"], "needs_case": True} for k, v in CASE_QUESTIONS.items()] +
            [{"id": k, "question": q, "needs_case": False} for k, q in GENERAL_QUESTIONS.items()])


def answer(question_id: str, case_path: Optional[str]) -> str:
    """The answer to one offline question; case questions need case_path."""
    if question_id in GENERAL_ANSWERS:
        return GENERAL_ANSWERS[question_id]
    entry = CASE_QUESTIONS.get(question_id)
    if entry is None:
        raise KeyError(question_id)
    if not case_path or not os.path.isdir(case_path):
        return "Select a processed case first: this question is answered from the case's own files."
    func: Callable[[str], str] = entry["answer"]  # type: ignore[assignment]
    return func(case_path)


def answer_with_rows(question_id: str, case_path: Optional[str]) -> Dict[str, object]:
    """The answer, and the rows its shown lines came from (each once), for flagging from the answer."""
    rows: List[Dict[str, str]] = []
    token = _citing.set(rows)
    try:
        text = answer(question_id, case_path)
    finally:
        _citing.reset(token)
    seen, unique = set(), []
    for row in rows:
        key = (row["host"], row["file"], row["row_ref"])
        if key not in seen:
            seen.add(key)
            unique.append(row)
    return {"answer": text, "rows": unique}


def unavailable_reason(status: Dict[str, object], host: str, model: str) -> str:
    """Why free-text answers don't work right now, in words an analyst can act on."""
    if not status.get("available"):
        return (f"Smith's free-text answers come from a local language model served by Ollama, and Ollama isn't "
                f"reachable at {host}, so it's either not installed or not running. Nothing is sent to a cloud "
                f"service instead. Install and start Ollama, then `ollama pull {model}`; until then, the questions "
                f"below are answered straight from the case files, without a model.")
    if not status.get("model_loaded"):
        return (f"Ollama is running at {host}, but the model Rowanholt uses ({model}) isn't pulled. "
                f"Run `ollama pull {model}` (or set ROWANHOLT_MODEL_NAME to one of: "
                f"{', '.join(status.get('models') or []) or 'none installed'}). Until then, the questions below "
                f"are answered straight from the case files.")
    return ""
