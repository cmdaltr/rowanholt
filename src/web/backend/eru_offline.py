"""
Eru without an LLM: questions answered straight from Elrond's case output.

Free-text questions need Ollama. When it isn't there, Ask Eru offers these
instead: each reads the case directory (<case>/<host>/artefacts/cooked/*.csv,
<case>/<host>/analysis/*.csv, <case>/mitre_techniques.txt, <case>/threat_groups.csv) and summarises what
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
# Cooked CSVs whose Flag column marks a finding (Elrond's Windows, Linux and macOS processors)
FLAGGED_CSVS = ("pam.csv", "sudoers.csv", "autostart.csv", "udev_rules.csv", "preload.csv", "shell_init.csv",
                "kernel_modules.csv", "btm_items.csv", "emond_rules.csv", "periodic.csv")
PERSISTENCE_LISTS = ("startup_items.csv", "generators.csv")
# stacking.py's PERSISTENCE (the backend doesn't import the analysis package; a test keeps them equal)
STACKING_PERSISTENCE = {"scheduled task", "wmi consumer", "service (Windows)", "autorun (Windows)", "service (systemd)",
                        "autorun (Linux)", "kernel module", "autorun (macOS)"}
RARE_ROWS = 8
# The rows the lines shown so far came from, while answer_with_rows() runs
_citing: ContextVar[Optional[List[Dict[str, str]]]] = ContextVar("eru_offline_citing", default=None)


class Cited(str):
    """A line of an answer, with the row it was built from."""
    cite: Optional[Dict[str, str]] = None


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


def _rows(path: Path) -> List[Dict[str, str]]:
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            return list(csv.DictReader(fh))
    except (OSError, csv.Error) as e:
        logger.debug(f"Couldn't read {path}: {e}")
        return []


def _numbered(path: Path) -> Iterator[Tuple[str, Dict[str, str], Dict[str, str]]]:
    """(row reference, row, row as hashed) for each CSV row: references and hashes as case_files gives them."""
    for number, row in enumerate(_rows(path), start=2):
        yield str(number), row, case_files.csv_row(row)


def _where(host: Path, path: Path) -> Tuple[str, str]:
    """The (host, file) a citation names: the host folder and the path in it, or the case's own file."""
    try:
        return host.name, str(path.relative_to(host))
    except ValueError:
        return case_files.CASE_HOST, path.name


def _json_records(path: Path, keep_index: bool = False) -> List:
    """A JSON file's records; with keep_index, everything in the list, so positions are the file's own."""
    try:
        records = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError) as e:
        logger.debug(f"Couldn't read {path}: {e}")
        return []
    if not isinstance(records, list):
        return []
    return records if keep_index else [r for r in records if isinstance(r, dict)]


def _cooked(host: Path, pattern: str) -> Iterable[Path]:
    return sorted((host / "artefacts" / "cooked").rglob(pattern))


def _bullets(lines: Iterable[str], limit: int = MAX_ROWS) -> str:
    lines = list(lines)
    citing = _citing.get()
    if citing is not None:
        citing.extend(line.cite for line in lines[:limit] if getattr(line, "cite", None))
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
        cooked = list(_cooked(host, "*.csv")) + list(_cooked(host, "*.json"))
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
        for name in FLAGGED_CSVS:
            for path in _cooked(host, name):
                for ref, row, normal in _numbered(path):
                    flag = row.get("Flag") or ""
                    # out-of-tree and unsigned alone are DKMS and VM drivers; only an odd file location is a lead
                    if name == "kernel_modules.csv" and not ("no module file" in flag or "outside" in flag):
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
        for path in _cooked(host, "wbem.json"):
            for index, sub in enumerate(_json_records(path, keep_index=True)):
                if isinstance(sub, dict) and not sub.get("note"):
                    action = "; ".join(str(v) for v in sub.get("consumer_values") or [])
                    text = (f"WMI subscription: {sub.get('filter_name')} -> {sub.get('consumer_class')} "
                            f"'{sub.get('consumer_name')}'" + (f": {action}" if action else ""))
                    lines.append(_cited(text, *_where(host, path), f"#{index}", case_files.json_row(sub)))
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
        records = [r for p in _cooked(host, "login_records.csv") for r in _rows(p)]
        users = Counter(r.get("User", "") for r in records if r.get("Type") == "USER_PROCESS" and r.get("User"))
        failed = Counter((r.get("Address") or r.get("Host") or "?") for r in records if r.get("Source", "").endswith("btmp"))
        if users:
            lines.append("logins: " + ", ".join(f"{u} ({n})" for u, n in users.most_common(10)))
        if failed:
            lines.append("failed logins by source: " + ", ".join(f"{s} ({n})" for s, n in failed.most_common(10)))
        for path in _cooked(host, "lastlog.csv"):
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
        rows = _rows(host / "analysis" / "iocs.csv")
        if not rows:
            continue
        kinds = Counter(r.get("indicator_type", "?") for r in rows)
        values = Counter(r.get("ioc", "") for r in rows if r.get("indicator_type") in ("ipv4", "ipv6", "domain", "url", "email"))
        sections.append(f"**{host.name}**: {len(rows)} indicators (" + ", ".join(f"{k} {n}" for k, n in kinds.most_common()) +
                        ")\n" + _bullets(f"{v} (×{n})" for v, n in values.most_common(MAX_ROWS)))
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
        path = host / "analysis" / "threat_intel_matches.csv"
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
    groups_csv = Path(case_path) / "threat_groups.csv"
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
        for pattern in ("*bash_history.csv", "*zsh_history.csv", "shell_histories.csv", "*ConsoleHost_history*.csv"):
            for path in _cooked(host, pattern):
                for ref, row, normal in _numbered(path):
                    command = row.get("Command") or next(iter(row.values()), "") or ""
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
                 for p in _cooked(host, "tmp_executables.csv") for ref, r, normal in _numbered(p)]
        if lines:
            sections.append(f"**{host.name}**\n" + _bullets(lines))
    if not sections:
        return "No executables were listed in /tmp, /var/tmp or /dev/shm (Linux, Gandalf collections)."
    return "**Executables in temporary directories:**\n\n" + "\n\n".join(sections)


def detections(case_path: str) -> str:
    sections = []
    for host in _hosts(case_path):
        lines = []
        for p in _cooked(host, "defender_detections.csv"):
            lines += [_cited(f"Defender: {r.get('ThreatName') or r.get('Threat') or ''} {r.get('Path') or ''}".strip(),
                             *_where(host, p), ref, normal) for ref, r, normal in _numbered(p)]
        for p in _cooked(host, "webshells.csv"):
            lines += [_cited(f"web shell: {r.get('Source')} ({r.get('Indicators')})", *_where(host, p), ref, normal)
                      for ref, r, normal in _numbered(p)]
        for p in _cooked(host, "xprotect_*.csv"):
            lines += [_cited(f"XProtect ({p.stem}): {', '.join(f'{k}={v}' for k, v in list(r.items())[:4])}",
                             *_where(host, p), ref, normal) for ref, r, normal in list(_numbered(p))[:10]]
        if lines:
            sections.append(f"**{host.name}**\n" + _bullets(lines))
    if not sections:
        return "No Defender detections, XProtect events or web shells in the processed artefacts."
    return "**Detections:**\n\n" + "\n\n".join(sections)


def rare(case_path: str) -> str:
    """The top of Elrond's stacking across hosts (<case>/stacking.csv): persistence, then programs."""
    stacking_csv = Path(case_path) / "stacking.csv"
    rows = list(_numbered(stacking_csv))
    if not rows:
        return ("Nothing was stacked for this case. Stacking compares hosts, so it needs two or more, and runs with "
                "Elrond's analysis (--Analysis); something is called rare only among three or more hosts of an OS.")
    def line(numbered: Tuple[str, Dict[str, str], Dict[str, str]]) -> Cited:
        ref, r, normal = numbered
        return _cited(f"#{r.get('Rank')} {r.get('Value')} ({r.get('Family')}): on {r.get('Hosts With It')} of "
                      f"{r.get('Hosts In Case')} hosts ({r.get('Hosts')}); {r.get('Reasons')}",
                      case_files.CASE_HOST, stacking_csv.name, ref, normal)
    persistence = [n for n in rows if (n[1].get("Family") or "").split(",")[0] in STACKING_PERSISTENCE]
    programs = [n for n in rows if n not in persistence]
    parts = []
    if persistence:
        parts.append(f"**Ways back in** ({len(persistence)})\n" + _bullets(map(line, persistence), RARE_ROWS))
    if programs:
        parts.append(f"**Programs and process pairs** ({len(programs)})\n" + _bullets(map(line, programs), RARE_ROWS))
    return ("**What's rare across the hosts** (stacking.csv, highest score first):\n\n" + "\n\n".join(parts) +
            "\n\nEach row is a lead, not a verdict: rare can be an older build or a busier host. "
            "To flag one, open its artefact on that host in the case browser.")


def analysis(case_path: str) -> str:
    sections = []
    for host in _hosts(case_path):
        path = host / "analysis" / "analysis.csv"
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
        "**Turning on Eru's free-text answers**\n\n"
        "Eru generates answers with a local model served by Ollama, so case data never leaves this machine.\n"
        "1. Install Ollama: `brew install ollama` on macOS, or see ollama.com for Linux and Windows.\n"
        "2. Start it: `ollama serve` (the macOS app starts it for you).\n"
        "3. Pull the model Rivendell is set to use (RIVENDELL_MODEL_NAME, default llama3.2:3b): `ollama pull llama3.2:3b`.\n"
        "4. Rivendell's backend reaches it at OLLAMA_HOST (default http://host.docker.internal:11434 from Docker). "
        "Point that at another machine's Ollama if this one is short of memory.\n"
        "Reload Ask Eru once it's running: the LLM badge turns green."
    ),
    "windows_persistence": (
        "**Where Windows persistence lives, and where Rivendell shows it**\n\n"
        "• Run/RunOnce keys and services: registry (SOFTWARE, SYSTEM, NTUSER.DAT), tagged T1547.001 / T1543.003\n"
        "• Scheduled tasks: System32\\Tasks (Artemis) and the TaskScheduler event log, T1053.005\n"
        "• Startup folders: startup_items.csv, T1547.001\n"
        "• WMI subscriptions: the WMI repository (carved when Artemis can't parse it), T1546.003\n"
        "• BITS jobs: bits/qmgr, T1197\n"
        "Check the Navigator layer for what was actually tagged in a case."
    ),
    "linux_persistence": (
        "**Linux persistence checklist, as Rivendell collects it**\n\n"
        "• cron and at: cron/, crontab, T1053.003\n"
        "• systemd units, user units and generators: services/, autostart.csv, generators.csv, T1543.002\n"
        "• shell start-up: /etc/profile(.d), bashrc, rc.local: shell_init.csv, T1546.004 / T1037.004\n"
        "• loader: ld.so.preload: preload.csv, T1574.006\n"
        "• PAM and sudoers: pam.csv, sudoers.csv, T1556.003 / T1548.003\n"
        "• udev, XDG autostart, SSH authorized_keys, kernel modules: udev_rules.csv, autostart.csv, kernel_modules.csv"
    ),
    "macos_persistence": (
        "**macOS persistence checklist, as Rivendell collects it**\n\n"
        "• LaunchAgents and LaunchDaemons (system, Apple's and per user): plists, T1543.001 / T1543.004\n"
        "• Login and background items as macOS 13+ tracks them: btm_items.csv, T1547.015\n"
        "• emond rules: emond_rules.csv, T1546.014\n"
        "• periodic scripts and *.local: periodic.csv\n"
        "• kernel extensions: kextpolicy_*.csv, T1547.006\n"
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
    "enable_llm": "How do I turn on Eru's free-text answers?",
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
        return (f"Eru's free-text answers come from a local language model served by Ollama, and Ollama isn't "
                f"reachable at {host}, so it's either not installed or not running. Nothing is sent to a cloud "
                f"service instead. Install and start Ollama, then `ollama pull {model}`; until then, the questions "
                f"below are answered straight from the case files, without a model.")
    if not status.get("model_loaded"):
        return (f"Ollama is running at {host}, but the model Rivendell uses ({model}) isn't pulled. "
                f"Run `ollama pull {model}` (or set RIVENDELL_MODEL_NAME to one of: "
                f"{', '.join(status.get('models') or []) or 'none installed'}). Until then, the questions below "
                f"are answered straight from the case files.")
    return ""
