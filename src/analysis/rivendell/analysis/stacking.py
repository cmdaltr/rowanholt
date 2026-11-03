"""Least frequency of occurrence across a case's hosts (stacking), with explainable features.

Each host contributes the set of values it has in a few families: processes (Prefetch, Amcache,
4688 and Sysmon 1), parent and child pairs, services (7045, systemd units), scheduled tasks
(4698, task files), autoruns (Run keys, startup items, Linux autostart, BTM), WMI consumers and kernel modules. A value
on few of the case's hosts is the long tail; <case>/stacking.csv lists it, ranked by a score
that is the sum of named features, so every row says why it's there:

    rare             on one host, or on at most a fifth of the hosts that have that family at all
    user path        under a user-writable folder (Users, AppData, Temp, /tmp, /dev/shm, /home, ProgramData)
    generated name   a name that looks machine-made: few vowels, a long consonant run, digits and
                     letters interleaved, or long hex
    not in baseline  absent from a clean baseline, when one is given (built with build_baseline)

A family is compared across the hosts of its operating system (a host's OS is that of the
families it has values in), so a Windows host's processes aren't rare because the case also holds
a Linux host, while a WMI consumer on one of five Windows hosts is, even when the other four have
none. Linux hosts are compared within their distribution family (Debian, RHEL, SUSE, Arch, Alpine),
from a collected os-release or, failing that, the distro's fingerprints in what was collected:
otherwise a lone Rocky host among Ubuntu ones makes every unit of its distro rare. Its rows say
which family they were compared in. With fewer than MIN_HOSTS hosts of that OS nothing in the family is called rare: on two
hosts, "on one of them" is a diff of their builds, not a long tail. A baseline still applies.

Rows rank by score, then the fewest hosts, then persistence (autoruns, services, tasks, WMI
consumers, kernel modules) before execution (processes, parent and child pairs): at the same score
a rare way back in is the stronger lead, where a rare program is often just an older or busier host.

A score is a lead, never a verdict: nothing here tags a technique. Stacking needs two or more
hosts; with one, stack_case returns None and writes nothing.

Stdlib only, as the plan requires (docs/ROADMAP.md). A learned model (an isolation forest) was
considered and dropped on 29 October 2026: stacking found every plant in the lab.
"""

import csv
import json
import math
import os
import re
from collections import Counter, defaultdict
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple

# Host and Row: the row on that host's Artefact the value was read from, as the case browser refers to it
# (CSV line number with the header as 1, or #index in a JSON list), so a stacking row can be flagged there.
# Sources: the same for every host with it (up to MAX_SOURCES), as a JSON list of [host, artefact, row]
HEADER = ["Rank", "Score", "Family", "Value", "Hosts With It", "Hosts In Case", "Hosts", "Reasons", "Artefact",
          "Example", "Host", "Row", "Sources"]
MAX_SOURCES = 10
BASELINE_HEADER = ["Family", "Value"]
MAX_JSON_BYTES = 256 << 20
MAX_ROWS = 2000
USER_PATH = re.compile(r"(?i)(?:\\users\\|\\appdata\\|\\temp\\|\\programdata\\|^/tmp/|^/dev/shm/|^/home/|^/var/tmp/|"
                       r"/users/[^/]+/(?:downloads|desktop|library/caches)/)")
# Windows' own folders, where consonant-heavy names are Microsoft's (mscorsvw, comppkgsrv), not machine-made
SYSTEM_PATH = re.compile(r"(?i)\\windows\\(?!temp\\)")
MIN_HOSTS = 3  # hosts of an OS before a value on few of them counts as rare
WEIGHTS = {"rare": 2.0, "user path": 1.5, "generated name": 1.0, "not in baseline": 1.0}
VOWELS = set("aeiouy")
FAMILY_OS = {"process": "windows", "parent > child": "windows", "scheduled task": "windows",
             "wmi consumer": "windows", "service (Windows)": "windows", "autorun (Windows)": "windows",
             "service (systemd)": "linux", "autorun (Linux)": "linux", "kernel module": "linux",
             "autorun (macOS)": "macos"}

PERSISTENCE = {"scheduled task", "wmi consumer", "service (Windows)", "autorun (Windows)", "service (systemd)",
               "autorun (Linux)", "kernel module", "autorun (macOS)"}

Value = Tuple[str, str, str, str]  # (family, value, example, row reference)

# Fingerprints of a distribution family, looked for in a host's raw file names and its values
DISTRO_MARKERS = {
    "debian": ("apt-daily", "dpkg-db-backup", "etc+bash.bashrc", "etc+apt+", "unattended-upgrades"),
    "rhel": ("dnf-makecache", "rpmdb-rebuild", "etc+bashrc", "etc+yum", "etc+dnf+", "crond.service"),
    "suse": ("zypper", "etc+zypp+"),
    "arch": ("pacman", "etc+pacman"),
    "alpine": ("etc+apk+", "openrc"),
}
OS_RELEASE_FAMILY = {"debian": "debian", "ubuntu": "debian", "rhel": "rhel", "fedora": "rhel", "centos": "rhel",
                     "rocky": "rhel", "almalinux": "rhel", "ol": "rhel", "amzn": "rhel", "suse": "suse",
                     "opensuse": "suse", "sles": "suse", "arch": "arch", "alpine": "alpine"}


def _json_records(path: str) -> Iterator[Tuple[str, dict]]:
    """(row reference, record): #index in the file's list. An object is one record, #0, unless it holds
    items or records, which the case browser lists instead; those get no reference rather than a wrong one."""
    if os.path.getsize(path) > MAX_JSON_BYTES:
        return
    with open(path, encoding="utf-8", errors="replace") as fh:
        try:
            data = json.load(fh)
        except ValueError:
            return
    if not isinstance(data, list):
        if isinstance(data, dict):
            yield ("" if data.get("items") or data.get("records") else "#0"), data
        return
    for number, record in enumerate(data):
        if isinstance(record, dict):
            yield f"#{number}", record


def _csv_rows(path: str) -> Iterator[Tuple[str, Dict[str, str]]]:
    """(row reference, row): the line number with the header as 1."""
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        for number, row in enumerate(csv.DictReader(fh), start=2):
            yield str(number), row


def _event(record: dict) -> Tuple[Optional[int], Dict[str, str]]:
    """(EventID, EventData) from an evtx record as Elrond cooks it."""
    event = (record.get("data") or {}).get("Event") or {}
    system = event.get("System") or {}
    event_id = system.get("EventID")
    if isinstance(event_id, dict):
        event_id = event_id.get("#text")
    data = event.get("EventData") or {}
    if not isinstance(data, dict):
        data = {}
    try:
        return int(event_id), {k: str(v) for k, v in data.items() if not isinstance(v, (dict, list))}
    except (TypeError, ValueError):
        return None, {}


def _base(path: str) -> str:
    return re.split(r"[\\/]", path.strip().strip('"'))[-1].lower()


def _norm_path(path: str) -> str:
    """A path with the user's name taken out, so C:\\Users\\alice\\x and C:\\Users\\bob\\x stack together."""
    path = path.strip().strip('"').lower()
    return re.sub(r"(?i)(\\users\\|/users/|/home/)[^\\/]+", r"\1*", path)


def _prefetch(path: str) -> Iterable[Value]:
    for ref, r in _json_records(path):
        name = (r.get("filename") or "").lower()
        if name:
            # The program's own path is among the files it loaded; the example carries it. The list arrives
            # as its Python text, backslashes doubled
            loaded = re.findall(r"[^'\",\[\]]+", str(r.get("accessed_files") or "").replace("\\\\", "\\"))
            full = next((f.strip() for f in loaded if f.strip().lower().endswith("\\" + name)), name)
            yield "process", name, full, ref


def _amcache(path: str) -> Iterable[Value]:
    for ref, r in _json_records(path):
        full = r.get("path") or ""
        if full:
            yield "process", _norm_path(full), full, ref


def _security(path: str) -> Iterable[Value]:
    for ref, r in _json_records(path):
        event_id, data = _event(r)
        if event_id == 4688 and data.get("NewProcessName"):
            child = _norm_path(data["NewProcessName"])
            yield "process", child, data["NewProcessName"], ref
            if data.get("ParentProcessName"):
                yield ("parent > child", f"{_base(data['ParentProcessName'])} > {_base(child)}",
                       data.get("CommandLine", ""), ref)
        elif event_id == 4698 and data.get("TaskName"):
            yield "scheduled task", _norm_name(data["TaskName"].strip("\\")), data["TaskName"], ref


def _sysmon(path: str) -> Iterable[Value]:
    for ref, r in _json_records(path):
        event_id, data = _event(r)
        if event_id == 1 and data.get("Image"):
            yield "process", _norm_path(data["Image"]), data["Image"], ref
            if data.get("ParentImage"):
                yield ("parent > child", f"{_base(data['ParentImage'])} > {_base(data['Image'])}",
                       data.get("CommandLine", ""), ref)


def _system(path: str) -> Iterable[Value]:
    for ref, r in _json_records(path):
        event_id, data = _event(r)
        if event_id == 7045 and data.get("ServiceName"):
            yield "service (Windows)", data["ServiceName"].lower(), data.get("ImagePath", ""), ref


def _systemd(path: str) -> Iterable[Value]:
    name = os.path.basename(path)[:-len(".json")]
    yield "service (systemd)", name.lower(), name, "#0"


def _startup_items(path: str) -> Iterable[Value]:
    for ref, r in _csv_rows(path):
        target = r.get("Target") or r.get("Item") or ""
        if target:
            yield "autorun (Windows)", _norm_path(target), f"{r.get('Item', '')}: {target}", ref


def _norm_name(name: str) -> str:
    """A name with the install's GUIDs and SIDs taken out: Edge's update tasks and SoftLanding's are named
    for the machine or user, so every host's own would otherwise be rare."""
    name = re.sub(r"\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}", "{*}", name.lower())
    return re.sub(r"s-1-5-21(?:-\d+){3,4}", "s-1-5-21-*", name)


def _task_file(path: str) -> Iterable[Value]:
    # A collection carries every task, where 4698 only shows the ones created while Security was auditing
    for ref, r in _json_records(path):
        for task in r.get("tasks") or []:
            name = ((task.get("registration_info") or {}).get("uri") or "").strip("\\")
            if name:
                run = ((task.get("actions") or {}).get("exec") or [{}])[0]
                yield ("scheduled task", _norm_name(name),
                       f"{run.get('command') or ''} {run.get('arguments') or ''}".strip(), ref)


def _run_keys(path: str) -> Iterable[Value]:
    for ref, r in _json_records(path):
        if r.get("Plugin") == "run" and r.get("AppName"):
            yield ("autorun (Windows)", r["AppName"].lower(), f"{r.get('RegistryKey', '')}: {r.get('AppLocation', '')}",
                   ref)


def _autostart(path: str) -> Iterable[Value]:
    for ref, r in _csv_rows(path):
        if r.get("Name") or r.get("Command"):
            yield "autorun (Linux)", (r.get("Name") or r.get("Command") or "").lower(), r.get("Command", ""), ref


def _btm(path: str) -> Iterable[Value]:
    for ref, r in _csv_rows(path):
        value = r.get("ExecutablePath") or r.get("Identifier") or r.get("Name") or ""
        if value:
            yield "autorun (macOS)", _norm_path(value), f"{r.get('Name', '')}: {r.get('ExecutablePath', '')}", ref


def _wmi(path: str) -> Iterable[Value]:
    for ref, r in _json_records(path):
        if r.get("consumer_name") and not r.get("note"):
            values = " ".join(str(v) for v in r.get("consumer_values") or [])
            yield "wmi consumer", f"{r.get('consumer_class', '')}: {r['consumer_name']}".lower(), values, ref


def _kernel_modules(path: str) -> Iterable[Value]:
    for ref, r in _csv_rows(path):
        if r.get("Name"):
            yield "kernel module", r["Name"].lower(), r.get("Path", ""), ref


# (test on the cooked path relative to the host's cooked folder, extractor)
SOURCES: List[Tuple[Callable[[str], bool], Callable[[str], Iterable[Value]]]] = [
    (lambda p: p.startswith("prefetch/") and p.endswith(".json"), _prefetch),
    (lambda p: p.startswith("amcache/") and p.endswith(".json"), _amcache),
    (lambda p: p == "evt/Security.json", _security),
    (lambda p: p.startswith("evt/") and "Sysmon" in p and p.endswith(".json"), _sysmon),
    (lambda p: p == "evt/System.json", _system),
    (lambda p: p.startswith("services/") and p.endswith(".json"), _systemd),
    (lambda p: p.startswith("tasks/") and p.endswith(".json"), _task_file),
    (lambda p: p.startswith("registry/") and p.endswith(".json"), _run_keys),
    (lambda p: p.endswith("startup_items.csv"), _startup_items),
    (lambda p: p.endswith("autostart.csv"), _autostart),
    (lambda p: p.endswith("btm_items.csv"), _btm),
    (lambda p: p.endswith("wbem.json"), _wmi),
    (lambda p: p.endswith("kernel_modules.csv"), _kernel_modules),
]


def host_values(host_dir: str) -> Dict[Tuple[str, str], Tuple[str, str, str]]:
    """{(family, value): (artefact, example, row reference)} for one host: each value once, wherever it was
    first seen."""
    cooked = os.path.join(host_dir, "artefacts", "cooked")
    found: Dict[Tuple[str, str], Tuple[str, str]] = {}
    for root, _, files in os.walk(cooked):
        for name in sorted(files):
            full = os.path.join(root, name)
            relative = os.path.relpath(full, cooked).replace(os.sep, "/")
            for test, extract in SOURCES:
                if not test(relative):
                    continue
                try:
                    for family, value, example, ref in extract(full):
                        found.setdefault((family, value), (f"artefacts/cooked/{relative}", example[:300], ref))
                except (OSError, csv.Error):
                    continue  # an unreadable artefact leaves its values out; the rest still stack
    return found


def _os_release_family(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            fields = dict(line.strip().split("=", 1) for line in fh if "=" in line)
    except OSError:
        return ""
    for name in [fields.get("ID", "")] + fields.get("ID_LIKE", "").split():
        family = OS_RELEASE_FAMILY.get(name.strip('"').lower())
        if family:
            return family
    return ""


def linux_distro(host_dir: str, values: Iterable[Tuple[str, str]]) -> str:
    """A Linux host's distribution family: from os-release when one was collected, else the family
    whose fingerprints are most present; '' when nothing says."""
    names = []
    for root, _, files in os.walk(os.path.join(host_dir, "artefacts", "raw")):
        for name in files:
            if name.endswith("os-release"):
                family = _os_release_family(os.path.join(root, name))
                if family:
                    return family
            names.append(name.lower())
    text = " ".join(names + [value for _, value in values])
    hits = {family: sum(marker in text for marker in markers) for family, markers in DISTRO_MARKERS.items()}
    best = max(hits, key=lambda family: hits[family])
    return best if hits[best] else ""


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def looks_generated(name: str) -> bool:
    """Whether a file or unit name looks machine-made rather than named by a person: entropy alone
    flags every long English compound (backgroundtaskhost), so this asks for its shape instead."""
    stem = re.sub(r"\.[a-z0-9]{1,4}$", "", name.lower())
    alnum = re.sub(r"[^a-z0-9]", "", stem)
    if len(alnum) < 8:
        return False
    if re.fullmatch(r"[0-9a-f]{16,}", alnum):
        return True
    letters = [c for c in alnum if c.isalpha()]
    switches = sum(a.isdigit() != b.isdigit() for a, b in zip(alnum, alnum[1:]))
    if switches >= 4 and entropy(alnum) > 3.0:
        return True
    if len(letters) >= 8 and sum(c in VOWELS for c in letters) / len(letters) < 0.2:
        return True
    return bool(re.search(r"[bcdfghjklmnpqrstvwxz]{6,}", stem))


def reasons(family: str, value: str, with_it: int, hosts: int, baseline: Optional[Set[Tuple[str, str]]],
            example: str = "") -> List[str]:
    """The named features behind a value's score. A process from Prefetch is valued by its name alone, so its
    example, the path it ran from, says whether a Windows folder vouches for the name."""
    found = []
    if with_it <= max(1, hosts // 5):
        found.append("rare")
    if USER_PATH.search(value):
        found.append("user path")
    where = example if family == "process" and re.search(r"[\\/]", example) else value
    if looks_generated(_base(value.split(" > ")[-1].split(": ")[-1])) and not SYSTEM_PATH.search(where):
        found.append("generated name")
    if baseline is not None and (family, value) not in baseline:
        found.append("not in baseline")
    return found


def hosts(output_directory: str) -> List[str]:
    return sorted(os.path.join(output_directory, d) for d in os.listdir(output_directory)
                  if os.path.isdir(os.path.join(output_directory, d, "artefacts", "cooked")))


def stack(per_host: Dict[str, Dict[Tuple[str, str], Tuple[str, str, str]]],
          baseline: Optional[Set[Tuple[str, str]]] = None,
          distros: Optional[Dict[str, str]] = None) -> List[Dict[str, str]]:
    """Ranked rows for every value that's rare across the hosts (or new against the baseline).
    distros ({host: distribution family}) splits the Linux hosts into one comparison per family."""
    def group(host: str, family: str) -> str:
        os_name = FAMILY_OS[family]
        return f"{os_name}:{distros[host]}" if os_name == "linux" and distros and distros.get(host) else os_name

    on: Dict[Tuple[str, str, str], List[str]] = defaultdict(list)
    of_os: Dict[str, Set[str]] = defaultdict(set)
    for host, values in per_host.items():
        for family, value in values:
            on[(group(host, family), family, value)].append(host)
            of_os[group(host, family)].add(host)
    rows = []
    for (compared, family, value), with_it in on.items():
        total = len(of_os[compared])
        if total < MIN_HOSTS and baseline is None:
            continue
        artefact, example, ref = per_host[with_it[0]][(family, value)]
        why = reasons(family, value, len(with_it), total, baseline, example)
        if total < MIN_HOSTS:
            why = [r for r in why if r != "rare"]
        if "rare" not in why and "not in baseline" not in why:
            continue
        score = sum(WEIGHTS[r] for r in why)
        shown = f"{family}, {compared.split(':')[1]}" if ":" in compared else family
        rows.append({"Score": f"{score:.1f}", "Family": shown, "Value": value, "Hosts With It": str(len(with_it)),
                     "Hosts In Case": str(total), "Hosts": "; ".join(sorted(with_it)[:10]), "Reasons": ", ".join(why),
                     "Artefact": artefact, "Example": example, "Host": with_it[0], "Row": ref,
                     "Sources": json.dumps([[h, *[per_host[h][(family, value)][i] for i in (0, 2)]]
                                            for h in sorted(with_it)[:MAX_SOURCES]])})
    rows.sort(key=lambda r: (-float(r["Score"]), int(r["Hosts With It"]), r["Family"].split(",")[0] not in PERSISTENCE,
                             r["Family"], r["Value"]))
    for number, row in enumerate(rows, start=1):
        row["Rank"] = str(number)
    return rows[:MAX_ROWS]


def read_baseline(path: str) -> Set[Tuple[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return {(r["Family"], r["Value"]) for r in csv.DictReader(fh) if r.get("Family")}


def build_baseline(output_directories: Iterable[str], path: str) -> int:
    """Every value on the clean hosts of these cases, as a baseline file for stack_case."""
    values: Set[Tuple[str, str]] = set()
    for directory in output_directories:
        for host_dir in hosts(directory):
            values.update(host_values(host_dir))
    with open(path, "w", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        writer.writerow(BASELINE_HEADER)
        writer.writerows(sorted(values))
    return len(values)


def stack_case(output_directory: str, baseline_path: str = "") -> Optional[Dict[str, int]]:
    """Write <case>/stacking.csv; None when the case has fewer than two hosts."""
    host_dirs = hosts(output_directory)
    if len(host_dirs) < 2:
        return None
    per_host = {os.path.basename(h): host_values(h) for h in host_dirs}
    distros = {os.path.basename(h): linux_distro(h, per_host[os.path.basename(h)]) for h in host_dirs
               if any(FAMILY_OS[family] == "linux" for family, _ in per_host[os.path.basename(h)])}
    baseline = read_baseline(baseline_path) if baseline_path else None
    rows = stack(per_host, baseline, distros)
    with open(os.path.join(output_directory, "stacking.csv"), "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=HEADER)
        writer.writeheader()
        writer.writerows(rows)
    return {"hosts": len(host_dirs), "values": sum(len(v) for v in per_host.values()), "rows": len(rows)}


def precision_at_k(stacking_csv: str, expected: Iterable[str], k: int = 20) -> float:
    """The share of the top k rows whose value contains one of the expected (seeded) values:
    how the lab measures stacking before Eru is given it."""
    needles = [e.lower() for e in expected]
    with open(stacking_csv, newline="", encoding="utf-8") as fh:
        top = [r for _, r in zip(range(k), csv.DictReader(fh))]
    if not top:
        return 0.0
    return sum(any(n in r["Value"] or n in r["Example"].lower() for n in needles) for r in top) / len(top)


if __name__ == "__main__":
    import argparse

    cli = argparse.ArgumentParser(description="Stack a case's hosts, or build a baseline from clean cases.")
    cli.add_argument("cases", nargs="+", help="Elrond case directories")
    cli.add_argument("--baseline", metavar="OUT", help="write a baseline of every value in these cases instead")
    cli.add_argument("--against", metavar="FILE", default="", help="score the case against this baseline")
    options = cli.parse_args()
    if options.baseline:
        print(f"{build_baseline(options.cases, options.baseline)} values written to {options.baseline}")
    else:
        for case in options.cases:
            print(case, stack_case(case, options.against) or "fewer than two hosts: nothing to stack")
