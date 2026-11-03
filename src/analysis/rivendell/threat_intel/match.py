"""A whole case against threat intelligence, once Elrond's analysis is done.

Per host, every text field of every cooked artefact and of analysis/iocs.csv is matched
(threat_intel/index.py), into <host>/analysis/threat_intel_matches.csv: one row per evidential
element found in a field, with the groups, techniques and sources behind it. IOCs that match get
their watchlist_match filled in iocs.csv.

For the case, threat_groups.csv ranks the groups whose evidence turned up: first by how many
atomic indicators (IPs, domains, hashes, URLs) specific to it matched, then distinct elements specific
to few groups (an element more than COMMON_BREADTH groups use says little about who), then by how
many of the group's techniques the case has. The Basis column says which of those the rank rests on,
so one shared PowerShell switch never reads like attribution. Technique overlap
on its own is a weak signal, since half the matrix is common to everyone: a group listed on overlap
alone says so in its Basis column. Nothing here names who did it; it says whose tradecraft the
evidence resembles, and why.
"""

import csv
import json
import os
import re
from collections import defaultdict
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from rivendell.threat_intel.index import COMMON_BREADTH, ThreatIntelIndex, by_element
from rivendell.threat_intel.schema import Indicator

MATCH_HEADER = ["Artefact", "Record", "Field", "Value", "Element", "Kind", "Groups Using", "Common", "Groups",
                "Techniques", "Sources", "Reference URL"]
GROUP_HEADER = ["Rank", "Group", "Basis", "Atomic Elements", "Specific Elements", "Common Elements", "Elements",
                "Techniques In Case", "Group Techniques", "Overlap"]
MAX_ROWS_PER_ELEMENT = 50  # per host: the rest are counted, not listed
MAX_JSON_BYTES = 256 << 20
MAX_FIELD = 20000
NOT_TEXT = re.compile(r"^[\d\s:.,+\-TZ/]*$")
OVERLAP_ONLY_GROUPS = 10
ATOMIC = ("ip", "domain", "hash", "url")
# Gandalf's own PowerShell, logged as script blocks while it collected: its reg save, net use and the
# rest are the acquisition, not the intrusion
COLLECTOR_SCRIPTS = re.compile(r"(?:^|[\\/])(?:Invoke-Gandalf|Invoke-ArtefactAcquisition)\.ps1$", re.IGNORECASE)
SNIPPET = 300


def _records(path: str) -> Iterator[Tuple[str, Dict[str, str]]]:
    """(record label, {field: text}) for each row of a CSV or record of a JSON artefact."""
    if path.endswith(".csv"):
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            for number, row in enumerate(csv.DictReader(fh), start=2):
                yield str(number), {k or "": v or "" for k, v in row.items() if isinstance(v, str)}
        return
    if os.path.getsize(path) > MAX_JSON_BYTES:
        return
    with open(path, encoding="utf-8", errors="replace") as fh:
        try:
            data = json.load(fh)
        except ValueError:
            return
    records = data if isinstance(data, list) else [data]
    for number, record in enumerate(records):
        fields: Dict[str, str] = {}
        _flatten(record, "", fields)
        yield f"#{number}", fields


def _flatten(value, prefix: str, out: Dict[str, str]) -> None:
    if isinstance(value, dict):
        for key, inner in value.items():
            _flatten(inner, f"{prefix}.{key}" if prefix else str(key), out)
    elif isinstance(value, list):
        for position, inner in enumerate(value):
            _flatten(inner, f"{prefix}[{position}]", out)
    elif isinstance(value, str):
        out[prefix] = value


def _collector_blocks(records: List[Tuple[str, Dict[str, str]]]) -> set:
    """ScriptBlockIds of the script blocks Gandalf's collector logged (every part of a block shares
    its id, though only some parts carry the Path)."""
    blocks = set()
    for _, fields in records:
        block = next((v for k, v in fields.items() if k.endswith("ScriptBlockId")), "")
        path = next((v for k, v in fields.items() if k.endswith("EventData.Path")), "")
        if block and COLLECTOR_SCRIPTS.search(path.strip()):
            blocks.add(block)
    return blocks


def _snippet(value: str, element: str) -> str:
    """SNIPPET characters of value around the element, so the row shows what matched."""
    at = value.lower().find(element.lower())
    start = max(0, min(at - SNIPPET // 3, len(value) - SNIPPET)) if at > 0 else 0
    return value[start:start + SNIPPET]


def _artefacts(host_dir: str) -> Iterable[str]:
    cooked = os.path.join(host_dir, "artefacts", "cooked")
    for root, _, files in os.walk(cooked):
        for name in sorted(files):
            if name.endswith((".csv", ".json")):
                yield os.path.join(root, name)
    iocs = os.path.join(host_dir, "analysis", "iocs.csv")
    if os.path.isfile(iocs):
        yield iocs


def hosts(output_directory: str) -> List[str]:
    return sorted(os.path.join(output_directory, d) for d in os.listdir(output_directory)
                  if os.path.isdir(os.path.join(output_directory, d, "artefacts")))


def match_host(host_dir: str, index: ThreatIntelIndex) -> Tuple[List[Dict[str, str]], Dict[str, Dict], int]:
    """(match rows, {element: summary}, records left out as Gandalf's own) for one host."""
    rows: List[Dict[str, str]] = []
    collector = 0
    listed: Dict[str, int] = defaultdict(int)
    elements: Dict[str, Dict] = {}
    for path in _artefacts(host_dir):
        relative = os.path.relpath(path, host_dir)
        records: Iterable[Tuple[str, Dict[str, str]]] = _records(path)
        blocks: set = set()
        if path.endswith(".json") and "powershell" in os.path.basename(path).lower():
            records = list(records)
            blocks = _collector_blocks(records)
        for record, fields in records:
            if blocks and next((v for k, v in fields.items() if k.endswith("ScriptBlockId")), "") in blocks:
                collector += 1
                continue
            for field, value in fields.items():
                if len(value) < 3 or NOT_TEXT.match(value):
                    continue
                for entry in by_element(index.match(value[:MAX_FIELD])):
                    key = str(entry["element"]).lower()
                    summary = elements.setdefault(key, {**entry, "hits": 0})
                    summary["hits"] += 1
                    listed[key] += 1
                    if listed[key] > MAX_ROWS_PER_ELEMENT:
                        continue
                    rows.append({
                        "Artefact": relative, "Record": record, "Field": field, "Value": _snippet(value, str(entry["element"])),
                        "Element": entry["element"], "Kind": entry["kind"], "Groups Using": str(entry["breadth"]),
                        "Common": "yes" if entry["breadth"] > COMMON_BREADTH else "",
                        "Groups": "; ".join(entry["groups"][:10]) + (" ..." if len(entry["groups"]) > 10 else ""),
                        "Techniques": ", ".join(sorted(entry["techniques"])),
                        "Sources": "; ".join(entry["sources"]),
                        "Reference URL": next((i.reference_url for i in entry["indicators"] if i.reference_url), ""),
                    })
    return rows, elements, collector


def _fill_watchlist(host_dir: str, elements: Dict[str, Dict]) -> int:
    """watchlist_match in iocs.csv for each IOC that's an evidential element."""
    path = os.path.join(host_dir, "analysis", "iocs.csv")
    if not os.path.isfile(path) or not elements:
        return 0
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        header, rows = reader.fieldnames or [], list(reader)
    if "watchlist_match" not in header:
        return 0
    filled = 0
    for row in rows:
        entry = elements.get((row.get("ioc") or "").strip().lower())
        if entry and not row.get("watchlist_match"):
            groups = ", ".join(entry["groups"][:3]) or "; ".join(entry["sources"][:2])
            row["watchlist_match"] = f"threat intel: {groups}"
            filled += 1
    if filled:
        with open(path, "w", newline="", encoding="utf-8") as out:
            writer = csv.DictWriter(out, fieldnames=header)
            writer.writeheader()
            writer.writerows(rows)
    return filled


def _case_techniques(output_directory: str) -> set:
    path = os.path.join(output_directory, "mitre_techniques.txt")
    if not os.path.isfile(path):
        return set()
    with open(path, encoding="utf-8", errors="replace") as fh:
        return {line.strip().upper() for line in fh if re.fullmatch(r"T\d{4}(?:\.\d{3})?", line.strip().upper())}


def rank_groups(indicators: List[Indicator], elements: Dict[str, Dict], case_techniques: set) -> List[Dict[str, str]]:
    techniques_by_group: Dict[str, set] = defaultdict(set)
    for indicator in indicators:
        if indicator.threat_group and indicator.technique_id:
            techniques_by_group[indicator.threat_group].add(indicator.technique_id.upper())
    matched: Dict[str, Dict[str, set]] = defaultdict(lambda: {"specific": set(), "common": set(), "atomic": set()})
    for entry in elements.values():
        for group in entry["groups"]:
            matched[group]["common" if entry["breadth"] > COMMON_BREADTH else "specific"].add(str(entry["element"]))
            if entry["kind"] in ATOMIC and entry["breadth"] <= COMMON_BREADTH:
                matched[group]["atomic"].add(str(entry["element"]))
    ranked = []
    for group in set(matched) | set(techniques_by_group):
        known = techniques_by_group.get(group, set())
        # A parent technique in the case counts for its sub-techniques and the other way round
        in_case = {t for t in known if t in case_techniques or t.split(".")[0] in case_techniques
                   or any(c.split(".")[0] == t for c in case_techniques)}
        found = matched.get(group, {"specific": set(), "common": set(), "atomic": set()})
        ranked.append({"group": group, "specific": found["specific"], "common": found["common"],
                       "atomic": found["atomic"], "in_case": in_case, "known": known})
    ranked.sort(key=lambda g: (-len(g["atomic"]), -len(g["specific"]), -len(g["in_case"]) / max(1, len(g["known"])),
                               g["group"]))
    with_evidence = [g for g in ranked if g["specific"] or g["common"]]
    overlap_only = [g for g in ranked if not (g["specific"] or g["common"]) and len(g["in_case"]) >= 3]
    overlap_only.sort(key=lambda g: (-len(g["in_case"]) / max(1, len(g["known"])), g["group"]))
    rows = []
    for number, g in enumerate(with_evidence + overlap_only[:OVERLAP_ONLY_GROUPS], start=1):
        basis = ("atomic indicators" if g["atomic"] else "several specific procedures" if len(g["specific"]) > 1
                 else "one shared procedure" if g["specific"] else "common tooling only" if g["common"]
                 else "technique overlap only")
        rows.append({
            "Rank": str(number), "Group": g["group"], "Basis": basis,
            "Atomic Elements": str(len(g["atomic"])), "Specific Elements": str(len(g["specific"])),
            "Common Elements": str(len(g["common"])),
            "Elements": "; ".join(sorted(g["specific"]) + sorted(g["common"]))[:1000],
            "Techniques In Case": ", ".join(sorted(g["in_case"])), "Group Techniques": str(len(g["known"])),
            "Overlap": f"{len(g['in_case']) / len(g['known']):.0%}" if g["known"] else "",
        })
    return rows


def match_case(output_directory: str, indicators: List[Indicator], log=None) -> Dict[str, int]:
    """Match every host in the case; returns counts for the audit log. log(message) reports progress."""
    index = ThreatIntelIndex(indicators, scope="case")
    totals = {"indicators": len(index), "hosts": 0, "matches": 0, "elements": 0, "iocs": 0, "groups": 0,
              "collector": 0}
    case_elements: Dict[str, Dict] = {}
    for host_dir in hosts(output_directory):
        rows, elements, collector = match_host(host_dir, index)
        totals["collector"] += collector
        os.makedirs(os.path.join(host_dir, "analysis"), exist_ok=True)
        with open(os.path.join(host_dir, "analysis", "threat_intel_matches.csv"), "w", newline="", encoding="utf-8") as out:
            writer = csv.DictWriter(out, fieldnames=MATCH_HEADER)
            writer.writeheader()
            writer.writerows(rows)
        totals["iocs"] += _fill_watchlist(host_dir, elements)
        totals["hosts"] += 1
        totals["matches"] += sum(e["hits"] for e in elements.values())
        for key, entry in elements.items():
            case_elements.setdefault(key, entry)
        if log:
            log(f"{os.path.basename(host_dir)}: {len(elements)} threat intelligence elements matched")
    totals["elements"] = len(case_elements)
    groups = rank_groups(index.indicators, case_elements, _case_techniques(output_directory))
    with open(os.path.join(output_directory, "threat_groups.csv"), "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=GROUP_HEADER)
        writer.writeheader()
        writer.writerows(groups)
    totals["groups"] = len(groups)
    return totals
