#!/usr/bin/env python3
"""
Score an Elrond output against the lab's ground truth: every seeded artefact in a
target's expected.json, and whether Elrond collected it, cooked it, tagged its
ATT&CK technique and found the strings and IOCs it should.

    lab/verify-expected.py <elrond output dir> <acquisitions dir> [--json]

<elrond output dir> is Elrond's destination (it holds mitre_techniques.txt and a
folder per host); <acquisitions dir> holds a folder per target with its
expected.json, as ./lab.sh gandalf-collect leaves them. A host is matched to its
target by name, or paired when there's only one of each.

Checks per seeded item (a dash where expected.json asks nothing of that kind):
  collected  the file's name is in the host's raw/ (path entries only)
  cooked     the named cooked table exists (.jsonl, or an older case's .csv or .json)
  attack     the technique ID is in mitre_techniques.txt ("not run" when only YARA gives it, attack_by)
  expect     every string appears somewhere in the host's output
  yara       every rule name appears in the output (skipped unless YARA ran)
  keywords   every keyword appears in the output (skipped unless keywords ran)
Exits 1 when any check fails.
"""
import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

TEXT_SUFFIXES = (".jsonl", ".csv", ".json", ".txt", ".log", ".tsv", ".audit")
MAX_TEXT_BYTES = 64 << 20
RECORDS = Path(__file__).resolve().parents[1] / "src" / "analysis" / "rowanholt" / "core" / "records.py"
RELEASE = Path(__file__).resolve().parents[1] / "src" / "analysis" / "rowanholt" / "post" / "mitre" / "attack_release.json"


def load_records():
    """Rowanholt's records module, loaded by path: the analysis package isn't installed on the host."""
    spec = importlib.util.spec_from_file_location("records", RECORDS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


records = load_records()
REVOKED = json.loads(RELEASE.read_text(encoding="utf-8")).get("revoked", {})


def current_id(technique_id: str) -> str:
    """The pinned release's ID (attack_lookup.current_id): a revoked technique's replacement, so an
    expected.json naming the Atomic test's T1070.001 matches Elrond's T1685.005, and an older
    case's mitre_techniques.txt matches an expected.json that names the v20.1 ID."""
    tid = technique_id.strip().upper()
    return REVOKED.get(tid, tid)


def values(value) -> list:
    """A record's values as text, nested ones too: JSON escapes a backslash or a quote, so the
    text is matched against what the record holds, not how it's written."""
    if isinstance(value, dict):
        return [v for item in value.values() for v in values(item)]
    if isinstance(value, list):
        return [v for item in value for v in values(item)]
    return [] if value is None else [str(value)]


def read_text(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return ""
        if path.suffix == ".jsonl":
            return "\n".join(v for _, record in records.read_records(path) for v in values(record))
        return path.read_text(errors="ignore")
    except (OSError, records.RecordsError):
        return ""


def table(folder: Path, name: str) -> bool:
    """A table exists, whatever its suffix (expected.json may name an older case's CSV)."""
    return records.table_path(folder, name).exists()


def format_problems(host_dir: Path) -> list:
    """Every JSON Lines table Elrond wrote for a host that breaks the format: a line that isn't a
    record, or a record without the envelope."""
    problems = []
    for path in sorted(host_dir.rglob("*" + records.SUFFIX)):
        if "raw" in path.relative_to(host_dir).parts:
            continue
        problems += [f"{path.relative_to(host_dir)}: {p}" for p in records.check_file(path)[:3]]
    return problems


def host_corpus(host_dir: Path) -> str:
    """Everything Elrond wrote for a host, except the raw evidence itself."""
    parts = []
    for root, dirs, files in os.walk(host_dir):
        if Path(root).name == "raw":
            dirs[:] = []
            continue
        for name in files:
            if name.endswith(TEXT_SUFFIXES):
                parts.append(read_text(Path(root) / name))
    return "\n".join(parts).lower()


def raw_names(host_dir: Path) -> set:
    names = set()
    for raw in host_dir.glob("**/raw"):
        for root, _, files in os.walk(raw):
            names.update(files)
    return names


def collected(path: str, names: set) -> bool:
    base = path.rstrip("/").split("/")[-1].lstrip(".")
    return any(n == base or n.endswith("+" + base) or n.endswith("+." + base) or n.lstrip(".") == base for n in names)


def pair_hosts(out_dir: Path, acq_dir: Path) -> list:
    hosts = [d for d in sorted(out_dir.iterdir()) if d.is_dir() and (d / "artefacts").is_dir()]
    targets = [d for d in sorted(acq_dir.iterdir()) if (d / "expected.json").is_file()]
    pairs = []
    for t in targets:
        match = [h for h in hosts if h.name.lower() == t.name.lower()]
        if not match and len(hosts) == 1 and len(targets) == 1:
            match = hosts
        if match:
            pairs.append((match[0], t))
        else:
            print(f"  [!] no Elrond output for target {t.name}", file=sys.stderr)
    return pairs


def verify(host: Path, target: Path, techniques: set) -> list:
    expected = json.loads((target / "expected.json").read_text(encoding="utf-8-sig"))
    corpus, names = host_corpus(host), raw_names(host)
    cooked = host / "artefacts" / "cooked"
    yara_ran = table(host / "analysis", "yara")
    keywords_ran = table(host / "analysis", "keyword_matches")
    rows = []
    for item in expected.get("seeded", []):
        label = item.get("path") or item.get("artefact", "?")
        row = {"item": label}
        row["collected"] = collected(item["path"], names) if "path" in item else None
        row["cooked"] = table(cooked, item["cooked"]) if "cooked" in item else None
        attack = current_id(item["attack"]) if "attack" in item else None
        row["attack"] = (attack in techniques or attack.split(".")[0] in techniques) if attack else None
        if attack and row["attack"] and attack not in techniques:
            row["attack"] = "parent"
        # A technique only YARA gives (the web shell marker in a web root) can't be there without it
        if item.get("attack_by") == "yara" and not yara_ran and row["attack"] is False:
            row["attack"] = "not run"
        row["expect"] = [s for s in item.get("expect", []) if s.lower() not in corpus] if "expect" in item else None
        row["yara"] = ([r for r in item["yara"] if r.lower() not in corpus] if yara_ran else "not run") if "yara" in item else None
        row["keywords"] = ([k for k in item["keywords"] if k.lower() not in corpus] if keywords_ran else "not run") if "keywords" in item else None
        rows.append(row)
    # An IOC only in a seeded file's text (sync.ps1's download URL) is found by --extractIocs
    # alone; without it, a missing IOC wasn't looked for rather than missed
    missing = [i for i in expected.get("iocs", []) if i.lower() not in corpus]
    iocs_ran = table(host / "analysis", "iocs")
    rows.append({"item": "IOCs", "expect": missing if iocs_ran or not missing else "not run"})
    rows.append({"item": "JSON Lines format", "format": format_problems(host)})
    return rows


def cell(value) -> str:
    if value is None:
        return "-"
    if value is True or value == []:
        return "ok"
    if value is False:
        return "MISSING"
    if isinstance(value, list):
        return "MISSING: " + ", ".join(value)
    return str(value)


def failed(row: dict) -> bool:
    return any(v is False or (isinstance(v, list) and v) for k, v in row.items() if k != "item")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("output")
    parser.add_argument("acquisitions")
    parser.add_argument("--json", action="store_true", help="print the results as JSON")
    args = parser.parse_args()
    out_dir, acq_dir = Path(args.output), Path(args.acquisitions)
    techniques = {current_id(t) for t in read_text(out_dir / "mitre_techniques.txt").split()}
    results, bad = {}, 0
    for host, target in pair_hosts(out_dir, acq_dir):
        rows = verify(host, target, techniques)
        results[f"{target.name} ({host.name})"] = rows
        bad += sum(failed(r) for r in rows)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        cols = ("collected", "cooked", "attack", "expect", "yara", "keywords", "format")
        for name, rows in results.items():
            print(f"\n== {name}: {sum(not failed(r) for r in rows)}/{len(rows)} pass")
            for r in rows:
                marks = "  ".join(f"{c}={cell(r.get(c))}" for c in cols if r.get(c) is not None)
                print(f"  {'FAIL' if failed(r) else 'ok  '} {r['item'][:62]:62}  {marks}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
