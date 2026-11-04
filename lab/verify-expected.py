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
  cooked     the named cooked file exists
  attack     the technique ID is in mitre_techniques.txt ("not run" when only YARA gives it, attack_by)
  expect     every string appears somewhere in the host's output
  yara       every rule name appears in the output (skipped unless YARA ran)
  keywords   every keyword appears in the output (skipped unless keywords ran)
Exits 1 when any check fails.
"""
import argparse
import json
import os
import sys
from pathlib import Path

TEXT_SUFFIXES = (".csv", ".json", ".txt", ".log", ".tsv", ".audit")
MAX_TEXT_BYTES = 64 << 20


def read_text(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return ""
        return path.read_text(errors="ignore")
    except OSError:
        return ""


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
    yara_ran = (host / "analysis" / "yara.csv").exists()
    keywords_ran = (host / "analysis" / "keyword_matches.csv").exists()
    rows = []
    for item in expected.get("seeded", []):
        label = item.get("path") or item.get("artefact", "?")
        row = {"item": label}
        row["collected"] = collected(item["path"], names) if "path" in item else None
        row["cooked"] = (cooked / item["cooked"]).exists() if "cooked" in item else None
        row["attack"] = (item["attack"] in techniques or item["attack"].split(".")[0] in techniques) if "attack" in item else None
        if "attack" in item and row["attack"] and item["attack"] not in techniques:
            row["attack"] = "parent"
        # A technique only YARA gives (the web shell marker in a web root) can't be there without it
        if item.get("attack_by") == "yara" and not yara_ran and row["attack"] is False:
            row["attack"] = "not run"
        row["expect"] = [s for s in item.get("expect", []) if s.lower() not in corpus] if "expect" in item else None
        row["yara"] = ([r for r in item["yara"] if r.lower() not in corpus] if yara_ran else "not run") if "yara" in item else None
        row["keywords"] = ([k for k in item["keywords"] if k.lower() not in corpus] if keywords_ran else "not run") if "keywords" in item else None
        rows.append(row)
    iocs = expected.get("iocs", [])
    rows.append({"item": "IOCs", "expect": [i for i in iocs if i.lower() not in corpus]})
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
    techniques = set(read_text(out_dir / "mitre_techniques.txt").split())
    results, bad = {}, 0
    for host, target in pair_hosts(out_dir, acq_dir):
        rows = verify(host, target, techniques)
        results[f"{target.name} ({host.name})"] = rows
        bad += sum(failed(r) for r in rows)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        cols = ("collected", "cooked", "attack", "expect", "yara", "keywords")
        for name, rows in results.items():
            print(f"\n== {name}: {sum(not failed(r) for r in rows)}/{len(rows)} pass")
            for r in rows:
                marks = "  ".join(f"{c}={cell(r.get(c))}" for c in cols if r.get(c) is not None)
                print(f"  {'FAIL' if failed(r) else 'ok  '} {r['item'][:62]:62}  {marks}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
