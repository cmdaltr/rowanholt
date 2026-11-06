#!/usr/bin/env python3 -tt
import os
import re
import subprocess
import time
from datetime import datetime
from typing import Dict, List

from rowanholt.audit import write_audit_log_entry
from rowanholt.core.records import SUFFIX, write_records
from rowanholt.process.extractions.artemis import _record_techniques
from rowanholt.process.linux_artefacts import WEB_ROOTS, WEB_SCRIPTS
from rowanholt.utils import safe_input

# rule meta keys that carry ATT&CK technique IDs (attack = "T1059.001, T1105")
TECHNIQUE_META = re.compile(r'^\s*(?:attack|attack_id|mitre|mitre_att|mitre_attack|technique|techniques)\s*=\s*"([^"]*)"',
                            re.I | re.M)
TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
RULE = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+(\w+)", re.M)


def rule_techniques(yara_file):
    """{rule name: [technique IDs]} from each rule's meta section."""
    try:
        with open(yara_file, encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except OSError:
        return {}
    starts = [(m.start(), m.group(1)) for m in RULE.finditer(source)] + [(len(source), None)]
    techniques = {}
    for (start, name), (end, _) in zip(starts, starts[1:]):
        found = [t for value in TECHNIQUE_META.findall(source[start:end]) for t in TECHNIQUE_ID.findall(value)]
        if found:
            techniques[name] = found
    return techniques


YARA_FIELDS = ("yara_rule", "yara_file", "file", "path", "offset", "signature_name", "matched_data")


def match_techniques(row: Dict[str, str], by_rule: Dict[str, List[str]]) -> List[str]:
    """One yara table row's techniques: its rule's, and T1505.003 for a script in a web root."""
    found = list(by_rule.get(row["yara_rule"], []))
    if web_script(f"{row['path']}/{row['file']}"):
        found.append("T1505.003")
    return found


def web_script(path):
    """A script in a web root (flattened by Gandalf, or as found on a mounted image)."""
    name = path.split("/")[-1]
    lower = path.lower()
    in_root = name.startswith(WEB_ROOTS) or any("/" + r.replace("+", "/") in lower for r in WEB_ROOTS)
    return in_root and lower.endswith(WEB_SCRIPTS)


def validate_yara(verbosity, output_directory, img, yara_file, binary_dir):
    """Validate YARA rule file syntax before scanning."""
    # Validate syntax by scanning /dev/null - validates rules without actual scanning
    result = subprocess.run(
        ["yara", yara_file, "/dev/null"],
        capture_output=True,
        encoding="UTF-8",
    )

    if result.returncode != 0 and "error" in result.stderr.lower():
        error_msg = result.stderr if result.stderr else result.stdout
        print(f"    '{yara_file.split('/')[-1]}' error: {error_msg}")
        print("    Skipping this YARA file due to syntax errors.")
        return

    invoke_yara(verbosity, output_directory, img, yara_file, binary_dir)


def yara_rows(yara_output):
    """(rule, file, offset, string, data) rows from yara -s output, and the (rule, file) matches.
    A rule that matched on its condition alone (filesize, pe.*) prints no string lines; it still
    gets a row, with "-" for the string, where it used to be left out of the yara table."""
    rows, matched, current, had_strings = [], [], None, False
    for line in yara_output.split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith("0x") and line.count(":") >= 2 and current:
            offset, sig_name, data = line.split(":", 2)
            rows.append((*current, offset, sig_name.lstrip("$"), data.lstrip()))
            had_strings = True
            continue
        parts = line.split(" ", 1)
        if len(parts) == 2:
            if current and not had_strings:
                rows.append((*current, "-", "-", "-"))
            current, had_strings = (parts[0], parts[1]), False
            matched.append(current)
    if current and not had_strings:
        rows.append((*current, "-", "-", "-"))
    return rows, set(matched)


def invoke_yara(verbosity, output_directory, img, yara_file, binary_dir):
    """Run YARA rules against target directory and save results."""
    img_name = img.split("::")[0]
    yara_rule_name = yara_file.split("/")[-1]

    print(f"      Invoking '{yara_rule_name}' against '{img_name}', please stand by...")

    # Run YARA scan. -N: Linux images contain /dev/fd -> /proc/self/fd, which
    # resolves to yara's own fds (including the mount) and recurses forever.
    scan_dir = "/" + binary_dir.strip("/")
    result = subprocess.run(
        ["yara", "-r", "-N", "-s", "-w", yara_file, scan_dir],
        capture_output=True,
        text=True,
    )

    # Parse results - YARA output format: "rule_name file_path"
    # With -s flag, also shows: "offset:$string_name:matched_data"
    yara_output = result.stdout.strip()

    if not yara_output:
        print(f"       No evidence found based on '{yara_rule_name}'.")
        return

    rows, matched = yara_rows(yara_output)
    # A rule's meta can name the techniques it detects; any hit on a web-root script
    # is a likely web shell
    by_rule = rule_techniques(yara_file)
    records = []
    for rule, path, offset, sig_name, matched_data in rows:
        file_name, file_path = path.split("/")[-1], "/".join(path.split("/")[:-1])
        records.append(dict(zip(YARA_FIELDS, (rule, yara_file, file_name, file_path, offset, sig_name, matched_data))))
        entry = f"{datetime.now().isoformat()},{img_name},yara,rule '{rule}' (${sig_name}) matched in '{file_name}'\n"
        prnt = f" -> {datetime.now().isoformat().replace('T', ' ')} -> YARA rule '{rule}' matched in '{file_name}'"
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
    write_records(os.path.join(output_directory, img_name, "analysis", f"yara{SUFFIX}"), records, host=img_name,
                  artefact="yara", techniques=lambda row: match_techniques(row, by_rule))
    matches_found = len(rows)

    techniques = {t for rule, _ in matched for t in by_rule.get(rule, [])}
    if any(web_script(path) for _, path in matched):
        techniques.add("T1505.003")
    if techniques:
        _record_techniques(os.path.join(output_directory, "mitre_techniques.txt"), sorted(techniques))

    if matches_found > 0:
        print(f"       Found {matches_found} YARA matches.")
    else:
        print(f"       No string matches found for '{yara_rule_name}'.")


def run_yara_signatures(
    verbosity, output_directory, img, loc, collectfiles, yara_files
):
    if collectfiles:
        all_or_collected = safe_input("      Run Yara signatures against all files or just those collected for '{}'?\n      [A]ll  [C]ollected\t[A]ll ".format(
                img.split("::")[0]
            )
        )
    else:
        all_or_collected = "A"
    if all_or_collected != "A":
        binary_dir = output_directory + img.split("::")[0] + "/files"
    else:
        binary_dir = loc
    for yara_file in yara_files:
        validate_yara(verbosity, output_directory, img, yara_file, binary_dir)
