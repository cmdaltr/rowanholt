#!/usr/bin/env python3 -tt
import os
import plistlib
from datetime import datetime

from rowanholt.audit import write_audit_log_entry
from rowanholt.core.records import SUFFIX, write_records
from rowanholt.process.extractions.mitre_tagger import launchd_technique, tag_mitre_technique


def _plist_value(value):
    """Plist values as JSON: scalars as strings (as Elrond has always shown
    them), containers kept as containers."""
    if isinstance(value, dict):
        return {str(k): _plist_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plist_value(v) for v in value]
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def plist_record(plistdata):
    """One cooked plist record, plus the launchd fields analysis looks for:
    Process (Program), CommandLine (ProgramArguments) and Plist (Label)."""
    if not isinstance(plistdata, dict):
        return {"Values": _plist_value(plistdata)}
    record = {str(k): _plist_value(v) for k, v in plistdata.items()}
    if isinstance(plistdata.get("Program"), str):
        record["Process"] = plistdata["Program"].lower()
    arguments = plistdata.get("ProgramArguments")
    if isinstance(arguments, (list, tuple)):
        record["CommandLine"] = " ".join(str(a) for a in arguments).lower()
    if isinstance(plistdata.get("Label"), str):
        record["Plist"] = plistdata["Label"].lower()
    return record


def process_plist(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    table = (output_directory + img.split("::")[0] + "/artefacts/cooked" + vss_path_insert + "plists/"
             + artefact.split("/")[-1])
    if os.path.exists(table + SUFFIX):
        return
    try:
        with open(artefact, "rb") as plist:
            plistdata = plistlib.load(plist)
    except (plistlib.InvalidFileException, ValueError, OSError):
        return  # not a parseable plist
    entry, prnt = "{},{},{},'{}' plist file\n".format(
        datetime.now().isoformat(),
        vssimage.replace("'", ""),
        stage,
        artefact.split("/")[-1].split("+")[-1],
    ), " -> {} -> {} plist file '{}' from {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        artefact.split("/")[-1].split("+")[-1],
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    # A launch agent or daemon that isn't Apple's; not every plist on a Mac
    technique = launchd_technique(artefact, plistdata)
    raw = artefact.find("/artefacts/")
    write_records(table + SUFFIX, [plist_record(plistdata)], host=img.split("::")[0],
                  artefact="plists/" + artefact.split("/")[-1], source_path=artefact[raw + 1:] if raw >= 0 else artefact,
                  techniques=[technique] if technique else [])
    if technique:
        tag_mitre_technique(output_directory, img, "plist", technique)
