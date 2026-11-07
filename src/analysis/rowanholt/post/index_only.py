"""Index a case Elrond has already processed into Splunk, Elastic and the ATT&CK Navigator, without
mounting, extracting or processing anything again (elrond.py --Index).

The hosts and their platforms come from the case folder: the audit log's "identified platform"
entries, else a Gandalf host's artefacts/host.info. Memory-only hosts aren't indexed this way.
"""

import os
from datetime import datetime
from typing import Dict, List, Tuple

from rowanholt.audit import write_audit_log_entry
from rowanholt.core.identify import parse_gandalf_host_info

AUDIT_LOG = "rowanholt_audit.log"


class IndexOnlyError(ValueError):
    """A folder with no processed hosts to index."""


def _audit_platforms(output_directory: str) -> Dict[str, str]:
    platforms: Dict[str, str] = {}
    audit = os.path.join(output_directory, AUDIT_LOG)
    if not os.path.isfile(audit):
        return platforms
    with open(audit, encoding="utf-8", errors="replace") as log:
        for line in log:
            parts = line.rstrip("\n").split(",", 3)
            if len(parts) == 4 and parts[2] == "identified platform" and parts[3]:
                platforms[parts[1]] = parts[3]  # the latest identification wins
    return platforms


def case_hosts(output_directory: str) -> Tuple[Dict[str, str], List[str]]:
    """allimgs for a processed case ({<host>/artefacts/raw: "<host>::<platform>"}, as the ingest
    registers them), and the host folders whose platform nothing records."""
    platforms = _audit_platforms(output_directory)
    allimgs: Dict[str, str] = {}
    unknown: List[str] = []
    for name in sorted(os.listdir(output_directory)):
        host_dir = os.path.join(output_directory, name)
        if name.startswith(".") or not os.path.isdir(os.path.join(host_dir, "artefacts", "cooked")):
            continue  # .previous/ (earlier extractions), files, and folders that aren't hosts
        platform = platforms.get(name, "")
        host_info = os.path.join(host_dir, "artefacts", "host.info")
        if not platform and os.path.isfile(host_info):
            with open(host_info, encoding="utf-8", errors="replace") as info:
                platform = parse_gandalf_host_info(info.readline().strip())[1]
        if platform:
            allimgs[os.path.join(host_dir, "artefacts", "raw")] = f"{name}::{platform}"
        else:
            unknown.append(name)
    return allimgs, unknown


def index_case(output_directory: str, case: str, verbosity: str, splunk: bool, elastic: bool,
               navigator: bool) -> List[str]:
    """Index the case's processed hosts; the targets that failed (each is tried, whatever the
    others do)."""
    from rowanholt.post.elastic.config import configure_elastic_stack
    from rowanholt.post.mitre.nav_config import configure_navigator
    from rowanholt.post.splunk.config import configure_splunk_stack

    output_directory = os.path.join(output_directory, "")  # the SIEM writers join onto a trailing /
    allimgs, unknown = case_hosts(output_directory)
    for name in unknown:
        print(f"   No platform recorded for '{name}'; not indexing it")
    if not allimgs:
        raise IndexOnlyError(f"no processed hosts in {output_directory} (a host folder holds artefacts/cooked/)")
    hosts = ", ".join(value.split("::")[0] for value in allimgs.values())
    print(f"   Indexing {len(allimgs)} processed host(s): {hosts}")

    failed: List[str] = []
    usercred = pswdcred = None
    if splunk:
        print("\n  -> \033[1;36mCommencing Splunk Phase...\033[1;m\n  ----------------------------------------")
        try:
            usercred, pswdcred = configure_splunk_stack(verbosity, output_directory, case, "splunk", allimgs)
        except Exception as error:  # report it and go on to the other targets
            print(f"     ERROR: Splunk indexing failed: {error}")
            failed.append("Splunk")
        print("  ----------------------------------------\n  -> Completed Splunk Phase.\n")
    if elastic:
        print("\n  -> \033[1;36mCommencing Elastic Phase...\033[1;m\n  ----------------------------------------")
        try:
            configure_elastic_stack(verbosity, output_directory, case, "elastic", allimgs)
        except Exception as error:
            print(f"     ERROR: Elastic indexing failed: {error}")
            failed.append("Elastic")
        print("  ----------------------------------------\n  -> Completed Elastic Phase.\n")
    if navigator:
        print("\n  -> \033[1;36mCommencing Navigator Phase...\033[1;m\n  ----------------------------------------")
        try:
            configure_navigator(verbosity, case, splunk, elastic, usercred, pswdcred, output_directory)
        except Exception as error:
            print(f"     ERROR: Navigator layer failed: {error}")
            failed.append("Navigator")
        print("  ----------------------------------------\n  -> Completed Navigator Phase.\n")

    targets = [t for t, on in (("Splunk", splunk), ("Elastic", elastic), ("Navigator", navigator)) if on]
    outcome = f"indexed into {', '.join(targets)}" + (f"; {', '.join(failed)} failed" if failed else "")
    write_audit_log_entry(
        verbosity, output_directory,
        f"{datetime.now().isoformat()},{case},index only,{outcome.replace(',', ';')} ({hosts.replace(',', ';')})\n",
        f" -> {datetime.now().isoformat().replace('T', ' ')} -> {outcome}, without processing again",
    )
    return failed
