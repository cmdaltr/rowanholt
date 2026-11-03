"""
DEPRECATED: This module is no longer used.
EVTX processing has been moved to artemis.py which uses the Artemis forensic parser.

This file is kept for reference only and will be removed in a future version.
Use dernvale.process.extractions.artemis.extract_eventlogs() instead.
"""

import os
import subprocess
from datetime import datetime

from dernvale.audit import write_audit_log_entry

# DEPRECATED: Use Artemis for EVTX parsing instead
# This path points to old evtx_dump binary which is no longer installed
EVTX_DUMP_PATH = "/usr/local/bin/evtx_dump"


def extract_evtx(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
    evtjsonlist,
):
    """Extract EVTX using Rust-based evtx_dump with JSON output"""
    # Check if evtx_dump exists
    if not os.path.exists(EVTX_DUMP_PATH):
        entry, prnt = "{},{},{},'{}' event log (skipped - evtx_dump not found)\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
            artefact.split("/")[-1],
        ), " -> {} -> skipped '{}' event log for {} (evtx_dump not found at {})".format(
            datetime.now().isoformat().replace("T", " "),
            artefact.split("/")[-1],
            vssimage,
            EVTX_DUMP_PATH,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        return

    output_json_path = (
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "evt/"
        + artefact.split("/")[-1]
        + ".json"
    )

    entry, prnt = "{},{},{},'{}' event log\n".format(
        datetime.now().isoformat(),
        vssimage.replace("'", ""),
        stage,
        artefact.split("/")[-1],
    ), " -> {} {} event log for {}".format(
        stage,
        artefact.split("/")[-1],
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)

    evtx_file_path = (
        output_directory
        + img.split("::")[0]
        + "/artefacts/raw"
        + vss_path_insert
        + "evt/"
        + artefact.split("/")[-1]
    )

    # Run Rust evtx_dump with JSON lines output, writing directly to file
    # -o jsonl = JSON lines format (one JSON object per line)
    # -t 1 = single thread to preserve record order
    try:
        with open(output_json_path, 'w') as outfile:
            process = subprocess.Popen(
                [EVTX_DUMP_PATH, "-o", "jsonl", "-t", "1", evtx_file_path],
                stdout=outfile,
                stderr=subprocess.PIPE
            )
            _, stderr_data = process.communicate()

        if process.returncode != 0:
            stderr_text = stderr_data.decode('utf-8', errors='replace') if stderr_data else ''
            error_msg = stderr_text.replace('\n', ' ').replace(',', ';').replace("'", "")[:200]
            entry, prnt = "{},{},evtx_dump error,'{}'\n".format(
                datetime.now().isoformat(),
                vssimage.replace("'", ""),
                error_msg
            ), " -> {} -> evtx_dump failed for '{}': {}".format(
                datetime.now().isoformat().replace('T', ' '),
                artefact.split("/")[-1],
                error_msg[:100]
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)

    except Exception as e:
        entry, prnt = "{},{},evtx_dump exception,'{}'\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            str(e)[:200]
        ), " -> {} -> evtx_dump exception for '{}': {}".format(
            datetime.now().isoformat().replace('T', ' '),
            artefact.split("/")[-1],
            str(e)[:100]
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
