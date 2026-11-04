#!/usr/bin/env python3 -tt
import subprocess
import os
from datetime import datetime

from rowanholt.audit import write_audit_log_entry


def extract_usn(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
):
    entry, prnt = "{},{},{},'{}' usn journal\n".format(
        datetime.now().isoformat(),
        vssimage.replace("'", ""),
        stage,
        artefact.split("/")[-1].split("_")[-1],
    ), " -> {} -> {} '{}' for {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        artefact.split("/")[-1].split("_")[-1],
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)

    # Check if USN journal file exists and is not empty
    # Skip processing if file is empty to avoid usn.py hanging
    if not os.path.exists(artefact):
        if verbosity != "":
            print(f"     Warning: USN journal file does not exist: {artefact}")
        return

    file_size = os.path.getsize(artefact)
    if file_size == 0:
        return

    # Use USN-Journal-Parser for $UsnJrnl parsing
    # usn.py command: usn.py --csv -f <file> -o <output>
    output_csv = (
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "journal_usn.csv"
    )

    try:
        # Add timeout to prevent infinite hangs (max 10 minutes for USN parsing)
        process = subprocess.Popen(
            [
                "usn.py",
                "--csv",
                "-f",
                artefact,
                "-o",
                output_csv,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            process.communicate(timeout=600)  # 10 minute timeout
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            if verbosity != "":
                print(f"     Warning: USN-Journal-Parser timed out after 10 minutes")
    except Exception as e:
        if verbosity != "":
            print(f"     Warning: USN-Journal-Parser failed: {e}")
