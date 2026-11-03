#!/usr/bin/env python3 -tt
import os
import re
import subprocess
import time
from datetime import datetime

from dernvale.audit import write_audit_log_entry
from dernvale.mount import ewf_raw

EWF_IMAGE = re.compile(r"\.(?:e|ex|l|lx|s)01$", re.I)


def carve_source(image_path):
    """What foremost reads: the image itself, or for an EWF image the raw media
    ewfmount exposes (carving the E01 container finds compressed chunks, E8).
    None when an EWF image's raw media isn't mounted."""
    if EWF_IMAGE.search(image_path):
        return ewf_raw(image_path)
    return image_path


def carve_files(output_directory, verbosity, d, artefact_directory, img, vssimage):
    print(
        "\n       \033[1;33mCarving files from unallocated space for {}...\033[1;m".format(
            vssimage
        )
    )
    source = carve_source(d + img.split("::")[0])
    if source is None:
        print("       Warning: '{}' isn't mounted as raw media; skipped carving it".format(img.split("::")[0]))
        entry, prnt = "{},{},{},skipped (EWF media not mounted)\n".format(
            datetime.now().isoformat(), vssimage.replace("'", ""), "carving"
        ), " -> {} -> skipped carving {}: EWF media not mounted".format(
            datetime.now().isoformat().replace("T", " "), vssimage
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        return
    subprocess.Popen(
        [
            "foremost",
            source,
            "-o",
            artefact_directory + "/carved",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    # foremost's audit.txt is kept: it records the input foremost scanned and
    # per-type counts, which is the only evidence of what carving covered.
    for eachdir in os.listdir(artefact_directory + "/carved"):
        if not os.path.isdir(artefact_directory + "/carved/" + eachdir):
            continue
        for eachfile in os.listdir(artefact_directory + "/carved/" + eachdir):
            print("     Successfully carved '{}' from {}".format(eachfile, vssimage))
            entry, prnt = "{},{},{},'{}'\n".format(
                datetime.now().isoformat(),
                vssimage.replace("'", ""),
                "carving",
                eachfile,
            ), " -> {} -> {} artefact '{}' for {}".format(
                datetime.now().isoformat().replace("T", " "),
                "carved",
                eachfile,
                vssimage,
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            time.sleep(0.1)

    entry, prnt = "{},{},{},completed\n".format(
        datetime.now().isoformat(), vssimage.replace("'", ""), "carving"
    ), " -> {} -> {} artefacts from {}".format(
        datetime.now().isoformat().replace("T", " "),
        "carved",
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    print(
        "       \033[1;33mCarved all available files, from {}\n\033[1;m".format(
            vssimage
        )
    )
