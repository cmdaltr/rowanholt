import os
import re
import subprocess
from datetime import datetime

from rowanholt.audit import write_audit_log_entry


def extract_shimcache(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage
):
    # Check if ShimCacheParser.py exists
    shimcache_parser = "/usr/local/bin/ShimCacheParser.py"
    if not os.path.exists(shimcache_parser):
        entry, prnt = "{},{},{},'ShimCache (skipped - parser not found)'\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
        ), " -> {} ShimCache for {} (skipped - ShimCacheParser.py not found)".format(
            stage,
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        return

    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + ".shimcache.csv",
        "a",
    ):
        entry, prnt = "{},{},{},'ShimCache'\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
        ), " -> {} ShimCache for {}".format(
            stage,
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        subprocess.Popen(
            [
                shimcache_parser,
                "-i",
                output_directory
                + img.split("::")[0]
                + "/artefacts/raw"
                + vss_path_insert
                + ".SYSTEM",
                "-o",
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + ".shimcache.csv",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + ".shimcache.csv",
        "r",
    ) as shimread:
        for shimline in shimread:
            winproc = str(
                re.findall(r"[^\,]+\,[^\,]+(\,[^\,]+).*", shimline)[0]
            ).lower()
            tempshimline = re.sub(
                r"([^\,]+\,[^\,]+)(\,[^\,]+)(.*)",
                r"\1\2\3_-_-_-_-_-_",
                shimline,
            )
            newshimline = tempshimline.replace("_-_-_-_-_-_", winproc)
            with open(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "shimcache.csv",
                "a",
            ) as shimwrite:
                shimwrite.write(
                    newshimline.replace("Last Modified", "LastWriteTime")
                    .replace(",path", ",Process")
                    .replace("\\", "/")
                )
    try:
        os.remove(
            output_directory
            + img.split("::")[0]
            + "/artefacts/raw"
            + vss_path_insert
            + ".SYSTEM"
        )
        os.remove(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + ".shimcache.csv"
        )
    except:
        pass
