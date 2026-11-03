import os
import re
import shutil
import subprocess
import time
from datetime import datetime

from dernvale.audit import write_audit_log_entry


def convert_plaso_timeline(verbosity, output_directory, stage, img):
    lineno = 0
    converted_count = 0
    skipped_count = 0
    with open(
        output_directory + img.split("::")[0] + "/artefacts/plaso_timeline.csv",
        "a",
    ) as plasocsv:
        plasocsv.write(
            "LastWriteTime,timestamp_desc,logsource,source_long,message,parser,display_name,tag,Message,Artefact\n"
        )
        with open("./.plaso/plaso_timeline.csvtmp", "r") as plasotmp:
            for eachline in plasotmp:
                if lineno != 0:
                    matches = re.findall(
                        r"^([^,]+),([^,]+,[^,]+,[^,]+),([^,]+),([^,]+),([^,]+),([^,]+)",
                        eachline,
                    )
                    if not matches:
                        # Line doesn't match expected format, skip it
                        skipped_count += 1
                        lineno += 1
                        continue
                    (
                        LastWriteTime,
                        timestamp_desc__logsource__source_long,
                        Message,
                        parser,
                        Artefact,
                        tag,
                    ) = matches[0]
                    if (
                        LastWriteTime != "0000-00-00T00:00:00"
                    ):  # removing all entries without timestamp to reduce size
                        plasocsv.write(
                            "{},{},{},{},{},{},{},{}\n".format(
                                LastWriteTime,
                                timestamp_desc__logsource__source_long,
                                Message,
                                parser,
                                Artefact,
                                tag,
                                Message.lower().replace("\\\\", "/").replace("\\", "/"),
                                Artefact.lower()
                                .replace("\\\\", "/")
                                .replace("\\", "/"),
                            )
                        )
                        converted_count += 1
                lineno += 1
    print(f"     Converted {converted_count} timeline entries ({skipped_count} skipped)")
    entry, prnt = "{},{},{},{}\n".format(
        datetime.now().isoformat(),
        img.split("::")[0],
        stage,
        img.split("::")[0],
    ), " -> {} -> {} '{}'".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        img.split("::")[0],
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)


PSTEAL_SOURCE_OPTIONS = ["--partitions", "all", "--volumes", "all", "--vss_stores", "none", "--unattended"]


def find_psteal():
    """Find the psteal.py script location."""
    # Try common locations
    candidates = [
        "/usr/local/bin/psteal.py",
        "/usr/local/bin/psteal",
        "/usr/bin/psteal.py",
        "/usr/bin/psteal",
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate

    # Try to find it via shutil.which
    psteal_path = shutil.which("psteal.py") or shutil.which("psteal")
    if psteal_path:
        return psteal_path

    # Try Python module path
    try:
        import plaso
        plaso_dir = os.path.dirname(plaso.__file__)
        psteal_script = os.path.join(plaso_dir, "scripts", "psteal.py")
        if os.path.exists(psteal_script):
            return psteal_script
    except ImportError:
        pass

    return None


def create_plaso_timeline(verbosity, output_directory, stage, img, d, timelineimage):
    print("\n    Creating timeline for {}...".format(timelineimage))
    entry, prnt = "{},{},{},commenced\n".format(
        datetime.now().isoformat(), timelineimage, stage
    ), " -> {} -> creating timeline for '{}'".format(
        datetime.now().isoformat().replace("T", " "), timelineimage
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)

    # Find psteal script
    psteal_path = find_psteal()
    if not psteal_path:
        error_msg = "ERROR: Plaso (psteal) not found. Timeline creation requires plaso to be installed."
        print(f"     {error_msg}")
        print("     Install plaso with: pip3 install plaso")
        entry = "{},{},{},failed - plaso not installed\n".format(
            datetime.now().isoformat(), timelineimage, stage
        )
        write_audit_log_entry(verbosity, output_directory, entry, f" -> {error_msg}")
        return False

    # Find the source image path - check directly in d or in subdirectories
    img_name = img.split("::")[0]
    timelineimagepath = None

    # First check if image is directly in source directory
    direct_path = os.path.join(d, img_name)
    if os.path.exists(direct_path):
        timelineimagepath = direct_path
    else:
        # Search in subdirectories
        for image_directory in os.listdir(d):
            subdir_path = os.path.join(d, image_directory)
            if os.path.isdir(subdir_path):
                potential_path = os.path.join(subdir_path, img_name)
                if os.path.exists(potential_path):
                    timelineimagepath = potential_path
                    break

    if timelineimagepath is None:
        error_msg = f"ERROR: Could not find source image '{img_name}' in '{d}'"
        print(f"     {error_msg}")
        entry = "{},{},{},failed - image not found\n".format(
            datetime.now().isoformat(), timelineimage, stage
        )
        write_audit_log_entry(verbosity, output_directory, entry, f" -> {error_msg}")
        return False

    print(
        "     Entering plaso to create timeline for '{}', please stand by...".format(
            timelineimage
        )
    )
    time.sleep(2)
    if os.path.exists(".plaso"):
        shutil.rmtree("./.plaso")
    os.mkdir(".plaso")
    os.chdir("./.plaso")

    # Build command - use python3 if psteal is a .py file, otherwise run directly
    if psteal_path.endswith('.py'):
        cmd = ["python3", psteal_path]
    else:
        cmd = [psteal_path]

    # Without a terminal psteal can't answer its own partition/volume prompts: it
    # read EOF and exited 0 with an empty CSV on any multi-partition image (E12).
    # Every partition and volume (LVM, APFS) is processed; shadow copies aren't,
    # as before (they were never reachable unattended either).
    cmd.extend(PSTEAL_SOURCE_OPTIONS + [
        "--source",
        timelineimagepath,
        "-o",
        "dynamic",
        "-w",
        "./plaso_timeline.csvtmp",
    ])

    # Run psteal with completely clean PYTHONPATH to avoid conflicts with elrond modules
    # Plaso has its own module paths and doesn't need PYTHONPATH
    env = os.environ.copy()
    env["PYTHONPATH"] = ""

    print(f"     Running: {' '.join(cmd)} (with clean PYTHONPATH)")
    psteal = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL)
    psteal.communicate()
    os.chdir("..")

    # Check if timeline was created
    timeline_tmp = "./.plaso/plaso_timeline.csvtmp"
    if psteal.returncode != 0 or not os.path.exists(timeline_tmp) or os.path.getsize(timeline_tmp) == 0:
        error_msg = "ERROR: Plaso failed to create timeline file (psteal exit {})".format(psteal.returncode)
        print(f"     {error_msg}")
        entry = "{},{},{},failed - no output\n".format(
            datetime.now().isoformat(), timelineimage, stage
        )
        write_audit_log_entry(verbosity, output_directory, entry, f" -> {error_msg}")
        if os.path.exists("./.plaso"):
            shutil.rmtree("./.plaso")
        return False

    convert_plaso_timeline(verbosity, output_directory, stage, img)
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    shutil.rmtree("./.plaso")
    return True
