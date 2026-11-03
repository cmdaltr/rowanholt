#!/usr/bin/env python3 -tt
import os
import re
import sys
import time
from collections import OrderedDict
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.process.process import determine_vss_image
from rivendell.process.process import process_artefacts
from rivendell.process.extra_artefacts import is_extra_artefact
from rivendell.process.linux_artefacts import is_linux_artefact
from rivendell.process.mac_artefacts import is_mac_artefact
from rivendell.utils import safe_listdir, safe_iterdir

# Gandalf's Windows collections beyond the core set (process/windows_artefacts.py)
WINDOWS_RAW_FOLDERS = re.compile(
    r"/artefacts/raw(?:/vss\d+)?/(?:recyclebin|tasks|startup|bits|search|defender|pca|wer|lnk|notepad)/"
)


def select_artefacts_to_process(img, process_list, artefacts_list, processed_artefacts):
    # Whole paths, not substrings: raw/SYSTEM is a prefix of raw/SYSTEM.LOG1, etc+sudoers of etc+sudoers.d+x
    seen = set(processed_artefacts)
    for each in process_list:
        file_count = 0
        for root, _, files in os.walk(each):
            for f in files:  # identifying artefacts for processing
                file_count += 1
                # Log progress every 20000 files to show it's not hanging
                if file_count % 20000 == 0:
                    print(f" -> {datetime.now().isoformat().replace('T', ' ')} -> ...scanned {file_count:,} files...")
                if (img.split("::")[0] in root) and (
                    root + "/" + f not in seen
                ): # ensure to check both the file (f) and the path (root) for specific matching strings
                    if (
                        f.endswith("MFT")
                        or f.endswith("LogFile")
                        or f.endswith("UsnJrnl")
                        or f.endswith("ObjId")
                        or f.endswith("Reparse")
                        or f.endswith("SAM")
                        or f.endswith("SECURITY")
                        or f.endswith("SOFTWARE")
                        or f.endswith("SYSTEM")
                        or f.endswith("NTUSER.DAT")
                        or f.endswith("UsrClass.dat")
                        or f.endswith(".evtx")
                        or f.endswith("ActivitiesCache.db")
                        or f.endswith("setupapi.dev.log")
                        or f.endswith("hiberfil.sys")
                        or f.endswith("MEMORY.DMP")
                        or f.endswith("pagefile.sys")
                        or f.endswith("swapfile.sys")
                        or f.endswith("-ms")
                        or f.endswith(".pf")
                        or f.endswith(".etl")
                        or f.endswith("OBJECTS.DATA")
                        or f.endswith(".mdb")
                        or f.endswith(".db")
                        or f.endswith(".bcf")
                        or f.endswith(".hve")
                        or f.endswith("SRUDB.dat")
                        or "/S-1-5-21-" in root + "/" + f
                        or f.endswith("+bash_aliases")
                        or f.endswith("+bash_history")
                        or f.endswith("+zsh_history")
                        or f.endswith("+bash_logout")
                        or f.endswith("+bashrc")
                        or f.endswith("crontab")
                        or f.endswith("group")
                        or f.endswith("hosts")
                        or "/journal/" in root
                        or f.endswith("passwd")
                        or f.endswith("shadow")
                        or f.endswith("log")
                        or "log.1" in f
                        or "__audit_" in f
                        or "+audit_" in f
                        or f.endswith(".plist")
                        or f.endswith(".conf")
                        or f.split("/")[-1].startswith("job.")
                        or f.endswith(".service")
                        or f.endswith(".target")
                        or f.endswith(".socket")
                        or "/raw/mail" in root + "/" + f
                        or "/raw/browsers" in root + "/" + f
                        or "/carved/" in root
                        or WINDOWS_RAW_FOLDERS.search(root + "/")
                        or is_linux_artefact(root + "/" + f)
                        or is_mac_artefact(root + "/" + f)
                        or is_extra_artefact(root + "/" + f)
                    ):
                        artefacts_list.append(each + ": " + root + "/" + f)
                        processed_artefacts.append(root + "/" + f)
                        seen.add(root + "/" + f)
        print(f" -> {datetime.now().isoformat().replace('T', ' ')} -> {file_count:,} files scanned, {len(artefacts_list):,} artefacts found")
    return artefacts_list


def select_pre_process_artefacts(
    output_directory,
    verbosity,
    d,
    flags,
    stage,
    cwd,
    imgs,
    vssimage,
    artefact,
    vssmem,
    volatility,
    volchoice,
    vss,
    memtimeline,
    collectfiles,
):
    stage = "processing"
    process_list, artefacts_list = [], []

    # Increase recursion limit for Volatility processing of memory artifacts (hiberfil.sys, etc.)
    # Volatility 3's plugin system has deep call stacks that exceed Python's default limit (1000)
    # Increased to 10000 after testing showed 5000 was insufficient
    original_recursion_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(10000)

    try:
        print(
            "\n\n  -> \033[1;36mCommencing Processing Phase...\033[1;m\n  ----------------------------------------"
        )
        time.sleep(1)
        imgs = OrderedDict(sorted(imgs.items(), key=lambda x: x[1]))
        processed_imgs, processed_artefacts = [], []
        for _, img in imgs.items():  # identifying artefacts and processing function
            # Extract basename for comparison since img may contain full path
            img_basename = img.split("::")[0].split("/")[-1]
            # Check if this is a memory image by looking at the type field (index 2)
            # Format: filename::mount_point::type (where type is 'disk' or 'memory')
            img_type = img.split("::")[2] if len(img.split("::")) > 2 else ""
            if img_basename not in processed_imgs and img_type != "memory":  # identifying artefacts for processing
                # Use safe_iterdir for macOS Docker VirtioFS filesystem compatibility
                for entry in safe_iterdir(output_directory):
                    each = entry.name
                    if each + "/" == output_directory or each == img_basename:
                        raw_path = os.path.join(output_directory, each, "artefacts", "raw")
                        for raw_entry in safe_iterdir(raw_path):
                            eachdir = raw_entry.name
                            if (
                                "vss" in eachdir
                                and os.path.isdir(
                                    os.path.realpath(
                                        output_directory
                                        + each
                                        + "/artefacts/raw/"
                                        + eachdir
                                    )
                                )
                                and not os.path.exists(
                                    output_directory
                                    + img_basename
                                    + "/artefacts/cooked/"
                                    + eachdir
                                )
                            ):
                                os.makedirs(
                                    output_directory
                                    + img_basename
                                    + "/artefacts/cooked/"
                                    + eachdir
                                )
                            elif not os.path.exists(
                                output_directory + img_basename + "/artefacts/cooked/"
                            ):
                                os.makedirs(
                                    output_directory
                                    + img_basename
                                    + "/artefacts/cooked/"
                                )
                        process_list.append(output_directory + each + "/artefacts/raw/")
                try:
                    os.remove(".temp.log")
                except:
                    pass
                artefacts_list = select_artefacts_to_process(
                    img, process_list, artefacts_list, processed_artefacts
                )  # identifying artefacts for processing
                if len(artefacts_list) == 0:
                    print(
                        "    No artefacts were collected for {}.\n    Please try again.\n\n".format(
                            img_basename
                        )
                    )
                processed_imgs.append(img_basename)
        for _, img in imgs.items():  # processing identified artefacts
            # Extract basename for display and path construction
            img_basename = img.split("::")[0].split("/")[-1]
            if "vss" in img.split("::")[1]:
                vssimage = (
                    "'"
                    + img_basename
                    + "' ("
                    + img.split("::")[1]
                    .split("_")[1]
                    .replace("vss", "volume shadow copy #")
                    + ")"
                )
            else:
                vssimage = "'" + img_basename + "'"
            print("    processing artefacts for {}...".format(vssimage), flush=True)
            entry, prnt = "{},{},{},commenced\n".format(
                datetime.now().isoformat(), vssimage.replace("'", ""), stage
            ), " -> {} -> {} artefacts for {}".format(
                datetime.now().isoformat().replace("T", " "), stage, vssimage
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            try:
                for each in artefacts_list:
                    ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
                    artefact = str(ia[0][1])
                    if not artefact.split("/")[-1].startswith(
                        "#"
                    ):  # processing primary image artefacts
                        try:
                            vssmem = determine_vss_image(
                                output_directory,
                                verbosity,
                                volatility,
                                d,
                                stage,
                                imgs,
                                img,
                                vssimage,
                                artefact,
                                vssmem,
                                volchoice,
                                vss,
                                memtimeline,
                                collectfiles,
                            )
                        except Exception as inner_e:
                            import traceback
                            print(f"\n{'='*70}", flush=True)
                            print(f"EXCEPTION IN determine_vss_image!", flush=True)
                            print(f"Exception Type: {type(inner_e).__name__}", flush=True)
                            print(f"Exception Message: {inner_e}", flush=True)
                            print(f"{'='*70}", flush=True)
                            print(f"Artefact: {artefact}", flush=True)
                            print(f"Image: {vssimage}", flush=True)
                            print(f"\nFull Traceback with all frames:", flush=True)
                            traceback.print_exc()
                            print(f"\nLocal variables:", flush=True)
                            print(f"  verbosity type: {type(verbosity)}, value: {repr(verbosity)}", flush=True)
                            print(f"  'verbose' in locals(): {'verbose' in locals()}", flush=True)
                            if 'verbose' in locals():
                                print(f"  verbose value: {repr(locals()['verbose'])}", flush=True)
                            print(f"{'='*70}\n", flush=True)
                            raise
            except RecursionError as e:
                import traceback
                print(f"\n{'='*70}", flush=True)
                print(f"RECURSION ERROR DETECTED!", flush=True)
                print(f"{'='*70}", flush=True)
                print(f"Artefact: {artefact if 'artefact' in locals() else 'unknown'}", flush=True)
                print(f"Image: {vssimage}", flush=True)
                print(f"\nFull Traceback:", flush=True)
                traceback.print_exc()
                print(f"{'='*70}\n", flush=True)
                # Write to audit log
                error_entry = f"{datetime.now().isoformat()},{vssimage.replace(chr(39), '')},processing,RECURSION_ERROR\n"
                write_audit_log_entry(verbosity, output_directory, error_entry, "")
                raise
            # below sections are for multi-paritied drives
            for each in artefacts_list:
                ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
                artefact = str(ia[0][1])
                if artefact.split("/")[-1].startswith(
                    "#1"
                ):  # processing secondary image artefacts
                    vssmem = determine_vss_image(
                        output_directory,
                        verbosity,
                        volatility,
                        d,
                        stage,
                        imgs,
                        img,
                        vssimage,
                        artefact,
                        vssmem,
                        volchoice,
                        vss,
                        memtimeline,
                        collectfiles,
                    )
            for each in artefacts_list:
                ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
                artefact = str(ia[0][1])
                if artefact.split("/")[-1].startswith(
                    "#2"
                ):  # processing tertiary image artefacts
                    vssmem = determine_vss_image(
                        output_directory,
                        verbosity,
                        volatility,
                        d,
                        stage,
                        imgs,
                        img,
                        vssimage,
                        artefact,
                        vssmem,
                        volchoice,
                        vss,
                        memtimeline,
                        collectfiles,
                    )
            for each in artefacts_list:
                ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
                artefact = str(ia[0][1])
                if artefact.split("/")[-1].startswith(
                    "#3"
                ):  # processing secondary, tertiary etc. image artefacts
                    vssmem = determine_vss_image(
                        output_directory,
                        verbosity,
                        volatility,
                        d,
                        stage,
                        imgs,
                        img,
                        vssimage,
                        artefact,
                        vssmem,
                        volchoice,
                        vss,
                        memtimeline,
                        collectfiles,
                    )
            for each in artefacts_list:
                ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
                artefact = str(ia[0][1])
                if artefact.split("/")[-1].startswith(
                    "#4"
                ):  # processing secondary, tertiary etc. image artefacts
                    vssmem = determine_vss_image(
                        output_directory,
                        verbosity,
                        volatility,
                        d,
                        stage,
                        imgs,
                        img,
                        vssimage,
                        artefact,
                        vssmem,
                        volchoice,
                        vss,
                        memtimeline,
                        collectfiles,
                    )
            for each in artefacts_list:
                ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
                artefact = str(ia[0][1])
                if artefact.split("/")[-1].startswith(
                    "#5"
                ):  # processing secondary, tertiary etc. image artefacts
                    vssmem = determine_vss_image(
                        output_directory,
                        verbosity,
                        volatility,
                        d,
                        stage,
                        imgs,
                        img,
                        vssimage,
                        artefact,
                        vssmem,
                        volchoice,
                        vss,
                        memtimeline,
                        collectfiles,
                    )
            for each in artefacts_list:
                ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
                artefact = str(ia[0][1])
                if artefact.split("/")[-1].startswith(
                    "#6"
                ):  # processing secondary, tertiary etc. image artefacts
                    vssmem = determine_vss_image(
                        output_directory,
                        verbosity,
                        volatility,
                        d,
                        stage,
                        imgs,
                        img,
                        vssimage,
                        artefact,
                        vssmem,
                        volchoice,
                        vss,
                        memtimeline,
                        collectfiles,
                    )
            for each in artefacts_list:
                ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
                artefact = str(ia[0][1])
                if artefact.split("/")[-1].startswith(
                    "#7"
                ):  # processing secondary, tertiary etc. image artefacts
                    vssmem = determine_vss_image(
                        output_directory,
                        verbosity,
                        volatility,
                        d,
                        stage,
                        imgs,
                        img,
                        vssimage,
                        artefact,
                        vssmem,
                        volchoice,
                        vss,
                        memtimeline,
                        collectfiles,
                    )
            for each in artefacts_list:
                ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
                artefact = str(ia[0][1])
                if artefact.split("/")[-1].startswith(
                    "#8"
                ):  # processing secondary, tertiary etc. image artefacts
                    vssmem = determine_vss_image(
                        output_directory,
                        verbosity,
                        volatility,
                        d,
                        stage,
                        imgs,
                        img,
                        vssimage,
                        artefact,
                        vssmem,
                        volchoice,
                        vss,
                        memtimeline,
                        collectfiles,
                    )
            for each in artefacts_list:
                ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
                artefact = str(ia[0][1])
                if artefact.split("/")[-1].startswith(
                    "#9"
                ):  # processing secondary, tertiary etc. image artefacts
                    vssmem = determine_vss_image(
                        output_directory,
                        verbosity,
                        volatility,
                        d,
                        stage,
                        imgs,
                        img,
                        vssimage,
                        artefact,
                        vssmem,
                        volchoice,
                        vss,
                        memtimeline,
                        collectfiles,
                    )
            if collectfiles:
                process_list.clear()
                if os.path.exists(
                    os.path.join(output_directory + img_basename + "/carved/")
                ):
                    print(
                        "\n      \033[1;33m{} carved files for {}...\033[1;m".format(
                            stage.title(), vssimage
                        )
                    )
                    process_list.append(
                        os.path.join(output_directory + img_basename + "/carved/")
                    )
                    artefacts_list.clear()
                    artefacts_list = select_artefacts_to_process(
                        img, process_list, artefacts_list, processed_artefacts
                    )
                    for each in artefacts_list:
                        ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
                        artefact = str(ia[0][1])
                        vssmem = process_artefacts(
                            output_directory,
                            verbosity,
                            volatility,
                            d,
                            stage,
                            imgs,
                            img,
                            vssimage,
                            "/",
                            artefact,
                            vssmem,
                            volchoice,
                            vss,
                            memtimeline,
                            collectfiles,
                        )
                    print(
                        "       \033[1;33mProcessed carved files for {}\n\033[1;m".format(
                            vssimage
                        )
                    )
            entry, prnt = "{},{},{},completed\n".format(
                datetime.now().isoformat(), vssimage.replace("'", ""), stage
            ), " -> {} -> processing completed for {}".format(
                datetime.now().isoformat().replace("T", " "), vssimage
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            print("  -> Completed Processing Phase for {}".format(vssimage))
            print()
            processed_imgs.append(img_basename)
        if "02processing" not in str(flags):
            flags.append("02processing")
        os.chdir(cwd)
    finally:
        # Restore original recursion limit (always executed, even if exception occurs)
        sys.setrecursionlimit(original_recursion_limit)

    # Note: "Completed Processing Phase" message is now printed in core.py
    # after deferred memory processing completes
    time.sleep(1)
