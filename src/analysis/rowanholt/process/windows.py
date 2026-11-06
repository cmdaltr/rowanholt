#!/usr/bin/env python3 -tt
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path

from rowanholt.audit import write_audit_log_entry
from rowanholt.core.records import SUFFIX, RecordsError, read_records, table_path, write_records
from rowanholt.memory.memory import process_memory
from rowanholt.process.extractions.clipboard import extract_clipboard
from rowanholt.process.extractions.registry.profile import extract_registry_profile
from rowanholt.process.extractions.registry.system import extract_registry_system
from rowanholt.process.extractions.usb import extract_usb
from rowanholt.process.extractions import artemis
from rowanholt.process.wmi_repository import wmi_subscriptions

# Track which prefetch directories have been processed to avoid duplicates
_processed_prefetch_dirs = set()


def process_mft(
    verbosity, vssimage, output_directory, img, artefact, vss_path_insert, stage
):
    """Process $MFT using Artemis (Rust-based forensic parser)"""
    # artefact is already the full path to the $MFT file
    mft_file_path = artefact

    # Always log MFT processing
    import sys
    print(
        " -> {} -> processing '$MFT' for {}".format(
            datetime.now().isoformat().replace("T", " "),
            vssimage
        )
    )
    sys.stdout.flush()

    if not os.path.exists(mft_file_path):
        print(
            " -> {} -> WARNING: $MFT file not found: {}".format(
                datetime.now().isoformat().replace("T", " "),
                mft_file_path
            )
        )
        return

    artemis.extract_mft(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        mft_file=mft_file_path,
    )


def process_usn(
    verbosity, vssimage, output_directory, img, artefact, vss_path_insert, stage
):
    """Process $UsnJrnl using Artemis (Rust-based forensic parser)"""
    # artefact is already the full path to the $UsnJrnl file
    usnjrnl_path = artefact

    # Always log USN Journal processing
    print(
        " -> {} -> processing '$UsnJrnl' for {}".format(
            datetime.now().isoformat().replace("T", " "),
            vssimage
        )
    )

    if not os.path.exists(usnjrnl_path):
        print(
            " -> {} -> WARNING: $UsnJrnl file not found: {}".format(
                datetime.now().isoformat().replace("T", " "),
                usnjrnl_path
            )
        )
        return

    # The $MFT collected beside it gives each entry its full path
    mft_path = os.path.join(os.path.dirname(usnjrnl_path), "$MFT")
    artemis.extract_usnjrnl(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        usnjrnl_file=usnjrnl_path,
        mft_file=mft_path if os.path.isfile(mft_path) else None,
    )


def process_usb(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
):
    entry, prnt = "{},{},{},'{}'\n".format(
        datetime.now().isoformat(), vssimage.replace("'", ""), stage, vss_path_insert
    ), " -> {} -> {} '{}' from {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        artefact.split("/")[-1],
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    with open(artefact, encoding="ISO-8859-1") as setupapi:
        setupdata = setupapi.read()
    extract_usb(
        output_directory,
        img,
        vss_path_insert,
        jsondict,
        jsonlist,
        setupdata,
    )


def process_shimcache(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage
):
    """Process Shimcache using Artemis (Rust-based forensic parser)"""
    # Always log shimcache processing
    print(
        " -> {} -> processing 'ShimCache' for {}".format(
            datetime.now().isoformat().replace("T", " "),
            vssimage
        )
    )

    system_hive = output_directory + img.split("::")[0] + "/artefacts/raw" + vss_path_insert + "registry/SYSTEM"
    if not os.path.exists(system_hive):
        print(
            " -> {} -> WARNING: SYSTEM hive not found: {}".format(
                datetime.now().isoformat().replace("T", " "),
                system_hive
            )
        )
        return

    artemis.extract_shimcache(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        system_hive=system_hive,
    )


def process_registry_system(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
):
    regjsonlist = []
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "registry/"
        + artefact.split("/")[-1]
        + ".jsonl"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "registry"
            )
        except:
            pass
        entry, prnt = "{},{},{},'{}' registry hive\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
            artefact.split("/")[-1],
        ), " -> {} -> {} registry hive '{}' from {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            artefact.split("/")[-1],
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        extract_registry_system(
            output_directory,
            img,
            vss_path_insert,
            artefact,
            jsondict,
            jsonlist,
            regjsonlist,
        )


def process_registry_profile(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
):
    regusr, regart = artefact.split("/")[-1].split("+")
    regjsonlist = []
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "/registry/"
        + regusr
        + "+"
        + regart
        + ".jsonl"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "/registry"
            )
        except:
            pass
        entry, prnt = "{},{},{},'{}' ({}) registry hive\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
            regart,
            regusr,
        ), " -> {} -> {} '{}' {} registry hive from {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            regusr,
            regart,
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        extract_registry_profile(
            output_directory,
            img,
            vss_path_insert,
            artefact,
            jsondict,
            jsonlist,
            regjsonlist,
            regusr,
            regart,
        )


def process_evtx(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
):
    """Process Windows Event Logs using Artemis (Rust-based forensic parser)"""
    # artefact is already the full path to the .evtx file
    evtx_file = artefact

    # Create output directory
    evt_output_dir = (
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "evt"
    )
    os.makedirs(evt_output_dir, exist_ok=True)

    # Always log event log processing
    evtx_name = artefact.split("/")[-1]
    print(
        " -> {} -> processing '{}' event log for {}".format(
            datetime.now().isoformat().replace("T", " "),
            evtx_name,
            vssimage
        )
    )

    if os.path.exists(evtx_file):
        artemis.extract_eventlogs(
            verbosity=verbosity,
            vssimage=vssimage,
            output_directory=output_directory,
            img=img,
            vss_path_insert=vss_path_insert,
            stage=stage,
            evtx_file=evtx_file,
        )
    else:
        print(
            " -> {} -> WARNING: event log file not found: {}".format(
                datetime.now().isoformat().replace("T", " "),
                evtx_file
            )
        )


def process_clipboard(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
):
    clipjsonlist = []
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "clipboard/"
        + artefact.split("/")[-1]
        + ".jsonl"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "clipboard"
            )
        except:
            pass
        extract_clipboard(
            verbosity,
            vssimage,
            output_directory,
            img,
            vss_path_insert,
            stage,
            artefact,
            jsondict,
            jsonlist,
            clipjsonlist,
        )


def collected_dir(output_directory, img, vss_path_insert, *names):
    """First existing directory among the collected raw artefacts: Gandalf
    writes prefetch/ and wmi/, the image collector prefetch/ and wbem/."""
    raw = output_directory + img.split("::")[0] + "/artefacts/raw" + vss_path_insert
    for name in names:
        if os.path.isdir(raw + name + "/"):
            return raw + name + "/"
    return None


def process_prefetch(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    mount_location,
):
    """Process Windows Prefetch files using Artemis (Rust-based forensic parser)"""
    prefetch_dir = collected_dir(output_directory, img, vss_path_insert, "prefetch") or "{}/Windows/Prefetch/".format(mount_location)

    # Create a unique key for this prefetch directory to avoid reprocessing
    prefetch_key = output_directory + img.split("::")[0] + vss_path_insert + "prefetch"
    if prefetch_key in _processed_prefetch_dirs:
        return
    _processed_prefetch_dirs.add(prefetch_key)

    # Always log prefetch processing
    print(
        " -> {} -> processing prefetch for '{}'".format(
            datetime.now().isoformat().replace("T", " "),
            vssimage
        )
    )

    if not os.path.exists(prefetch_dir):
        print(
            " -> {} -> WARNING: Prefetch directory not found: {}".format(
                datetime.now().isoformat().replace("T", " "),
                prefetch_dir
            )
        )
        return

    artemis.extract_prefetch(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        prefetch_dir=prefetch_dir,
    )


def process_wmi(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
):
    """Process WMI persistence using Artemis (Rust-based forensic parser)"""
    # WMI repository is typically at Windows/System32/wbem/Repository
    wmi_dir = collected_dir(output_directory, img, vss_path_insert, "wbem", "wmi")

    if not wmi_dir:
        return

    # Get specific file being processed for better logging
    artefact_name = artefact.split("/")[-1] if artefact else "OBJECTS.DATA"


    artemis.extract_wmipersist(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        wmi_dir=wmi_dir,
    )


def process_wbem(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
):
    """Process WBEM/WMI repository using Artemis (Rust-based forensic parser)"""
    print(f"    [DEBUG-WBEM] Entered process_wbem, verbosity={verbosity}, artefact={artefact}", flush=True)
    # WBEM is processed via wmipersist in Artemis - this is a wrapper for compatibility
    wbem_dir = collected_dir(output_directory, img, vss_path_insert, "wbem", "wmi")

    if not wbem_dir:
        print(f"    [DEBUG-WBEM] wbem_dir does not exist, returning", flush=True)
        return

    # Get specific file being processed for better logging
    artefact_name = artefact.split("/")[-1] if artefact else "OBJECTS.DATA"

    print(f"    [DEBUG-WBEM] About to call artemis.extract_wmipersist", flush=True)
    result = artemis.extract_wmipersist(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        wmi_dir=wbem_dir,
    )
    print(f"    [DEBUG-WBEM] artemis.extract_wmipersist returned: {result}", flush=True)
    carve_wmi_subscriptions(verbosity, vssimage, output_directory, img, vss_path_insert, stage, wbem_dir)
    print(f"    [DEBUG-WBEM] About to return from process_wbem", flush=True)


def carve_wmi_subscriptions(verbosity, vssimage, output_directory, img, vss_path_insert, stage, wbem_dir):
    """Carve event subscriptions from OBJECTS.DATA when Artemis found none
    (it can't parse Windows 11 repositories, E35)."""
    cooked = output_directory + img.split("::")[0] + "/artefacts/cooked" + vss_path_insert
    found = table_path(cooked, "wbem")
    try:
        if found.is_file() and next(read_records(found), None):
            return
    except (OSError, RecordsError):
        pass
    objects_data = os.path.join(wbem_dir, "OBJECTS.DATA")
    if not os.path.isfile(objects_data):
        return
    try:
        subscriptions = wmi_subscriptions(Path(objects_data))
    except OSError as e:
        print(" -> {} -> WARNING: could not carve WMI subscriptions: {}".format(
            datetime.now().isoformat().replace("T", " "), e
        ))
        return
    if not subscriptions:
        return
    raw = wbem_dir.find("/artefacts/")
    write_records(cooked + "wbem" + SUFFIX, subscriptions, host=img.split("::")[0], artefact="wbem",
                  source_path=os.path.join(wbem_dir[raw + 1:] if raw >= 0 else wbem_dir, "OBJECTS.DATA"),
                  techniques=lambda record: [] if "note" in record else ["T1546.003"])
    for record in subscriptions:
        if "note" in record:
            continue
        entry, prnt = "{},{},{},WMI event subscription '{}' -> '{}' ({})\n".format(
            datetime.now().isoformat(), vssimage.replace("'", ""), stage,
            record["filter_name"], record["consumer_name"], record["consumer_class"],
        ), " -> {} -> WMI event subscription '{}' -> {} '{}' for {}".format(
            datetime.now().isoformat().replace("T", " "), record["filter_name"],
            record["consumer_class"], record["consumer_name"], vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
    # Only a subscription Windows doesn't create itself is evidence of T1546.003
    if any("note" not in record for record in subscriptions):
        artemis.enrich_with_mitre(wbem_json, "wmipersist")


def process_sru(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    """Process SRUM database using Artemis (Rust-based forensic parser)"""
    # artefact is already the full path to SRUDB.dat
    srum_file = artefact

    # Always log SRUM processing
    print(
        " -> {} -> processing 'SRUM' for {}".format(
            datetime.now().isoformat().replace("T", " "),
            vssimage
        )
    )

    if not os.path.exists(srum_file):
        print(
            " -> {} -> WARNING: SRUM database not found: {}".format(
                datetime.now().isoformat().replace("T", " "),
                srum_file
            )
        )
        return

    artemis.extract_srum(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        srum_file=srum_file,
    )


def process_ual(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "ual/"
        + artefact.split("/")[-1]
        + ".jsonl"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "ual"
            )
        except:
            pass
        entry, prnt = "{},{},{},'{}' user access log \n".format(
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
        try:
            kstrike_list = str(
                subprocess.Popen(
                    [
                        "python3",
                        "/opt/elrond/elrond/tools/KStrike/KStrike.py",
                        artefact,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[0]
            )[2:-4].split("\\r\\n")
            if len(kstrike_list) > 1:
                header = kstrike_list[0][0:-4].split("||")
                rows = []
                for ual_entry in kstrike_list[1:]:
                    values = ual_entry[0:-4].split("||")
                    row = dict(zip(header, values))
                    row["LastWriteTime"] = ual_entry.split("||")[4] if len(values) > 4 else ""
                    rows.append(row)
                raw = artefact.find("/artefacts/")
                write_records(
                    output_directory + img.split("::")[0] + "/artefacts/cooked" + vss_path_insert + "ual/"
                    + artefact.split("/")[-1] + SUFFIX, rows, host=img.split("::")[0],
                    artefact="ual/" + artefact.split("/")[-1], source_path=artefact[raw + 1:] if raw >= 0 else artefact,
                    time_field="LastWriteTime")
        except KeyError as error:
            entry, prnt = "{},{},{},'{}' user access log [{}]\n".format(
                error,
                datetime.now().isoformat(),
                vssimage.replace("'", ""),
                stage,
                artefact.split("/")[-1].split("_")[-1],
            ), " -> {} -> {} '{}' experienced {} for {}".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                artefact.split("/")[-1].split("_")[-1],
                error,
                vssimage,
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)


def process_jumplists(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    """Process Windows Jumplists using Artemis (Rust-based forensic parser)"""
    # Always log jumplist processing
    print(
        " -> {} -> processing jumplist '{}' for {}".format(
            datetime.now().isoformat().replace("T", " "),
            artefact.split("/")[-1],
            vssimage,
        )
    )

    # artefact contains the path to the jumplist file
    if os.path.exists(artefact):
        artemis.extract_jumplists(
            verbosity=verbosity,
            vssimage=vssimage,
            output_directory=output_directory,
            img=img,
            vss_path_insert=vss_path_insert,
            stage=stage,
            jumplist_file=artefact,
        )
    else:
        print(
            " -> {} -> WARNING: Jumplist file not found: {}".format(
                datetime.now().isoformat().replace("T", " "),
                artefact
            )
        )


def process_outlook(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    """Process Outlook OST/PST files using Artemis (Rust-based forensic parser)"""

    # Artemis supports OST files; for PST we may need to keep readpst as fallback
    if artefact.lower().endswith('.ost') and os.path.exists(artefact):
        artemis.extract_outlook(
            verbosity=verbosity,
            vssimage=vssimage,
            output_directory=output_directory,
            img=img,
            vss_path_insert=vss_path_insert,
            stage=stage,
            ost_file=artefact,
        )
    elif artefact.lower().endswith('.pst') and os.path.exists(artefact):
        # Fallback to readpst for PST files
        (
            entry,
            prnt,
        ) = "{},{},{},'{}' ({}) outlook file\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
            artefact.split("/")[-1],
            artefact.split("/")[-2],
        ), " -> {} -> {} outlook file '{}' ({}) from {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            artefact.split("/")[-1],
            artefact.split("/")[-2],
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        if not os.path.exists(os.path.join(artefact.split(".pst")[0])):
            subprocess.Popen(
                [
                    "sudo",
                    "readpst",
                    artefact,
                    "-D",
                    "-S",
                    "-o",
                    "/".join(os.path.join(artefact.split(".pst")[0]).split("/")[:-1]),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()


def process_hiberfil(
    d,
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    volchoice,
    vss,
    vssmem,
    memtimeline,
):
    os.makedirs(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "memory"
    )
    profile, vssmem = process_memory(
        output_directory,
        verbosity,
        d,
        stage,
        img,
        artefact,
        volchoice,
        vss,
        vssmem,
        memtimeline,
    )
    return profile, vssmem


def process_pagefile(
    verbosity, vssimage, output_directory, img, vss_path_insert, artefact
):
    strings_file = (output_directory + img.split("::")[0] + "/artefacts/cooked" + vss_path_insert + "memory/"
                    + artefact.split("/")[-1] + ".strings")
    # Each paging file its own: the memory/ folder existing only meant the first one was done
    if not os.path.exists(strings_file):
        os.makedirs(os.path.dirname(strings_file), exist_ok=True)
        entry, prnt = "{},{},extracting strings,'{}'\n".format(
            datetime.now().isoformat(),
            vssimage,
            artefact.split("/")[-1],
        ), " -> {} -> extracting strings from '{}' from {}".format(
            datetime.now().isoformat().replace("T", " "),
            artefact.split("/")[-1],
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        # No shell, so ">>" never redirected anything: strings' output goes to the file itself
        with open(strings_file, "ab") as out:
            subprocess.Popen(["strings", artefact], stdout=out, stderr=subprocess.PIPE).communicate()
        (
            entry,
            prnt,
        ) = "{},{},extraction of strings complete,'{}'\n".format(
            datetime.now().isoformat(),
            vssimage,
            artefact.split("/")[-1],
        ), " -> {} -> extraction of strings from '{}' completed from {}".format(
            datetime.now().isoformat().replace("T", " "),
            artefact.split("/")[-1],
            vssimage,
        )
