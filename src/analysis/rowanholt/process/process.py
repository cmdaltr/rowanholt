#!/usr/bin/env python3 -tt
import os
import re

from rowanholt.process.browser import process_browser_index
from rowanholt.process.browser import process_browser
from rowanholt.process.mac import process_plist
from rowanholt.process.linux import process_journal
from rowanholt.process.nix import is_shell_rc, process_bash_history, process_shell_rc
from rowanholt.process.nix import process_zsh_history
from rowanholt.process.nix import process_email
from rowanholt.process.nix import process_group
from rowanholt.process.nix import process_logs
from rowanholt.process.nix import process_service
from rowanholt.process.windows import process_clipboard
from rowanholt.process.windows import process_evtx
from rowanholt.process.windows import process_hiberfil
from rowanholt.process.windows import process_jumplists
from rowanholt.process.windows import process_mft
from rowanholt.process.windows import process_outlook
from rowanholt.process.windows import process_pagefile
from rowanholt.process.windows import process_prefetch
from rowanholt.process.windows import (
    process_registry_system,
)
from rowanholt.process.windows import process_registry_profile
from rowanholt.process.windows import process_shimcache
from rowanholt.process.windows import process_sru
from rowanholt.process.windows import process_ual
from rowanholt.process.windows import process_usb
from rowanholt.process.windows import process_usn
from rowanholt.process.windows import process_wbem
from rowanholt.process.windows import process_wmi
from rowanholt.process.extra_artefacts import process_extra_artefact
from rowanholt.process.linux_artefacts import process_linux_artefact
from rowanholt.process.mac_artefacts import process_mac_artefact
from rowanholt.process.windows_artefacts import process_windows_artefact
from rowanholt.core.records import SUFFIX, write_records

# A listing's first character, as `ls -l` on Windows (MKS) writes it
ITEM_TYPES = {"-": "file", "d": "directory", "l": "link", "b": "block-special", "c": "character-special",
              "n": "network", "p": "FIFO", "s": "socket", "D": "demand-recall", "E": "encrypted", "O": "offline",
              "S": "sparse"}


def process_artefacts(
    output_directory,
    verbosity,
    volatility,
    d,
    stage,
    imgs,
    img,
    vssimage,
    vss_path_insert,
    artefact,
    vssmem,
    volchoice,
    vss,
    memtimeline,
    collectfiles=True,
):
    from datetime import datetime
    jsondict = {}
    jsonlist = []
    img_name = img.split("::")[0]
    if img_name in artefact:
        # Skip macOS resource fork files (AppleDouble files starting with ._)
        # These are metadata files created by macOS, not actual forensic artefacts
        artefact_basename = os.path.basename(artefact)
        if artefact_basename.startswith("._"):
            return
        if artefact.endswith("setupapi.dev.log"):
            process_usb(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith("$MFT"):
            process_mft(
                verbosity,
                vssimage,
                output_directory,
                img,
                artefact,
                vss_path_insert,
                stage,
            )
        elif process_extra_artefact(
            verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
        ):
            pass  # thumbcache, $LogFile, PSReadLine, Amcache, cron, SSH, accounts, TCC, Biome, ASL, staged files
        elif process_windows_artefact(
            verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
        ):
            pass  # raw/<recyclebin|tasks|startup|bits|search|defender|pca|wer|lnk|notepad>/, hosts
        elif process_linux_artefact(
            verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
        ):
            pass  # raw/linux/, and the extra user_profiles/ histories
        elif process_mac_artefact(
            verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
        ):
            pass  # raw/macos/ (plists it doesn't parse fall through to process_plist)
        elif artefact.endswith("$UsnJrnl"):
            process_usn(
                verbosity,
                vssimage,
                output_directory,
                img,
                artefact,
                vss_path_insert,
                stage,
            )
        # Artemis writes shimcache.jsonl (shimcache.json before JSON Lines); ShimCache.csv was
        # the old parser's, so the check never matched and shimcache re-ran for every .SYSTEM
        elif artefact.endswith(".SYSTEM") and not any(os.path.exists(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + name
        ) for name in ("shimcache.jsonl", "shimcache.json")):
            process_shimcache(
                verbosity, vssimage, output_directory, img, vss_path_insert, stage
            )
        elif (
            artefact.endswith("SAM")
            or artefact.endswith("SECURITY")
            or artefact.endswith("SOFTWARE")
            or artefact.endswith("SYSTEM")
            and not artefact.endswith(".SYSTEM")
        ):
            process_registry_system(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith("+NTUSER.DAT") or artefact.endswith("+UsrClass.dat"):
            process_registry_profile(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith(".evtx"):
            process_evtx(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif "/prefetch" in artefact.lower():
            process_prefetch(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                re.findall(r"'([^']+)', '" + re.escape(img), str(imgs))[0],
            )
        elif artefact.endswith(("_ActivitiesCache.db", "+ActivitiesCache.db")):
            process_clipboard(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith(".etl"):
            process_wmi(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith("OBJECTS.DATA"):
            print(f"    [DEBUG-PROCESS] About to call process_wbem for {artefact}", flush=True)
            process_wbem(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
            print(f"    [DEBUG-PROCESS] process_wbem returned successfully", flush=True)
        elif artefact.endswith("SRUDB.dat"):
            process_sru(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif (
            artefact.endswith("Current.mdb")
            or artefact.endswith("SystemIdentity.mdb")
            or artefact.endswith("}}.mdb")
        ):
            process_ual(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif artefact.endswith("-ms") and "+" in artefact:
            process_jumplists(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif artefact.endswith(".pst"):
            process_outlook(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif artefact.endswith(".plist"):
            process_plist(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif artefact.endswith("zsh_history"):
            process_zsh_history(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif is_shell_rc(artefact):
            process_shell_rc(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif artefact.endswith("bash_history"):
            process_bash_history(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif artefact.endswith(".emlx"):
            process_email(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith("/group"):
            process_group(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif "journal" in artefact:
            process_journal(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif (
            artefact.endswith("log") or artefact.endswith("log.1")
        ) and "/logs/" in artefact:  # no year in DateTime field
            process_logs(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif (
            artefact.endswith(".service")
            or artefact.endswith(".target")
            or artefact.endswith(".socket")
            or artefact.endswith(".timer")
        ):
            process_service(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith("index.dat"):
            process_browser_index(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif (
            (
                artefact.endswith("History")
                and ("edge" in artefact.lower() or "chrome" in artefact.lower())
            )
            or (artefact.endswith("History.db") and "safari" in artefact)
            or ("places.sqlite" in artefact and "firefox" in artefact)
        ):
            process_browser(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif artefact.endswith("hiberfil.sys") and volatility:
            # TEMPORARY: Skip hiberfil.sys processing due to infinite recursion in Volatility
            # TODO: Investigate and fix Volatility recursion issue
            # See: docs/DEFERRED_MEMORY_PROCESSING.md for details
            print(f"      [WARNING] Skipping hiberfil.sys Volatility processing due to known recursion issue")
            print(f"      File collected but not processed: {artefact}")
            # if not os.path.exists(
            #     output_directory
            #     + img.split("::")[0]
            #     + "/artefacts/cooked"
            #     + vss_path_insert
            #     + "memory"
            # ):
            #     process_hiberfil(
            #         d,
            #         verbosity,
            #         vssimage,
            #         output_directory,
            #         img,
            #         vss_path_insert,
            #         stage,
            #         artefact,
            #         volchoice,
            #         vss,
            #         vssmem,
            #         memtimeline,
            #     )
        elif artefact.endswith("MEMORY.DMP") and volatility:
            pass
        elif (
            artefact.endswith("pagefile.sys") or artefact.endswith("swapfile.sys")
        ) and volatility:
            process_pagefile(
                verbosity, vssimage, output_directory, img, vss_path_insert, artefact
            )
        elif artefact.endswith("LastAccessTimes.txt"):
            with open(artefact, encoding="utf-8", errors="ignore") as last_access_times:
                access_times = last_access_times.read()
            rows = []
            for segment in access_times.split("\n\n"):
                lines = segment.split("\n")
                if len(lines) < 2:
                    continue
                directory, blocks = lines[0], lines[1]
                for line in lines[2:]:
                    metadata = re.findall(
                        r"^\s*(\d+)\s+([\-dlbcnpsDEOS])([rwxacsht\-\+]+)\s+(\d+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+(\d+)(?:,\s+\d+)?\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+([^\s]+)\s(.*)$",
                        line,
                    )
                    # https://www.mkssoftware.com/docs/man1/ls.1.asp
                    if not metadata or metadata[0][-1] in ('"."', '".."'):
                        continue
                    inode, kind, permissions, links, user, group, author, size, when, zone, name = metadata[0]
                    rows.append({
                        "Directory": directory, "Blocks": blocks, "Inode": inode, "Type": ITEM_TYPES.get(kind, kind),
                        # read (r), write (w), execute (x), archive (a), compressed (c), system (s), hidden (h), temporary (t)
                        "Permissions": permissions, "Links": links, "User": user, "Group": group, "Author": author,
                        "Size": size, "LastAccessTime": f"{when}{zone}", "Name": name,
                    })
            raw = artefact.find("/artefacts/")
            write_records(output_directory + img.split("::")[0] + "/artefacts/LastAccessTimes" + SUFFIX, rows,
                          host=img.split("::")[0], artefact="LastAccessTimes",
                          source_path=artefact[raw + 1:] if raw >= 0 else artefact, time_field="LastAccessTime")
    return vssmem


def determine_vss_image(
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
    collectfiles=True,
):
    from datetime import datetime
    if (
        "_vss" in img
        and "volume shadow c" in vssimage
        and "/vss" + vssimage[-2] in artefact
    ):
        vssmem = process_artefacts(
            output_directory,
            verbosity,
            volatility,
            d,
            stage,
            imgs,
            img,
            vssimage,
            "/"
            + vssimage.split("(")[1].replace("volume shadow copy #", "vss")[:-1]
            + "/",
            artefact,
            vssmem,
            volchoice,
            vss,
            memtimeline,
            collectfiles,
        )
    elif (
        "_vss" not in img
        and "volume shadow c" not in vssimage
        and "/vss" not in artefact
    ):
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
    return vssmem
