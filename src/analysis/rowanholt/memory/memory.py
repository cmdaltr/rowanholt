#!/usr/bin/env python3 -tt
import os
import shutil
import subprocess
import time
from datetime import datetime

from rowanholt.audit import write_audit_log_entry
from rowanholt.memory.volcore import (
    assess_volatility_choice,
    dump_vol3_ziphex,
    choose_custom_profile,
    get_volatility3_symbols_dir,
)

# Try to import volatility3 profiles - they may not be installed
try:
    from rowanholt.memory.volatility3.Linux import Linux
    from rowanholt.memory.volatility3.macOS1 import macOS1
    from rowanholt.memory.volatility3.macOS2 import macOS2
except ImportError:
    Linux = None
    macOS1 = None
    macOS2 = None


def identify_memory_profile(
    output_directory,
    verbosity,
    d,
    image_filename,
    artefact_path,
    volchoice,
):
    """Identify the Volatility profile for a memory image without processing.

    This function uses Volatility to identify the OS/profile for a memory image
    but does NOT extract artefacts. It's used during the identification phase
    to save profile info for later processing.

    Args:
        output_directory: Base output directory for the case
        verbosity: Verbosity level
        d: Mount point directory
        image_filename: Name of the memory image file
        artefact_path: Path to the memory image artefact
        volchoice: Volatility version choice ("2.6", "3", or "both")

    Returns:
        The identified profile/symbol table name
    """
    try:
        print(f" -> {datetime.now().isoformat().replace('T', ' ')} -> identifying memory profile for '{image_filename}'")

        # Determine memory extension
        if artefact_path.endswith("hiberfil.sys"):
            memext = ".raw"
        else:
            memext = ""

        # Volatility 3 OS detection - try Windows first
        vol3oscheck = vol3_check_os(artefact_path, memext, "windows.info.Info")
        if (
            "Windows" in vol3oscheck
            and "windows" in vol3oscheck
            and "ntkrnl" in vol3oscheck
        ):
            return "Windows"

        banner_os = kernel_banner_os(d, artefact_path, memext)
        if banner_os:
            return banner_os

        # Check macOS
        if macOS1 is not None and macOS2 is not None:
            ziphexdump1, ziphexdump2 = macOS1(), macOS2()
            dump_vol3_ziphex(d, "macOS", ziphexdump1 + ziphexdump2)
            vol3oscheck = vol3_check_os(artefact_path, memext, "mac.list_files.List_Files")
            if "MacOS" in vol3oscheck and "/System/Library/" in vol3oscheck:
                return "macOS"

        # Check Linux
        if Linux is not None:
            ziphexdump = Linux()
            dump_vol3_ziphex(d, "Linux", ziphexdump)
        vol3oscheck = vol3_check_os(artefact_path, memext, "linux.elfs.Elfs")
        if "linux" in vol3oscheck and "sudo" in vol3oscheck:
            return "Linux"

        # Default to Windows if we can't detect
        return "Windows"

    except Exception as e:
        print(f" -> {datetime.now().isoformat().replace('T', ' ')} -> ERROR identifying memory profile: {e}")
        import traceback
        traceback.print_exc()
        # Always return a valid profile even on error
        return "Windows"


FIVE_LEVEL_MARK = b"NUMBER(pgtable_l5_enabled)=1"
FIVE_LEVEL_WARNING = (
    "uses 5-level page tables (LA57), which Volatility 3 can't translate: plugins that read "
    "kernel memory will return nothing or fail, so an empty result doesn't mean a clean host. "
    "Physical scans (linux.psscan) still work")


def five_level_paging(path):
    """Whether a Linux image's kernel ran with 5-level page tables, from its VMCOREINFO note.
    Read-only; False when the file can't be read."""
    import mmap

    try:
        with open(path, "rb") as image, mmap.mmap(image.fileno(), 0, access=mmap.ACCESS_READ) as data:
            return data.find(FIVE_LEVEL_MARK) != -1
    except (OSError, ValueError):
        return False


def kernel_banner_os(d, artefact, memext):
    """ "Linux" or "macOS" from the kernel banner in the image (writing that OS's bundled
    symbols as the other checks do), or "" when there's neither. The process-based checks need
    something that happens to be running (sudo for Linux): a Linux image without it was called
    Windows."""
    banners = vol3_check_os(artefact, memext, "banners.Banners")
    if "Linux version" in banners:
        if Linux is not None:
            dump_vol3_ziphex(d, "Linux", Linux())
        return "Linux"
    if "Darwin Kernel Version" in banners:
        if macOS1 is not None and macOS2 is not None:
            dump_vol3_ziphex(d, "macOS", macOS1() + macOS2())
        return "macOS"
    return ""


def vol3_check_os(artefact, memext, plugin):
    """Run Volatility 3 plugin to check OS type.

    Uses the vol.py wrapper script installed by Dockerfile.forensics.
    Falls back to 'vol' command if wrapper not found.
    """
    # Use the vol.py wrapper created by Dockerfile.forensics
    # This wrapper isolates Volatility 3 from elrond's PYTHONPATH
    vol_cmd = "/usr/local/bin/vol.py"
    if not os.path.exists(vol_cmd):
        # Fallback to 'vol' command (installed by pip)
        vol_cmd = "vol"

    try:
        proc = subprocess.Popen(
            [
                vol_cmd,
                "-f",
                artefact + memext,
                plugin,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = proc.communicate()
        vol3oscheck = str(stdout)[2:-1]

    except Exception as e:
        # If volatility fails, return empty string to fall through to defaults
        vol3oscheck = ""

    return vol3oscheck


def process_memory(
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
):
    """Process memory image using Volatility 3.

    Args:
        output_directory: Base output directory for the case
        verbosity: Verbosity level
        d: Mount point directory
        stage: Processing stage ("processing" or "identification")
        img: Image identifier in format "filename::memory_Platform"
        artefact: Full path to the memory image file
        volchoice: Volatility version (always "3" now)
        vss: Volume shadow copy flag
        vssmem: VSS memory info
        memtimeline: Memory timeline flag
    """
    if artefact.endswith("hiberfil.sys"):
        memext = ".raw"
    else:
        memext = ""

    # Build output paths based on stage
    if stage == "processing":
        if "vss" in artefact:
            mempath, volprefix, vssimage = (
                img.split("::")[0].split("/")[-1] + "/",
                "      ",
                "'"
                + img.split("::")[0]
                + "' ("
                + img.split("::")[1]
                .split("_")[1]
                .replace("vss", "volume shadow copy #")
                + ")",
            )
        else:
            mempath, volprefix, vssimage = (
                img.split("::")[0].split("/")[-1] + "/",
                "      ",
                "'" + img.split("::")[0] + "'",
            )
    else:
        # Handle case where img doesn't contain "::" (standalone memory image processing)
        img_name = img.split("::")[0] if "::" in img else img
        mempath, volprefix, vssimage = (
            artefact.split("/")[-1],
            "   ",
            "'" + img_name + "'",
        )

    # Volatility 3 processing
    vol3oscheck = vol3_check_os(artefact, memext, "windows.info.Info")
    windows = ("Windows" in vol3oscheck and "windows" in vol3oscheck and "ntkrnl" in vol3oscheck) or (
        vssmem and vssmem.startswith("Win"))
    banner_os = "" if windows else kernel_banner_os(d, artefact, memext)
    if windows:
        profile, profileplatform = "Windows", "Windows"
    elif banner_os:
        profile, profileplatform = banner_os, banner_os
    else:
        # Check if macOS profile helpers are available
        if macOS1 is not None and macOS2 is not None:
            profile, ziphexdump1, ziphexdump2 = "macOS", macOS1(), macOS2()
            dump_vol3_ziphex(d, profile, ziphexdump1 + ziphexdump2)
            vol3oscheck = vol3_check_os(artefact, memext, "mac.list_files.List_Files")
            if "MacOS" in vol3oscheck and "/System/Library/" in vol3oscheck:
                profileplatform = "macOS"
            else:
                # Check if Linux profile helper is available
                if Linux is not None:
                    profile, ziphexdump = "Linux", Linux()
                    dump_vol3_ziphex(d, profile, ziphexdump)
                profileplatform = "Linux"
                vol3oscheck = vol3_check_os(artefact, memext, "linux.elfs.Elfs")
                if "linux" in vol3oscheck and "sudo" in vol3oscheck:
                    pass
                else:
                    print(
                        "    elrond has identified that there is no available symbol table for this image.\n    You will need to create your own symbol table; information is provided in SUPPORT.md\n    Once you have created the symbol table and placed it in the respective directory (.../volatility3/volatility3/symbols[/windows/mac/linux]/), return to elrond."
                    )
                    time.sleep(5)
                    customprofile = choose_custom_profile(volchoice)
                    if customprofile != "SKIPPED" and customprofile != "S":
                        if "::Windows" in customprofile:
                            profileplatform = "Windows"
                        elif "::macOS" in customprofile:
                            profileplatform = "macOS"
                        else:
                            profileplatform = "Linux"
                        profile = customprofile.split("::")[0]
                    else:
                        profile, profileplatform = "", ""
        else:
            # Profile helpers not available, try Linux detection directly
            profileplatform = "Linux"
            profile = "Linux"
            if Linux is not None:
                ziphexdump = Linux()
                dump_vol3_ziphex(d, profile, ziphexdump)
            vol3oscheck = vol3_check_os(artefact, memext, "linux.elfs.Elfs")
            if "linux" in vol3oscheck and "sudo" in vol3oscheck:
                pass
            else:
                print(
                    "    elrond has identified that there is no available symbol table for this image.\n    You will need to create your own symbol table; information is provided in SUPPORT.md\n    Once you have created the symbol table and placed it in the respective directory (.../volatility3/volatility3/symbols[/windows/mac/linux]/), return to elrond."
                )
                time.sleep(5)
                customprofile = choose_custom_profile(volchoice)
                if customprofile != "SKIPPED" and customprofile != "S":
                    if "::Windows" in customprofile:
                        profileplatform = "Windows"
                    elif "::macOS" in customprofile:
                        profileplatform = "macOS"
                    else:
                        profileplatform = "Linux"
                    profile = customprofile.split("::")[0]
                else:
                    profile, profileplatform = "", ""

    # Clean up symbol table cache directories
    if os.path.exists(
        "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/__pycache__"
    ):
        shutil.rmtree(
            "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/__pycache__"
        )
    if os.path.exists(
        "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/__MACOSX"
    ):
        shutil.rmtree(
            "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/__MACOSX"
        )

    # Log identification results if not in processing stage
    if stage != "processing":
        if profile != "":
            entry, prnt = "{},identification,{},{} ({})\n".format(
                datetime.now().isoformat(),
                artefact.split("/")[-1],
                profileplatform,
                profile,
            ), " -> {} -> identified platform as '{}' for '{}'".format(
                datetime.now().isoformat().replace("T", " "),
                profileplatform,
                artefact.split("/")[-1],
            )
            print(
                "   Identified platform of '{}' for '{}'.".format(
                    profile, artefact.split("/")[-1]
                )
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
        else:
            entry, prnt = "{},identification,{},skipped\n".format(
                datetime.now().isoformat(),
                artefact.split("/")[-1],
            ), " -> {} -> identification of platform SKIPPED for '{}'".format(
                datetime.now().isoformat().replace("T", " "),
                artefact.split("/")[-1],
            )
            print(
                "   Identification SKIPPED for '{}'.".format(
                    artefact.split("/")[-1]
                )
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)

    # Extract memory artefacts if profile was identified
    if profile != "" and profileplatform != "":
        assess_volatility_choice(
            verbosity,
            output_directory,
            "3",  # Always use Volatility 3
            volprefix,
            artefact,
            profile,
            mempath,
            memext,
            vssimage,
            memtimeline,
        )

    # A Linux image with no process list is where 5-level page tables show; the image is read
    # for the kernel's note only then (a full read of a large image off a USB disk takes minutes)
    no_pslist = not any(
        os.path.exists(p) and os.path.getsize(p) > 0
        for p in (os.path.join(output_directory + mempath, name)
                  for name in ("memory_linux.pslist.PsList.json", "linux.pslist.PsList.json")))
    if profileplatform == "Linux" and no_pslist and five_level_paging(artefact + memext):
        entry, prnt = "{},processing,{},5-level page tables\n".format(
            datetime.now().isoformat(), artefact.split("/")[-1]
        ), " -> {} -> WARNING: '{}' {}".format(
            datetime.now().isoformat().replace("T", " "), artefact.split("/")[-1], FIVE_LEVEL_WARNING
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)

    return profile, vssmem
