#!/usr/bin/env python3 -tt
"""Volatility 3 core functions for memory image processing."""
import os
import random
import re
import subprocess
import time
from zipfile import ZipFile

from rowanholt.memory.plugins import extract_memory_artefacts
from rowanholt.utils import safe_input


def get_volatility3_symbols_dir():
    """Get the Volatility 3 symbols directory path.

    Tries to find the volatility3 installation dynamically, with fallbacks
    for different Python versions and installation methods.

    Returns:
        Path to volatility3 symbols directory, or empty string if not found.
    """
    # Try to find volatility3 via Python import
    try:
        import volatility3
        vol3_path = os.path.dirname(volatility3.__file__)
        symbols_dir = os.path.join(vol3_path, "symbols")
        if os.path.exists(symbols_dir):
            return symbols_dir
    except ImportError:
        pass

    # Fallback: Check common installation paths
    common_paths = [
        "/usr/local/lib/python3.10/dist-packages/volatility3/symbols",
        "/usr/local/lib/python3.11/dist-packages/volatility3/symbols",
        "/usr/local/lib/python3.12/dist-packages/volatility3/symbols",
        "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols",  # Legacy
        "/usr/lib/python3/dist-packages/volatility3/symbols",
    ]

    for path in common_paths:
        if os.path.exists(path):
            return path

    return ""


def assess_volatility_choice(
    verbosity,
    output_directory,
    volchoice,
    volprefix,
    artefact,
    profile,
    mempath,
    memext,
    vssimage,
    memtimeline,
):
    """Extract memory artefacts using Volatility 3."""
    profile, vssmem = extract_memory_artefacts(
        verbosity,
        output_directory,
        "3",
        volprefix,
        artefact,
        profile,
        mempath,
        memext,
        vssimage,
        memtimeline,
        "volatility3",
    )
    return profile, vssmem


def dump_vol3_ziphex(d, profile, ziphexdump):
    """Dump Volatility 3 symbol table from hex-encoded zip."""
    with open(d + "/..profile.hex", "w") as profilehex:
        profilehex.write(ziphexdump)
    subprocess.call(
        [
            "xxd",
            "-plain",
            "-revert",
            d + "/..profile.hex",
            d + "/.profile.zip",
        ]
    )  # produce hexdump: xxd -p <file_name>
    if profile == "macOS":
        osdir = "mac"
    else:
        osdir = "linux"

    # Find the volatility3 symbols directory dynamically
    symbols_dir = get_volatility3_symbols_dir()
    if not symbols_dir:
        print("    Warning: Could not find Volatility 3 symbols directory")
        os.remove(d + "/..profile.hex")
        os.remove(d + "/.profile.zip")
        return

    if not os.path.exists(os.path.join(symbols_dir, osdir)):
        with ZipFile(d + "/.profile.zip") as vol3_symbols:
            vol3_symbols.extractall(symbols_dir)
    os.remove(d + "/..profile.hex")
    os.remove(d + "/.profile.zip")


def choose_custom_profile(volchoice):
    """Choose a custom Volatility 3 symbol table."""
    customready, waitingquotes = safe_input("     Ready? Yes(Y)/No(N)/Skip(S) [Y] ", default="y"), [
        "Ready when you are",
        "Take you time",
        "No rush",
        "No pressure",
        "Standing by",
        "Awaiting input",
    ]
    symbolorprofile, pattern = "symbol table", re.compile(
        r"\ [^\ ]+\ [A-Z][a-z]{2}\ [\d\ +]{2}\ [^\ ]+\ (.*)\.json",
        re.IGNORECASE,
    )

    # Find volatility3 symbols directory dynamically
    symbols_dir = get_volatility3_symbols_dir()
    if symbols_dir:
        ls_paths = [
            os.path.join(symbols_dir, "windows", "ntkrnlmp.pdb"),
            os.path.join(symbols_dir, "windows", "ntkrpamp.pdb"),
            os.path.join(symbols_dir, "windows", "tcpip.pdb"),
            os.path.join(symbols_dir, "mac"),
            os.path.join(symbols_dir, "linux"),
        ]
        # Filter to only existing paths
        ls_paths = [p for p in ls_paths if os.path.exists(p)]
    else:
        ls_paths = []

    if ls_paths:
        imported = str(
            re.findall(
                pattern,
                str(
                    subprocess.Popen(
                        ["ls", "-lah"] + ls_paths,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[0]
                ),
            )
        ).replace(".json.xz", "")
    else:
        imported = ""

    # Normalize to uppercase for comparison
    customready = customready.upper() if customready else "S"
    if customready != "Y" and customready != "N" and customready != "S":
        print("Invalid selection. You can select either Yes (Y), No (N) or Skip (S).")
        return choose_custom_profile(volchoice)
    else:
        if customready == "N":
            print("    OK. {}...".format(random.choice(waitingquotes)))
            time.sleep(5)
            return choose_custom_profile(volchoice)
        elif customready == "Y":
            customsymbolorprofile = process_custom_profile(
                imported, symbolorprofile, " you have just created:"
            )
            if "windows" in customsymbolorprofile:
                profileplatform = "Windows"
            elif "mac" in customsymbolorprofile:
                profileplatform = "macOS"
            else:
                profileplatform = "Linux"
            customprofile = "{}::{}".format(customsymbolorprofile, profileplatform)
        else:
            customprofile = "SKIPPED"
    return customprofile


def process_custom_profile(imported, symbolorprofile, customprofileinsert):
    """Process a custom Volatility 3 symbol table selection."""
    if customprofileinsert != "":
        customsymbolorprofile = safe_input("    If importing a Windows symbol table, enter 'Windows' otherwise please provide the name of the custom {}{} ".format(
                symbolorprofile, customprofileinsert
            )
        )
        if customsymbolorprofile != "Windows" and customsymbolorprofile not in str(
            imported
        ):
            print(
                "      Invalid {}. This {} does not match any which have been imported into volatility.".format(
                    symbolorprofile, symbolorprofile
                )
            )
            if len(imported) > 0:
                print(
                    "       These are the currently imported and selectable {}s: {}".format(
                        symbolorprofile, str(imported)[2:-2].replace("'", "")
                    )
                )
            else:
                print(
                    "      No valid {}s have been imported into volatility, please try again...".format(
                        symbolorprofile
                    )
                )
            customsymbolorprofile = process_custom_profile(
                imported, symbolorprofile, ":"
            )
    return customsymbolorprofile
