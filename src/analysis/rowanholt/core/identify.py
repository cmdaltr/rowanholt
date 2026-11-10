#!/usr/bin/env python3 -tt
import json
import os
import re
import time
from datetime import datetime

from rowanholt.audit import write_audit_log_entry
from rowanholt.meta import extract_metadata
from rowanholt.memory.memory import process_memory, identify_memory_profile
from rowanholt.utils import safe_input


# File to store memory image profile information for deferred processing
MEMORY_PROFILES_FILE = ".memory_profiles.json"


def save_memory_profile(output_directory, image_name, profile_info):
    """Save memory image profile information for later processing.

    Args:
        output_directory: Base output directory for the case
        image_name: Name of the memory image file
        profile_info: Dictionary containing profile data (platform, profile, volchoice, path, etc.)
    """
    # Normalize the output_directory path
    output_directory = output_directory.rstrip('/') + '/'
    profiles_path = os.path.join(output_directory, MEMORY_PROFILES_FILE)

    profiles = {}
    if os.path.exists(profiles_path):
        try:
            with open(profiles_path, "r") as f:
                profiles = json.load(f)
        except (json.JSONDecodeError, IOError):
            profiles = {}
    profiles[image_name] = profile_info
    try:
        with open(profiles_path, "w") as f:
            json.dump(profiles, f, indent=2)
    except Exception as e:
        print(f" -> {datetime.now().isoformat().replace('T', ' ')} -> ERROR saving memory profile: {e}")


def load_memory_profiles(output_directory):
    """Load saved memory image profiles.

    Args:
        output_directory: Base output directory for the case

    Returns:
        Dictionary of image_name -> profile_info
    """
    # Normalize the output_directory path
    output_directory = output_directory.rstrip('/') + '/'
    profiles_path = os.path.join(output_directory, MEMORY_PROFILES_FILE)

    if os.path.exists(profiles_path):
        try:
            with open(profiles_path, "r") as f:
                profiles = json.load(f)
            return profiles
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def print_identification(verbosity, output_directory, disk_image, osplatform):
    print("   Identified platform of '{}' for '{}'.".format(osplatform, disk_image))
    entry, prnt = "{},{},identified platform,{}\n".format(
        datetime.now().isoformat(),
        disk_image,
        osplatform,
    ), " -> {} -> identified platform of '{}' for '{}'".format(
        datetime.now().isoformat().replace("T", " "),
        osplatform,
        disk_image,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)


def identify_disk_image(verbosity, output_directory, disk_image, mount_location):
    if not mount_location.endswith("/"):
        mount_location = mount_location + "/"
    if len(os.listdir(mount_location)) > 0:
        if (
            "MFTMirr" in str(os.listdir(mount_location))
            or ("Bitmap" in str(os.listdir(mount_location)))
            or ("LogFile" in str(os.listdir(mount_location)))
            or ("Boot" in str(os.listdir(mount_location)))
            or ("Windows" in str(os.listdir(mount_location)))
        ):
            if "MSOCache" in str(os.listdir(mount_location)):
                windows_os = "Windows7"
            elif not os.path.isdir(mount_location + "Windows"):
                # NTFS but no Windows folder (a recovery or data volume; $Boot shows on every one)
                return disk_image
            elif "Windows" in str(os.listdir(mount_location)) or "Boot" in str(
                os.listdir(mount_location)
            ):
                if (
                    "BrowserCore" in str(os.listdir(mount_location + "Windows/"))
                    or "Containers" in str(os.listdir(mount_location + "Windows/"))
                    or "IdentityCRL" in str(os.listdir(mount_location + "Windows/"))
                ):
                    windows_os = "Windows Server 2022"
                elif (
                    "DsfrAdmin" in str(os.listdir(mount_location + "Windows/"))
                    and "WaaS" in str(os.listdir(mount_location + "Windows/"))
                    and "WMSysPr9.prx" in str(os.listdir(mount_location + "Windows/"))
                ):
                    windows_os = "Windows Server 2019"
                elif "InfusedApps" in str(os.listdir(mount_location + "Windows/")):
                    windows_os = "Windows Server 2016"
                elif "ToastData" in str(os.listdir(mount_location + "Windows/")):
                    windows_os = "Windows Server 2012R2"
                else:
                    windows_os = "Windows Server"
            else:
                windows_os = "Windows10"
            """
            else:
                windows_os = "Windows11"
            """
            print_identification(verbosity, output_directory, disk_image, windows_os)
            disk_image = disk_image + "::" + windows_os
        # macOS detection: Check for /Applications, /System, /Library (standard macOS layout)
        elif (
            "Applications" in str(os.listdir(mount_location))
            and "System" in str(os.listdir(mount_location))
            and "Library" in str(os.listdir(mount_location))
        ):
            print_identification(verbosity, output_directory, disk_image, "macOS")
            disk_image = disk_image + "::macOS"
        # APFS container detection: macOS in /root subdirectory (apfs-fuse mounts)
        elif (
            "root" in str(os.listdir(mount_location))
            and os.path.isdir(os.path.join(mount_location, "root"))
            and os.path.exists(os.path.join(mount_location, "root", "Applications"))
            and os.path.exists(os.path.join(mount_location, "root", "System"))
            and os.path.exists(os.path.join(mount_location, "root", "Library"))
        ):
            print_identification(verbosity, output_directory, disk_image, "macOS")
            disk_image = disk_image + "::macOS"
        # Linux detection: Check for standard Linux directories
        # /etc, /usr, /var are more reliable indicators than root+media
        elif (
            "etc" in str(os.listdir(mount_location))
            and "usr" in str(os.listdir(mount_location))
            and "var" in str(os.listdir(mount_location))
        ):
            # Verify it's not macOS (which also has etc, usr, var)
            if not (
                "Applications" in str(os.listdir(mount_location))
                and "System" in str(os.listdir(mount_location))
            ):
                print_identification(verbosity, output_directory, disk_image, "Linux")
                disk_image = disk_image + "::Linux"
        # Fallback: Original Linux detection for backwards compatibility
        elif "root" in str(os.listdir(mount_location)) and "media" in str(
            os.listdir(mount_location)
        ):
            print_identification(verbosity, output_directory, disk_image, "Linux")
            disk_image = disk_image + "::Linux"
    return disk_image


def identify_memory_image(
    verbosity,
    output_directory,
    flags,
    auto,
    metacollected,
    cwd,
    sha256,
    nsrl,
    f,
    ot,
    d,
    path,
    volchoice,
    vss,
    vssmem,
    memtimeline,
):
    """Identify memory image profile and save for later processing.

    This function only identifies the Volatility profile/symbol table for the memory
    image and saves it to the output directory. The actual memory processing
    (artefact extraction) is deferred to the processing phase via process_deferred_memory().
    """
    if not auto:
        wtm = safe_input("  Do you wish to process '{}'? Y/n [Y] ".format(f), default="y")
    else:
        wtm = "y"
    if wtm != "n":
        if not metacollected:
            extract_metadata(
                verbosity,
                output_directory,
                f,
                path,
                "metadata",
                sha256,
                nsrl,
            )
        entry, prnt = (
            "LastWriteTime,elrond_host,elrond_stage,elrond_log_entry\n",
            " -> {} -> created audit log file for '{}'".format(
                datetime.now().isoformat().replace("T", " "), f
            ),
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)

        # Identify the memory profile without processing
        symbolprofile = identify_memory_profile(
            output_directory,
            verbosity,
            d,
            f,
            path,
            volchoice,
        )

        # Determine platform from profile
        if "Win" in str(symbolprofile) or "win" in str(symbolprofile):
            memoryplatform = "Windows memory"
        elif (
            "macOS" == symbolprofile
            or "Mac" in str(symbolprofile)
            or "11." in str(symbolprofile)
            or "10." in str(symbolprofile)
        ):
            memoryplatform = "macOS memory"
        else:
            memoryplatform = "Linux memory"

        # Save profile info for deferred processing
        profile_info = {
            "profile": symbolprofile,
            "platform": memoryplatform,
            "volchoice": volchoice,
            "path": path,
            "mount_point": d,
            "vss": vss,
            "vssmem": vssmem,
            "memtimeline": memtimeline,
        }
        save_memory_profile(output_directory, f, profile_info)

        print("   Identified profile '{}' ({}) for '{}'. Processing deferred to processing phase.".format(
            symbolprofile, memoryplatform, f
        ))
        entry, prnt = "{},{},identified memory profile,{} ({})\n".format(
            datetime.now().isoformat(),
            f,
            symbolprofile,
            memoryplatform,
        ), " -> {} -> identified memory profile '{}' for '{}'".format(
            datetime.now().isoformat().replace("T", " "),
            symbolprofile,
            f,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)

        ot[d] = "{}::{}_{}".format(
            f,
            memoryplatform.replace(" ", "_").split("_")[1],
            memoryplatform.replace(" ", "_").split("_")[0],
        )
        if "02processing" not in str(flags):
            flags.append("02processing")
        os.chdir(cwd)
    else:
        print("    OK. '{}' will not be processed.\n".format(f))
    return ot


def process_deferred_memory(
    verbosity,
    output_directory,
    flags,
    d,
):
    """Process memory images that were identified in the identification phase.

    This function reads saved memory profile information and processes
    each memory image using its identified Volatility profile.
    """
    profiles = load_memory_profiles(output_directory)
    if not profiles:
        return

    print("\n  -> Processing {} deferred memory image(s)...".format(len(profiles)))

    for image_name, profile_info in profiles.items():
        print(" -> {} -> processing memory image '{}' with profile '{}'...".format(
            datetime.now().isoformat().replace("T", " "),
            image_name,
            profile_info.get("profile", "unknown")
        ))

        try:
            # Default to Volatility 3 if volchoice is empty or not set
            volchoice = profile_info.get("volchoice", "3") or "3"
            path = profile_info.get("path", "")
            mount_point = profile_info.get("mount_point", d)
            vss = profile_info.get("vss", False)
            vssmem = profile_info.get("vssmem", "")
            memtimeline = profile_info.get("memtimeline", False)
            profile = profile_info.get("profile", "")
            platform = profile_info.get("platform", "Windows memory")

            # Construct img in the format expected by process_memory: "filename::memory_Platform"
            # platform is like "Windows memory", "macOS memory", or "Linux memory"
            platform_parts = platform.replace(" ", "_").split("_")
            if len(platform_parts) >= 2:
                # Format: filename::memory_Windows (or memory_macOS, memory_Linux)
                img_with_platform = "{}::{}_{}".format(
                    image_name,
                    platform_parts[1],  # "memory"
                    platform_parts[0],  # "Windows"/"macOS"/"Linux"
                )
            else:
                # Fallback if platform format is unexpected
                img_with_platform = "{}::memory_Windows".format(image_name)

            # Process with Volatility 3 (only version supported)
            # Note: stage must be "processing" to match the expected value in process_memory()
            process_memory(
                output_directory,
                verbosity,
                mount_point,
                "processing",
                img_with_platform,
                path,
                "3",
                vss,
                vssmem,
                memtimeline,
            )

            print(" -> {} -> completed processing memory image '{}'".format(
                datetime.now().isoformat().replace("T", " "),
                image_name,
            ))

        except Exception as e:
            print(" -> {} -> ERROR processing memory image '{}': {}".format(
                datetime.now().isoformat().replace("T", " "),
                image_name,
                str(e)
            ))
            entry, prnt = "{},{},memory processing failed,{}\n".format(
                datetime.now().isoformat(),
                image_name,
                str(e),
            ), ""
            write_audit_log_entry(verbosity, output_directory, entry, prnt)

    if "02processing" not in str(flags):
        flags.append("02processing")


def parse_gandalf_host_info(first_line):
    """Host and platform from host.info's first line.

    Current collectors write '<host>::<platform>'. Older gandalf.sh archives hold
    `uname -a` ('Linux <host> ...') and older gandalf.py ones Python's
    "uname_result(system='Linux', node='<host>', ...)".
    """
    if "::" in first_line:
        gandalf_host, osplatform = first_line.split("::", 1)
        return gandalf_host, osplatform
    match = re.search(r"system='([^']*)', node='([^']*)'", first_line)
    if match:
        system, gandalf_host = match.groups()
    else:
        fields = first_line.split()
        if len(fields) < 2:
            raise ValueError("unrecognised Gandalf host.info: {!r}".format(first_line))
        system, gandalf_host = fields[0], fields[1]
    return gandalf_host, "macOS" if system == "Darwin" else system


def identify_gandalf_host(output_directory, verbosity, host_info_file):
    time.sleep(2)
    with open(host_info_file) as host_info:
        first_line = host_info.readline().strip()
    gandalf_host, osplatform = parse_gandalf_host_info(first_line)
    print_identification(verbosity, output_directory, gandalf_host, osplatform)
    return gandalf_host, osplatform
