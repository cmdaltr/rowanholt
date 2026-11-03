#!/usr/bin/env python3 -tt
import os
import random
import re
import shutil
import subprocess
import sys
import time
from collections import OrderedDict
from datetime import datetime

from rivendell.core.core import collect_process_keyword_analysis_timeline
from rivendell.audit import write_audit_log_entry
from rivendell.core.gandalf import assess_gandalf
from rivendell.core.identify import identify_memory_image
from rivendell.meta import extract_metadata
from rivendell.mount import mount_images
from rivendell.mount import unmount_images


def is_memory_image(filename, imgformat, filepath=None):
    """
    Detect if a file is a memory image rather than a disk image.

    Memory images are identified by:
    1. File extensions: .mem, .vmem, .dmp, .lime, .aff4 (definite memory)
    2. Filename patterns like -raw.001, -memory.001 (memory dump with split extension)
    3. File type output containing 'crash dump', 'Windows memory', 'MS Windows hibernation'
    4. For ambiguous extensions (.raw, .001, .bin under 32GB): return False to try mounting first
       - If mounting fails, the caller can fall back to memory processing

    Returns True if the file appears to be a memory image.
    """
    import re
    filename_lower = filename.lower()
    imgformat_lower = imgformat.lower() if imgformat else ""

    # Memory-specific extensions (definitive indicators)
    # Note: .raw is NOT included here as it's ambiguous (could be VMDK converted to raw, etc.)
    memory_extensions = ['.mem', '.vmem', '.dmp', '.lime', '.aff4', '.img', '.001']
    has_definite_memory_ext = any(filename_lower.endswith(ext) for ext in memory_extensions)

    # Check for patterns like -raw.001, -memory.001, -memdump.001, etc.
    # These are memory dumps that have been split or renamed
    memory_filename_patterns = ['-memory.', '-memdump.', '-mem.', '-physmem.']
    has_memory_pattern = any(pattern in filename_lower for pattern in memory_filename_patterns)

    # File type indicators for memory images (from 'file' command output)
    memory_format_indicators = ['crash dump', 'windows memory', 'ms windows hibernation']
    is_memory_format = any(indicator in imgformat_lower for indicator in memory_format_indicators)

    # Definite memory: has memory extension, memory pattern in filename, or file type indicates memory
    if has_definite_memory_ext or has_memory_pattern or is_memory_format:
        return True

    # For ambiguous extensions (.raw, .001, .bin), we return False to try mounting first
    # If mounting fails, the caller should fall back to treating it as a memory image
    # This approach is faster since mounting is quicker than Volatility profile detection

    return False


from rivendell.post.clean import archive_artefacts
from rivendell.post.clean import delete_artefacts
from rivendell.post.clean import cleanup_small_files_and_empty_dirs
from rivendell.post.clean import output_folder_name
from rivendell.post.clean import tidy_processed_output
from rivendell.post.elastic.config import configure_elastic_stack
from rivendell.post.mitre.nav_config import configure_navigator
from rivendell.post.splunk.config import configure_splunk_stack
from rivendell.post.yara import run_yara_signatures
from rivendell.utils import safe_input, is_noninteractive, safe_print


def main(
    directory,
    case,
    analysis,
    auto,
    collect,
    vss,
    delete,
    elastic,
    gandalf,
    collectfiles,
    extractiocs,
    iocsfile,
    misplaced_binaries,
    masquerading,
    keywords,
    volatility,
    metacollected,
    navigator,
    nsrl,
    magicbytes,
    hashall,
    hashcollected,
    process,
    splunk,
    symlinks,
    timeline,
    memorytimeline,
    userprofiles,
    veryverbose,
    verbose,
    yara,
    archive,
    d,
    cwd,
    sha256,
    allimgs,
    flags,
    elrond_mount,
    ewf_mount,
    system_artefacts,
    quotes,
    asciitext,
    skip_unmount=False,  # Skip unmounting previous images (for multi-image phased processing)
    phase=None,  # Phase control: "mount", "collect", "process", or None for full pipeline
    mounted_imgs=None,  # Pre-populated imgs dict from mount phase (for collect/process phases)
):
    partitions = []
    unmounted = []  # images found that no mount method could open (E9)
    hashing_enabled = hashall or hashcollected

    # Only clear screen in interactive mode
    if not is_noninteractive():
        subprocess.Popen(["clear"])
        time.sleep(2)
        print("\n\n    \033[1;36mElrond DFIR Analysis\033[1;m\n\n")
    if not collect and not gandalf:
        print(
            "\n  You MUST use the collect switch (-C) or gandalf switch (-G)\n   If you are processing acquired disk and/or memory images, you must invoke the collect switch (-C)\n   If you have previously collected artefacts having used gandalf, you must invoke the gandalf switch (-G)\n\n  Please try again.\n\n\n"
        )
        sys.exit(1)
    if collect and gandalf:
        print(
            "\n  You cannot use the collect switch (-C) and the collect gandalf (-G).\n   If you are processing acquired disk and/or memory images, you must invoke the collect switch (-C).\n   If you have previously collected artefacts using gandalf, you must invoke the gandalf switch (-G).\n\n  Please try again.\n\n\n"
        )
        sys.exit(1)
    if volatility and not process:
        print(
            "\n  If you are just processing memory images, you must invoke the process switch (-P) with the memory switch (-M).\n\n  Please try again.\n\n\n"
        )
        sys.exit(1)
    if (not collect or gandalf) and (
        vss or collectfiles or symlinks or timeline or userprofiles
    ):
        if gandalf:
            gandalforcollect = "gandalf switch (-G)"
        else:
            gandalforcollect = "collect switch (-C)"
        if (not collect or gandalf) and vss:
            collectand = "vss switch (-c)"
        elif (not collect or gandalf) and collectfiles:
            collectand = "collectfiles switch (-F)"
        elif (not collect or gandalf) and symlinks:
            collectand = "symlinks switch (-s)"
        elif (not collect or gandalf) and timeline:
            collectand = "timeline switch (-t)"
        elif (not collect or gandalf) and userprofiles:
            collectand = "userprofiles switch (-U)"
        if gandalf:
            # A Gandalf archive (or Mordor dataset) is collected already: nothing to collect from
            print(
                "\n\n  The {} can't be used with the {}: a Gandalf archive has nothing left to collect. Please try again.\n\n\n\n".format(
                    collectand, gandalforcollect
                )
            )
        else:
            print(
                "\n\n  In order to use the {}, you must also invoke the {}. Please try again.\n\n\n\n".format(
                    collectand, gandalforcollect
                )
            )
        sys.exit(1)
    if memorytimeline and not volatility:
        print(
            "\n\n  You cannot provide the memorytimeline switch (-t) without provided the Volatility switch (-M). Please try again.\n\n\n\n"
        )
        sys.exit(1)
    # Skip validation when in phased mode (mount/collect phases don't need process for analysis)
    if analysis and not process and phase not in ("mount", "collect"):
        print(
            "\n\n  You cannot provide the Analysis switch (-A) without provided the Processing switch (-P). Please try again.\n\n\n\n"
        )
        sys.exit(1)
    if nsrl and not hashing_enabled:
        print(
            "\n\n  The NSRL switch (-H) requires hashing. Enable either --hashAll or --hashCollected to proceed.\n\n\n\n"
        )
        sys.exit(1)
    if yara:
        if not os.path.isdir(yara[0]):
            print(
                "\n\n  '{}' is not a valid directory or does not exist. Please try again.\n\n\n\n".format(
                    yara[0]
                )
            )
            sys.exit(1)
    if keywords and not os.path.isfile(keywords[0]):
        # Checked later only after mounting and collection, hours in
        print(
            "\n\n  '{}' is not a keywords file or does not exist. Please try again.\n\n\n\n".format(
                keywords[0]
            )
        )
        sys.exit(1)
    starttime, ot, imgs, foundimgs, doneimgs, d, vssmem = (
        datetime.now().isoformat(),
        {},
        {},
        [],
        [],
        directory[0],
        "",
    )
    if (veryverbose and verbose) or veryverbose:
        verbosity = "veryverbose"
    elif verbose:
        verbosity = "verbose"
    else:
        verbosity = ""
    if collectfiles:
        if collectfiles != True:
            if len(collectfiles) > 0:
                if collectfiles.startswith("include:") or collectfiles.startswith("exclude:"):
                    # Path to inclusion/exclusion file
                    if not os.path.exists(collectfiles[8:]):
                        print(
                            "\n  [-F --collectfiles] - '{}' does not exist and/or is an invalid file, please try again.\n\n".format(
                                collectfiles[8:]
                            )
                        )
                        sys.exit(1)
                elif "," in collectfiles or re.match(r'^[a-zA-Z0-9]+$', collectfiles):
                    # Comma-separated extension list (e.g., "exe,dll,sys") or single extension
                    # This is valid - will be handled as inline extension filter
                    pass
                else:
                    print(
                        "\n  [-F --collectfiles] - invalid format. Use one of:\n"
                        "   1. No argument (collect all files)\n"
                        "   2. Comma-separated extensions: exe,dll,sys\n"
                        "   3. Path to include/exclude file: include:/path/to/file.txt\n"
                        "  Please try again.\n\n"
                    )
                    sys.exit(1)
    if yara:
        if not os.path.exists(yara[0]):
            print(
                "\n  [-Y --yara] - '{}' does not exist and/or is an invalid directory, please try again.\n\n".format(
                    yara[0]
                )
            )
            sys.exit(1)
    # apfs-fuse is now installed by default in the Docker container
    # No need to check or prompt for installation
    if os.path.exists("/opt/elrond/elrond/tools/.profiles"):
        os.remove("/opt/elrond/elrond/tools/.profiles")
    if len(directory) > 1:
        od = directory[-1]  # Last element is always the destination
        if not od.endswith("/"):
            od = od + "/"
        if not os.path.isdir(od):
            if not auto:
                make_od = safe_input(
                    "  You have specified an output directory that does not currently exist.\n    Would you like to create '{}'? Y/n [Y] ".format(
                        od
                    ),
                    default="y"
                )
            else:
                make_od = "y"
            if make_od != "n":
                try:
                    os.makedirs(od)
                    print(
                        "  '{}' has been created successfully.\n".format(
                            os.path.realpath(os.path.dirname(od) + "/")
                        )
                    )
                except PermissionError:
                    print(
                        "  A permissions error occured when creating '{}'.\n    Please try again as 'sudo'.\n  ----------------------------------------\n\n".format(
                            od
                        )
                    )
                    sys.exit(1)
                except Exception as e:
                    if "Input/output error" in str(e):
                        print(
                            "  An input/output error occured when trying to create '{}'.\n    Ensure the full path of '{}' is accessible.\n  ----------------------------------------\n\n".format(
                                od, od
                            )
                        )
                    else:
                        print(
                            "  An unknown error occured when trying to create '{}'.\n    Restart SIFT and try again.\n  ----------------------------------------\n\n".format(
                                od
                            )
                        )
                    sys.exit(1)
            else:
                print(
                    "\n    You have three choices:\n     -> Specify a directory that exists\n     -> Confirm creation of a specified directory\n     -> Provide no output directory (cwd is default)\n\n  Please try again.\n  ----------------------------------------\n\n"
                )
                sys.exit(1)
        output_directory = od
    else:
        output_directory = "./"

    # Handle case where d is a file path (e.g., /path/to/image.E01) instead of a directory
    # Track if we should process only a specific image file
    specific_image_file = None
    if os.path.isfile(d):
        # Remember the specific file to process
        specific_image_file = os.path.basename(d)
        # Extract directory from file path
        d = os.path.dirname(d)
        if not d:
            d = "./"
        elif not d.endswith("/"):
            d = d + "/"
        # Update directory array as well for consistency
        directory[0] = d

    if not os.path.isdir(d) or len(os.listdir(d)) == 0:
        print(
            "\n  [directory] - '{}' does not exist, is not a directory or is empty, please try again.\n\n".format(
                d
            )
        )
        sys.exit(1)
    elif not gandalf and len(os.listdir(d)) > 0 and (  # Gandalf directories hold host folders, not images
        ".e01" not in str(os.listdir(d)).lower()
        and ".vmdk" not in str(os.listdir(d)).lower()
        and ".dd" not in str(os.listdir(d)).lower()
        and ".raw" not in str(os.listdir(d)).lower()
        and ".img" not in str(os.listdir(d)).lower()
        and ".001" not in str(os.listdir(d)).lower()
    ):
        print(
            "\n  [directory] - '{}' does not contain any valid files (.E01/.VMDK/.dd/.raw/.img/.001)\n   for elrond to assess.\n   Please ensure you are referencing the correct directory path and try again.\n\n\n".format(
                d
            )
        )
        sys.exit(1)
    # Unmount any previously mounted images (unless in multi-image phased mode)
    if not skip_unmount:
        unmount_images(elrond_mount, ewf_mount)
    if volatility:
        # Always use Volatility3 (installed by default in Docker container)
        volchoice = "3"
        if memorytimeline:
            memtimeline = memorytimeline
        else:
            memtimeline = ""
    else:
        volchoice = ""
        memtimeline = ""
    # PHASE CONTROL: Skip mounting if in collect/process/analyse/index phase (images already mounted)
    if phase in ("collect", "process", "analyse", "index") and mounted_imgs:
        print("  -> Using pre-mounted images from mount phase.")
        allimgs = mounted_imgs.get("allimgs", {})
        imgs = mounted_imgs.get("imgs", {})
        output_directory = mounted_imgs.get("output_directory", output_directory)
        partitions = mounted_imgs.get("partitions", [])
        # Set f and path from the source (d parameter contains the image path)
        if specific_image_file:
            f = specific_image_file
        else:
            f = os.path.basename(d.rstrip('/'))
        path = d
        # Set appropriate stage for each phase
        if phase == "collect":
            stage = "collecting"
        elif phase == "process":
            stage = "processing"
        elif phase == "analyse":
            stage = "analysing"
        elif phase == "index":
            stage = "indexing"
        else:
            stage = "processing"
        # Skip to collection/processing
    else:
        # Only print phase start in legacy (non-phased) mode - elrond.py handles phase announcements
        if phase is None:
            safe_print(
                "\n  -> \033[1;36mCommencing Identification Phase...\033[1;m\n  ----------------------------------------"
            )
            print(" -> {} -> starting image mounting and identification...".format(
                datetime.now().isoformat().replace("T", " ")
            ))
            time.sleep(1)
    if collect and phase not in ("collect", "process", "analyse", "index"):  # collect artefacts from disk/memory images (mount phase)
        # If a specific image file was provided, only iterate top-level directory
        # and only process that file (skip subdirectories which may contain
        # artefacts from previous jobs)
        if specific_image_file:
            # Only process files in the top-level directory, not subdirectories
            files_to_process = [(d, [specific_image_file])]
        else:
            # Walk the entire directory tree (legacy behavior for directory input)
            files_to_process = [(root, files) for root, _, files in os.walk(d)]

        for root, files in files_to_process:  # Mounting images
            for f in files:
                if os.path.exists(os.path.join(root, f)):  # Mounting images
                    if (
                        ".FA" not in f
                        and ".FB" not in f
                        and ".FC" not in f
                        and ".FD" not in f
                        and ".FE" not in f
                        and ".FF" not in f
                        and ".FG" not in f
                        and ".FH" not in f
                        and ".FI" not in f
                        and ".FJ" not in f
                        and ".FK" not in f
                        and ".FL" not in f
                        and ".FM" not in f
                        and ".FN" not in f
                        and ".FO" not in f
                        and ".FP" not in f
                        and ".FQ" not in f
                        and ".FR" not in f
                        and ".FS" not in f
                        and ".FT" not in f
                        and ".FU" not in f
                        and ".FV" not in f
                        and ".FW" not in f
                        and ".FX" not in f
                        and ".FY" not in f
                        and ".FZ" not in f
                        and (
                            (
                                f.split(".E")[0] + ".E" not in str(foundimgs)
                                and f.split(".e")[0] + ".e" not in str(foundimgs)
                            )
                            and (
                                f.split(".F")[0] + ".F" not in str(foundimgs)
                                and f.split(".f")[0] + ".f" not in str(foundimgs)
                            )
                        )
                    ):
                        path, imgformat, fsize = (
                            os.path.join(root, f),
                            str(
                                subprocess.Popen(
                                    ["file", os.path.join(root, f)],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                ).communicate()[0]
                            )[2:-3].split(": ")[1],
                            os.stat(os.path.join(root, f)).st_size,
                        )
                        if fsize > 1073741824:  # larger than 1GB
                            if not os.path.isdir(output_directory + f):
                                try:
                                    os.mkdir(os.path.join(output_directory, f))
                                    foundimgs.append(
                                        os.path.join(root, f)
                                        + "||"
                                        + root
                                        + "||"
                                        + f
                                        + "||"
                                        + imgformat
                                    )
                                except PermissionError:
                                    print(
                                        "\n    '{}' could not be created. Are you running as root?".format(
                                            os.path.join(output_directory, f)
                                        )
                                    )
                                    sys.exit()
                            else:
                                print(
                                    "\n    '{}' already exists in '{}'\n     Please remove it before trying again.\n\n\n".format(
                                        f, output_directory
                                    )
                                )
                                sys.exit()
        for (
            foundimg
        ) in (
            foundimgs
        ):  # potentially add ova and vdi - https://superuser.com/questions/915615/mount-vmware-disk-images-under-linux
            stage = "mounting"
            path, root, f, imgformat = foundimg.split("||")

            # Check if this is a memory image
            # Note: 'path' is already the full filepath from foundimg.split("||")
            if is_memory_image(f, imgformat, path):
                # Memory image detected - always process with Volatility
                # (regardless of whether Memory option was explicitly checked)
                print(" -> {} -> identified '{}' as memory image, will save profile for deferred processing".format(
                    datetime.now().isoformat().replace("T", " "), f
                ))
                if hashing_enabled:
                    if not os.path.exists(output_directory + f + "/meta_audit.log"):
                        with open(
                            output_directory + f + "/meta_audit.log", "w"
                        ) as metaimglog:
                            metaimglog.write(
                                "Filename,SHA256,known-good,Entropy,Filesize,LastWriteTime,LastAccessTime,LastInodeChangeTime,Permissions,FileType\n"
                            )
                    with open(path, "rb") as metaimg:
                        buffer = metaimg.read(262144)
                        while len(buffer) > 0:
                            sha256.update(buffer)
                            buffer = metaimg.read(262144)
                        metaentry = (
                            path
                            + ","
                            + sha256.hexdigest()
                            + ",unknown,N/A,N/A,N/A,N/A,N/A,N/A,N/A\n"
                        )
                    with open(output_directory + f + "/meta_audit.log", "a") as metaimglog:
                        metaimglog.write(metaentry)
                    extract_metadata(
                        verbosity,
                        output_directory,
                        f,
                        path,
                        "metadata",
                        sha256,
                        nsrl,
                    )
                ot = identify_memory_image(
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
                )
                for mempath, memimg in ot.items():
                    allimgs[memimg] = mempath
                allimgs = OrderedDict(sorted(allimgs.items(), key=lambda x: x[1]))
                print()
                continue  # Skip to next image (don't try to mount memory images)

            # Print mounting message so UI shows progress during long mount operations
            print(" -> {} -> mounting '{}' ...".format(
                datetime.now().isoformat().replace("T", " "), f
            ))
            if (
                "Expert Witness" in imgformat
                or (
                    "VMDK" in imgformat
                    or ("VMware" and " disk image" in imgformat)
                    and (f.endswith(".vmdk"))
                )
                or (
                    "DOS/MBR boot sector" in imgformat
                    and (f.endswith(".raw") or f.endswith(".dd") or f.endswith(".img"))
                )
            ):
                time.sleep(2)
                if not auto:
                    wish_to_mount = safe_input(
                        "  Do you wish to mount '{}'? Y/n [Y] ".format(f),
                        default="y"
                    )
                else:
                    wish_to_mount = "y"
                if wish_to_mount != "n":
                    if hashing_enabled:
                        if not os.path.exists(output_directory + f + "/meta_audit.log"):
                            with open(
                                output_directory + f + "/meta_audit.log", "w"
                            ) as metaimglog:
                                metaimglog.write(
                                    "Filename,SHA256,NSRL,Entropy,Filesize,LastWriteTime,LastAccessTime,LastInodeChangeTime,Permissions,FileType\n"
                                )
                        with open(path, "rb") as metaimg:
                            buffer = metaimg.read(262144)
                            while len(buffer) > 0:
                                sha256.update(buffer)
                                buffer = metaimg.read(262144)
                            metaentry = (
                                path
                                + ","
                                + sha256.hexdigest()
                                + ",unknown,N/A,N/A,N/A,N/A,N/A,N/A,N/A\n"
                            )
                        with open(
                            output_directory + f + "/meta_audit.log", "a"
                        ) as metaimglog:
                            metaimglog.write(metaentry)
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
                    print("   Attempting to mount '{}'...".format(f))
                    allimgs, partitions = mount_images(
                        d,
                        auto,
                        verbosity,
                        output_directory,
                        path,
                        f,
                        elrond_mount,
                        ewf_mount,
                        allimgs,
                        imgformat,
                        vss,
                        "mounting",
                        cwd,
                        quotes,
                        partitions,
                    )
                    partitions = list(set(partitions))
                    if len(allimgs) > 0 and f in str(allimgs):
                        entry, prnt = "{},{},{},completed\n".format(
                            datetime.now().isoformat(), f, "mounting"
                        ), " -> {} -> mounted '{}'".format(
                            datetime.now().isoformat().replace("T", " "), f
                        )
                        write_audit_log_entry(verbosity, output_directory, entry, prnt)
                    else:
                        print("   Unfortunately, '{}' could not be mounted".format(f))
                        unmounted.append(f)
                        entry, prnt = "{},{},{},failed\n".format(
                            datetime.now().isoformat(), f, "mounting"
                        ), " -> {} -> not mounted '{}'".format(
                            datetime.now().isoformat().replace("T", " "), f
                        )
                        write_audit_log_entry(verbosity, output_directory, entry, prnt)

                        # For ambiguous extensions (.raw, .dd) under 32GB, fallback to memory processing
                        ambiguous_extensions = ['.raw', '.dd']
                        is_ambiguous = any(f.lower().endswith(ext) for ext in ambiguous_extensions)
                        max_memory_size = 32 * 1024 * 1024 * 1024  # 32GB
                        try:
                            file_size = os.path.getsize(path)
                        except (OSError, IOError):
                            file_size = max_memory_size + 1  # Assume too large if can't check

                        if is_ambiguous and file_size < max_memory_size:
                            print(" -> {} -> mount failed, attempting to process '{}' as memory image...".format(
                                datetime.now().isoformat().replace("T", " "), f
                            ))
                            ot = identify_memory_image(
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
                            )
                            for mempath, memimg in ot.items():
                                allimgs[memimg] = mempath
                            allimgs = OrderedDict(sorted(allimgs.items(), key=lambda x: x[1]))
                        else:
                            # Clean up the empty directory to avoid phantom directories
                            phantom_dir = os.path.join(output_directory, f)
                            if os.path.isdir(phantom_dir):
                                try:
                                    # Only remove if empty or contains only audit files we created
                                    dir_contents = os.listdir(phantom_dir)
                                    if len(dir_contents) == 0 or dir_contents == ["meta_audit.log"] or dir_contents == ["rivendell_audit.log"] or set(dir_contents) == {"meta_audit.log", "rivendell_audit.log"}:
                                        shutil.rmtree(phantom_dir)
                                        print(f"   Removed empty directory for unmounted image '{f}'")
                                except Exception as e:
                                    print(f"   Warning: Could not remove phantom directory: {e}")
                else:
                    print("    OK. '{}' will not be mounted.\n".format(f))
                allimgs = {**allimgs, **ot}
                print()
            elif volatility and ("data" in imgformat or "crash dump" in imgformat):
                if hashing_enabled:
                    if not os.path.exists(output_directory + f + "/meta_audit.log"):
                        with open(
                            output_directory + f + "/meta_audit.log", "w"
                        ) as metaimglog:
                            metaimglog.write(
                                "Filename,SHA256,known-good,Entropy,Filesize,LastWriteTime,LastAccessTime,LastInodeChangeTime,Permissions,FileType\n"
                            )
                    with open(path, "rb") as metaimg:
                        buffer = metaimg.read(262144)
                        while len(buffer) > 0:
                            sha256.update(buffer)
                            buffer = metaimg.read(262144)
                        metaentry = (
                            path
                            + ","
                            + sha256.hexdigest()
                            + ",unknown,N/A,N/A,N/A,N/A,N/A,N/A,N/A\n"
                        )
                    with open(output_directory + f + "/meta_audit.log", "a") as metaimglog:
                        metaimglog.write(metaentry)
                    extract_metadata(
                        verbosity,
                        output_directory,
                        f,
                        path,
                        "metadata",
                        sha256,
                        nsrl,
                    )
                ot = identify_memory_image(
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
                )
                for mempath, memimg in ot.items():
                    allimgs[memimg] = mempath
                allimgs = OrderedDict(sorted(allimgs.items(), key=lambda x: x[1]))
                print()
    elif gandalf and not (phase in ("collect", "process", "analyse", "index") and mounted_imgs):
        # Gandalf source node (in place of mount + collect): ingest each acquisition
        # into <output>/<host>/artefacts/raw/ and register it like a mounted image.
        assess_gandalf(
            auto,
            gandalf,
            vss,
            nsrl,
            volatility,
            metacollected,
            ot,
            d,
            cwd,
            sha256,
            flags,
            output_directory,
            verbosity,
            allimgs,
            imgs,
            volchoice,
            vssmem,
            memtimeline,
        )
    allimgs = OrderedDict(sorted(allimgs.items(), key=lambda x: x[1]))
    if len(allimgs) > 0:
        for (
            image_location,
            image_name,
        ) in allimgs.items():  # populating just a 'disk image' dictionary
            if "::" in image_name and "::memory_" not in image_name:
                imgs[image_location] = image_name
        time.sleep(1)
        # Don't print phase completion in mount phase - elrond.py will handle it after all images
        if phase != "mount":
            print(
                "  ----------------------------------------\n  -> Completed Identification Phase.\n"
            )
    elif unmounted:
        # E9: a busy or unmountable image used to end here with exit status 0, so the
        # job "completed" in seconds with no output
        print("\n   ERROR: no image could be processed; {} could not be mounted: {}\n".format(
            "it" if len(unmounted) == 1 else "these", ", ".join(unmounted)), flush=True)
        sys.exit(2)
    else:
        nodisks = safe_input(
            "  No images exist in the provided directory.\n   Please try again."
        )
        sys.exit(1)
    time.sleep(1)

    # PHASE CONTROL: If mount-only phase, return after mounting
    if phase == "mount":
        return allimgs, imgs, output_directory, partitions

    if collect or gandalf:  # Collection (disk images only), Processing, Keyword Searching, Analysis & Timelining
        # Determine collect/process phase for core function
        core_phase = None
        if phase == "collect":
            core_phase = "collect"
        elif phase == "process":
            core_phase = "process"
        elif phase == "analyse":
            core_phase = "analyse"
        elif phase == "index":
            # Skip core function entirely for index phase - go straight to Splunk/Elastic
            core_phase = None

        # Skip core function for index phase - only run Splunk/Elastic/Navigator
        if phase != "index":
            collect_process_keyword_analysis_timeline(
                auto,
                collect,
                process,
                analysis,
                magicbytes,
                extractiocs,
                iocsfile,
                timeline,
                vss,
                collectfiles,
                nsrl,
                keywords,
                volatility,
                metacollected,
                symlinks,
                userprofiles,
                verbose,
                d,
                cwd,
                sha256,
                flags,
                system_artefacts,
                output_directory,
                verbosity,
                f,
                allimgs,
                imgs,
                path,
                volchoice,
                vssmem,
                memtimeline,
                stage,
                phase=core_phase,
            )

        # PHASE CONTROL: If collect-only phase, return after collection
        if phase == "collect":
            print("  -> Collect phase complete.")
            return allimgs, imgs, output_directory, partitions

        # PHASE CONTROL: If process-only phase, return after processing
        if phase == "process":
            print("  -> Process phase complete.")
            return allimgs, imgs, output_directory, partitions

        # PHASE CONTROL: Skip to indexing if in "index" phase (analysis already done)
        if phase == "index":
            pass  # Fall through to indexing section below

        # MITRE tagging now happens incrementally during artefact extraction in artemis.py
        # Here we just deduplicate the techniques file for Navigator layer generation
        if navigator and process and phase != "index":
            for root, dirs, _ in os.walk(output_directory):
                # Find the image directory containing mitre_techniques.txt
                techniques_file = os.path.join(root, "mitre_techniques.txt")
                if os.path.exists(techniques_file):
                    try:
                        # Read and deduplicate techniques
                        with open(techniques_file, 'r') as f:
                            techniques = set(line.strip() for line in f if line.strip())
                        # Rewrite with unique techniques only
                        with open(techniques_file, 'w') as f:
                            for tech_id in sorted(techniques):
                                f.write(f"{tech_id}\n")
                        if techniques:
                            print(" -> {} -> MITRE tagging complete: {} unique techniques identified".format(
                                datetime.now().isoformat().replace("T", " "),
                                len(techniques)
                            ))
                    except Exception as e:
                        print(f"     Warning: MITRE techniques file error: {e}")
    allimgs, imgs, elrond_mount, img_list = (
        OrderedDict(sorted(allimgs.items(), key=lambda x: x[1])),
        OrderedDict(sorted(imgs.items(), key=lambda x: x[1])),
        [
            "/mnt/elrond_mount00",
            "/mnt/elrond_mount01",
            "/mnt/elrond_mount02",
            "/mnt/elrond_mount03",
            "/mnt/elrond_mount04",
            "/mnt/elrond_mount05",
            "/mnt/elrond_mount06",
            "/mnt/elrond_mount07",
            "/mnt/elrond_mount08",
            "/mnt/elrond_mount09",
            "/mnt/elrond_mount10",
            "/mnt/elrond_mount11",
            "/mnt/elrond_mount12",
            "/mnt/elrond_mount13",
            "/mnt/elrond_mount14",
            "/mnt/elrond_mount15",
            "/mnt/elrond_mount16",
            "/mnt/elrond_mount17",
            "/mnt/elrond_mount18",
            "/mnt/elrond_mount19",
        ],
        [],
    )
    if (
        len(allimgs) > 0
    ):  # Post-processing metadata, YARA, Splunk, Elastic, Archive, Deletion
        if hashing_enabled:
            safe_print(
                "\n\n  -> \033[1;36mCommencing Metadata phase for proccessed artefacts...\033[1;m\n  ----------------------------------------"
            )
            time.sleep(1)
            imgs_metad = []
            for _, img in allimgs.items():
                print(
                    "\n    Collecting metadata from processed artefacts for '{}'...".format(
                        img.split("::")[0]
                    )
                )
                extract_metadata(
                    verbosity,
                    output_directory,
                    img,
                    output_directory + img.split("::")[0] + "/artefacts/raw/",
                    stage,
                    sha256,
                    nsrl,
                )
                if os.path.exists(
                    output_directory + img.split("::")[0] + "/artefacts/cooked/"
                ):
                    extract_metadata(
                        verbosity,
                        output_directory,
                        img,
                        output_directory + img.split("::")[0] + "/artefacts/cooked/",
                        stage,
                        sha256,
                        nsrl,
                    )
                if os.path.exists(
                    output_directory + img.split("::")[0] + "/artefacts/carved/"
                ):
                    extract_metadata(
                        verbosity,
                        output_directory,
                        img,
                        output_directory + img.split("::")[0] + "/artefacts/carved/",
                        stage,
                        sha256,
                        nsrl,
                    )
                if os.path.exists(output_directory + img.split("::")[0] + "/analysis/"):
                    extract_metadata(
                        verbosity,
                        output_directory,
                        img,
                        output_directory + img.split("::")[0] + "/analysis/",
                        stage,
                        sha256,
                        nsrl,
                    )
                if os.path.exists(output_directory + img.split("::")[0] + "/files/"):
                    extract_metadata(
                        verbosity,
                        output_directory,
                        img,
                        output_directory + img.split("::")[0] + "/files/",
                        stage,
                        sha256,
                        nsrl,
                    )
                if (
                    os.path.exists(output_directory + img.split("::")[0])
                    and "memory_" in img.split("::")[1]
                ):
                    extract_metadata(
                        verbosity,
                        output_directory,
                        img,
                        output_directory + img.split("::")[0],
                        stage,
                        sha256,
                        nsrl,
                    )
                if img.split("::")[0] not in imgs_metad:
                    imgs_metad.append(img.split("::")[0])
                print(
                    "     Completed collection of metadata from processed artefacts for '{}'".format(
                        img.split("::")[0]
                    )
                )
            print(
                "  ----------------------------------------\n  -> Completed Metadata phase for proccessed artefacts.\n"
            )
            time.sleep(1)
        if misplaced_binaries:
            safe_print(
                "\n\n  -> \033[1;36mCommencing Misplaced Binaries Detection (T1036.005)...\033[1;m\n  ----------------------------------------"
            )
            time.sleep(1)
            from rivendell.analysis.misplaced import detect_misplaced_binaries
            for loc, img in imgs.items():
                if not auto:
                    yes_misplaced = safe_input(
                        "  Do you wish to scan for misplaced binaries in '{}'? Y/n [Y] ".format(
                            img.split("::")[0]
                        )
                    )
                if auto or yes_misplaced != "n":
                    detect_misplaced_binaries(
                        loc, output_directory, verbosity, img, img.split("::")[0]
                    )
            flags.append("06misplaced")
            print(
                "  ----------------------------------------\n  -> Completed Misplaced Binaries Phase.\n"
            )
            time.sleep(1)
        if masquerading:
            safe_print(
                "\n\n  -> \033[1;36mCommencing Masquerading Detection (T1036)...\033[1;m\n  ----------------------------------------"
            )
            time.sleep(1)
            from rivendell.analysis.masquerading import detect_masquerading
            for loc, img in imgs.items():
                if not auto:
                    yes_masq = safe_input(
                        "  Do you wish to scan for masquerading techniques in '{}'? Y/n [Y] ".format(
                            img.split("::")[0]
                        )
                    )
                if auto or yes_masq != "n":
                    detect_masquerading(
                        loc, output_directory, verbosity, img, img.split("::")[0]
                    )
            flags.append("06masquerading")
            print(
                "  ----------------------------------------\n  -> Completed Masquerading Detection Phase.\n"
            )
            time.sleep(1)
        if yara:
            safe_print(
                "\n\n  -> \033[1;36mCommencing Yara Phase...\033[1;m\n  ----------------------------------------"
            )
            time.sleep(1)
            yara_files = []
            for yroot, _, yfiles in os.walk(yara[0]):
                for yfile in yfiles:
                    if yfile.endswith(".yara") or yfile.endswith(".yar"):
                        yara_files.append(os.path.join(yroot, yfile))
            if not yara_files:
                print(f"     WARNING: No YARA rule files (.yar or .yara) found in {yara[0]}")
            for loc, img in imgs.items():
                if not auto:
                    yes_yara = safe_input(
                        "  Do you wish to conduct Yara analysis for '{}'? Y/n [Y] ".format(
                            img.split("::")[0]
                        )
                    )
                if auto or yes_yara != "n":
                    run_yara_signatures(
                        verbosity, output_directory, img, loc, collectfiles, yara_files
                    )
            flags.append("07yara")
            print(
                "  ----------------------------------------\n  -> Completed Yara Phase.\n"
            )
            time.sleep(1)

        # Clean up small files (<10 bytes) and empty directories after processing
        cleanup_small_files_and_empty_dirs(output_directory)

        # PHASE CONTROL: If analyse-only phase, return after analysis (before indexing)
        if phase == "analyse":
            print("  -> Analyse phase complete.")
            return allimgs, imgs, output_directory, partitions

        # Initialize credentials to None (will be set if Splunk/Elastic configured)
        usercred, pswdcred = None, None

        if splunk:
            print(
                "\n\n  -> \033[1;36mCommencing Splunk Phase...\033[1;m\n  ----------------------------------------"
            )
            print("     Indexing artefacts to Splunk (this may take several minutes for large datasets)...")
            # Ensure Splunk is installed before configuring
            try:
                from elrond.tools.siem_installer import SIEMInstaller
                siem_installer = SIEMInstaller()
                splunk_installed = siem_installer.ensure_siem_installed('splunk')
            except (ImportError, Exception):
                splunk_installed = True  # Assume installed if checker unavailable

            if not splunk_installed:
                print("\n  \033[1;31mWARNING: Splunk is not installed. Skipping Splunk phase.\033[0m\n")
            else:
                try:
                    usercred, pswdcred = configure_splunk_stack(
                        verbosity,
                        output_directory,
                        case,
                        "splunk",
                        allimgs,
                    )
                    flags.append("08splunk")
                    print(
                        "  ----------------------------------------\n  -> Completed Splunk Phase.\n"
                    )
                except Exception as e:
                    # Log the error instead of silently skipping
                    print("     ERROR: Splunk configuration failed: {}".format(e))
                    import traceback
                    traceback.print_exc()
            time.sleep(1)
        if elastic:
            print(
                "\n\n  -> \033[1;36mCommencing Elastic Phase...\033[1;m\n  ----------------------------------------"
            )
            print("     Indexing artefacts to Elasticsearch and generating Kibana dashboards...")
            print("     (this may take several minutes for large datasets)")
            # Ensure Elasticsearch and Kibana are installed before configuring
            siem_installer = None
            try:
                from elrond.tools.siem_installer import SIEMInstaller
                siem_installer = SIEMInstaller()
                es_installed = siem_installer.ensure_siem_installed('elasticsearch')
                kb_installed = siem_installer.ensure_siem_installed('kibana')
            except (ImportError, Exception):
                es_installed = True  # Assume installed if checker unavailable
                kb_installed = True

            if not (es_installed and kb_installed):
                print("\n  \033[1;31mWARNING: Elastic Stack is not fully installed. Skipping Elastic phase.\033[0m\n")
            else:
                try:
                    # Verify version match (only if siem_installer was successfully created)
                    if siem_installer is not None:
                        match, match_msg = siem_installer.version_checker.check_elasticsearch_kibana_match()
                        if not match:
                            print(f"\n  \033[1;33mWARNING: {match_msg}\033[0m")
                            print("  \033[1;33mProceeding with caution...\033[0m\n")

                    configure_elastic_stack(
                        verbosity,
                        output_directory,
                        case,
                        "elastic",
                        allimgs,
                    )
                    flags.append("09elastic")
                except Exception as e:
                    print(f"\n  \033[1;31mWARNING: Elastic configuration failed: {e}\033[0m")
                    print("  -> Skipping Elastic phase.\n")
            print(
                "  ----------------------------------------\n  -> Completed Elastic Phase.\n"
            )
            time.sleep(1)
        if navigator:  # mapping to attack-navigator
            print(
                "\n\n  -> \033[1;36mCommencing Navigator Phase...\033[1;m\n  ----------------------------------------"
            )
            print("     Generating ATT&CK Navigator layer from identified MITRE techniques...")
            time.sleep(1)
            # MITRE techniques were already identified during processing phase
            # Navigator just reads the techniques file and generates the layer
            navresults = configure_navigator(
                verbosity, case, splunk, elastic, usercred, pswdcred, output_directory
            )
            if navresults != "":
                flags.append("10navigator")
            print(
                "  ----------------------------------------\n  -> Completed Navigator Phase.\n"
            )
            time.sleep(1)
        if archive or delete:
            # Once per case, archive before delete: per image, the second image's
            # archive held a case whose first host was already deleted
            if archive:
                archive_artefacts(verbosity, output_directory)
                flags.append("11archiving")
            if delete:
                delete_artefacts(verbosity, output_directory)
                flags.append("12deletion")
    endtime, fmt, timestringprefix = (
        datetime.now().isoformat(),
        "%Y-%m-%dT%H:%M:%S.%f",
        "Total elasped time: ",
    )
    st, et = datetime.strptime(starttime, fmt), datetime.strptime(endtime, fmt)
    totalsecs, secs = int(round((et - st).total_seconds())), int(
        round((et - st).total_seconds() % 60)
    )
    if round((et - st).total_seconds()) > 3600:
        hours, mins = round((et - st).total_seconds() / 60 / 60), round(
            (et - st).total_seconds() / 60 % 60
        )
        if hours > 1 and mins > 1 and secs > 1:
            timetaken = "{} hours, {} minutes and {} seconds.".format(
                str(hours), str(mins), str(secs)
            )
        elif hours > 1 and mins > 1 and secs == 1:
            timetaken = "{} hours, {} minutes and {} second.".format(
                str(hours), str(mins), str(secs)
            )
        elif hours > 1 and mins == 1 and secs > 1:
            timetaken = "{} hours, {} minute and {} seconds.".format(
                str(hours), str(mins), str(secs)
            )
        elif hours == 1 and mins > 1 and secs > 1:
            timetaken = "{} hour, {} minutes and {} seconds.".format(
                str(hours), str(mins), str(secs)
            )
        elif hours > 1 and mins == 1 and secs == 1:
            timetaken = "{} hours, {} minute and {} second.".format(
                str(hours), str(mins), str(secs)
            )
        elif hours == 1 and mins > 1 and secs == 1:
            timetaken = "{} hour, {} minutes and {} second.".format(
                str(hours), str(mins), str(secs)
            )
        elif hours == 1 and mins == 1 and secs > 1:
            timetaken = "{} hour, {} minute and {} seconds.".format(
                str(hours), str(mins), str(secs)
            )
        elif hours > 1 and mins > 1 and secs == 0:
            timetaken = "{} hours and {} minutes.".format(str(hours), str(mins))
        elif hours > 1 and mins == 0 and secs > 0:
            timetaken = "{} hours and {} seconds.".format(str(hours), str(secs))
        elif hours == 1 and mins > 1 and secs == 0:
            timetaken = "{} hour and {} minutes.".format(str(hours), str(mins))
        elif hours == 1 and mins == 0 and secs > 0:
            timetaken = "{} hour and {} second.".format(str(hours), str(secs))
        elif hours > 1 and mins == 0 and secs == 0:
            timetaken = "{} hours.".format(str(hours))
        elif hours == 1 and mins == 0 and secs == 0:
            timetaken = "{} hour.".format(str(hours))
    elif 3600 > round((et - st).total_seconds()) > 60:
        mins = round((et - st).total_seconds() / 60)
        if mins > 1 and secs > 1:
            timetaken = "{} minutes and {} seconds.".format(str(mins), str(secs))
        elif mins == 1 and secs > 1:
            timetaken = "{} minute and {} seconds.".format(str(mins), str(secs))
        elif mins > 1 and secs == 1:
            timetaken = "{} minutes and {} second.".format(str(mins), str(secs))
        elif mins == 1 and secs == 1:
            timetaken = "{} minute and {} second.".format(str(mins), str(secs))
        else:
            timetaken = "{} minutes.".format(str(mins))
    else:
        if secs > 1:
            timetaken = "{} seconds.".format(str(secs))
        else:
            timetaken = "{} second.".format(str(secs))
    OrderedDict(sorted(imgs.items(), key=lambda x: x[1]))
    for _, eachimg in imgs.items():
        img_list.append(eachimg)
    partitions = sorted(list(set(partitions)))
    if vss:
        for eachimg, partition in zip(img_list, partitions):
            if (
                "Windows" in eachimg.split("::")[1]
                and (
                    ".E01" in eachimg.split("::")[0] or ".e01" in eachimg.split("::")[0]
                )
                and "memory_" not in eachimg.split("::")[1]
                and "_vss" not in eachimg.split("::")[1]
            ):
                if len(partitions) > 1:
                    partition_insert = " ({} partition)".format(
                        partition.split("||")[0][2::]
                    )
                else:
                    partition_insert = ""
                if not auto:
                    inspectedvss = safe_input(
                        "\n\n  ----------------------------------------\n   Have you reviewed the Volume Shadow Copies for '{}'{}? Y/n [Y] ".format(
                            eachimg.split("::")[0], partition_insert
                        )
                    )
                else:
                    inspectedvss = "y"
                if inspectedvss != "n":
                    unmount_images(elrond_mount, ewf_mount)
                    print(
                        "    Unmounted Volume Shadow Copies for '{}'\n  ----------------------------------------\n".format(
                            eachimg.split("::")[0]
                        )
                    )
    else:
        unmount_images(elrond_mount, ewf_mount)
    safe_print(
        "\n\n  -> \033[1;36mFinished. {}{}\033[1;m\n  ----------------------------------------".format(
            timestringprefix, timetaken
        )
    )
    time.sleep(1)
    if len(flags) > 0:
        doneimgs, sortedflags = [], re.sub(
            r"', '\d{2}", r", ", str(sorted(set(flags))).title()[4:-2]
        )
        if ", " in sortedflags:
            more_than_one_phase = "phases"
            flags = sortedflags.split(", ")
            lastflag = " and " + flags[-1]
            flags.pop()
            flags = (
                str(flags).replace("[", "").replace("]", "").replace("'", "") + lastflag
            )
        else:
            flags = str(flags)[4:-2].title()
            more_than_one_phase = "phase"
        if len(allimgs) > 0:
            for _, eachimg in allimgs.items():
                doneimgs.append(eachimg.split("::")[0])
    doneimgs = sorted(list(set(doneimgs)))
    unmount_images(elrond_mount, ewf_mount)
    for eachimg, eachname in allimgs.items():
        img_output_dir = output_directory + output_folder_name(eachimg, eachname)
        tidy_processed_output(img_output_dir)
    for doneimg in doneimgs:
        print("       '{}'".format(doneimg))
        entry, prnt = "{},{},finished,'{}'-'{}': ({} seconds)".format(
            datetime.now().isoformat(), doneimg, st, et, totalsecs
        ), "[{}] -> elrond completed for '{}'".format(
            datetime.now().isoformat().replace("T", " "), doneimg
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        time.sleep(1)
    print("  ----------------------------------------")
    print()
    if len(allimgs.items()) > 0 and (splunk or elastic or navigator):
        if splunk:
            print("    Splunk Web:           127.0.0.1:8000/en-US/app/elrond/")
        if elastic:
            print(
                "    elasticsearch:        127.0.0.1:9200\n    Kibana:               127.0.0.1:5601"
            )
        if navigator:
            print("    ATT&CK® Navigator:    127.0.0.1:4200")
        print()
        print("  ----------------------------------------")
        print("\n")
    os.chdir(cwd)
