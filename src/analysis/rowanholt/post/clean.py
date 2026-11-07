#!/usr/bin/env python3 -tt
import os
import shutil
import time
from datetime import datetime
from zipfile import ZipFile

from rowanholt.audit import write_audit_log_entry
from rowanholt.core.records import SUFFIX, read_records


def archive_artefacts(verbosity, output_directory):
    stage = "archiving"
    print(
        "\n\n  -> \033[1;36mCommencing Archive Phase...\033[1;m\n  ----------------------------------------"
    )

    # Get case name from output_directory (remove trailing slash)
    case_dir = output_directory.rstrip("/")
    case_name = case_dir.split("/")[-1]
    # In the case directory, beside the hosts (E13: it went in the parent, outside the
    # job's output, where the job and the web UI never look); deletion keeps it
    archive_path = os.path.join(case_dir, case_name + ".zip")

    print("    Archiving case '{}'...".format(case_name))
    entry, prnt = "{},{},{},commenced\n".format(
        datetime.now().isoformat(), case_name, stage
    ), " -> {} -> {} case '{}'".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        case_name,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)

    print("     Creating archive at '{}'...".format(archive_path))
    z = ZipFile(archive_path, "w")
    skipped_files = 0
    for ziproot, _, zipfiles in os.walk(output_directory):
        for zf in zipfiles:
            # Skip macOS metadata files (._* AppleDouble files)
            if zf.startswith("._"):
                skipped_files += 1
                continue

            filepath = os.path.join(ziproot, zf)
            # Exclude the archive itself
            if filepath != archive_path:
                try:
                    # Store with relative path from case directory
                    arcname = os.path.relpath(filepath, output_directory)
                    z.write(filepath, arcname)
                except (OSError, IOError, PermissionError) as e:
                    # Log permission errors but continue archiving
                    if verbosity:  # '', 'verbose' or 'veryverbose'
                        print(f"     Warning: Could not archive '{zf}': {e}")
                    skipped_files += 1
    z.close()

    if skipped_files > 0:
        print(f"     Skipped {skipped_files} file(s) due to permissions or metadata")

    print("  -> Completed Archiving Phase for case '{}'".format(case_name))
    entry, prnt = "{},{},{},completed\n".format(
        datetime.now().isoformat(), case_name, stage
    ), " -> {} -> archiving completed for case '{}'".format(
        datetime.now().isoformat().replace("T", " "),
        case_name,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    print(
        "  ----------------------------------------\n  -> Completed Archiving Phase.\n"
    )
    time.sleep(1)


def delete_artefacts(verbosity, output_directory):
    stage = "deleting"
    print(
        "\n\n  -> \033[1;36mCommencing Deletion Phase...\033[1;m\n  ----------------------------------------"
    )
    dlist = []
    for each in os.listdir(output_directory):
        if os.path.exists(output_directory + each + "/artefacts"):
            dlist.append(output_directory + each)
    for deach in dlist:
        print("    Deleting artefacts for {}...".format(deach.split("/")[-1]))
        entry, prnt = "{},{},{},commenced\n".format(
            datetime.now().isoformat(), deach.split("/")[-1], stage
        ), " -> {} -> {} artefacts for '{}'".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            deach.split("/")[-1],
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        print("     Deleting files for '{}'...".format(deach.split("/")[-1]))
        for droot, ddir, dfile in os.walk(deach):
            for eachdir in ddir:
                name = droot + "/" + eachdir
                if not name.endswith(deach):
                    shutil.rmtree(droot + "/" + eachdir)
            for eachfile in dfile:
                name = droot + "/" + eachfile
                if not name.endswith(
                    deach.split("/")[-1] + "/" + deach.split("/")[-1] + ".log"
                ) and not name.endswith(
                    deach.split("/")[-1] + "/" + deach.split("/")[-1] + ".zip"
                ):
                    os.remove(droot + "/" + eachfile)
        print("  -> Completed Deletion Phase for {}".format(deach.split("/")[-1]))
        entry, prnt = "{},{},{},completed\n".format(
            datetime.now().isoformat(), deach.split("/")[-1], stage
        ), " -> {} -> deletion completed for '{}'".format(
            datetime.now().isoformat().replace("T", " "),
            deach.split("/")[-1],
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        print(
            "  ----------------------------------------\n  -> Completed Deletion Phase.\n"
        )
        time.sleep(1)


def cleanup_small_files_and_empty_dirs(output_directory, min_file_size=10):
    """
    Clean up small files (<10 bytes) and empty directories after processing.

    This removes artifacts that are effectively empty or contain no useful data.
    Also removes macOS metadata files (._* AppleDouble files).

    Args:
        output_directory: Base output directory to clean
        min_file_size: Minimum file size in bytes (files smaller than this are deleted)

    Returns:
        Tuple of (deleted_files_count, deleted_dirs_count)
    """
    deleted_files = 0
    deleted_dirs = 0

    print(f" -> {datetime.now().isoformat().replace('T', ' ')} -> cleaning up small files and empty directories...")

    # One bottom-up walk: a directory's files go before the directory is checked, so
    # nested empty directories fall in the same pass. Collected artefacts
    # (artefacts/raw/) are left alone: an empty .bash_history is evidence
    # (T1070.003), not clutter.
    top = os.path.normpath(output_directory)
    for root, dirs, files in os.walk(top, topdown=False):
        if "/artefacts/raw/" not in root.replace(os.sep, "/") + "/":
            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    if filename.startswith("._") or os.path.getsize(filepath) < min_file_size:
                        os.remove(filepath)
                        deleted_files += 1
                except (OSError, IOError):
                    pass
        if root != top:
            try:
                os.rmdir(root)  # only succeeds when empty
                deleted_dirs += 1
            except OSError:
                pass

    if deleted_files > 0 or deleted_dirs > 0:
        print(f"     Cleaned up {deleted_files} small files and {deleted_dirs} empty directories")

    return deleted_files, deleted_dirs


def output_folder_name(key, value):
    """The case folder an allimgs entry's output is in. Disk images and Gandalf hosts
    carry '<name>::<platform>' as the value (keyed by mount point or raw/ directory);
    memory images carry it as the key (the value is the dump's directory)."""
    entry = value if "::" in str(value) else key
    return str(entry).split("::")[0].rstrip("/").split("/")[-1]


def has_no_records(path: str, max_empty_size: int = 100) -> bool:
    """Whether a processed file holds nothing: a JSON Lines or CSV table with no records (a
    one-record JSON Lines file can be under 100 bytes, so size alone won't do), or any other
    file of ``max_empty_size`` bytes or less (an old case's [] or {})."""
    if path.lower().endswith((SUFFIX, ".csv")):
        try:
            return next(iter(read_records(path)), None) is None
        except (OSError, ValueError):
            return False
    return os.stat(path).st_size <= max_empty_size


def tidy_processed_output(img_output_dir, max_empty_size=100):
    """Tidy one host's processed output at the end of a run: drop tables with no records
    (and other near-empty files) from cooked/ and analysis/, and lift a lone CSV or JSON file
    out of its cooked/ subdirectory as cooked/<subdirectory><ext> (a JSON Lines table isn't
    moved: its records' artefact is its path). Collected artefacts under
    raw/ are evidence, whatever their size, and aren't touched."""
    cooked_dir = os.path.join(img_output_dir, "artefacts", "cooked")
    for processed in (cooked_dir, os.path.join(img_output_dir, "analysis")):
        for root, _, files in os.walk(processed):
            for name in files:
                path = os.path.join(root, name)
                try:
                    if has_no_records(path, max_empty_size):
                        os.remove(path)
                except OSError:
                    pass
    if not os.path.isdir(cooked_dir):
        return
    for subdir in os.listdir(cooked_dir):
        subdir_path = os.path.join(cooked_dir, subdir)
        if not os.path.isdir(subdir_path):
            continue
        entries = os.listdir(subdir_path)
        # A JSON Lines table stays where it is: its records name it by its path under cooked/
        if (len(entries) == 1 and os.path.isfile(os.path.join(subdir_path, entries[0]))
                and not entries[0].endswith(SUFFIX)):
            ext = os.path.splitext(entries[0])[1]
            dst = os.path.join(cooked_dir, subdir + ext)
            if not os.path.exists(dst):
                try:
                    shutil.move(os.path.join(subdir_path, entries[0]), dst)
                except OSError:
                    pass
