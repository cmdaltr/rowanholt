#!/usr/bin/env python3 -tt
import os
import shutil
from datetime import datetime

from dernvale.audit import write_audit_log_entry

# Directories to exclude from user profile copies when DERNVALE_EXCLUDE_PROFILE_CACHE is set
PROFILE_CACHE_EXCLUSIONS = [
    'AppData/Local/Temp',
    'AppData/Local/Packages',
    'AppData/Local/Microsoft/Windows/INetCache',
    'AppData/Local/Microsoft/Windows/Temporary Internet Files',
    'AppData/Local/Google/Chrome/User Data/Default/Cache',
    'AppData/Local/Google/Chrome/User Data/Default/Code Cache',
    'AppData/Local/Mozilla/Firefox/Profiles',  # Will exclude cache subdirs
    'AppData/Local/Microsoft/Edge/User Data/Default/Cache',
    'AppData/Local/CrashDumps',
    'AppData/Local/Spotify/Storage',
    'AppData/Local/Discord/Cache',
    'AppData/Local/Microsoft/Teams/Cache',
]


def _profile_ignore_patterns(exclude_cache):
    """Return an ignore function for shutil.copytree that excludes cache directories."""
    def _ignore(directory, files):
        if not exclude_cache:
            return []
        ignored = []
        for f in files:
            full_path = os.path.join(directory, f)
            # Check if this path matches any exclusion pattern
            for exclusion in PROFILE_CACHE_EXCLUSIONS:
                # Normalize path separators
                norm_path = full_path.replace('\\', '/')
                norm_exclusion = exclusion.replace('\\', '/')
                if norm_exclusion in norm_path:
                    ignored.append(f)
                    break
        return ignored
    return _ignore


def _copy_with_progress(src, dst, profile_name, vssimage, symlinks=False, exclude_cache=False):
    """Copy a directory tree with progress logging and optional cache exclusion."""
    # Check if debug logging is enabled
    debug_enabled = os.environ.get('DERNVALE_DEBUG_PROFILE_COPY', '').lower() in ('true', '1', 'yes')

    if debug_enabled:
        file_count = 0
        last_report = datetime.now()
        report_interval = 60  # Report progress every 60 seconds

        def copy_with_count(src_file, dst_file):
            nonlocal file_count, last_report
            shutil.copy2(src_file, dst_file)
            file_count += 1

            # Report progress periodically
            now = datetime.now()
            if (now - last_report).total_seconds() >= report_interval:
                print(
                    " -> {} -> ... copied {} files for profile '{}' for '{}'".format(
                        now.isoformat().replace("T", " "),
                        file_count,
                        profile_name,
                        vssimage,
                    )
                )
                last_report = now

        copy_func = copy_with_count
    else:
        copy_func = shutil.copy2

    ignore_func = _profile_ignore_patterns(exclude_cache) if exclude_cache else None

    shutil.copytree(
        src,
        dst,
        symlinks=symlinks,
        copy_function=copy_func,
        ignore=ignore_func,
    )


def windows_users(
    dest,
    img,
    item,
    output_directory,
    stage,
    symlinkvalue,
    userprofiles,
    verbosity,
    vssimage,
    vsstext,
):
    (
        item_list,
        regdest,
        jumpdest,
        clipdest,
        maildest,
        bwsrdest,
        userdest,
        mail_dirs,
    ) = (
        os.listdir(item),
        dest + "registry/",
        dest + "jumplists",
        dest + "clipboard/",
        dest + "mail/",
        dest + "browsers/",
        dest + "user_profiles/",
        [],
    )
    for each in item_list:
        if os.path.isdir(item + each):
            # Log artefact collection at the start (not full profile copy)
            print(
                " -> {} -> collecting artefacts for profile '{}' for '{}'".format(
                    datetime.now().isoformat().replace("T", " "),
                    each,
                    vssimage,
                )
            )
            # ntuser.dat
            try:
                os.stat(regdest)
            except:
                os.makedirs(regdest)
            (
                entry,
                prnt,
            ) = "{},{},{},'{}' (NTUSER.DAT) registry hive\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                each,
            ), " -> {} NTUSER.DAT registry hive from profile '{}'{} for '{}'".format(
                stage,
                each,
                vsstext.replace("vss", "volume shadow copy #"),
                img.split("::")[0],
            )
            write_audit_log_entry(
                verbosity,
                output_directory,
                entry,
                prnt,
            )
            try:
                shutil.copy2(
                    item + each + "/NTUSER.DAT",
                    regdest + "/" + each + "+NTUSER.DAT",
                )
            except:
                pass

            # usrclass.dat
            try:
                os.stat(regdest)
            except:
                os.makedirs(regdest)
            (
                entry,
                prnt,
            ) = "{},{},{},'{}' (UsrClass.dat) registry hive\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                each,
            ), " -> {} UsrClass.dat registry hive from profile '{}'{} for '{}'".format(
                stage,
                each,
                vsstext.replace("vss", "volume shadow copy #"),
                img.split("::")[0],
            )
            write_audit_log_entry(
                verbosity,
                output_directory,
                entry,
                prnt,
            )
            try:
                shutil.copy2(
                    item + each + "/AppData/Local/Microsoft/Windows/UsrClass.dat",
                    regdest + "/" + each + "+UsrClass.dat",
                )
            except:
                pass

            # ConsoleHost_history.txt
            try:
                os.stat(dest)
            except:
                os.makedirs(dest)
            (
                entry,
                prnt,
            ) = "{},{},{},'{}' (ConsoleHost_history.txt) PowerShell history\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                each,
            ), " -> {} ConsoleHost_history.txt PowerShell history hive from profile '{}'{} for '{}'".format(
                stage,
                each,
                vsstext.replace("vss", "volume shadow copy #"),
                img.split("::")[0],
            )
            write_audit_log_entry(
                verbosity,
                output_directory,
                entry,
                prnt,
            )
            try:
                shutil.copy2(
                    item + each + "/AppData/Local/Microsoft/Windows/UsrClass.dat",
                    dest + "/" + each + "+PowerShell_Console_history.txt",
                )
            except:
                pass

            # clipboard
            try:
                os.stat(clipdest)
            except:
                os.makedirs(clipdest)
            (
                entry,
                prnt,
            ) = "{},{},{},'{}' clipboard\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                each,
            ), " -> {} clipboard artefacts for profile '{}'{} for '{}'".format(
                stage,
                each,
                vsstext.replace("vss", "volume shadow copy #"),
                img.split("::")[0],
            )
            write_audit_log_entry(
                verbosity,
                output_directory,
                entry,
                prnt,
            )
            if os.path.exists(item + each + "/AppData/Local/ConnectedDevicesPlatform/"):
                for clipboard in os.listdir(
                    item + each + "/AppData/Local/ConnectedDevicesPlatform/"
                ):
                    if os.path.isfile(
                        item
                        + each
                        + "/AppData/Local/ConnectedDevicesPlatform/"
                        + clipboard
                    ) and (
                        clipboard == "ActivitiesCache.db"
                        or clipboard == "ActivitiesCache.db-shm"
                        or clipboard == "ActivitiesCache.db-wal"
                    ):
                        try:
                            shutil.copy2(
                                item
                                + each
                                + "/AppData/Local/ConnectedDevicesPlatform/"
                                + clipboard,
                                clipdest + "/" + each + "+" + clipboard,
                            )
                        except:
                            pass
                    else:
                        if os.path.isdir(
                            item
                            + each
                            + "/AppData/Local/ConnectedDevicesPlatform/"
                            + clipboard
                        ):
                            for clipboardfile in os.listdir(
                                item
                                + each
                                + "/AppData/Local/ConnectedDevicesPlatform/"
                                + clipboard
                            ):
                                if os.path.isfile(
                                    item
                                    + each
                                    + "/AppData/Local/ConnectedDevicesPlatform/"
                                    + clipboard
                                    + "/"
                                    + clipboardfile
                                ) and (
                                    clipboardfile == "ActivitiesCache.db"
                                    or clipboardfile == "ActivitiesCache.db-shm"
                                    or clipboardfile == "ActivitiesCache.db-wal"
                                ):
                                    try:
                                        shutil.copy2(
                                            item
                                            + each
                                            + "/AppData/Local/ConnectedDevicesPlatform/"
                                            + clipboard
                                            + "/"
                                            + clipboardfile,
                                            clipdest
                                            + "/"
                                            + each
                                            + "+"
                                            + clipboard
                                            + "_"
                                            + clipboardfile,
                                        )
                                    except:
                                        pass

            # jumplists
            try:
                os.stat(jumpdest)
            except:
                os.makedirs(jumpdest)
            (
                entry,
                prnt,
            ) = "{},{},{},'{}' jumplists\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                each,
            ), " -> {} jumplist artefacts for profile '{}'{} for '{}'".format(
                stage,
                each,
                vsstext.replace("vss", "volume shadow copy #"),
                img.split("::")[0],
            )
            write_audit_log_entry(
                verbosity,
                output_directory,
                entry,
                prnt,
            )
            if os.path.exists(
                item
                + each
                + "/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/"
            ):
                for jump in os.listdir(
                    item
                    + each
                    + "/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/"
                ):
                    try:
                        shutil.copy2(
                            item
                            + each
                            + "/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/"
                            + jump,
                            jumpdest + "/" + each + "+" + jump,
                        )
                    except:
                        pass
            if os.path.exists(
                item
                + each
                + "/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/"
            ):
                for jump in os.listdir(
                    item
                    + each
                    + "/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/"
                ):
                    try:
                        shutil.copy2(
                            item
                            + each
                            + "/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/"
                            + jump,
                            jumpdest + "/" + each + "+" + jump,
                        )
                    except:
                        pass

            # outlook
            try:
                os.stat(maildest)
            except:
                os.makedirs(maildest)
            if os.path.exists(
                item
                + each
                + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.Outlook/"
            ):
                if (
                    len(
                        os.listdir(
                            item
                            + each
                            + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.Outlook/"
                        )
                    )
                    > 0
                ):
                    for every in os.listdir(
                        item
                        + each
                        + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.Outlook/"
                    ):
                        if (
                            len(
                                os.listdir(
                                    item
                                    + each
                                    + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.Outlook/"
                                    + every
                                )
                            )
                            > 0
                        ):
                            mail_dirs.append(
                                item
                                + each
                                + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.Outlook/"
                                + every
                            )
            if os.path.exists(item + each + "/Documents/Outlook Files/"):
                mail_dirs.append(item + each + "/Documents/Outlook Files/")
            if len(mail_dirs) > 0:
                (
                    entry,
                    prnt,
                ) = "{},{},{},'{}' outlook artefacts\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    each,
                ), " -> {} outlook artefacts for '{}'{} for '{}'".format(
                    stage,
                    each,
                    vsstext.replace(
                        "vss",
                        "volume shadow copy #",
                    ),
                    img.split("::")[0],
                )
                write_audit_log_entry(
                    verbosity,
                    output_directory,
                    entry,
                    prnt,
                )
                for every in mail_dirs:
                    try:
                        os.stat(maildest + each + "/" + every.split("/")[-1])
                    except:
                        os.makedirs(maildest + each + "/" + every.split("/")[-1])
                    for everyfile in os.listdir(every):
                        try:
                            shutil.copy2(
                                every + "/" + everyfile,
                                maildest
                                + each
                                + "/"
                                + every.split("/")[-1]
                                + "/"
                                + everyfile.split("/")[-1],
                            )
                        except:
                            pass
            try:
                os.stat(bwsrdest)
            except:
                os.makedirs(bwsrdest)
            if (
                os.path.exists(
                    item + each + "/AppData/Local/Microsoft/Edge/User Data/Default/"
                )
                or os.path.exists(
                    item + each + "/AppData/Local/Microsoft/Windows/History/"
                )
                or os.path.exists(
                    item
                    + each
                    + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/"
                )
            ):
                if os.path.exists(
                    item + each + "/AppData/Local/Microsoft/Edge/User Data/Default/"
                ):
                    (
                        entry,
                        prnt,
                    ) = "{},{},{},Edge artefacts\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                    ), " -> {} Edge artefacts{} for '{}'".format(
                        stage,
                        vsstext.replace(
                            "vss",
                            "volume shadow copy #",
                        ),
                        img.split("::")[0],
                    )
                    write_audit_log_entry(
                        verbosity,
                        output_directory,
                        entry,
                        prnt,
                    )
                    for every in os.listdir(
                        item + each + "/AppData/Local/Microsoft/Edge/User Data/Default/"
                    ):
                        if every == "History":
                            try:
                                os.stat(bwsrdest + each + "/Edge/")
                            except:
                                os.makedirs(bwsrdest + each + "/Edge/")
                            if os.path.exists(
                                item
                                + each
                                + "/AppData/Local/Microsoft/Edge/User Data/Default/"
                                + every
                            ):
                                try:
                                    shutil.copy2(
                                        item
                                        + each
                                        + "/AppData/Local/Microsoft/Edge/User Data/Default/"
                                        + every,
                                        bwsrdest + each + "/Edge/" + every,
                                    )
                                except:
                                    pass

                elif os.path.exists(
                    item + each + "/AppData/Local/Microsoft/Windows/History/"
                ):
                    (
                        entry,
                        prnt,
                    ) = "{},{},{},Internet Explorer artefacts\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                    ), " -> {} Internet Explorer artefacts{} for '{}'".format(
                        stage,
                        vsstext.replace(
                            "vss",
                            "volume shadow copy #",
                        ),
                        img.split("::")[0],
                    )
                    write_audit_log_entry(
                        verbosity,
                        output_directory,
                        entry,
                        prnt,
                    )
                    for every in os.listdir(
                        item + each + "/AppData/Local/Microsoft/Windows/History/"
                    ):
                        if (
                            every == "Content.IE5"
                            or every == "History.IE5"
                            or every == "Low"
                        ):
                            try:
                                os.stat(bwsrdest + each + "/IE/")
                            except:
                                os.makedirs(bwsrdest + each + "/IE/")
                            if (
                                len(
                                    os.listdir(
                                        item
                                        + each
                                        + "/AppData/Local/Microsoft/Windows/History/"
                                        + every
                                    )
                                )
                                > 0
                            ):
                                try:
                                    shutil.copytree(
                                        item
                                        + each
                                        + "/AppData/Local/Microsoft/Windows/History/"
                                        + every,
                                        bwsrdest + each + "/IE/" + every,
                                        symlinks=symlinkvalue,
                                    )
                                except:
                                    pass

                else:
                    (
                        entry,
                        prnt,
                    ) = "{},{},{},Temporary Internet Files\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                    ), " -> {} Temporary Internet Files{} for '{}'".format(
                        stage,
                        vsstext.replace(
                            "vss",
                            "volume shadow copy #",
                        ),
                        img.split("::")[0],
                    )
                    write_audit_log_entry(
                        verbosity,
                        output_directory,
                        entry,
                        prnt,
                    )
                    for every in os.listdir(
                        item
                        + each
                        + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/"
                    ):
                        if (
                            every == "Content.IE5"
                            or every == "History.IE5"
                            or every == "Low"
                        ):
                            try:
                                os.stat(
                                    bwsrdest + each + "/IE/Temporary Internet Files/"
                                )
                            except:
                                os.makedirs(
                                    bwsrdest + each + "/IE/Temporary Internet Files/"
                                )
                            if (
                                len(
                                    os.listdir(
                                        item
                                        + each
                                        + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/"
                                        + every
                                    )
                                )
                                > 0
                            ):
                                try:
                                    shutil.copytree(
                                        item
                                        + each
                                        + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/"
                                        + every,
                                        bwsrdest
                                        + each
                                        + "/IE/Temporary Internet Files/"
                                        + every,
                                        symlinks=symlinkvalue,
                                    )
                                except:
                                    pass
            if os.path.exists(
                item + each + "/AppData/Local/Google/Chrome/User Data/Default/"
            ):
                if (
                    len(
                        os.listdir(
                            item
                            + each
                            + "/AppData/Local/Google/Chrome/User Data/Default/"
                        )
                    )
                    > 0
                ):
                    (
                        entry,
                        prnt,
                    ) = "{},{},{},Google Chrome artefacts\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                    ), " -> {} Google Chrome artefacts{} for '{}'".format(
                        stage,
                        vsstext.replace(
                            "vss",
                            "volume shadow copy #",
                        ),
                        img.split("::")[0],
                    )
                    write_audit_log_entry(
                        verbosity,
                        output_directory,
                        entry,
                        prnt,
                    )
                    for every in os.listdir(
                        item + each + "/AppData/Local/Google/Chrome/User Data/Default/"
                    ):
                        try:
                            os.stat(bwsrdest + each + "/chrome/")
                        except:
                            os.makedirs(bwsrdest + each + "/chrome/")
                        try:
                            if every == "History":
                                shutil.copy2(
                                    item
                                    + each
                                    + "/AppData/Local/Google/Chrome/User Data/Default/"
                                    + every,
                                    bwsrdest + each + "/chrome/",
                                )
                            elif every == "Local Storage":
                                shutil.copytree(
                                    item
                                    + each
                                    + "/AppData/Local/Google/Chrome/User Data/Default/"
                                    + every,
                                    bwsrdest + each + "/chrome/Local Settings",
                                    symlinks=symlinkvalue,
                                )
                        except:
                            pass
            if os.path.exists(item + each + "/AppData/Local/Mozilla/Firefox/Profiles/"):
                if (
                    len(
                        os.listdir(
                            item + each + "/AppData/Local/Mozilla/Firefox/Profiles/"
                        )
                    )
                    > 0
                ):
                    (
                        entry,
                        prnt,
                    ) = "{},{},{},Mozilla Firefox artefacts\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                    ), " -> {} Mozilla Firefox artefacts{} for '{}'".format(
                        stage,
                        vsstext.replace(
                            "vss",
                            "volume shadow copy #",
                        ),
                        img.split("::")[0],
                    )
                    write_audit_log_entry(
                        verbosity,
                        output_directory,
                        entry,
                        prnt,
                    )
                    for every in os.listdir(
                        item + each + "/AppData/Local/Mozilla/Firefox/Profiles/"
                    ):
                        try:
                            os.stat(bwsrdest + each + "/firefox/")
                        except:
                            os.makedirs(bwsrdest + each + "/firefox/")
                        try:
                            if os.path.exists(
                                item
                                + each
                                + "/AppData/Local/Mozilla/Firefox/Profiles/"
                                + every
                                + "/places.sqlite"
                            ):
                                shutil.copy2(
                                    item
                                    + each
                                    + "/AppData/Local/Mozilla/Firefox/Profiles/"
                                    + every
                                    + "/places.sqlite",
                                    bwsrdest + each + "/firefox/",
                                )
                        except:
                            pass
    if userprofiles:
        # Check environment variable for cache exclusion
        exclude_cache = os.environ.get('DERNVALE_EXCLUDE_PROFILE_CACHE', '').lower() in ('true', '1', 'yes')
        for each in item_list:
            try:
                os.stat(userdest)
            except:
                os.makedirs(userdest)
            if os.path.isdir(item + each):
                # Print initiation message BEFORE the copy starts
                cache_msg = " (excluding caches)" if exclude_cache else ""
                print(
                    " -> {} -> copying full user profile '{}' for '{}'{}...".format(
                        datetime.now().isoformat().replace("T", " "),
                        each,
                        vssimage,
                        cache_msg,
                    )
                )
                (
                    entry,
                    prnt,
                ) = "{},{},{},'{}' user profile\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    each,
                ), " -> {} '{}' user profile{} for '{}'".format(
                    stage,
                    each,
                    vsstext.replace(
                        "vss",
                        "volume shadow copy #",
                    ),
                    img.split("::")[0],
                )
                write_audit_log_entry(
                    verbosity,
                    output_directory,
                    entry,
                    prnt,
                )
                try:
                    _copy_with_progress(
                        item + each,
                        userdest + "/" + each,
                        each,
                        vssimage,
                        symlinks=symlinkvalue,
                        exclude_cache=exclude_cache,
                    )
                except Exception as e:
                    # Extract just source file paths from shutil.Error
                    if hasattr(e, 'args') and e.args and isinstance(e.args[0], list):
                        failed_files = [err[0] for err in e.args[0] if isinstance(err, tuple) and len(err) >= 1]
                        error_msg = str(failed_files)
                    else:
                        error_msg = str(e)[:100]
                    print(
                        " -> {} -> error during copying user profile '{}' for '{}': {}".format(
                            datetime.now().isoformat().replace("T", " "),
                            each,
                            vssimage,
                            error_msg,
                        )
                    )
