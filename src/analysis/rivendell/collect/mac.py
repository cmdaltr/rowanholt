#!/usr/bin/env python3 -tt
import glob
import os
import shutil
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.collect.linux import _flat, _walk
from rivendell.collect.users.mac import mac_users

# Collected into raw/macos/ under their path with '/' as '+' (process/mac_artefacts.py).
# gandalf.sh and gandalf.py carry the same lists; keep the three in step.
MACOS_EXTRA_DATABASES = (
    "/private/var/db/SystemPolicyConfiguration/ExecPolicy", "/private/var/db/SystemPolicyConfiguration/KextPolicy",
    "/private/var/protected/xprotect/XPdb", "/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm",
    "/private/var/folders/*/*/0/com.apple.notificationcenter/db2/db",
    "/Users/*/Library/Group Containers/group.com.apple.usernoted/db2/db",
)
MACOS_EXTRA_FILES = (
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist", "/private/etc/periodic.conf",
    "/private/etc/daily.local", "/private/etc/weekly.local", "/private/etc/monthly.local", "/private/etc/launchd.conf",
    "/private/etc/rc.common", "/Library/Receipts/InstallHistory.plist",
    "/Users/*/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
)
MACOS_POWERLOG = "/private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL"
# directory, depth, largest file, file name suffixes (empty: any)
MACOS_EXTRA_DIRS = (
    ("/private/etc/periodic", 2, 1 << 20, ()),
    ("/private/etc/emond.d", 2, 1 << 20, ()),
    ("/private/var/db/emondClients", 1, 1 << 20, ()),
    ("/Users/*/Library/Application Support/com.apple.sharedfilelist", 2, 10 << 20, (".sfl2", ".sfl3")),
)
MACOS_BIOME = ("/private/var/db/biome/streams/restricted", "/Users/*/Library/Biome/streams/restricted")
MACOS_BIOME_MAX_FILES = 2000
# The unified-log store into raw/unified_log_store/ with its layout kept, uuidtext/ first (nothing
# reads without it), then the newest files first, up to 2 GB, as gandalf.sh and gandalf.py take it
MACOS_LOG_STORES = (("/private/var/db/uuidtext", "uuidtext"), ("/private/var/db/diagnostics", "diagnostics"))
MACOS_LOG_STORE_MAX = 2 << 30


def collect_macos_log_store(mnt, dest):
    """Copy the unified-log store from a mounted image; returns the number of files taken."""
    budget, count = MACOS_LOG_STORE_MAX, 0
    for top, label in MACOS_LOG_STORES:
        files = []
        for source in _walk(mnt + top, 4) if os.path.isdir(mnt + top) else []:
            try:
                if not os.path.islink(source):
                    files.append((os.path.getmtime(source), os.path.getsize(source), source))
            except OSError:
                pass
        for _, size, source in sorted(files, reverse=True):
            if size > budget:
                continue
            target = os.path.join(dest, "unified_log_store", label, os.path.relpath(source, mnt + top))
            try:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.copy2(source, target)
            except OSError:
                continue
            budget -= size
            count += 1
    return count


def collect_macos_extras(mnt, dest, img, output_directory, stage, verbosity):
    """
    BTM items, shared file lists, Notification Center, ExecPolicy, KextPolicy,
    XProtect, emond, periodic, InstallHistory, PowerLog and Biome from a mounted
    macOS image, into raw/macos/; the unified-log store into raw/unified_log_store/.
    """
    macos = dest + "macos/"
    os.makedirs(macos, exist_ok=True)
    count = 0

    def take(source, limit=64 << 20):
        nonlocal count
        try:
            if not os.path.isfile(source) or os.path.islink(source) or not 0 < os.path.getsize(source) <= limit:
                return
            shutil.copy2(source, macos + _flat(source[len(mnt):]))
            count += 1
        except OSError:
            pass

    for pattern in MACOS_EXTRA_DATABASES:
        for source in sorted(glob.glob(mnt + pattern)):
            take(source)
            take(source + "-wal")
    take(mnt + MACOS_POWERLOG, 256 << 20)
    take(mnt + MACOS_POWERLOG + "-wal", 256 << 20)
    for pattern in MACOS_EXTRA_FILES:
        for source in sorted(glob.glob(mnt + pattern)):
            take(source)
    for pattern, depth, limit, suffixes in MACOS_EXTRA_DIRS:
        for top in sorted(glob.glob(mnt + pattern)):
            for source in _walk(top, depth):
                if not suffixes or source.endswith(suffixes):
                    take(source, limit)
    biome = 0
    for pattern in MACOS_BIOME:
        for top in sorted(glob.glob(mnt + pattern)):
            for source in _walk(top, 4):
                if biome >= MACOS_BIOME_MAX_FILES:
                    break
                take(source, 10 << 20)
                biome += 1
    count += collect_macos_log_store(mnt, dest)
    entry, prnt = "{},{},{},macos background items and policy databases\n".format(
        datetime.now().isoformat(), img.split("::")[0], stage
    ), " -> {} -> {} {} macOS background-item, policy-database, Biome and unified-log artefacts from '{}'".format(
        datetime.now().isoformat().replace("T", " "), stage, count, img.split("::")[0]
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)



def collect_mac_artefacts(
    dest,
    img,
    item,
    mnt,
    output_directory,
    sha256,
    stage,
    symlinkvalue,
    userprofiles,
    verbosity,
    volatility,
    vssimage,
    vsstext,
):
    if not os.path.isdir(item):  # files
        if (
            item == mnt + "/etc/passwd"
            or item == mnt + "/etc/shadow"
            or item == mnt + "/etc/group"
        ):
            entry, prnt = "{},{},{},'{}'\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                item,
            ), " -> {} -> {} '/etc/{}' file from '{}'".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                item.split("/")[-1],
                img.split("::")[0],
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            try:
                shutil.copy2(item, dest)
            except:
                pass

        if item == mnt + "/etc/hosts":
            entry, prnt = "{},{},{},'/etc/hosts'\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
            ), " -> {} -> {} '/etc/hosts' from '{}'".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                img.split("::")[0],
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            try:
                shutil.copy2(item, dest)
            except:
                pass

        if item == mnt + "/etc/crontab":
            entry, prnt = "{},{},{},'{}'\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                item,
            ), " -> {} -> {} '{}'{} from '{}'".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                item,
                vsstext.replace("vss", "volume shadow copy #"),
                img.split("::")[0],
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            try:
                shutil.copy2(item, dest)
            except:
                pass

    elif len(os.listdir(item)) > 0:  # directories
        if (
            item == mnt + "/Library/Logs"
            or item == mnt + "/etc/security"
            or item == mnt + "/var/log"
        ):
            try:
                os.stat(dest + "logs/")
            except:
                os.makedirs(dest + "logs/")
            item_list = os.listdir(item)
            for each in item_list:
                try:
                    (
                        entry,
                        prnt,
                    ) = "{},{},{},'{}' file\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                        each,
                    ), " -> {} -> {} log '{}' from '{}'".format(
                        datetime.now().isoformat().replace("T", " "),
                        stage,
                        each,
                        img.split("::")[0],
                    )
                    write_audit_log_entry(
                        verbosity,
                        output_directory,
                        entry,
                        prnt,
                    )
                    if "etc/security" not in item:
                        prefix = item.split("/")[-2].lower() + "+"
                    else:
                        prefix = item.split("/")[-1].lower() + "+"
                    shutil.copy2(
                        item + "/" + each,
                        dest + "logs/" + prefix + each,
                    )
                except:
                    pass

        if (
            item == mnt + "/Library/Preferences"
            or item == mnt + "/Library/LaunchAgents"
            or item == mnt + "/Library/LaunchDaemons"
            or item == mnt + "/Library/StartupItems"
            or item == mnt + "/System/Library/Preferences"
            or item == mnt + "/System/Library/LaunchAgents"
            or item == mnt + "/System/Library/LaunchDaemons"
            or item == mnt + "/System/Library/StartupItems"
        ):
            try:
                os.stat(dest + "plists/")
            except:
                os.makedirs(dest + "plists/")
            item_list = os.listdir(item)
            for each in item_list:
                if each.endswith(".plist"):
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' plist\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} plist '{}' from '{}'".format(
                            datetime.now().isoformat().replace("T", " "),
                            stage,
                            each,
                            img.split("::")[0],
                        )
                        write_audit_log_entry(
                            verbosity,
                            output_directory,
                            entry,
                            prnt,
                        )
                        if "System" in item:
                            prefix = (
                                item.split("/")[-3].lower()
                                + "+"
                                + item.split("/")[-1].lower()
                                + "-"
                            )
                        else:
                            prefix = item.split("/")[-1].lower() + "+"
                        shutil.copy2(
                            item + "/" + each,
                            dest + "plists/" + prefix + each,
                        )
                    except:
                        pass

        if item == mnt + "/.Trashes":
            dest = dest + "trash/"
            try:
                os.stat(dest + "trash/")
            except:
                os.makedirs(dest + "trash/")
            item_list = os.listdir(item)
            for each in item_list:
                try:
                    (
                        entry,
                        prnt,
                    ) = "{},{},{},'{}' trash file\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                        each,
                    ), " -> {} -> {} trash file '{}'{} from '{}'".format(
                        datetime.now().isoformat().replace("T", " "),
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
                    shutil.copy2(item + "/" + each, dest + "trash/")
                except:
                    pass

        if item == mnt + "/tmp":
            try:
                os.stat(dest + "tmp/")
            except:
                os.makedirs(dest + "tmp/")
            item_list = os.listdir(item)
            for each in item_list:
                if not os.path.isdir(each):
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' tmp file\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} tmp file '{}'{} from '{}'".format(
                            datetime.now().isoformat().replace("T", " "),
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
                        shutil.copy2(
                            item + "/" + each,
                            dest + "tmp/" + each,
                        )
                    except:
                        pass
                else:
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' tmp directory\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} tmp directory '{}'{} from '{}'".format(
                            datetime.now().isoformat().replace("T", " "),
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
                        shutil.copytree(
                            item + "/" + each,
                            dest + "tmp/" + each,
                        )
                    except:
                        pass

        if item == mnt + "/etc":
            collect_macos_extras(mnt, dest, img, output_directory, stage, verbosity)
        if item == mnt + "/Users/":
            dest = mac_users(
                dest,
                img,
                item,
                output_directory,
                stage,
                sha256,
                symlinkvalue,
                userprofiles,
                verbosity,
                vssimage,
                vsstext,
            )
        if volatility and item == mnt + "/":
            item_list = os.listdir(item)
            if len(item_list) > 0:
                for each in item_list:
                    if (
                        item == mnt + "/var/vm/sleepimage"
                        or item == mnt + "/var/vm/swapfile"
                    ):
                        if not os.path.exists(dest + each):
                            (
                                entry,
                                prnt,
                            ) = "{},{},{},'{}'\n".format(
                                datetime.now().isoformat(),
                                img.split("::")[0],
                                stage,
                                each,
                            ), " -> {} -> {} '{}'{} from '{}'".format(
                                datetime.now().isoformat().replace("T", " "),
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
                            shutil.copy2(item + each, dest + each)
