#!/usr/bin/env python3 -tt
import csv
import glob
import os
import re
import shutil
import stat
from datetime import datetime

from rowanholt.audit import write_audit_log_entry
from rowanholt.collect.linux import _flat, _walk
from rowanholt.collect.users.mac import mac_users

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
# Per-user crontabs, into raw/cron/ as <user>+crontab, as gandalf.sh takes them
MACOS_CRONTABS = ("/private/var/at/tabs/*", "/usr/lib/cron/tabs/*")
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
# Spotlight's index stores, as Gandalf takes them: store.db with the dbStr maps it needs, flattened
MACOS_SPOTLIGHT_ROOTS = ("/System/Volumes/Data/.Spotlight-V100", "/.Spotlight-V100")
MACOS_SPOTLIGHT_FILES = re.compile(r"^(?:\.?store\.db|dbStr-\d+\.map\..+|VolumeConfiguration\.plist)$")
MACOS_SPOTLIGHT_MAX = 1 << 30
# A listing of where an attacker stages and hides things, into raw/macos/gandalf+file_listing.csv:
# (folder, depth). Homes only near the top: their Library is collected artefact by artefact.
MACOS_LISTING_ROOTS = (("/private/tmp", 8), ("/private/var/tmp", 8), ("/Users/Shared", 8), ("/Users", 3))
MACOS_LISTING_SKIP = frozenset({"Library", ".Trash", "node_modules", ".git"})
MACOS_LISTING_MAX = 100000
MACOS_LISTING_FIELDS = ("Path", "Type", "Size", "Mode", "UID", "MTime", "Target", "Kind", "FinderHidden")
FINDER_INVISIBLE = 0x4000  # kIsInvisible in the Finder flags, bytes 8-9 of com.apple.FinderInfo


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


def collect_macos_spotlight(mnt, dest):
    """Copy Spotlight's index stores from a mounted image into raw/spotlight/, named as Gandalf names them
    (Store-V2+<UUID>+store.db); returns the number of files taken."""
    count = 0
    for top in MACOS_SPOTLIGHT_ROOTS:
        if not os.path.isdir(mnt + top):
            continue
        for source in _walk(mnt + top, 3):
            try:
                if not MACOS_SPOTLIGHT_FILES.match(os.path.basename(source)) or os.path.islink(source) or \
                        os.path.getsize(source) > MACOS_SPOTLIGHT_MAX:
                    continue
                target = os.path.join(dest, "spotlight", os.path.relpath(source, mnt + top).replace(os.sep, "+"))
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.copy2(source, target)
                count += 1
            except OSError:
                continue
        break  # the Data volume's, else the root's: the same store under two paths
    return count


def _content_kind(path):
    """What a file holds, from its first bytes: a keychain database, PEM certificates or keys,
    a Mach-O binary or a script; '' otherwise."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
    except OSError:
        return ""
    if head[:4] == b"kych":
        return "keychain"
    if head.startswith(b"-----BEGIN"):
        return "pem-key" if b"PRIVATE KEY" in head else "pem-certificate"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho"
    return "script" if head[:2] == b"#!" else ""


def _finder_hidden(path):
    """Whether the Finder flags make it invisible (SetFile -a V, or a written FinderInfo). Only where
    the mount exposes extended attributes; chflags hidden is an inode flag apfs-fuse doesn't show."""
    try:
        info = os.getxattr(path, "com.apple.FinderInfo", follow_symlinks=False)
    except (AttributeError, OSError):
        return ""
    return "yes" if len(info) >= 10 and int.from_bytes(info[8:10], "big") & FINDER_INVISIBLE else ""


def macos_file_listing(mnt):
    """Every entry in the temp folders, /Users/Shared and the top of each home, without following
    symlinks: what it is, who owns it, when it changed, and what it holds."""
    rows, seen = [], set()
    for folder, depth in MACOS_LISTING_ROOTS:
        top = mnt + folder
        stack = [(top, 0)]
        while stack and len(rows) < MACOS_LISTING_MAX:
            current, level = stack.pop()
            try:
                entries = sorted(os.scandir(current), key=lambda e: e.name)
            except OSError:
                continue
            for entry in entries:
                if entry.path in seen or len(rows) >= MACOS_LISTING_MAX:
                    continue
                seen.add(entry.path)
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                kind, target = "", ""
                if stat.S_ISLNK(info.st_mode):
                    entry_type = "symlink"
                    try:
                        target = os.readlink(entry.path)
                    except OSError:
                        pass
                elif stat.S_ISDIR(info.st_mode):
                    entry_type = "directory"
                    if level + 1 < depth and entry.name not in MACOS_LISTING_SKIP:
                        stack.append((entry.path, level + 1))
                elif stat.S_ISREG(info.st_mode):
                    entry_type, kind = "file", _content_kind(entry.path)
                else:
                    continue
                rows.append({"Path": entry.path[len(mnt):], "Type": entry_type, "Size": info.st_size,
                             "Mode": oct(info.st_mode & 0o7777), "UID": info.st_uid, "MTime": int(info.st_mtime),
                             "Target": target, "Kind": kind, "FinderHidden": _finder_hidden(entry.path)})
    return rows


def collect_macos_file_listing(mnt, dest):
    """The listing as raw/macos/gandalf+file_listing.csv; how many entries it holds."""
    rows = macos_file_listing(mnt)
    if rows:
        with open(dest + "macos/gandalf+file_listing.csv", "w", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=MACOS_LISTING_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
    return len(rows)


def collect_macos_extras(mnt, dest, img, output_directory, stage, verbosity):
    """
    BTM items, shared file lists, Notification Center, ExecPolicy, KextPolicy,
    XProtect, emond, periodic, InstallHistory, PowerLog and Biome from a mounted
    macOS image, into raw/macos/, with a listing of the temp folders and homes; per-user crontabs
    into raw/cron/; the unified-log store into raw/unified_log_store/, Spotlight's
    index into raw/spotlight/.
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
    for pattern in MACOS_CRONTABS:
        for source in sorted(glob.glob(mnt + pattern)):
            if os.path.isfile(source) and not os.path.islink(source):
                os.makedirs(dest + "cron/", exist_ok=True)
                try:
                    shutil.copy2(source, dest + "cron/" + os.path.basename(source) + "+crontab")
                    count += 1
                except OSError:
                    pass
    count += collect_macos_log_store(mnt, dest)
    count += collect_macos_spotlight(mnt, dest)
    count += collect_macos_file_listing(mnt, dest)
    entry, prnt = "{},{},{},macos background items and policy databases\n".format(
        datetime.now().isoformat(), img.split("::")[0], stage
    ), " -> {} -> {} {} macOS background-item, policy-database, Biome, unified-log and Spotlight artefacts from '{}'".format(
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
    # the path as the lists below name it: /private/etc is /etc (collect.py takes /private's)
    spot = mnt + item[len(mnt + "/private"):] if item.startswith(mnt + "/private/") else item
    if not os.path.isdir(item):  # files
        if (
            spot == mnt + "/etc/passwd"
            or spot == mnt + "/etc/shadow"
            or spot == mnt + "/etc/group"
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

        if spot == mnt + "/etc/hosts":
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

        if spot == mnt + "/etc/crontab":
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
            spot == mnt + "/Library/Logs"
            or spot == mnt + "/etc/security"
            or spot == mnt + "/var/log"
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
            spot == mnt + "/Library/Preferences"
            or spot == mnt + "/Library/LaunchAgents"
            or spot == mnt + "/Library/LaunchDaemons"
            or spot == mnt + "/Library/StartupItems"
            or spot == mnt + "/System/Library/Preferences"
            or spot == mnt + "/System/Library/LaunchAgents"
            or spot == mnt + "/System/Library/LaunchDaemons"
            or spot == mnt + "/System/Library/StartupItems"
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

        if spot == mnt + "/.Trashes":
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

        if spot == mnt + "/tmp":
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

        if spot == mnt + "/etc":
            collect_macos_extras(mnt, dest, img, output_directory, stage, verbosity)
        if spot == mnt + "/Users/":
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
        if volatility and spot == mnt + "/":
            item_list = os.listdir(item)
            if len(item_list) > 0:
                for each in item_list:
                    if (
                        spot == mnt + "/var/vm/sleepimage"
                        or spot == mnt + "/var/vm/swapfile"
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
