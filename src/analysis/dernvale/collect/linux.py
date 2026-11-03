#!/usr/bin/env python3 -tt
import csv
import hashlib
import os
import shutil
import stat
from datetime import datetime

from dernvale.audit import write_audit_log_entry
from dernvale.collect.users.linux import linux_users

# Collected into raw/linux/ under their path with '/' as '+' (process/linux_artefacts.py).
# gandalf.sh and gandalf.py carry the same lists; keep the three in step.
LINUX_EXTRA_FILES = (
    "/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/environment", "/etc/profile", "/etc/bash.bashrc",
    "/etc/bashrc", "/etc/rc.local", "/etc/sudoers", "/run/utmp", "/var/run/utmp", "/var/log/wtmp",
    "/var/log/btmp", "/var/log/lastlog", "/var/log/faillog",
    "/var/lib/wtmpdb/wtmp.db", "/var/lib/lastlog/lastlog2.db",
    "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db",
    "/var/lib/containers/storage/overlay-containers/containers.json",
    "/var/lib/containers/storage/db.sql", "/var/lib/containers/storage/db.sql-wal",
    "/var/lib/containers/storage/libpod/bolt_state.db",
)
# directory, depth, largest file, file name suffixes (empty: any)
LINUX_EXTRA_DIRS = (
    ("/etc/ld.so.conf.d", 1, 1 << 20, ()),
    ("/etc/profile.d", 1, 1 << 20, ()),
    ("/etc/pam.d", 1, 1 << 20, ()),
    ("/etc/sudoers.d", 1, 1 << 20, ()),
    ("/etc/udev/rules.d", 1, 1 << 20, (".rules",)),
    ("/usr/lib/udev/rules.d", 1, 1 << 20, (".rules",)),
    ("/lib/udev/rules.d", 1, 1 << 20, (".rules",)),
    ("/etc/systemd/system-generators", 1, 10 << 20, ()),
    ("/etc/systemd/user-generators", 1, 10 << 20, ()),
    ("/usr/local/lib/systemd/system-generators", 1, 10 << 20, ()),
    ("/etc/xdg/autostart", 1, 1 << 20, (".desktop",)),
    ("/etc/update-motd.d", 1, 1 << 20, ()),
    ("/etc/nginx", 3, 1 << 20, ()),
    ("/etc/apache2", 3, 1 << 20, ()),
    ("/etc/httpd", 3, 1 << 20, ()),
    ("/var/lib/docker/containers", 2, 10 << 20, ("config.v2.json", "hostconfig.json")),
    ("/var/lib/docker/containers", 2, 64 << 20, ("-json.log",)),
    ("/var/log/pods", 3, 64 << 20, (".log",)),
    ("/etc/kubernetes/manifests", 1, 1 << 20, (".yaml", ".yml", ".json")),
    ("/var/log/kubernetes", 2, 256 << 20, (".log",)),
)
CONTAINER_MAX_FILES = 5000  # per container, in its writable-layer listing
CONTAINER_COPY_MAX_FILES = 500  # executables copied per container, into raw/container_layer/<id>/
CONTAINER_COPY_MAX_BYTES = 64 << 20
WEB_ROOTS = ("/var/www", "/srv/www", "/srv/http", "/usr/share/nginx/html")
WEB_SCRIPTS = (".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phar", ".inc", ".jsp", ".jspx",
               ".asp", ".aspx", ".ashx", ".asmx", ".cgi", ".pl", ".py", ".sh", ".cfm")
WEB_MAX_FILES = 5000
# under each home: user_profiles/<user>+<name without the dot>
LINUX_USER_FILES = (".zsh_history", ".viminfo", ".lesshst", ".python_history", ".mysql_history",
                    ".psql_history", ".wget-hsts", ".local/share/recently-used.xbel")
LINUX_USER_DIRS = ((".config/autostart", (".desktop",)), (".config/systemd/user", (".service", ".timer")))
TMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
LISTING_MAX_HASH = 100 << 20


def _flat(path):
    return path.lstrip("/").replace("/", "+")


def _walk(top, depth):
    """Files under top, at most depth levels down, without following symlinks."""
    top_depth = top.rstrip("/").count("/")
    for root, dirs, files in os.walk(top):
        if root.count("/") - top_depth + 1 >= depth:
            dirs[:] = []
        for name in files:
            yield os.path.join(root, name)


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def executable_kind(path):
    """'elf', 'script' or 'executable' for a file worth listing in a temp directory, else ''."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
        mode = os.lstat(path).st_mode
    except OSError:
        return ""
    if head == b"\x7fELF":
        return "elf"
    if head[:2] == b"#!":
        return "script"
    return "executable" if mode & 0o111 else ""


def container_layers(mnt):
    """(container id, writable-layer directory) for each Docker container on overlay2."""
    docker = mnt + "/var/lib/docker"
    try:
        ids = sorted(os.listdir(docker + "/containers"))
    except OSError:
        return
    for cid in ids:
        try:
            with open(os.path.join(docker, "image/overlay2/layerdb/mounts", cid, "mount-id")) as fh:
                upper = os.path.join(docker, "overlay2", fh.read().strip(), "diff")
        except OSError:
            continue
        yield cid, upper


def container_change_listing(mnt):
    """Each Docker container's writable layer: everything changed since its image, with deleted
    files as overlay whiteouts (character devices 0/0). Listed and hashed; the executables
    among them are copied by collect_linux_extras."""
    rows = []
    for cid, upper in container_layers(mnt):
        for count, source in enumerate(_walk(upper, 12)):
            if count >= CONTAINER_MAX_FILES:
                break
            try:
                info = os.lstat(source)
            except OSError:
                continue
            kind, digest = "", ""
            if stat.S_ISCHR(info.st_mode):
                kind = "deleted"
            elif stat.S_ISREG(info.st_mode):
                kind = executable_kind(source)
                if kind and info.st_size <= LISTING_MAX_HASH:
                    try:
                        digest = _sha256(source)
                    except OSError:
                        pass
            else:
                continue
            rows.append({"Container": cid[:12], "Path": source[len(upper):], "Size": info.st_size,
                         "Mode": oct(info.st_mode & 0o7777), "Kind": kind, "SHA256": digest,
                         "MTime": int(info.st_mtime)})
    return rows


def collect_linux_extras(mnt, dest, img, output_directory, stage, verbosity):
    """
    The persistence, login-record and history artefacts process/linux_artefacts.py
    parses, from a mounted Linux image: into raw/linux/ (and raw/user_profiles/), with
    a listing of executables in the temp directories as raw/linux/gandalf+tmp_executables.csv.
    """
    linux, profiles = dest + "linux/", dest + "user_profiles/"
    os.makedirs(linux, exist_ok=True)
    seen, count = set(), 0

    def take(source, destination, limit=None):
        nonlocal count
        try:
            info = os.lstat(source)
            real = os.path.realpath(source)
            if not stat.S_ISREG(info.st_mode) or info.st_size == 0 or real in seen:
                return
            if limit and info.st_size > limit:
                return
            seen.add(real)
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            shutil.copy2(source, destination)
            count += 1
        except OSError:
            pass

    for path in LINUX_EXTRA_FILES:
        take(mnt + path, linux + _flat(path), 64 << 20)
    for top, depth, limit, suffixes in LINUX_EXTRA_DIRS:
        if os.path.isdir(mnt + top):
            for source in _walk(mnt + top, depth):
                if not suffixes or source.endswith(suffixes):
                    take(source, linux + _flat(source[len(mnt):]), limit)
    web = 0
    for top in WEB_ROOTS:
        if os.path.isdir(mnt + top):
            for source in _walk(mnt + top, 6):
                if web >= WEB_MAX_FILES:
                    break
                if source.lower().endswith(WEB_SCRIPTS):
                    take(source, linux + _flat(source[len(mnt):]), 1 << 20)
                    web += 1
    homes = [mnt + "/root"]
    if os.path.isdir(mnt + "/home"):
        homes += [os.path.join(mnt + "/home", h) for h in sorted(os.listdir(mnt + "/home"))]
    for home in homes:
        if not os.path.isdir(home):
            continue
        user = os.path.basename(home)
        for name in LINUX_USER_FILES:
            take(os.path.join(home, name), profiles + user + "+" + os.path.basename(name).lstrip("."))
        for sub, suffixes in LINUX_USER_DIRS:
            if os.path.isdir(os.path.join(home, sub)):
                for source in _walk(os.path.join(home, sub), 1):
                    if source.endswith(suffixes):
                        take(source, linux + _flat(source[len(mnt):]), 1 << 20)
    rows = []
    for top in TMP_DIRS:
        if os.path.isdir(mnt + top):
            for source in _walk(mnt + top, 3):
                kind = executable_kind(source)
                if not kind:
                    continue
                info = os.lstat(source)
                rows.append({"Path": source[len(mnt):], "Size": info.st_size, "Mode": oct(info.st_mode & 0o7777),
                             "UID": info.st_uid, "Kind": kind,
                             "SHA256": _sha256(source) if info.st_size <= LISTING_MAX_HASH else "",
                             "MTime": int(info.st_mtime)})
    if rows:
        with open(linux + "gandalf+tmp_executables.csv", "w", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    changes = container_change_listing(mnt)
    if changes:
        with open(linux + "gandalf+container_changes.csv", "w", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=list(changes[0]))
            writer.writeheader()
            writer.writerows(changes)
    # The executables and scripts each container gained, as gandalf.py and gandalf.sh take them
    for cid, upper in container_layers(mnt):
        taken = 0
        for source in _walk(upper, 12):
            if taken >= CONTAINER_COPY_MAX_FILES:
                break
            before = count
            if executable_kind(source):
                take(source, dest + "container_layer/" + cid[:12] + "/" + _flat(source[len(upper):]),
                     CONTAINER_COPY_MAX_BYTES)
            taken += count - before
    entry, prnt = "{},{},{},linux persistence and history artefacts\n".format(
        datetime.now().isoformat(), img.split("::")[0], stage
    ), " -> {} -> {} {} Linux persistence, login-record and history artefacts from '{}'".format(
        datetime.now().isoformat().replace("T", " "), stage, count, img.split("::")[0]
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)



def collect_linux_artefacts(
    dest,
    img,
    item,
    mnt,
    output_directory,
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
            item == mnt + "/etc/security"
            or item == mnt + "/etc/systemd"
            or item == mnt + "/etc/modules-load"
        ):
            dest = dest + "conf/"
            try:
                os.stat(dest)
            except:
                os.makedirs(dest)
            item_list = os.listdir(item)
            for each in item_list:
                if each.endswith(".conf"):
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' configuration file\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} configuration file '{}'{} from '{}'".format(
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
                            dest + item.split("/")[-1].lower() + "+" + each,
                        )
                    except:
                        pass

        if item == mnt + "/var/log":
            try:
                os.stat(dest + "logs/")
            except:
                os.makedirs(dest + "logs/")
            item_list = os.listdir(item)
            for eachlog in item_list:
                try:
                    (
                        entry,
                        prnt,
                    ) = "{},{},{},'{}' log file\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                        eachlog,
                    ), " -> {} -> {} log file '{}'{} from '{}'".format(
                        datetime.now().isoformat().replace("T", " "),
                        stage,
                        eachlog,
                        vsstext.replace("vss", "volume shadow copy #"),
                        img.split("::")[0],
                    )
                    write_audit_log_entry(
                        verbosity,
                        output_directory,
                        entry,
                        prnt,
                    )
                    shutil.copy2(
                        item + "/" + eachlog,
                        dest + "logs/" + item.split("/")[-2].lower() + "+" + eachlog,
                    )
                except:
                    pass

        if item == mnt + "/var/log/journal":
            try:
                os.stat(dest + "journal/")
            except:
                os.makedirs(dest + "journal/")
            item_list = os.listdir(item)
            for eachdir in item_list:
                if os.path.isdir(os.path.join(item, eachdir)) and "journal" in os.path.join(item, eachdir):
                    try:
                        os.stat(dest + "journal/")
                    except:
                        os.makedirs(dest + "journal/")
                    (
                        entry,
                        prnt,
                    ) = "{},{},{},systemd journal files\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                    ), " -> {} -> {} systemd journal files{} from '{}'".format(
                        datetime.now().isoformat().replace("T", " "),
                        stage,
                        vsstext.replace("vss", "volume shadow copy #"),
                        img.split("::")[0],
                    )
                    write_audit_log_entry(
                        verbosity,
                        output_directory,
                        entry,
                        prnt,
                    )
                    shutil.copytree(
                        os.path.join(item, eachdir),
                        dest + "journal/" + eachdir,
                    )

        if item == mnt + "/usr/lib/systemd/user":
            try:
                os.stat(dest + "services/")
            except:
                os.makedirs(dest + "services/")
            item_list = os.listdir(item)
            for each in item_list:
                if (
                    each.endswith(".service")
                    or each.endswith(".target")
                    or each.endswith(".socket")
                ):
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' service file\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} service file '{}'{} from '{}'".format(
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
                            dest + "services/" + each,
                        )
                    except:
                        pass

        if item == mnt + "/var/cache/cups" or item == mnt + "/var/cups":
            try:
                os.stat(dest + "jobs/")
            except:
                os.makedirs(dest + "jobs/")
            item_list = os.listdir(item)
            for each in item_list:
                if each.startswith("job."):
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' job file\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} job file '{}'{} from '{}'".format(
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
                            dest + "jobs/" + each,
                        )
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
                        ) = "{},{},{},'{}' temp file\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} temp file '{}'{} from '{}'".format(
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
                        ) = "{},{},{},'{}' /tmp directory\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} /tmp directory '{}'{} from '{}'".format(
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

        if item == mnt + "/root":
            if os.path.exists(item + "/.bash_history"):
                (
                    entry,
                    prnt,
                ) = "{},{},{},'{}' bash files\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    item.split("/")[-1],
                ), " -> {} -> {} '{}'{} bash files from '{}'".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage,
                    item.split("/")[-1],
                    vsstext.replace("vss", "volume shadow copy #"),
                    img.split("::")[0],
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                try:
                    shutil.copy2(
                        item + "/.bash_aliases",
                        dest + item.split("/")[-1] + "+bash_aliases",
                    )
                    shutil.copy2(
                        item + "/.bash_history",
                        dest + item.split("/")[-1] + "+bash_history",
                    )
                    shutil.copy2(
                        item + "/.bash_logout",
                        dest + item.split("/")[-1] + "+bash_logout",
                    )
                    shutil.copy2(
                        item + "/.bashrc",
                        dest + item.split("/")[-1] + "+bashrc",
                    )
                    shutil.copy2(
                        item + "/.bash_session",
                        dest + item.split("/")[-1] + "+bash_session",
                    )
                except:
                    pass
            if os.path.exists(item + "/.local/share/keyrings/"):
                for keytype in os.listdir(item + "/.local/share/keyrings/"):
                    if keytype.endswith(".keyring") or keytype.endswith(".keystore"):
                        try:
                            (
                                entry,
                                prnt,
                            ) = "{},{},{},'root' {}\n".format(
                                datetime.now().isoformat(),
                                img.split("::")[0],
                                stage,
                                keytype.split(".key")[1],
                            ), " -> {} -> {} {} for profile 'root'{} from '{}'".format(
                                datetime.now().isoformat().replace("T", " "),
                                stage,
                                keytype.split(".key")[1],
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
                                item + "/.local/share/keyrings/" + keytype,
                                dest + "root--" + keytype,
                            )
                        except:
                            pass
        if item == mnt + "/etc":
            collect_linux_extras(mnt, dest, img, output_directory, stage, verbosity)
        if item == mnt + "/home":
            dest = linux_users(
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
