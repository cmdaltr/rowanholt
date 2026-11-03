"""Artefacts Gandalf collects that Elrond's other processors leave alone.

Each file is routed to a parser in process/extractions/ and written to cooked/<name>.csv:

  Windows   thumbcache/iconcache databases, $LogFile, paging files (strings),
            PSReadLine history, Amcache.hve (Artemis)
  Unix      crontab, cron.d and run-parts scripts, user crontabs and at jobs,
            authorized_keys and known_hosts, sshd_config, sudoers outside raw/linux/,
            passwd with shadow
  macOS     TCC.db, knowledgeC.db, QuarantineEventsV2, Biome streams, ASL stores, FSEvents
  staging   everything collected from temp and shared directories, flagging hidden
            names and download tooling
"""

import hashlib
import logging
import os
import re
from typing import Dict, List, Optional, Tuple

from rivendell.process.extractions import artemis
from rivendell.process.extractions import asl as asl_store
from rivendell.process.extractions import biome
from rivendell.process.extractions import fsevents
from rivendell.process.extractions import macos_databases
from rivendell.process.extractions import ntfs_logfile
from rivendell.process.extractions import paged_strings
from rivendell.process.extractions import powershell_history
from rivendell.process.extractions import thumbcache
from rivendell.process.extractions import unix_config
from rivendell.process.linux_artefacts import HEADERS as LINUX_HEADERS
from rivendell.process.linux_artefacts import _append_rows, _audit, _cooked, _techniques, sudoers_rows
from rivendell.process.mac_artefacts import sqlite_tables

logger = logging.getLogger(__name__)

RAW = re.compile(r"/artefacts/raw(?:/vss\d+)?/(.+)$")
PAGING_FILES = ("pagefile.sys", "swapfile.sys", "hiberfil.sys")
STAGING_DIRS = ("tmp/", "shared/", "var_tmp/", "dev_shm/", "container_layer/")
# dot-names the OS itself leaves in shared and temp directories
BENIGN_DOTFILES = {".localized", ".ds_store", ".betamigrated", ".placeholder", ".x11-unix", ".ice-unix", ".font-unix",
                   ".xim-unix", ".test-unix", ".com.apple.timemachine.supported"}
DOWNLOAD = re.compile(rb"\b(curl|wget|fetch)\b[^\n]{0,200}\bhttps?://|invoke-webrequest|downloadstring|urllib\.request", re.I)
SSH_KEY_TECHNIQUE_FLAGS = ("forced command", "sets environment", "comment names another host", "key for root")

HEADERS = {
    "thumbcache.csv": thumbcache.HEADER,
    "ntfs_logfile.csv": ntfs_logfile.HEADER,
    "paged_strings.csv": paged_strings.HEADER,
    "powershell_history.csv": powershell_history.HEADER,
    "cron.csv": unix_config.CRON_HEADER,
    "at_jobs.csv": unix_config.AT_HEADER,
    "ssh_keys.csv": unix_config.KEY_HEADER,
    "sshd_config.csv": unix_config.SSHD_HEADER,
    "accounts.csv": unix_config.ACCOUNT_HEADER,
    "sudoers.csv": LINUX_HEADERS["sudoers.csv"],
    "tcc.csv": macos_databases.TCC_HEADER,
    "knowledgec.csv": macos_databases.KNOWLEDGE_HEADER,
    "quarantine_events.csv": macos_databases.QUARANTINE_HEADER,
    "biome.csv": biome.HEADER,
    "asl.csv": asl_store.HEADER,
    "fsevents.csv": fsevents.HEADER,
    "staged_files.csv": ["Source", "Size", "SHA256", "Hidden", "Flag", "LastWriteTime"],
}
Route = Tuple[str, List[Dict], str, List[str]]


def raw_relative(artefact: str) -> Optional[str]:
    match = RAW.search(artefact)
    return match.group(1) if match else None


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _user_file(name: str) -> Tuple[str, str]:
    """<user>+<file> (user_profiles/) -> (user, file)."""
    user, _, kind = name.partition("+")
    return user, kind


def _route_windows(rel: str, name: str, artefact: str, cooked: str) -> Optional[Route]:
    lower = name.lower()
    if rel.startswith("thumbcache/") and lower.endswith(".db"):
        stem = os.path.splitext(name.split("+")[-1])[0]
        rows = thumbcache.thumbcache_rows(artefact, os.path.join(cooked, "thumbcache", stem))
        return "thumbcache.csv", rows, "thumbnail cache", []
    if rel == "$LogFile" or rel.endswith("/$LogFile"):
        rows, _ = ntfs_logfile.logfile_rows(artefact)
        return "ntfs_logfile.csv", rows, "NTFS $LogFile", []
    if lower in PAGING_FILES:
        return "paged_strings.csv", paged_strings.paged_strings(artefact), "paging file strings", []
    if rel.startswith("powershell/") and "consolehost_history" in lower:
        rows, techniques = powershell_history.powershell_history_rows(artefact, powershell_history.history_user(name))
        return "powershell_history.csv", rows, "PowerShell history", techniques
    return None


def _route_unix(rel: str, name: str, artefact: str, host: str) -> Optional[Route]:
    folder = rel.split("/")[0] if "/" in rel else ""
    if rel == "crontab":
        rows = unix_config.cron_rows(artefact, "/etc/crontab")
        return "cron.csv", rows, "crontab", ["T1053.003"] if any(r["Flag"] for r in rows) else []
    if folder == "at_jobs" or (folder == "cron_jobs" and name.startswith("atjobs+")) or \
            re.search(r"spool\+(cron\+)?at(jobs)?\+", name):
        if name.endswith(".SEQ") or "+spool+" in name.lower():
            return "", [], "", []
        spool = "/var/spool/cron/" if folder == "cron_jobs" else "/var/spool/at/" if folder == "at_jobs" else "/"
        rows = unix_config.at_rows(artefact, spool + name.replace("+", "/"))
        return "at_jobs.csv", rows, "at job", ["T1053.002"] if rows else []
    if folder == "cron_jobs" or name.endswith("+crontab") or re.search(r"spool\+cron|cron\+tabs|crontabs\+", name):
        # a user's crontab: /var/spool/cron/[crontabs/]<user>, or macOS cron/<user>+crontab
        user = name[:-len("+crontab")] if name.endswith("+crontab") else name.rpartition("+")[2]
        rows = unix_config.cron_rows(artefact, "crontab of " + user, user=user)
        return "cron.csv", rows, "user crontab", ["T1053.003"] if any(r["Flag"] for r in rows) else []
    if folder == "cron":
        # bash takes /etc/cron.d flat; gandalf.py names each <dir>+<file> (cron.d+x, cron.daily+x)
        source = "/etc/" + name.replace("+", "/", 1) if "+" in name else "/etc/cron.d/" + name
        rows = unix_config.cron_rows(artefact, source)
        return "cron.csv", rows, "cron job", ["T1053.003"] if any(r["Flag"] for r in rows) else []
    if name.endswith(("authorized_keys", "authorized_keys2", "known_hosts")):
        kind = "known_hosts" if name.endswith("known_hosts") else "authorized_keys"
        user = "root" if folder == "root" else _user_file(name)[0]
        rows = unix_config.ssh_key_rows(artefact, user, kind, host)
        tagged = kind == "authorized_keys" and any(
            flag in r["Flag"] for r in rows for flag in SSH_KEY_TECHNIQUE_FLAGS)
        return "ssh_keys.csv", rows, kind, ["T1098.004"] if tagged else []
    if name.endswith("sshd_config") or "sshd_config.d+" in name:
        return "sshd_config.csv", unix_config.sshd_config_rows(artefact, "/" + name.replace("+", "/")), "sshd_config", []
    if folder == "conf" and re.match(r"^etc\+sudoers(\+|$)|^etc\+sudoers\.d\+", name):
        twin = artefact.replace("/raw/conf/", "/raw/linux/")
        if os.path.exists(twin):
            return "", [], "", []  # raw/linux/ has the same file and linux_artefacts parses it
        rows = sudoers_rows(artefact)
        return "sudoers.csv", rows, "sudoers rules", ["T1548.003"] if any(r["Flag"] for r in rows) else []
    if rel == "passwd":
        shadow = os.path.join(os.path.dirname(artefact), "shadow")
        rows = unix_config.account_rows(artefact, shadow)
        odd = any("UID 0" in r["Flag"] for r in rows)
        return "accounts.csv", rows, "local accounts", ["T1136.001"] if odd else []
    return None


def _route_macos(rel: str, name: str, artefact: str) -> Optional[Route]:
    folder = rel.split("/")[0] if "/" in rel else ""
    if folder == "tcc" and name.endswith("TCC.db"):
        rows = macos_databases.tcc_rows(sqlite_tables(artefact, ["access"]), name)
        return "tcc.csv", rows, "TCC database", macos_databases.techniques(rows)
    if name.endswith("knowledgeC.db"):
        tables = sqlite_tables(artefact, ["ZOBJECT", "ZSOURCE"])
        return "knowledgec.csv", macos_databases.knowledgec_rows(tables), "KnowledgeC database", []
    if folder == "user_profiles" and name.endswith("+QuarantineEventsV2"):
        rows = macos_databases.quarantine_rows(sqlite_tables(artefact, ["LSQuarantineEvent"]), _user_file(name)[0])
        return "quarantine_events.csv", rows, "quarantine events", ["T1105"] if any(r["Flag"] for r in rows) else []
    if folder == "macos" and re.search(r"biome\+streams\+", name, re.I):
        return "biome.csv", biome.biome_rows(artefact, name), "Biome stream", []
    if name.endswith(".asl"):
        return "asl.csv", asl_store.asl_rows(artefact, name), "ASL log", []
    if folder == "fseventsd" and name != "fseventsd-uuid":
        return "fsevents.csv", fsevents.fsevents_rows(artefact), "FSEvents page", []
    return None


def _route_staging(rel: str, artefact: str) -> Optional[Route]:
    if not rel.startswith(STAGING_DIRS):
        return None
    folder, _, inner = rel.partition("/")
    parts = [p for p in re.split(r"[/+]", inner) if p]
    hidden = [p for p in parts if p.startswith(".") and not p.startswith("._") and p.lower() not in BENIGN_DOTFILES]
    flags, techniques = [], []
    if hidden:
        flags.append("hidden name")
        techniques.append("T1564.001")
    with open(artefact, "rb") as fh:
        head = fh.read(1 << 20)
    if DOWNLOAD.search(head):
        flags.append("downloads with a script or tool")
        techniques.append("T1105")
    if head[:4] in (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe") or head[:2] in (b"#!", b"MZ"):
        flags.append("executable")
    if folder == "container_layer":  # container_layer/<id>/<path>: what the container gained since its image
        source, parts = "container " + parts[0] + ":", parts[1:]
    else:
        source = {"tmp": "/tmp", "shared": "/Users/Shared", "var_tmp": "/var/tmp", "dev_shm": "/dev/shm"}[folder]
    row = {"Source": source + "/" + "/".join(parts), "Size": os.path.getsize(artefact), "SHA256": _sha256(artefact),
           "Hidden": "yes" if hidden else "no", "Flag": "; ".join(flags), "LastWriteTime": unix_config.mtime(artefact)}
    return "staged_files.csv", [row], "staged file", techniques


def is_extra_artefact(artefact: str) -> bool:
    """Whether this router reads the file (process/select.py uses it too)."""
    rel = raw_relative(artefact)
    if not rel:
        return False
    name = os.path.basename(rel)
    if name.startswith("._") or "+._" in name or name.endswith(("-wal", "-shm", "-journal")):
        return False
    if name == "Amcache.hve" or rel.startswith(STAGING_DIRS):
        return True
    return bool(_kind(rel, name))


def _kind(rel: str, name: str) -> str:
    """A cheap test for which route a file takes, without reading it."""
    lower, folder = name.lower(), (rel.split("/")[0] if "/" in rel else "")
    if (folder == "thumbcache" and lower.endswith(".db")) or rel.endswith("$LogFile") or lower in PAGING_FILES or \
            (folder == "powershell" and "consolehost_history" in lower):
        return "windows"
    if rel in ("crontab", "passwd") or folder in ("cron", "cron_jobs", "at_jobs") or \
            re.search(r"spool\+|crontabs\+|cron\+tabs|atjobs", name) or \
            name.endswith(("authorized_keys", "authorized_keys2", "known_hosts", "sshd_config")) or \
            "sshd_config.d+" in name or (folder == "conf" and name.startswith(("etc+sudoers",))):
        return "unix"
    if (folder == "tcc" and name.endswith("TCC.db")) or name.endswith("knowledgeC.db") or \
            name.endswith("+QuarantineEventsV2") or (folder == "macos" and "biome+streams+" in lower) or \
            name.endswith(".asl") or folder == "fseventsd":
        return "macos"
    return ""


def process_extra_artefact(verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact) -> bool:
    """
    Route one collected file to its parser. Returns True when the file is fully
    handled; False lets Elrond's other processors see it too (paging files still go
    to Volatility when --Memory is set).
    """
    if not is_extra_artefact(artefact):
        return False
    rel = raw_relative(artefact)
    name = os.path.basename(rel)
    host = img.split("::")[0]
    handled = name.lower() not in PAGING_FILES
    try:
        cooked = _cooked(output_directory, img, vss_path_insert)
        if name == "Amcache.hve":
            artemis.extract_amcache(verbosity=verbosity, vssimage=vssimage, output_directory=output_directory, img=img,
                                    vss_path_insert=vss_path_insert, stage=stage, amcache_file=artefact)
            return True
        kind = _kind(rel, name)
        route = _route_staging(rel, artefact) if rel.startswith(STAGING_DIRS) else None
        if route is None and kind == "windows":
            route = _route_windows(rel, name, artefact, cooked)
        elif route is None and kind == "unix":
            route = _route_unix(rel, name, artefact, host)
        elif route is None and kind == "macos":
            route = _route_macos(rel, name, artefact)
        if not route or not route[0]:
            return handled
        out, rows, what, techniques = route
        if _append_rows(os.path.join(cooked, out), HEADERS[out], rows):
            _audit(verbosity, output_directory, img, stage, vssimage, what, artefact)
            _techniques(output_directory, techniques)
    except Exception as e:
        logger.warning("could not process '%s' for %s: %s", name, vssimage, e)
    return handled
