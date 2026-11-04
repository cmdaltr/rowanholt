"""Linux artefacts collected into raw/linux/ beyond the core set, and the extra shell
histories in raw/user_profiles/.

Files in raw/linux/ are named after their path on the host with '/' as '+'
(etc+pam.d+sshd, var+log+wtmp, home+bob+.config+autostart+x.desktop), which is
how Gandalf (gandalf.sh, gandalf.py) and Elrond's own image collection both write
them. Gandalf's generated listings are gandalf+<name>.csv. Each parser writes a
cooked/*.csv; persistence and credential-access findings carry a Flag column and
tag their ATT&CK technique where the finding justifies it.
"""

import csv
import hashlib
import logging
import os
import re
import sqlite3
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

from rowanholt.audit import write_audit_log_entry
from rowanholt.process.extractions import artemis, containers, k8s_audit

logger = logging.getLogger(__name__)

LINUX_RAW = re.compile(r"/artefacts/raw/linux/")
# Gandalf -l/-L: a running container's processes, as its runtime listed them
LIVE_TOP = re.compile(r"/artefacts/raw/live_containers/(docker|podman)/([0-9a-f]{12})/top\.txt$")
USER_FILES = ("viminfo", "lesshst", "python_history", "mysql_history", "psql_history", "wget-hsts", "recently-used.xbel",
              "db.sql", "bolt_state.db")  # the last two: rootless Podman

# Commands an attacker leaves in a startup or init script and an administrator rarely does
SUSPICIOUS_COMMAND = re.compile(
    r"(?:curl|wget)\b[^|;]*\|\s*(?:ba|z|da)?sh\b|base64\s+(?:-d|--decode)|/dev/(?:tcp|udp)/|\bnc(?:at)?\b.*\s-[ec]\b|"
    r"\bsocat\b.*exec|python[23]?\s+-c\s*['\"].*socket|perl\s+-e\s*['\"].*socket|\bmkfifo\b|"
    r"(?:^|[\s'\"=])/(?:tmp|dev/shm|var/tmp)/|\bLD_PRELOAD\s*=|chmod\s+(?:\+x|[0-7]*7[0-7]{2})\s+/(?:tmp|dev/shm|var/tmp)",
    re.I,
)
WEBSHELL = re.compile(
    r"eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress|\$_(?:GET|POST|REQUEST|COOKIE))|"
    r"assert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)|"
    r"(?:system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|"
    r"preg_replace\s*\(\s*['\"].*/e['\"]|\$\w+\s*=\s*\$_(?:GET|POST|REQUEST)\[[^]]+\]\s*;\s*@?\$\w+\s*\(|"
    r"Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter|ProcessBuilder\s*\(.*request\.getParameter|"
    r"Process\.Start\s*\(.*Request(?:\.Form|\.QueryString|\[)|"
    r"\bos\.(?:system|popen)\s*\(.*(?:request\.|form\[|QUERY_STRING)|\bcmd\.exe\s+/c\b",
    re.I,
)
WEB_SCRIPTS = (".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phar", ".inc", ".jsp", ".jspx",
               ".asp", ".aspx", ".ashx", ".asmx", ".cgi", ".pl", ".py", ".sh", ".cfm")
WEB_ROOTS = ("var+www+", "srv+www+", "srv+http+", "usr+share+nginx+html+")

# PAM modules shipped by Linux-PAM and the distributions' common add-ons; anything else
# (or a module given by a path outside the security directories) is worth a look
PAM_MODULES = {
    "pam_access", "pam_cap", "pam_console", "pam_cracklib", "pam_debug", "pam_deny", "pam_echo", "pam_env",
    "pam_exec", "pam_faildelay", "pam_faillock", "pam_filter", "pam_fprintd", "pam_ftp", "pam_gdm",
    "pam_gnome_keyring", "pam_group", "pam_issue", "pam_keyinit", "pam_krb5", "pam_kwallet5", "pam_lastlog",
    "pam_ldap", "pam_limits", "pam_listfile", "pam_localuser", "pam_loginuid", "pam_mail", "pam_mkhomedir",
    "pam_motd", "pam_mount", "pam_namespace", "pam_nologin", "pam_oddjob_mkhomedir", "pam_passwdqc",
    "pam_permit", "pam_pwhistory", "pam_pwquality", "pam_rhosts", "pam_rootok", "pam_securetty", "pam_selinux",
    "pam_sepermit", "pam_setquota", "pam_shells", "pam_sss", "pam_stress", "pam_succeed_if", "pam_systemd",
    "pam_systemd_home", "pam_tally", "pam_tally2", "pam_time", "pam_timestamp", "pam_tty_audit", "pam_umask",
    "pam_unix", "pam_unix2", "pam_userdb", "pam_usertype", "pam_warn", "pam_wheel", "pam_winbind", "pam_xauth",
    "pam_ecryptfs", "pam_google_authenticator", "pam_u2f", "pam_yubico", "pam_duo", "pam_cgfs", "pam_snapper",
    "pam_lsass", "pam_mysql", "pam_radius_auth", "pam_ssh_agent_auth", "pam_sssd", "pam_pkcs11",
    "pam_ck_connector", "pam_lastlog2", "pam_wtmpdb", "pam_kwallet", "pam_unix_auth", "pam_unix_acct",
    "pam_unix_passwd", "pam_unix_session", "pam_smbpass", "pam_afs_session", "pam_abl",
}
PAM_DIRS = re.compile(r"^/(?:usr/)?lib(?:64|32)?/(?:[\w-]+-linux-gnu\w*/)?security/")
SUDO_ADMIN_GROUPS = {"root", "%sudo", "%wheel", "%admin"}
STANDARD_MODULE_DIRS = re.compile(r"^/(?:usr/)?lib/modules/")
UTMP_TYPES = {0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME", 5: "INIT_PROCESS",
              6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS", 9: "ACCOUNTING"}
UTMP_RECORD = struct.Struct("<hxxi32s4s32s256shhiii16s20x")  # glibc struct utmp, 384 bytes
LASTLOG_RECORD = struct.Struct("<i32s256s")  # 292 bytes, indexed by UID
FAILLOG_RECORD = struct.Struct("<hh12sqq")  # 32 bytes, indexed by UID
FAILED_LOGIN_THRESHOLD = 10

HEADERS = {
    "login_records.csv": ["Source", "Type", "User", "Terminal", "Host", "Address", "PID", "LastWriteTime"],
    "lastlog.csv": ["Source", "UID", "User", "Terminal", "Host", "LastWriteTime"],
    "faillog.csv": ["Source", "UID", "User", "Failures", "Maximum", "Terminal", "LastWriteTime"],
    "preload.csv": ["Source", "Library", "Flag"],
    "shell_init.csv": ["Source", "LineNumber", "Line", "Flag"],
    "pam.csv": ["Source", "Type", "Control", "Module", "Arguments", "Flag"],
    "sudoers.csv": ["Source", "LineNumber", "Line", "Flag"],
    "autostart.csv": ["Source", "Kind", "Name", "Command", "Flag"],
    "udev_rules.csv": ["Source", "LineNumber", "Rule", "Command", "Flag"],
    "generators.csv": ["Source", "Size", "SHA256"],
    "kernel_modules.csv": ["Name", "Size", "Instances", "State", "Taint", "Path", "SHA256", "Flag"],
    "tmp_executables.csv": ["Path", "Size", "Mode", "UID", "Kind", "SHA256", "LastWriteTime"],
    "webshells.csv": ["Source", "Size", "SHA256", "Indicators", "LastWriteTime"],
    "shell_histories.csv": ["User", "History", "Command"],
    "viminfo.csv": ["User", "Kind", "Value"],
    "wget_hsts.csv": ["User", "Host", "Port", "IncludeSubdomains", "Created"],
    "recently_used.csv": ["User", "URI", "Applications", "Added", "Modified", "Visited"],
    **containers.HEADERS,
    "k8s_audit.csv": k8s_audit.HEADER,
}
DOCKER_CONTAINERS = "/var/lib/docker/containers/"
CONTAINERD_META = "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"
# Podman's state: SQLite from 4.8 (its -wal beside it is read with it), bbolt before
PODMAN_SQLITE = "/var/lib/containers/storage/db.sql"
PODMAN_BOLT = "/var/lib/containers/storage/libpod/bolt_state.db"


def _cooked(output_directory: str, img: str, vss_path_insert: str) -> str:
    path = output_directory + img.split("::")[0] + "/artefacts/cooked" + vss_path_insert
    os.makedirs(path, exist_ok=True)
    return path


def _append_rows(path: str, header: List[str], rows: Iterable[Dict]) -> int:
    rows = list(rows)
    if not rows:
        return 0
    new = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=header, extrasaction="ignore")
        if new:
            writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def _audit(verbosity, output_directory, img, stage, vssimage, what, artefact):
    entry, prnt = "{},{},{},'{}'\n".format(
        datetime.now().isoformat(), img.split("::")[0], stage, os.path.basename(artefact)
    ), " -> {} -> {} {} '{}' for {}".format(
        datetime.now().isoformat().replace("T", " "), stage, what, os.path.basename(artefact), vssimage
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)


def epoch(seconds) -> str:
    """Seconds since 1970 as ISO 8601, or '' for zero or nonsense."""
    try:
        seconds = int(seconds)
        if seconds <= 0:
            return ""
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def host_path(name: str) -> str:
    """The path on the host a raw/linux/ file came from (etc+pam.d+sshd -> /etc/pam.d/sshd)."""
    return "/" + name.replace("+", "/")


def _cstr(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def _lines(path: str) -> List[str]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read().splitlines()


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _users_by_uid(artefact: str) -> Dict[int, str]:
    """UID -> name from the passwd collected beside raw/linux/ (raw/passwd)."""
    passwd = os.path.join(artefact.split("/artefacts/raw/")[0], "artefacts", "raw", "passwd")
    users = {}
    if os.path.isfile(passwd):
        for line in _lines(passwd):
            fields = line.split(":")
            if len(fields) > 2 and fields[2].isdigit():
                users[int(fields[2])] = fields[0]
    return users


# ---- login records ---------------------------------------------------------

def utmp_rows(path: str) -> List[Dict[str, str]]:
    """utmp, wtmp and btmp: one row per record."""
    rows = []
    with open(path, "rb") as fh:
        data = fh.read()
    source = host_path(os.path.basename(path))
    for offset in range(0, len(data) - UTMP_RECORD.size + 1, UTMP_RECORD.size):
        ut_type, pid, line, _, user, host, _, _, _, seconds, _, addr = UTMP_RECORD.unpack_from(data, offset)
        if ut_type == 0:
            continue
        if addr[4:] == b"\0" * 12:
            address = ".".join(str(b) for b in addr[:4]) if addr[:4] != b"\0\0\0\0" else ""
        else:
            address = ":".join(addr[i:i + 2].hex() for i in range(0, 16, 2))
        rows.append({
            "Source": source, "Type": UTMP_TYPES.get(ut_type, str(ut_type)), "User": _cstr(user),
            "Terminal": _cstr(line), "Host": _cstr(host), "Address": address, "PID": pid,
            "LastWriteTime": epoch(seconds),
        })
    return rows


def lastlog_rows(path: str, users: Dict[int, str]) -> List[Dict[str, str]]:
    rows = []
    source = host_path(os.path.basename(path))
    with open(path, "rb") as fh:
        uid = 0
        while True:
            record = fh.read(LASTLOG_RECORD.size)
            if len(record) < LASTLOG_RECORD.size:
                break
            seconds, line, host = LASTLOG_RECORD.unpack(record)
            if seconds:
                rows.append({"Source": source, "UID": uid, "User": users.get(uid, ""), "Terminal": _cstr(line),
                             "Host": _cstr(host), "LastWriteTime": epoch(seconds)})
            uid += 1
    return rows


def faillog_rows(path: str, users: Dict[int, str]) -> List[Dict[str, str]]:
    rows = []
    source = host_path(os.path.basename(path))
    with open(path, "rb") as fh:
        uid = 0
        while True:
            record = fh.read(FAILLOG_RECORD.size)
            if len(record) < FAILLOG_RECORD.size:
                break
            count, maximum, line, seconds, _ = FAILLOG_RECORD.unpack(record)
            if count > 0:
                rows.append({"Source": source, "UID": uid, "User": users.get(uid, ""), "Failures": count,
                             "Maximum": maximum, "Terminal": _cstr(line), "LastWriteTime": epoch(seconds)})
            uid += 1
    return rows


def _sqlite_rows(path: str, query: str) -> List[sqlite3.Row]:
    connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        return connection.execute(query).fetchall()
    finally:
        connection.close()


def _usec(value) -> str:
    try:
        return epoch(int(value) // 1_000_000) if value else ""
    except (TypeError, ValueError):
        return ""


def wtmpdb_rows(path: str) -> List[Dict[str, str]]:
    """wtmpdb's wtmp.db (util-linux 2.40+, Ubuntu 24.04+): a login and a logout row per session."""
    rows = []
    for r in _sqlite_rows(path, "SELECT * FROM wtmp ORDER BY Login"):
        keys = r.keys()
        kind = {1: "BOOT_TIME", 2: "RUN_LVL", 3: "USER_PROCESS"}.get(r["Type"], str(r["Type"])) if "Type" in keys else ""
        base = {"Source": "/var/lib/wtmpdb/wtmp.db", "Type": kind, "User": r["User"], "Terminal": r["TTY"] or "",
                "Host": r["RemoteHost"] or "", "Address": "", "PID": ""}
        rows.append(dict(base, LastWriteTime=_usec(r["Login"])))
        if r["Logout"]:
            rows.append(dict(base, Type="DEAD_PROCESS", LastWriteTime=_usec(r["Logout"])))
    return rows


def lastlog2_rows(path: str) -> List[Dict[str, str]]:
    """lastlog2.db (util-linux 2.40+): the last login per user, by name."""
    return [{"Source": "/var/lib/lastlog/lastlog2.db", "UID": "", "User": r["Name"], "Terminal": r["TTY"] or "",
             "Host": r["RemoteHost"] or "", "LastWriteTime": epoch(r["Time"])}
            for r in _sqlite_rows(path, "SELECT * FROM Lastlog2") if r["Time"]]


def failed_login_sources(rows: List[Dict[str, str]]) -> List[str]:
    """Hosts with at least FAILED_LOGIN_THRESHOLD failed logins in btmp."""
    counts: Dict[str, int] = {}
    for row in rows:
        key = row["Address"] or row["Host"]
        if key:
            counts[key] = counts.get(key, 0) + 1
    return sorted(k for k, v in counts.items() if v >= FAILED_LOGIN_THRESHOLD)


# ---- persistence and configuration ----------------------------------------

def _config_lines(path: str) -> Iterable[Tuple[int, str]]:
    for number, line in enumerate(_lines(path), 1):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            yield number, stripped


def preload_rows(path: str) -> List[Dict[str, str]]:
    source = host_path(os.path.basename(path))
    preload = source == "/etc/ld.so.preload"
    rows = []
    for _, line in _config_lines(path):
        for library in line.split():
            rows.append({"Source": source, "Library": library,
                         "Flag": "preloaded into every process" if preload else ""})
    return rows


def shell_init_rows(path: str) -> List[Dict[str, str]]:
    """Startup and login scripts: lines with a suspicious command, and anything rc.local runs."""
    source = host_path(os.path.basename(path))
    rc_local = source == "/etc/rc.local"
    rows = []
    for number, line in _config_lines(path):
        if SUSPICIOUS_COMMAND.search(line):
            rows.append({"Source": source, "LineNumber": number, "Line": line, "Flag": "suspicious command"})
        elif rc_local and line not in ("exit 0", "exit"):
            rows.append({"Source": source, "LineNumber": number, "Line": line, "Flag": "runs at boot"})
    return rows


def pam_rows(path: str) -> List[Dict[str, str]]:
    source = host_path(os.path.basename(path))
    rows = []
    for _, line in _config_lines(path):
        if line.startswith("@include"):
            continue
        fields = line.split()
        if len(fields) < 3:
            continue
        ptype, control = fields[0].lstrip("-"), fields[1]
        rest = fields[2:]
        if control.startswith("["):  # [success=1 default=ignore]
            while rest and not control.endswith("]"):
                control += " " + rest.pop(0)
        if not rest or control in ("include", "substack"):
            continue
        module, args = rest[0], " ".join(rest[1:])
        name = os.path.basename(module)
        name = name[:-3] if name.endswith(".so") else name
        flag = ""
        if module.startswith("/") and not PAM_DIRS.match(module):
            flag = "module outside the PAM security directory"
        elif name not in PAM_MODULES:
            flag = "non-standard module"
        elif name == "pam_exec":
            flag = "runs a command"
        elif name == "pam_permit" and ptype == "auth" and control == "sufficient":
            flag = "pam_permit grants authentication"
        rows.append({"Source": source, "Type": ptype, "Control": control, "Module": module,
                     "Arguments": args, "Flag": flag})
    return rows


def sudoers_rows(path: str) -> List[Dict[str, str]]:
    source = host_path(os.path.basename(path))
    rows = []
    for number, line in _config_lines(path):
        if line.startswith(("Defaults", "@include", "#include", "Cmnd_Alias", "User_Alias", "Host_Alias", "Runas_Alias")):
            continue
        who = line.split()[0]
        flags = []
        if "NOPASSWD" in line:
            flags.append("NOPASSWD")
        if "!authenticate" in line:
            flags.append("!authenticate")
        if re.search(r"=\s*(?:\([^)]*\)\s*)?(?:NOPASSWD:\s*)?ALL\s*$", line) and who not in SUDO_ADMIN_GROUPS:
            flags.append("full root for a non-admin principal")
        rows.append({"Source": source, "LineNumber": number, "Line": line, "Flag": "; ".join(flags)})
    return rows


def desktop_row(path: str) -> Optional[Dict[str, str]]:
    """An XDG autostart .desktop entry."""
    fields = {}
    for line in _lines(path):
        key, sep, value = line.partition("=")
        if sep and key.strip() in ("Name", "Exec", "Hidden", "X-GNOME-Autostart-enabled") and key.strip() not in fields:
            fields[key.strip()] = value.strip()
    if "Exec" not in fields:
        return None
    disabled = fields.get("Hidden", "").lower() == "true" or fields.get("X-GNOME-Autostart-enabled", "").lower() == "false"
    source = host_path(os.path.basename(path))
    flags = []
    if SUSPICIOUS_COMMAND.search(fields["Exec"]):
        flags.append("suspicious command")
    if disabled:
        flags.append("disabled")
    return {"Source": source, "Kind": "user autostart" if source.startswith(("/home/", "/root/")) else "system autostart",
            "Name": fields.get("Name", ""), "Command": fields["Exec"], "Flag": "; ".join(flags)}


def user_unit_row(path: str) -> Optional[Dict[str, str]]:
    """A per-user systemd unit (~/.config/systemd/user)."""
    commands = [v.strip() for k, _, v in (l.partition("=") for l in _lines(path)) if k.strip().startswith("Exec")]
    if not commands:
        return None
    command = " ; ".join(commands)
    return {"Source": host_path(os.path.basename(path)), "Kind": "systemd user unit",
            "Name": os.path.basename(path).split("+")[-1], "Command": command,
            "Flag": "suspicious command" if SUSPICIOUS_COMMAND.search(command) else ""}


def udev_rows(path: str) -> List[Dict[str, str]]:
    """udev rules that run a program (RUN, PROGRAM, IMPORT{program})."""
    source = host_path(os.path.basename(path))
    admin = source.startswith("/etc/udev/")
    rows = []
    for number, line in _config_lines(path):
        commands = re.findall(r"(?:RUN(?:\{\w+\})?\s*\+?=|PROGRAM\s*=|IMPORT\{program\}\s*=)\s*\"([^\"]*)\"", line)
        for command in commands:
            flags = []
            if SUSPICIOUS_COMMAND.search(command) or re.search(r"\b(?:ba|z|da)?sh\s+-c\b|/home/|/root/", command):
                flags.append("suspicious command")
            if admin:
                flags.append("administrator rule")
            rows.append({"Source": source, "LineNumber": number, "Rule": line, "Command": command,
                         "Flag": "; ".join(flags)})
    return rows


def kernel_module_rows(path: str) -> List[Dict[str, str]]:
    """gandalf+kernel_modules.csv: flag modules with no file, or a file outside /lib/modules."""
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        module_path = (row.get("Path") or "").strip()
        flags = []
        if not module_path:
            flags.append("no module file")
        elif module_path != "?" and not STANDARD_MODULE_DIRS.match(module_path):  # ?: modinfo unavailable
            flags.append("module file outside /lib/modules")
        if "O" in (row.get("Taint") or ""):
            flags.append("out-of-tree")
        if "E" in (row.get("Taint") or ""):
            flags.append("unsigned")
        row["Flag"] = "; ".join(flags)
    return rows


def tmp_executable_rows(path: str) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        row["LastWriteTime"] = epoch(row.get("MTime") or row.get("LastWriteTime"))
    return rows


def webshell_row(path: str) -> Optional[Dict[str, str]]:
    with open(path, "rb") as fh:
        text = fh.read(2 << 20).decode("utf-8", errors="replace")
    hits = sorted({m.group(0)[:60] for m in WEBSHELL.finditer(text)})
    if not hits:
        return None
    return {"Source": host_path(os.path.basename(path)), "Size": os.path.getsize(path), "SHA256": _sha256(path),
            "Indicators": " | ".join(hits), "LastWriteTime": epoch(os.path.getmtime(path))}


# ---- user histories ---------------------------------------------------------

def history_rows(path: str, user: str, kind: str) -> List[Dict[str, str]]:
    """python, mysql, psql and less histories: one row per command or search."""
    rows = []
    for line in _lines(path):
        if kind == "mysql_history":
            line = line.replace("\\040", " ")
            if line == "_HiStOrY_V2_":
                continue
        if kind == "lesshst":
            if not line.startswith('"'):
                continue
            line = line[1:]
        if line.strip():
            rows.append({"User": user, "History": kind, "Command": line})
    return rows


def viminfo_rows(path: str, user: str) -> List[Dict[str, str]]:
    """Files vim opened (marks, jumps, buffers) and its command and search history."""
    rows = []
    section = ""
    for line in _lines(path):
        if line.startswith("# "):
            section = line[2:].lower()
            continue
        if line.startswith("> "):
            rows.append({"User": user, "Kind": "file", "Value": line[2:].strip()})
        elif line.startswith("'") and section.startswith("file marks"):
            parts = line.split(None, 3)
            if len(parts) == 4:
                rows.append({"User": user, "Kind": "file mark", "Value": parts[3]})
        elif line.startswith(":") and section.startswith("command line history"):
            rows.append({"User": user, "Kind": "command", "Value": line[1:]})
        elif line.startswith(("?", "/")) and section.startswith("search string history"):
            rows.append({"User": user, "Kind": "search", "Value": line[1:]})
    return rows


def wget_hsts_rows(path: str, user: str) -> List[Dict[str, str]]:
    rows = []
    for _, line in _config_lines(path):
        fields = line.split()
        if len(fields) >= 4:
            rows.append({"User": user, "Host": fields[0], "Port": fields[1], "IncludeSubdomains": fields[2],
                         "Created": epoch(fields[3])})
    return rows


def recently_used_rows(path: str, user: str) -> List[Dict[str, str]]:
    """GTK's recently-used.xbel: files opened through the desktop."""
    rows = []
    for bookmark in ET.parse(path).getroot().iter("bookmark"):
        apps = [a.get("name", "") for a in bookmark.iter() if a.tag.endswith("application")]
        rows.append({"User": user, "URI": bookmark.get("href", ""), "Applications": ", ".join(a for a in apps if a),
                     "Added": bookmark.get("added", ""), "Modified": bookmark.get("modified", ""),
                     "Visited": bookmark.get("visited", "")})
    return rows


# ---- routing ----------------------------------------------------------------

def _techniques(output_directory: str, techniques: List[str]) -> None:
    if techniques:
        artemis._record_techniques(os.path.join(output_directory, "mitre_techniques.txt"), techniques)


def _route_linux(artefact: str) -> Tuple[str, List[Dict], str, List[str]]:
    """(cooked csv, rows, description, techniques) for one raw/linux/ file."""
    name = os.path.basename(artefact)
    path = host_path(name)
    base = re.sub(r"\.\d+$", "", path)  # wtmp.1, btmp.1
    if base.endswith(("/utmp", "/wtmp", "/btmp")):
        rows = utmp_rows(artefact)
        techniques = ["T1110.001"] if base.endswith("/btmp") and failed_login_sources(rows) else []
        return "login_records.csv", rows, "login records", techniques
    if path == "/var/lib/wtmpdb/wtmp.db":
        return "login_records.csv", wtmpdb_rows(artefact), "login records", []
    if path == "/var/lib/lastlog/lastlog2.db":
        return "lastlog.csv", lastlog2_rows(artefact), "lastlog", []
    if base == "/var/log/lastlog":
        return "lastlog.csv", lastlog_rows(artefact, _users_by_uid(artefact)), "lastlog", []
    if base == "/var/log/faillog":
        return "faillog.csv", faillog_rows(artefact, _users_by_uid(artefact)), "faillog", []
    if path == "/etc/ld.so.preload" or path == "/etc/ld.so.conf" or path.startswith("/etc/ld.so.conf.d/"):
        rows = preload_rows(artefact)
        return "preload.csv", rows, "dynamic linker configuration", ["T1574.006"] if any(r["Flag"] for r in rows) else []
    if path in ("/etc/environment", "/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/rc.local") or \
            path.startswith(("/etc/profile.d/", "/etc/update-motd.d/")):
        rows = shell_init_rows(artefact)
        techniques = []
        if any("LD_PRELOAD" in r["Line"] for r in rows):
            techniques.append("T1574.006")
        if any(r["Flag"] == "runs at boot" for r in rows):
            techniques.append("T1037.004")
        if any(r["Flag"] == "suspicious command" for r in rows):
            techniques.append("T1037.004" if path == "/etc/rc.local" else "T1546.004")
        return "shell_init.csv", rows, "shell startup script", techniques
    if path.startswith("/etc/pam.d/"):
        rows = pam_rows(artefact)
        return "pam.csv", rows, "PAM configuration", ["T1556.003"] if any(r["Flag"] for r in rows) else []
    if path == "/etc/sudoers" or path.startswith("/etc/sudoers.d/"):
        rows = sudoers_rows(artefact)
        flagged = any(r["Flag"] for r in rows) and not path.endswith("cloud-init-users")
        return "sudoers.csv", rows, "sudoers rules", ["T1548.003"] if flagged else []
    if "/autostart/" in path and path.endswith(".desktop"):
        row = desktop_row(artefact)
        rows = [row] if row else []
        tagged = [r for r in rows if r["Kind"] == "user autostart" or "suspicious" in r["Flag"]]
        return "autostart.csv", rows, "autostart entry", ["T1547.013"] if tagged else []
    if "/.config/systemd/user/" in path and path.endswith((".service", ".timer")):
        row = user_unit_row(artefact)
        return "autostart.csv", [row] if row else [], "systemd user unit", ["T1543.002"] if row else []
    if "/udev/rules.d/" in path and path.endswith(".rules"):
        rows = udev_rows(artefact)
        return "udev_rules.csv", rows, "udev rules", ["T1546.017"] if any("suspicious" in r["Flag"] for r in rows) else []
    if "/systemd/system-generators/" in path or "/systemd/user-generators/" in path:
        row = {"Source": path, "Size": os.path.getsize(artefact), "SHA256": _sha256(artefact)}
        return "generators.csv", [row], "systemd generator", ["T1543.002"]
    if name == "gandalf+kernel_modules.csv":
        rows = kernel_module_rows(artefact)
        odd = any("no module file" in r["Flag"] or "outside" in r["Flag"] for r in rows)
        return "kernel_modules.csv", rows, "kernel module list", ["T1547.006"] if odd else []
    if name == "gandalf+tmp_executables.csv":
        return "tmp_executables.csv", tmp_executable_rows(artefact), "temporary-directory executables", []
    if path.startswith(DOCKER_CONTAINERS):
        return _route_docker(artefact, path)
    if path == CONTAINERD_META:
        rows = containers.containerd_rows(artefact)
        return "docker_containers.csv", rows, "containerd containers", containers.container_techniques(rows)
    if path in (PODMAN_SQLITE, PODMAN_BOLT):
        rows = containers.podman_sqlite_rows(artefact) if path == PODMAN_SQLITE else containers.podman_bolt_rows(artefact)
        return "docker_containers.csv", rows, "Podman containers", containers.container_techniques(rows)
    if path.startswith("/var/log/pods/") and re.search(r"\.log(?:\.\d+)?$", path):
        parts = path.split("/")  # /var/log/pods/<namespace>_<pod>_<uid>/<container>/<n>.log
        if len(parts) >= 7:
            return "container_logs.csv", containers.cri_log_rows(artefact, parts[4], parts[5]), "pod log", []
    if name == "gandalf+container_changes.csv":
        rows = containers.container_change_rows(artefact)
        return "container_changes.csv", rows, "container writable layers", containers.change_techniques(rows)
    if path.startswith("/etc/kubernetes/manifests/") and path.endswith((".yaml", ".yml", ".json")):
        row = containers.static_pod_row(artefact, path)
        rows = [row] if row else []
        return "static_pods.csv", rows, "static pod manifest", containers.static_pod_techniques(rows)
    if path.startswith(("/var/log/kubernetes/", "/var/log/kube-apiserver")) and k8s_audit.looks_like_audit_log(artefact):
        rows = k8s_audit.audit_rows(artefact)
        return "k8s_audit.csv", rows, "Kubernetes audit log", k8s_audit.audit_techniques(rows)
    if name.startswith(WEB_ROOTS) and name.lower().endswith(WEB_SCRIPTS):
        row = webshell_row(artefact)
        return "webshells.csv", [row] if row else [], "web script", ["T1505.003"] if row else []
    return "", [], "", []


def _route_docker(artefact: str, path: str) -> Tuple[str, List[Dict], str, List[str]]:
    """A container's config.v2.json (read with the hostconfig.json beside it) or its json-file log."""
    container = path[len(DOCKER_CONTAINERS):].split("/")[0]
    if path.endswith("/config.v2.json"):
        row = containers.docker_container_row(artefact, artefact.replace("config.v2.json", "hostconfig.json"))
        rows = [row] if row else []
        return "docker_containers.csv", rows, "Docker container", containers.container_techniques(rows)
    if re.search(r"-json\.log(?:\.\d+)?$", path):
        return "container_logs.csv", containers.docker_log_rows(artefact, container), "container log", []
    return "", [], "", []  # hostconfig.json, read with config.v2.json


def _route_live(artefact: str) -> Tuple[str, List[Dict], str, List[str]]:
    runtime, container = LIVE_TOP.search(artefact).groups()
    rows = containers.live_process_rows(artefact, runtime, container, SUSPICIOUS_COMMAND)
    return "container_processes.csv", rows, "running container processes", []


def _route_user(artefact: str) -> Tuple[str, List[Dict], str, List[str]]:
    """(cooked csv, rows, description, techniques) for one extra user_profiles/<user>+<file>."""
    name = os.path.basename(artefact)
    user, _, kind = name.rpartition("+")
    user = user.split("+")[0]
    if kind in ("python_history", "mysql_history", "psql_history", "lesshst"):
        return "shell_histories.csv", history_rows(artefact, user, kind), kind, []
    if kind == "viminfo":
        return "viminfo.csv", viminfo_rows(artefact, user), kind, []
    if kind == "wget-hsts":
        return "wget_hsts.csv", wget_hsts_rows(artefact, user), kind, []
    if kind == "recently-used.xbel":
        return "recently_used.csv", recently_used_rows(artefact, user), kind, []
    if kind in ("db.sql", "bolt_state.db"):
        rows = containers.podman_sqlite_rows(artefact) if kind == "db.sql" else containers.podman_bolt_rows(artefact)
        for row in rows:
            row["Runtime"] = f"podman (rootless, {user})"
        return "docker_containers.csv", rows, "rootless Podman containers", containers.container_techniques(rows)
    return "", [], "", []


def is_linux_artefact(artefact: str) -> bool:
    """Whether one of these processors reads this file (process/select.py uses it too)."""
    if LINUX_RAW.search(artefact) or LIVE_TOP.search(artefact):
        return True
    name = os.path.basename(artefact)
    return "+" in name and name.rpartition("+")[2] in USER_FILES


def process_linux_artefact(verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact) -> bool:
    """Route one collected file to its parser. Returns False if it isn't one of these."""
    if not is_linux_artefact(artefact):
        return False
    try:
        route = _route_linux if LINUX_RAW.search(artefact) else _route_live if LIVE_TOP.search(artefact) else _route_user
        out, rows, what, techniques = route(artefact)
        if not out:
            return True  # collected for the analyst (web server configs, rotated logs) with nothing to parse
        if _append_rows(os.path.join(_cooked(output_directory, img, vss_path_insert), out), HEADERS[out], rows):
            _audit(verbosity, output_directory, img, stage, vssimage, what, artefact)
            _techniques(output_directory, techniques)
    except Exception as e:
        logger.warning("could not process '%s' for %s: %s", os.path.basename(artefact), vssimage, e)
    return True
