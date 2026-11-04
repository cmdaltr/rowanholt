"""Linux and macOS configuration Gandalf and Elrond collect but nothing else parses:
cron and at jobs, SSH keys and known hosts, sshd_config, and local accounts.

Each parser returns rows for a cooked CSV and flags what an analyst should look at.
Password hashes are never copied out of shadow: only their type and state.
"""

import base64
import hashlib
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

CRON_TIME = re.compile(r"^(@\w+|(\S+\s+){4}\S+)\s+(.*)$")
STAGING = re.compile(r"(^|[\s'\"=;|&(])(/tmp/|/var/tmp/|/dev/shm/|/Users/Shared/|/private/tmp/)|/\.[\w.-]+/")
SUSPICIOUS = re.compile(
    r"\b(curl|wget|fetch|nc|ncat|netcat|socat|telnet)\b|bash\s+-i|/dev/tcp/|base64\s+(-d|--decode)|"
    r"python[\d.]*\s+-c|perl\s+-e|php\s+-r|\|\s*(ba|z|da)?sh\b|chmod\s+\+x|mkfifo|openssl\s+s_client", re.I)
CRON_HEADER = ["Source", "User", "Schedule", "Command", "Flag", "LastWriteTime"]
AT_HEADER = ["Source", "Job", "User", "Command", "Flag", "LastWriteTime"]
KEY_HEADER = ["User", "File", "LineNumber", "KeyType", "Fingerprint", "Comment", "Options", "Hosts", "Flag"]
SSHD_HEADER = ["Source", "LineNumber", "Setting", "Value", "Flag"]
ACCOUNT_HEADER = ["User", "UID", "GID", "Home", "Shell", "CanLogIn", "Password", "PasswordChanged", "Flag"]
KEY_TYPES = ("ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
             "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
NO_LOGIN = ("/nologin", "/false", "/sync", "/shutdown", "/halt")
HASH_TYPES = {"1": "MD5", "2a": "bcrypt", "2b": "bcrypt", "2y": "bcrypt", "5": "SHA-256", "6": "SHA-512",
              "y": "yescrypt", "gy": "gost-yescrypt", "7": "scrypt"}


def mtime(path: str) -> str:
    try:
        return datetime.fromtimestamp(os.path.getmtime(path), timezone.utc).isoformat().replace("+00:00", "Z")
    except OSError:
        return ""


def _lines(path: str) -> List[str]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read().splitlines()


def command_flags(command: str) -> List[str]:
    flags = []
    if STAGING.search(command):
        flags.append("runs from a temp or hidden directory")
    if SUSPICIOUS.search(command):
        flags.append("network or shell tradecraft")
    return flags


# ---- cron and at -------------------------------------------------------------

def cron_rows(path: str, source: str, user: str = "") -> List[Dict[str, str]]:
    """
    One row per job in a crontab. System crontabs (/etc/crontab, /etc/cron.d/*) have
    a user field; per-user ones (spool) don't, and user names them. Scripts in
    cron.daily/hourly/weekly/monthly are listed as one row each, run by root.
    """
    rows, when = [], mtime(path)
    if re.search(r"/cron\.(hourly|daily|weekly|monthly)/|cron\.(hourly|daily|weekly|monthly)\+", source):
        if os.path.basename(path).lstrip(".") in ("placeholder",):
            return []
        period = re.search(r"cron\.(hourly|daily|weekly|monthly)", source).group(1)
        body = " ".join(l for l in _lines(path) if l.strip() and not l.lstrip().startswith("#"))
        return [{"Source": source, "User": "root", "Schedule": period, "Command": "run-parts script",
                 "Flag": "; ".join(command_flags(body)), "LastWriteTime": when}]
    system = not user
    for line in _lines(path):
        text = line.strip()
        if not text or text.startswith("#") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", text):
            continue
        match = CRON_TIME.match(text)
        if not match:
            continue
        schedule = " ".join(match.group(1).split())
        rest = match.group(3)
        job_user = user
        if system:
            parts = rest.split(None, 1)
            job_user, rest = (parts + [""])[0], (parts + ["", ""])[1].strip()
        flags = command_flags(rest)
        if schedule == "@reboot":
            flags.append("runs at boot")
        rows.append({"Source": source, "User": job_user, "Schedule": schedule, "Command": rest,
                     "Flag": "; ".join(flags), "LastWriteTime": when})
    return rows


def at_rows(path: str, source: str) -> List[Dict[str, str]]:
    """An at job: the spool file is a shell script; the command is what follows the environment set-up."""
    lines = _lines(path)
    if not lines:
        return []
    user = ""
    for line in lines[:5]:
        match = re.search(r"(?:atrun uid=\d+ gid=\d+|# mail\s+)(\S+)?", line)
        if match and match.group(1):
            user = match.group(1)
    body, started, in_guard = [], False, False
    for line in lines:
        text = line.strip()
        if in_guard:  # cd <dir> || {  echo 'Execution directory inaccessible' >&2;  exit 1  }
            in_guard = text != "}"
            continue
        if not started:
            # the job proper starts after the last cd into the working directory
            if re.match(r"^cd\s+\S+\s*(\|\|.*)?$", text):
                started = True
                in_guard = text.endswith("{")
                body = []
            continue
        if line.strip() and not line.startswith(("#", "export ")) and "=" not in line.split(" ")[0]:
            body.append(line.strip())
    command = "; ".join(body) or "; ".join(l for l in lines[-3:] if l.strip())
    return [{"Source": source, "Job": os.path.basename(path), "User": user, "Command": command[:4000],
             "Flag": "; ".join(command_flags(command)), "LastWriteTime": mtime(path)}]


# ---- SSH ---------------------------------------------------------------------

def _fingerprint(blob: str) -> str:
    try:
        digest = hashlib.sha256(base64.b64decode(blob + "=" * (-len(blob) % 4))).digest()
    except (ValueError, TypeError):
        return ""
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def _split_options(line: str) -> Tuple[str, str]:
    """authorized_keys options come first and may hold quoted spaces: (options, rest)."""
    if line.startswith(KEY_TYPES):
        return "", line
    quoted, i = False, 0
    while i < len(line):
        if line[i] == '"':
            quoted = not quoted
        elif line[i] == " " and not quoted:
            return line[:i], line[i + 1:].lstrip()
        i += 1
    return line, ""


def ssh_key_rows(path: str, user: str, kind: str, hostname: str = "") -> List[Dict[str, str]]:
    """authorized_keys (kind 'authorized_keys') or known_hosts (kind 'known_hosts')."""
    rows = []
    local = (hostname or "").lower().split(".")[0]
    for number, line in enumerate(_lines(path), 1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        row = {"User": user, "File": kind, "LineNumber": number, "KeyType": "", "Fingerprint": "", "Comment": "",
               "Options": "", "Hosts": "", "Flag": ""}
        flags = []
        if kind == "known_hosts":
            parts = text.split()
            if parts and parts[0].startswith("@"):  # @cert-authority / @revoked
                row["Options"], parts = parts[0], parts[1:]
            if len(parts) >= 3:
                row["Hosts"] = "(hashed)" if parts[0].startswith("|1|") else parts[0]
                row["KeyType"], row["Fingerprint"] = parts[1], _fingerprint(parts[2])
                row["Comment"] = " ".join(parts[3:])
        else:
            options, rest = _split_options(text)
            parts = rest.split()
            if len(parts) >= 2:
                row["KeyType"], row["Fingerprint"] = parts[0], _fingerprint(parts[1])
                row["Comment"] = " ".join(parts[2:])
            row["Options"] = options
            lowered = options.lower()
            if "command=" in lowered:
                flags.append("forced command")
            if "environment=" in lowered:
                flags.append("sets environment")
            if user == "root":
                flags.append("key for root")
            comment_host = row["Comment"].rpartition("@")[2].lower()
            if "@" in row["Comment"] and local and comment_host.split(".")[0] != local:
                flags.append("comment names another host")
            if not row["Comment"]:
                flags.append("no comment")
        row["Flag"] = "; ".join(flags)
        rows.append(row)
    return rows


def sshd_config_rows(path: str, source: str) -> List[Dict[str, str]]:
    """Every effective setting in sshd_config, flagging ones that weaken or redirect authentication."""
    rows = []
    for number, line in enumerate(_lines(path), 1):
        text = line.split("#", 1)[0].strip()
        if not text:
            continue
        parts = re.split(r"[\s=]+", text, maxsplit=1)
        setting, value = parts[0], (parts[1] if len(parts) > 1 else "").strip()
        key, lowered = setting.lower(), value.lower()
        flag = ""
        if key == "permitrootlogin" and lowered == "yes":
            flag = "root can log in with a password"
        elif key == "permitemptypasswords" and lowered == "yes":
            flag = "empty passwords allowed"
        elif key == "passwordauthentication" and lowered == "yes":
            flag = "password authentication"
        elif key == "authorizedkeysfile" and lowered not in (".ssh/authorized_keys", ".ssh/authorized_keys .ssh/authorized_keys2",
                                                             "%h/.ssh/authorized_keys"):
            flag = "non-default authorized keys file"
        elif key in ("authorizedkeyscommand", "authorizedprincipalscommand") and lowered != "none":
            flag = "keys come from a command"
        elif key == "forcecommand":
            flag = "forced command"
        elif key == "gatewayports" and lowered == "yes":
            flag = "remote port forwards open to all"
        elif key == "permittunnel" and lowered not in ("no", ""):
            flag = "tunnelling allowed"
        elif key == "port" and value != "22":
            flag = "non-standard port"
        rows.append({"Source": source, "LineNumber": number, "Setting": setting, "Value": value, "Flag": flag})
    return rows


# ---- accounts ----------------------------------------------------------------

def _password_state(field: Optional[str]) -> str:
    if field is None:
        return "unknown (no shadow)"
    if field == "":
        return "EMPTY"
    if field in ("*", "!", "!!", "!*", "*LK*") or field.startswith("!"):
        return "locked" if len(field) <= 3 else "locked (hash kept)"
    match = re.match(r"^\$([^$]+)\$", field)
    if match:
        return "set ({})".format(HASH_TYPES.get(match.group(1), "$" + match.group(1) + "$"))
    return "set (DES)" if len(field) == 13 else "set"


def account_rows(passwd_path: str, shadow_path: Optional[str] = None) -> List[Dict[str, str]]:
    """One row per local account from passwd, with its password state from shadow (never the hash)."""
    shadow = {}
    if shadow_path and os.path.exists(shadow_path):
        for line in _lines(shadow_path):
            fields = line.split(":")
            if len(fields) >= 3:
                shadow[fields[0]] = fields[1:3]
    rows = []
    for line in _lines(passwd_path):
        fields = line.split(":")
        if len(fields) < 7 or line.startswith("#"):
            continue
        name, _, uid, gid, _, home, shell = fields[:7]
        login = not shell.endswith(NO_LOGIN) and shell != ""
        hashed, changed = (shadow.get(name) or [None, ""])
        password = _password_state(hashed)
        try:
            changed = (datetime(1970, 1, 1) + timedelta(days=int(changed))).date().isoformat() if changed else ""
        except ValueError:
            changed = ""
        flags = []
        if uid == "0" and name != "root":
            flags.append("UID 0 besides root")
        if password == "EMPTY" and login:
            flags.append("no password and can log in")
        if uid.isdigit() and 0 < int(uid) < 1000 and login and password.startswith("set") and name not in ("sync",):
            flags.append("system account that can log in with a password")
        rows.append({"User": name, "UID": uid, "GID": gid, "Home": home, "Shell": shell,
                     "CanLogIn": "yes" if login else "no", "Password": password, "PasswordChanged": changed,
                     "Flag": "; ".join(flags)})
    return rows
