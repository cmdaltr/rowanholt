#!/usr/bin/env python3 -tt
import json
import os
import re
from datetime import datetime, timezone

from rowanholt.audit import write_audit_log_entry
from rowanholt.core.records import SUFFIX, write_records
from rowanholt.process.extractions.mail import (
    extract_email_artefacts,
)
from rowanholt.process.extractions.mitre_tagger import history_off, suspicious_shell, tag_mitre_technique, unusual_unit


def _table(output_directory, img, vss_path_insert, name):
    """A cooked table's path without its suffix, and its name as the envelope gives it."""
    return output_directory + img.split("::")[0] + "/artefacts/cooked" + vss_path_insert + name, name


def _write(table, rows, img, artefact, time_field=None, techniques=None):
    """Append rows to a cooked table as JSON Lines: table is _table's (path, name), or a path under
    cooked/ without its suffix, whose name is then its path there."""
    if isinstance(table, str):
        path = table
        name = re.sub(r"^vss\d+/", "", path.split("/artefacts/cooked", 1)[-1].lstrip("/"))
    else:
        path, name = table
    raw = artefact.find("/artefacts/")
    return write_records(path + SUFFIX, rows, host=img.split("::")[0], artefact=name,
                         source_path=artefact[raw + 1:] if raw >= 0 else artefact, time_field=time_field,
                         techniques=techniques)


# A user's shell startup files, as Gandalf and Elrond name them (<user>+<file>, the dot dropped)
SHELL_RC = ("bashrc", "bash_profile", "bash_login", "bash_logout", "bash_aliases", "profile", "zshrc", "zprofile",
            "zshenv", "zlogin", "zlogout")


def command_techniques(command: str) -> list:
    """A shell command's techniques: T1059.004 when suspicious, T1070.003 when it clears the history."""
    return (["T1059.004"] if suspicious_shell([command]) else []) + (["T1070.003"] if history_off([command]) else [])


def is_shell_rc(artefact: str) -> bool:
    name = artefact.rsplit("/", 1)[-1]
    return "+" in name and name.rsplit("+", 1)[1] in SHELL_RC


def process_shell_rc(verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact):
    """A user's rc file: its lines that switch the history off (T1070.003) or run something suspicious
    (T1546.004). Everyone has a .bashrc, so only those lines are kept."""
    user, kind = artefact.rsplit("/", 1)[-1].rsplit("+", 1)
    with open(artefact, encoding="utf-8", errors="ignore") as rc:
        lines = [line.rstrip("\n") for line in rc]
    rows = []
    for number, line in enumerate(lines, 1):
        if line.strip().startswith("#"):
            continue
        if history_off([line]):
            rows.append({"User": user, "File": "." + kind, "LineNumber": number, "Line": line,
                         "Flag": "disables shell history", "Technique": "T1070.003"})
        elif suspicious_shell([line]):
            rows.append({"User": user, "File": "." + kind, "LineNumber": number, "Line": line,
                         "Flag": "suspicious command", "Technique": "T1546.004"})
    if not rows:
        return
    entry, prnt = "{},{},{},{} ({}) file\n".format(
        datetime.now().isoformat(), vssimage.replace("'", ""), stage, kind, user
    ), " -> {} -> {} {} ({}) file from {}".format(
        datetime.now().isoformat().replace("T", " "), stage, kind, user, vssimage
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    _write(_table(output_directory, img, vss_path_insert, "shell_rc"), rows, img, artefact,
           techniques=lambda r: [r["Technique"]])
    for technique in sorted({r["Technique"] for r in rows}):
        tag_mitre_technique(output_directory, img, "bash_history", technique)


def process_bash_history(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    entry, prnt = "{},{},{},bash_history ({}) file\n".format(
        datetime.now().isoformat(),
        vssimage.replace("'", ""),
        stage,
        artefact.split("/")[-1].split("+")[0],
    ), " -> {} -> {} bash_history ({}) file from {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        artefact.split("/")[-1].split("+")[0],
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    with open(artefact, encoding="utf-8", errors="ignore") as bashcontent:
        commands = [line.rstrip("\n") for line in bashcontent]
    _write(_table(output_directory, img, vss_path_insert, artefact.split("/")[-1].split("+")[0] + "+bash_history"),
           ({"Command": c} for c in commands), img, artefact,
           techniques=lambda r: command_techniques(r["Command"]))
    # Every host has a shell history: only what it holds tags T1059.004
    if suspicious_shell(commands):
        tag_mitre_technique(output_directory, img, "bash_history")
    if history_off(commands):
        tag_mitre_technique(output_directory, img, "bash_history", "T1070.003")


ZSH_EXTENDED = re.compile(r"^: (\d+):\d+;(.*)$", re.S)


def parse_zsh_history(text):
    """
    Split zsh history into (timestamp, command) pairs. EXTENDED_HISTORY lines
    are ': <epoch>:<duration>;<command>' (macOS's default); plain lines have no
    timestamp. A trailing backslash continues a command onto the next line.
    """
    entries, pending = [], ""
    for line in text.splitlines():
        if pending:
            pending += "\n" + line
        else:
            pending = line
        if pending.endswith("\\"):
            continue
        match = ZSH_EXTENDED.match(pending)
        if match:
            when = datetime.fromtimestamp(int(match.group(1)), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            entries.append((when, match.group(2)))
        elif pending.strip():
            entries.append(("", pending))
        pending = ""
    if pending.strip():
        entries.append(("", pending))
    return entries


def process_zsh_history(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    user = artefact.split("/")[-1].split("+")[0]
    entry, prnt = "{},{},{},zsh_history ({}) file\n".format(
        datetime.now().isoformat(),
        vssimage.replace("'", ""),
        stage,
        user,
    ), " -> {} -> {} zsh_history ({}) file from {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        user,
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    with open(artefact, encoding="utf-8", errors="ignore") as zshcontent:
        entries = parse_zsh_history(zshcontent.read())
    _write(_table(output_directory, img, vss_path_insert, user + "+zsh_history"),
           ({"LastWriteTime": when, "Command": command} for when, command in entries), img, artefact, "LastWriteTime",
           lambda r: command_techniques(r["Command"]))
    # Shell history is the same technique whichever shell wrote it, when it holds something to see
    if suspicious_shell(command for _, command in entries):
        tag_mitre_technique(output_directory, img, "bash_history")
    if history_off(command for _, command in entries):
        tag_mitre_technique(output_directory, img, "bash_history", "T1070.003")


def process_email(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
):
    mailjsonlist = []
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "mail"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "mail"
            )
        except:
            pass
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "mail/"
        + artefact.split("/")[-2]
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "mail/"
                + artefact.split("/")[-2]
            )
        except:
            pass
    entry, prnt = "{},{},{},'{}' ({}) Mail artefact\n".format(
        datetime.now().isoformat(),
        vssimage.replace("'", ""),
        stage,
        artefact.split("/")[-1],
        artefact.split("/")[-2],
    ), " -> {} -> {} Mail artefact '{}' ({}) from {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        artefact.split("/")[-1],
        artefact.split("/")[-2],
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    emlxjson = (
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "mail/"
        + artefact.split("/")[-2]
        + "/"
        + artefact.split("/")[-1]
    )
    try:
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/raw"
            + vss_path_insert
            + "mail/emails/"
            + artefact.split("/")[-2]
            + "/"
            + artefact.split("/")[-1],
            "r",
            encoding="utf-8",
        ) as mailemlx:
            emlxchain = str(mailemlx.readlines())
    except:
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/raw"
            + vss_path_insert
            + "mail/emails/"
            + artefact.split("/")[-2]
            + "/"
            + artefact.split("/")[-1],
            "r",
            encoding="ISO-8859-1",
        ) as mailemlx:
            emlxchain = str(mailemlx.readlines())
    ThreadNo, allLinks = 1, []
    try:
        boundaryPattern = re.compile(r"boundary\=\"([^\"]+)", re.IGNORECASE)
        boundary = re.findall(boundaryPattern, emlxchain)[0]
    except:
        boundary = ""
    try:
        ReceivedTime = re.findall(
            r"(?P<ReceivedTime>[A-Z][a-z]{2}\,\ \d+\ [A-Z][a-z]{2}\ \d+(?:\\n\'\,\ \')?\ \d+\:\d+\:\d+[^\\]+)",
            emlxchain,
        )[0]
        jsondict["ReceivedTime"] = ReceivedTime
    except:
        pass
    try:
        ReceivedByPattern = re.compile(
            r"'Received\:\ by\ (?P<ReceivedBy>[A-Fa-f\d\.\:]+)[^\;]+\;(?:\ |\\n(?:[\'\,\ ]+)?)",
            re.IGNORECASE,
        )
        ReceivedBy = re.findall(ReceivedByPattern, emlxchain)[0]
        jsondict["ReceivedBy"] = ReceivedBy
    except:
        pass
    try:
        ReturnPathPattern = re.compile(
            r"'Return\-Path\:\ (?P<ReturnPath>[^\\]+)\\n",
            re.IGNORECASE,
        )
        ReturnPath = re.findall(ReturnPathPattern, emlxchain)[0]
        jsondict["ReturnPath"] = ReturnPath
    except:
        pass
    try:
        ReceivedFromPattern = re.compile(
            r"'Received\:\ from\ (?P<ReceivedFrom>[^\\]+)",
            re.IGNORECASE,
        )
        ReceivedFrom = re.findall(ReceivedFromPattern, emlxchain)[0]
        jsondict["ReceivedFrom"] = ReceivedFrom
    except:
        pass
    try:
        ReceivedFromIP = re.findall(
            r"((?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[A-Fa-f\d]+\:[A-Fa-f\d]+\:[A-Fa-f\d]+\:[A-Fa-f\d]+\:[A-Fa-f\d]+\:[A-Fa-f\d]+\:[A-Fa-f\d]+\:[A-Fa-f\d]+))",
            ReceivedFrom,
        )[0]
        jsondict["ReceivedFromIP"] = ReceivedFromIP
    except:
        pass
    try:
        FromPattern = re.compile(r"From\:\ ([^\\]+)", re.IGNORECASE)
        From = re.findall(FromPattern, emlxchain)[0]
        jsondict["From"] = From
    except:
        pass
    try:
        ToPattern = re.compile(r"To\:\ ([^\\]+)", re.IGNORECASE)
        To = re.findall(ToPattern, emlxchain)[0]
        jsondict["To"] = To
    except:
        pass
    try:
        SubjectPattern = re.compile(r"Subject\:\ ([^\\]+)", re.IGNORECASE)
        Subject = re.findall(SubjectPattern, emlxchain)[0]
        jsondict["Subject"] = Subject
    except:
        pass
    try:
        LastWriteTimePattern = re.compile(r"Date\:\ ([^\\]+)", re.IGNORECASE)
        LastWriteTime = re.findall(LastWriteTimePattern, emlxchain)[0]
        jsondict["LastWriteTime"] = LastWriteTime
    except:
        pass
    try:
        MessageIDPattern = re.compile(r"Message\-ID\:\ ([^\\]+)", re.IGNORECASE)
        MessageID = re.findall(MessageIDPattern, emlxchain)[0]
        jsondict["MessageID"] = MessageID
    except:
        pass
    try:
        MIMEVersionPattern = re.compile(r"MIME\-Version\:\ ([^\\]+)", re.IGNORECASE)
        MIMEVersion = re.findall(MIMEVersionPattern, emlxchain)[0]
        jsondict["MIMEVersion"] = MIMEVersion
    except:
        pass
    jsondict["Mailbox"], jsondict["ThreadNo"] = (
        artefact.split("/")[-2],
        ThreadNo,
    )
    if boundary != "":
        for eachmesg in emlxchain.split(boundary)[2:-1]:
            jsondict["Boundary"] = boundary
            extract_email_artefacts(
                eachmesg[6::],
                jsondict,
                mailjsonlist,
                ThreadNo,
                allLinks,
            )
    else:
        extract_email_artefacts(
            emlxchain,
            jsondict,
            mailjsonlist,
            ThreadNo,
            allLinks,
        )
    if len(mailjsonlist) > 0:
        _write(emlxjson, (json.loads(m) if isinstance(m, str) else m for m in mailjsonlist), img, artefact,
               "LastWriteTime")
    mailjsonlist.clear()
    # Tag MITRE technique for email
    tag_mitre_technique(output_directory, img, "email")


def process_group(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    entry, prnt = "{},{},{},group file\n".format(
        datetime.now().isoformat(), vssimage.replace("'", ""), stage
    ), " -> {} -> {} group file from {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    rows = []
    with open(artefact, encoding="utf-8", errors="ignore") as groupcontent:
        for groupline in groupcontent:
            fields = groupline.rstrip("\n").split(":")
            if len(fields) == 4:
                rows.append(dict(zip(("group_name", "password", "groupID", "group_list"), fields)))
    _write(_table(output_directory, img, vss_path_insert, "group"), rows, img, artefact)
    # Tag MITRE technique for group file
    tag_mitre_technique(output_directory, img, "group")


def process_logs(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
):
    logjsonlist = []
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "logs/"
        + artefact.split("/")[-1]
        + ".jsonl"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "logs"
            )
        except:
            pass
        logjson = (
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "logs/"
            + artefact.split("/")[-1]
        )
        if (
            "auth" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            or "boot" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            or "corecaptured"
            in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            or "dpkg" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            or "fsck_apfs"
            in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            or "fsck_hfs" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            or "hfs_convert"
            in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            or "install" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            or "kern" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            or "LKDC-setup"
            in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            or "syslog" in artefact.split("/")[-1].split("+")[-1]
            or "system" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            or "vmware-vmsvc"
            in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            or "vmware-vmsvc-root"
            in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            or "vmware-vmtoolsd-root"
            in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
        ):
            entry, prnt = "{},{},{},'{}' file\n".format(
                datetime.now().isoformat(),
                vssimage.replace("'", ""),
                stage,
                artefact.split("/")[-1].split("+")[-1],
            ), " -> {} -> {} file '{}' from {}".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                artefact.split("/")[-1].split("+")[-1],
                vssimage,
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            if (
                "auth" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "syslog" in artefact.split("/")[-1].split("+")[-1]
            ):
                with open(artefact, encoding="utf-8", errors="ignore") as logfile:
                    for eachinfo in logfile:
                        for eachkv in re.findall(
                            r"(?P<LastWriteTime>[A-Z][a-z]{2}\s+\d+\s+\d+\:\d+\:\d+)\s+(?P<Device>[^\ ]+)\s+(?:(?P<Profile>[^\ ]+)\:\s+)?(?P<Account>[^\ ]+)\s?\:\s+(?P<Message>.*)",
                            eachinfo,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 4:
                                (
                                    jsondict["LastWriteTime"],
                                    jsondict["Device"],
                                    jsondict["Profile"],
                                    jsondict["Account"],
                                    jsondict["Message"],
                                ) = (
                                    kv[0],
                                    kv[1],
                                    kv[2],
                                    kv[3],
                                    kv[4],
                                )
                            elif len(kv) > 3:
                                (
                                    jsondict["LastWriteTime"],
                                    jsondict["Device"],
                                    jsondict["Account"],
                                    jsondict["Message"],
                                ) = (kv[0], kv[1], kv[2], kv[3])
                            jsonlist.append(json.dumps(jsondict))
                        jsondict.clear()
            elif "kern" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]:
                with open(artefact, encoding="utf-8", errors="ignore") as logfile:
                    for eachinfo in logfile:
                        for eachkv in re.findall(
                            r"(?P<LastWriteTime>[A-Z][a-z]{2}\s+\d+\s+\d+\:\d+\:\d+)\s+(?P<Device>[^\ ]+)\s+(?P<Service>[^\[]+)(?:\[(?P<PID>\d+)\]\:\s+\<(?P<LogLevel>[^\>]+)\>)?\s+\[\s?\d+\.\d+\]\s+(?P<Message>.*)",
                            eachinfo,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 5:
                                (
                                    jsondict["LastWriteTime"],
                                    jsondict["Device"],
                                    jsondict["Service"],
                                    jsondict["PID"],
                                    jsondict["LogLevel"],
                                    jsondict["Message"],
                                ) = (
                                    kv[0],
                                    kv[1],
                                    kv[2],
                                    kv[3],
                                    kv[4],
                                    kv[5],
                                )
                            elif len(kv) > 4:
                                (
                                    jsondict["LastWriteTime"],
                                    jsondict["Device"],
                                    jsondict["Service"],
                                    jsondict["LogLevel"],
                                    jsondict["Message"],
                                ) = (
                                    kv[0],
                                    kv[1],
                                    kv[2],
                                    kv[3],
                                    kv[4],
                                )
                            jsonlist.append(json.dumps(jsondict))
                    jsondict.clear()
            elif (
                "corecaptured"
                in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            ):
                with open(artefact, encoding="utf-8", errors="ignore") as logfile:
                    for eachinfo in logfile:
                        for eachkv in re.findall(
                            r"(?P<LastWriteTime>[A-Za-z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2})\s(?P<Service>\w+)\:\:(?P<Message>.*)",
                            eachinfo,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                (
                                    jsondict["LastWriteTime"],
                                    jsondict["Service"],
                                    jsondict["Message"],
                                ) = (kv[0], kv[1], kv[2])
                            jsonlist.append(json.dumps(jsondict))
                    jsondict.clear()
            elif (
                "vmware-vmsvc"
                in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "vmware-vmsvc-root"
                in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "vmware-vmtoolsd-root"
                in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            ):
                with open(artefact, encoding="utf-8", errors="ignore") as logfile:
                    for eachinfo in logfile:
                        for eachkv in re.findall(
                            r"\[(?P<LastWriteTime>[^\]]+)\]\s+\[\s*(?P<Action>[^\]]+)\]\s+\[(?P<Service>[^\]]+)\]\s*(?P<Message>.*)",
                            eachinfo,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                (
                                    jsondict["LastWriteTime"],
                                    jsondict["Service"],
                                    jsondict["Message"],
                                ) = (kv[0], kv[1], kv[2])
                            jsonlist.append(json.dumps(jsondict))
                    jsondict.clear()
            elif (
                "LKDC-setup"
                in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            ):
                with open(artefact, encoding="utf-8", errors="ignore") as logfile:
                    for eachinfo in str(logfile.readlines()).split(
                        "...creating certificate..."
                    )[1:]:
                        for eachkv in re.findall(
                            r"\s*(?P<k>\w[^\'\:]+\w)\s+\:\s+(?P<v>[^\']+)\\n",
                            eachinfo.split("', 'Extension struct")[0],
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0].replace(" ", "")] = (
                                    kv[1].strip("\\n").strip()
                                )
                        for info in eachinfo.split("', 'Extension struct")[1:]:
                            for extinfo in info.split("\\n', '"):
                                for extkv in re.findall(
                                    r"\s*(?P<k>\w[^\'\:]+\w)\s+\:\s+(?P<v>[^\']+)",
                                    extinfo,
                                ):
                                    ekv = list(extkv)
                                    if len(ekv) > 0:
                                        jsondict[ekv[0].replace(" ", "")] = (
                                            ekv[1].strip("\\n").strip()
                                        )
                            jsonlist.append(json.dumps(jsondict))
                    jsondict.clear()
            elif (
                "fsck_apfs"
                in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "fsck_hfs"
                in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            ):
                with open(artefact, encoding="utf-8", errors="ignore") as logfile:
                    for eachinfo in str(logfile.readlines()).split(
                        ", '\\n', '\\n', "
                    ):
                        for eachkv in re.findall(
                            r"(?P<Disk>[\w\/]+)\:\s+(?P<Service>\w+)\sstarted\sat\s(?P<LastWriteTime>[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s\d{4})(?P<Message>[\S\s]+)\1\:\s+\2\s+completed\sat\s(?P<LastWriteTimeEnd>[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s\d{4})",
                            eachinfo,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                (
                                    jsondict["Service"],
                                    jsondict["Disk"],
                                    jsondict["LastWriteTime"],
                                    jsondict["LastWriteTimeEnd"],
                                    jsondict["Message"],
                                ) = (
                                    kv[1],
                                    kv[0],
                                    kv[2],
                                    kv[4],
                                    str(kv[3])[6:-6],
                                )
                            jsonlist.append(json.dumps(jsondict))
                    jsondict.clear()
            elif (
                "hfs_convert"
                in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            ):
                with open(artefact, encoding="utf-8", errors="ignore") as logfile:
                    logdata = str(logfile.readlines())
                for eachinfo in str(
                    re.sub(
                        r"(\'\,\s|\[)\'([A-Z][a-z]{2})\s",
                        r"||||\2\ ",
                        logdata,
                    )
                ).split("||||")[1:]:
                    for info in str(
                        re.sub(
                            r"(\d{2}\:\d{2}\:\d{2}\ \d{4}\:)\ ",
                            r"\1:::",
                            eachinfo.replace("['", "")
                            .replace("']", "")
                            .replace("  ", "")
                            .replace("\\ ", " ")
                            .replace("', '", ""),
                        )
                    ).split("::::")[1:]:
                        for everyinfo in info.split("\\n"):
                            if len(everyinfo.strip()) > 0:
                                (
                                    jsondict["LastWriteTime"],
                                    jsondict["Message"],
                                ) = (
                                    str(
                                        re.sub(
                                            r"^([A-Z][a-z]{2}\ [A-Z][a-z]{2})(\d+)(\ \d{2}\:\d{2}\:\d{2}\ \d{4})",
                                            r"\1 \2\3",
                                            str(
                                                re.sub(
                                                    r"(\d{2}\:\d{2}\:\d{2}\ \d{4}\:)\ ",
                                                    r"\1:::",
                                                    eachinfo.replace("['", "")
                                                    .replace("']", "")
                                                    .replace("  ", "")
                                                    .replace(
                                                        "\\ ",
                                                        " ",
                                                    )
                                                    .replace(
                                                        "', '",
                                                        "",
                                                    ),
                                                )
                                            ).split("::::")[0],
                                        )
                                    ),
                                    everyinfo.strip(),
                                )
                            jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif (
                "install" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            ):
                with open(artefact, encoding="utf-8", errors="ignore") as logfile:
                    logdata = str(logfile.readlines())
                for eachinfo in str(
                    re.sub(
                        r"(\d{4}\-\d{2}\-\d{2}\s\d{2}\:\d{2}\:\d{2})",
                        r"||||\1",
                        logdata,
                    )
                ).split("||||"):
                    for eachkv in re.findall(
                        r"^(?P<LastWriteTime>\d{4}\-\d{2}\-\d{2}\s\d{2}\:\d{2}\:\d{2}\-\d{2})\s(?P<Device>[^\s]+)\s(?P<Service>[^\[]+)\[(?P<PID>\d+)\]\:\s(?P<Message>.*)",
                        str(
                            eachinfo.strip("', '")
                            .replace("  ", "")
                            .replace("', '", "")
                            .replace('", "', "")
                            .replace("\\n", "")
                            .replace("\\t", "")
                            .replace("\\", "")
                            .replace("'/", "'")
                            .replace("', \"", "")
                        ),
                    ):
                        if len(eachkv) > 4:
                            (
                                jsondict["LastWriteTime"],
                                jsondict["Device"],
                                jsondict["Service"],
                                jsondict["PID"],
                                jsondict["Message"],
                            ) = (
                                eachkv[0],
                                eachkv[1],
                                eachkv[2],
                                eachkv[3],
                                eachkv[4].replace("\\", ""),
                            )
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            records = []
            for eachjson in jsonlist:
                record = json.loads(eachjson)
                if record.get("CommonName"):
                    record["Log"] = str(record["CommonName"]).lower().replace(" ", "_")
                records.append(record)
            if records:
                _write(logjson, records, img, artefact, "LastWriteTime")
            logjsonlist.clear()
            jsonlist.clear()
            # Tag MITRE technique for log file
            tag_mitre_technique(output_directory, img, "logs")


def process_service(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
):
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "services/"
        + artefact.split("/")[-1]
        + ".jsonl"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "services"
            )
        except:
            pass
        servicejson = (
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "services/"
            + artefact.split("/")[-1]
        )
        entry, prnt = "{},{},{},'{}' service file\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
            artefact.split("/")[-1].split("+")[-1],
        ), " -> {} -> {} service file '{}' from {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            artefact.split("/")[-1].split("+")[-1],
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        with open(artefact, encoding="utf-8", errors="ignore") as service:
            servicedata = str(service.readlines())
            for eachinfo in servicedata.split("\\n', '"):
                if "=" in eachinfo:
                    jsondict[
                        str(eachinfo.split("=")[0])
                        .strip()
                        .replace("Service", "Command")
                        .replace("BusName", "Command")
                        .replace("ExecStart", "Command")
                        .replace("Description", "Process")
                    ] = (
                        str(eachinfo.split("=")[1])
                        .strip()
                        .replace("\\", "")
                        .replace("n']", "")
                    )
            jsonlist.append(json.dumps(jsondict))
        jsondict.clear()
        records = [json.loads(j) for j in jsonlist]
        # Every host has its distribution's units: a unit tags T1543.002 when it runs from a
        # user-writable folder or runs a download or reverse shell
        _write(servicejson, records, img, artefact,
               techniques=lambda r: ["T1543.002"] if unusual_unit(json.dumps([r])) else [])
        jsonlist.clear()
        if unusual_unit(json.dumps(records)):
            tag_mitre_technique(output_directory, img, "service")
