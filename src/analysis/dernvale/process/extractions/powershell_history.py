"""PSReadLine history (ConsoleHost_history.txt): every interactive PowerShell command.

PSReadLine saves each command typed at a PowerShell console, per user, with no time
of its own. Each line becomes a row; lines that match common attacker tradecraft are
flagged and tagged with the technique they suggest.
"""

import re
from typing import Dict, List, Tuple

PATTERNS: Tuple[Tuple[str, str, "re.Pattern"], ...] = (
    ("download", "T1105", re.compile(
        r"invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|downloadstring|downloadfile|net\.webclient|"
        r"start-bitstransfer|curl(\.exe)?\s+http|wget\s+http|certutil.*-urlcache", re.I)),
    ("encoded command", "T1027", re.compile(r"\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{16,}|frombase64string", re.I)),
    ("invoke-expression", "T1059.001", re.compile(r"\biex\b|invoke-expression", re.I)),
    ("execution policy bypass", "T1059.001", re.compile(r"-ep\s+bypass|-executionpolicy\s+(bypass|unrestricted)|"
                                                      r"set-executionpolicy\s+(bypass|unrestricted)", re.I)),
    ("hidden window", "T1564.003", re.compile(r"-w(indowstyle)?\s+h(idden)?\b", re.I)),
    ("defender tampering", "T1562.001", re.compile(r"set-mppreference|add-mppreference|disablerealtimemonitoring|"
                                                  r"exclusionpath|tamperprotection", re.I)),
    ("amsi bypass", "T1562.001", re.compile(r"amsiutils|amsiinitfailed|amsi\.dll", re.I)),
    ("credential access", "T1003", re.compile(r"mimikatz|sekurlsa|lsadump|procdump.*lsass|comsvcs.*minidump|"
                                             r"get-credential|convertto-securestring.*-asplaintext", re.I)),
    ("log clearing", "T1070.001", re.compile(r"clear-eventlog|wevtutil\s+cl|remove-eventlog", re.I)),
    ("persistence", "T1053.005", re.compile(r"register-scheduledtask|new-scheduledtask|schtasks\s+/create", re.I)),
    ("persistence", "T1547.001", re.compile(r"(reg(\.exe)?\s+add|set-itemproperty|new-itemproperty)\b.*currentversion\\run",
                                           re.I)),
    ("persistence", "T1546.003", re.compile(r"__eventfilter|commandlineeventconsumer|set-wmiinstance", re.I)),
    ("remote execution", "T1021.006", re.compile(r"invoke-command|enter-pssession|new-pssession", re.I)),
    ("discovery", "T1087", re.compile(r"get-aduser|get-localuser|net\s+user|net\s+group|whoami\s+/all", re.I)),
    ("discovery", "T1069", re.compile(r"get-localgroupmember|get-adgroupmember|net\s+localgroup", re.I)),
    ("ads", "T1564.004", re.compile(r"-stream\s+\S|:\$data", re.I)),
    ("timestomp", "T1070.006", re.compile(r"\.(creationtime|lastwritetime|lastaccesstime)\s*=", re.I)),
)
HEADER = ["User", "LineNumber", "Command", "Flags", "Techniques"]


def history_user(name: str) -> str:
    """gandalf_ConsoleHost_history.txt or gandalf+ConsoleHost_history.txt -> gandalf."""
    for separator in ("_ConsoleHost_history", "+ConsoleHost_history"):
        if separator in name:
            return name.split(separator)[0]
    return ""


def powershell_history_rows(path: str, user: str = "") -> Tuple[List[Dict[str, str]], List[str]]:
    """(rows, techniques) for one ConsoleHost_history.txt."""
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        lines = fh.read().splitlines()
    rows, techniques = [], set()
    for number, line in enumerate(lines, 1):
        command = line.strip()
        if not command:
            continue
        flags, tagged = [], []
        for label, technique, pattern in PATTERNS:
            if pattern.search(command):
                if label not in flags:
                    flags.append(label)
                tagged.append(technique)
        if tagged:
            tagged.append("T1059.001")
        techniques.update(tagged)
        rows.append({"User": user, "LineNumber": number, "Command": command[:8000],
                     "Flags": ", ".join(flags), "Techniques": ", ".join(sorted(set(tagged)))})
    return rows, sorted(techniques)
