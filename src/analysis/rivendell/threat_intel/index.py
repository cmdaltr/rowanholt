"""Matching text from a case against threat intelligence indicators.

Each indicator's element is classified by its value (the fixed schema has no kind column):
ip, hash, url, domain, reg, path, file, cmd or software. Atomic indicators (ip, hash, url, domain)
match exactly; file names and tool names match as whole tokens; commands, registry keys and paths
match as phrases, in order, wherever they appear in a field.

What doesn't match, by design:
- Built-in binaries and commands (net, cmd.exe, rundll32.exe, whoami), tool names that are also
  ordinary words (empire), and anything under three characters. MITRESaw names them because a
  procedure used them, but they're on every host, so a match says nothing.
- Prose and documentation placeholders picked up by procedure extraction (Archer's indicator
  hygiene, archer/build/indicator_hygiene.py).
- Public resolvers and first-party domains (known_good.json, from Archer).

Procedure evidence (MITRESaw's) describes what a group did, not what only it leaves behind: it
names kernel32.dll, eth0 and .jpg as readily as Mimikatz, and those are on every host. Matching a
whole case (scope "case") takes from it only tool names and distinctive command phrases; its file
names, registry keys and paths answer a question about one value (scope "value", enrich_artefact).
Curated sources (the workbook, STIX, watchlists) match in full either way.

Every match carries its breadth: how many groups the element is evidence for. An element half the
groups use is a lead to look at, not an attribution, and threat_intel/match.py leaves elements
used by more than COMMON_BREADTH groups out of the group ranking.
"""

import html
import ipaddress
import json
import os
import re
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Set, Tuple

from rivendell.threat_intel.schema import Indicator

COMMON_BREADTH = 15
HERE = os.path.dirname(__file__)

HASH = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$")
DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
REGISTRY = re.compile(r"^(?:hklm|hkcu|hku|hkcr|hkcc|hkey_[a-z_]+)\\", re.I)
EXECUTABLE_SUFFIXES = (".exe", ".dll", ".sys", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".hta",
                       ".wsf", ".scr", ".cpl", ".msi", ".lnk", ".py", ".pl", ".sh", ".jar", ".so", ".elf", ".bin",
                       ".dat", ".tmp", ".zip", ".rar", ".7z", ".iso", ".doc", ".docm", ".xls", ".xlsm", ".pdf")
# A program's or script's name stands for the tool (mimikatz.exe is Mimikatz); a library's doesn't
# (winmm.dll is Windows, not the WinMM malware)
PROGRAM_SUFFIXES = (".exe", ".ps1", ".py", ".sh", ".bat", ".cmd", ".vbs", ".js", ".hta", ".jar", ".elf", ".bin")
REGISTRY_HIVES = (("hkey_local_machine", "hklm"), ("hkey_current_user", "hkcu"), ("hkey_users", "hku"),
                  ("hkey_classes_root", "hkcr"), ("hkey_current_config", "hkcc"))
# A hive, or a hive's top-level key, on its own: in every registry path, so never an indicator
HIVE_ROOT = re.compile(r"(?:hklm|hkcu|hku|hkcr|hkcc)(?:\\(?:software|system|sam|security|hardware|classes))?\\?")
TOKEN = re.compile(r"[a-z0-9_$~@#-]+(?:\.[a-z0-9_$~@#-]+)*")
URL = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>|]+", re.I)
GAP = "…"  # where a placeholder stood in a procedure's command

# On every Windows, Linux or macOS host, or used by administrators daily
GENERIC = {
    "cmd", "cmd.exe", "command", "powershell", "powershell.exe", "pwsh", "pwsh.exe", "net", "net.exe", "net1",
    "net1.exe", "reg", "reg.exe", "sc", "sc.exe", "wmic", "wmic.exe", "rundll32", "rundll32.exe", "regsvr32",
    "regsvr32.exe", "mshta", "mshta.exe", "certutil", "certutil.exe", "bitsadmin", "bitsadmin.exe", "schtasks",
    "schtasks.exe", "at", "at.exe", "tasklist", "tasklist.exe", "taskkill", "taskkill.exe", "whoami", "whoami.exe",
    "ipconfig", "ipconfig.exe", "netstat", "netstat.exe", "nslookup", "nslookup.exe", "ping", "ping.exe",
    "systeminfo", "systeminfo.exe", "hostname", "hostname.exe", "dir", "copy", "del", "type", "echo", "find",
    "findstr", "findstr.exe", "attrib", "attrib.exe", "cscript", "cscript.exe", "wscript", "wscript.exe",
    "explorer.exe", "svchost.exe", "lsass.exe", "lsass", "services.exe", "winlogon.exe", "csrss.exe", "smss.exe",
    "conhost.exe", "dllhost.exe", "msiexec", "msiexec.exe", "netsh", "netsh.exe", "route", "arp", "query", "quser",
    "qwinsta", "xcopy", "robocopy", "expand", "makecab", "curl", "curl.exe", "wget", "ssh", "scp", "sftp", "python",
    "python3", "perl", "bash", "sh", "zsh", "chmod", "chown", "crontab", "cron", "systemctl", "launchctl",
    "osascript", "systemsetup", "ls", "ps", "id", "uname", "cat", "kill", "sudo", "su", "useradd", "usermod",
    "passwd", "iptables", "tar", "zip", "unzip", "gzip", "base64", "nc", "netcat", "telnet", "ftp", "tftp", "mount",
    "rm", "mv", "cp", "touch", "history", "env", "export", "set", "start", "runas", "icacls", "takeown", "cacls",
    "vssadmin", "vssadmin.exe", "wevtutil", "wevtutil.exe", "nltest", "nltest.exe", "dsquery", "csvde", "ldifde",
    "fsutil", "bcdedit", "diskshadow", "ntdsutil", "esentutl", "forfiles", "pcalua", "mmc", "mmc.exe",
    "notepad.exe", "calc.exe", "taskmgr.exe", "regedit", "regedit.exe", "control", "control.exe", "winword.exe",
    "excel.exe", "outlook.exe", "iexplore.exe", "chrome.exe", "firefox.exe", "msedge.exe", "java", "java.exe",
    "javaw.exe", "node", "node.exe", "ruby", "php", "go", "docker", "kubectl", "git", "vim", "nano", "apt", "yum",
    "dnf", "brew", "pip", "npm", "openssl", "sqlite3", "dig", "host", "whois", "traceroute", "tracert",
    "systemd", "init", "launchd", "lsof", "top", "who", "w", "last", "lastlog", "dmesg", "journalctl", "logger",
    "defaults", "plutil", "security", "csrutil", "spctl", "kextload", "dscl", "scutil", "networksetup",
    "screencapture", "pbpaste", "pbcopy", "curl.exe", "tar.exe", "ssh.exe", "winrm", "winrs", "winrm.cmd",
    "wmiprvse.exe", "taskeng.exe", "taskhostw.exe", "sihost.exe", "spoolsv.exe", "searchindexer.exe",
}
# Tool names that are also ordinary words in titles, paths and messages
COMMON_WORDS = {"empire", "agent", "shell", "backdoor", "dropper", "loader", "stealer", "update", "updater", "helper",
                "client", "server", "service", "system", "windows", "office", "chrome", "remote", "proxy", "tunnel",
                "screen", "keylogger", "ransomware", "trojan", "downloader", "installer", "launcher", "sleep", "beacon",
                "nmap", "putty", "winrar", "teamviewer", "anydesk", "ngrok", "rclone", "mega", "dropbox", "onedrive",
                "outlook", "excel", "word", "adobe", "zoom", "slack", "skype", "telegram", "discord", "steam",
                # malware names that are also Windows or application strings
                "winmm", "crashpad", "rtm", "flame", "olympic"}
# Commands and accounts in every Windows event log and PowerShell script
GENERIC_PHRASES = {"nt authority\\system", "nt authority\\network service", "nt authority\\local service",
                   "-erroraction silentlycontinue", "-erroraction stop", "-ea silentlycontinue", "out-null",
                   "-executionpolicy remotesigned", "net start", "net stop"}
STOPWORDS = {"a", "an", "and", "are", "as", "at", "be", "by", "can", "for", "from", "has", "have", "how", "in", "into",
             "is", "it", "its", "may", "of", "on", "or", "such", "that", "the", "their", "this", "to", "used", "using",
             "via", "was", "well", "were", "which", "while", "with", "within"}
SYNTAX = set("-/\\=:\"{}|$%<>*[]_@&;^~+#")
PLACEHOLDER = re.compile(r"<[A-Za-z][\w\s|-]*>|\{[\w\s|/,-]+\}|\[\s*(?:user ?name|host ?name|ip|domain|path|file ?name|"
                         r"password|computer ?name|target|share|url|port)\s*\]", re.I)


def normalise(value: str) -> str:
    value = html.unescape(str(value)).strip().strip("`'\"").strip().lower()
    value = re.sub(r"\s+", " ", value)
    for long, short in REGISTRY_HIVES:
        value = value.replace(long, short)
    return value


def classify(value: str) -> str:
    """ip, hash, url, domain, reg, path, file, cmd or software, from the value alone."""
    v = normalise(value)
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if HASH.match(v):
        return "hash"
    if "://" in v:
        return "url"
    if REGISTRY.match(v):
        return "reg"
    if re.match(r"^(?:[a-z]:\\|%[a-z_]+%\\|\\\\)", v):  # C:\..., %APPDATA%\..., \\share\...
        return "path"
    if " " not in v and ("\\" in v or "/" in v or v.startswith("%")):
        return "path"
    if " " not in v and v.endswith(EXECUTABLE_SUFFIXES):
        return "file"
    if DOMAIN.match(v):
        return "domain"
    if " " in v:
        return "cmd"
    return "software"


def _prose(value: str) -> bool:
    words = value.split()
    if len(words) < 5:
        return False
    tokens = [w.strip(".,;:!?()") for w in words]
    if any(set(t) & SYNTAX or t.endswith((".exe", ".dll", ".ps1", ".sh")) for t in tokens):
        return False
    return sum(t in STOPWORDS for t in tokens) / len(tokens) >= 0.2


def usable(value: str, kind: str) -> Optional[str]:
    """The element as text to look for, or None when it can't be a meaningful match."""
    v = normalise(value)
    if not v or "citation:" in v or _prose(v):
        return None
    v = PLACEHOLDER.sub(GAP, v)
    if GAP in v:
        v = re.sub(re.escape(GAP) + r"+", GAP, v).strip(GAP + " ")
    stripped = re.sub(r"[\W_]", "", v.replace(GAP, ""))
    if len(stripped) < 3:
        return None
    if re.fullmatch(r"\.[a-z0-9]{1,5}", v) or (kind == "software" and not re.match(r"[a-z0-9]", v)):
        return None  # ".jpg", "-noprofile", "$u": a fragment, not an indicator
    if kind in ("software", "file") and (v in GENERIC or v in COMMON_WORDS or os.path.basename(v) in GENERIC):
        return None
    original = str(value).strip()
    if kind == "software" and original.isalpha() and original.islower():
        return None  # a word from a command line ("hidden" from -w hidden); tool names are proper nouns
    if v in GENERIC_PHRASES or HIVE_ROOT.fullmatch(v):
        return None
    if kind == "cmd":
        words = v.replace(GAP, " ").split()
        if len(words) == 1 or all(w in GENERIC or w.startswith(("-", "/")) or len(w) < 3 for w in words):
            return None  # "net user", "whoami /all": the command alone, on every host
    if kind == "path":
        parts = [p for p in re.split(r"[\\/]+", v) if p and not re.fullmatch(r"[a-z]:|%[a-z_]+%|~", p)]
        if len(v) < 10 or ("." not in parts[-1:][0] if parts else True) and len(parts) < 4:
            return None  # C:\ProgramData\Microsoft: a directory near the root holds every system file
    return v


def known_good() -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    try:
        with open(os.path.join(HERE, "known_good.json"), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return out
    for key, entry in data.items():
        if key.startswith("_"):
            continue
        out[key] = {str(v).lower() for v in (entry.get("values") if isinstance(entry, dict) else entry) or []}
    return out


def case_wide(indicator: Indicator, kind: str) -> bool:
    """Whether an indicator is matched across a whole case: everything from a curated source, and
    from procedure evidence only ATT&CK software names and command phrases of two or more words."""
    if not indicator.source_type.lower().startswith("mitresaw"):
        return True
    evidence = indicator.contextual_evidence.split(";", 1)[0].strip()
    if evidence == "software":
        return True
    return evidence == "cmd" and kind == "cmd"


class ThreatIntelIndex:
    """Indicators prepared for matching. Build once per case (or per process for Eru)."""

    def __init__(self, indicators: Iterable[Indicator], scope: str = "value"):
        good = known_good()
        first_party = good.get("first_party_domains", set())
        shared = good.get("shared_hosting", set())
        skip = good.get("ips", set()) | good.get("hashes", set()) | shared
        self.indicators: List[Indicator] = []
        self.kinds: List[str] = []
        self.exact: Dict[str, List[int]] = defaultdict(list)
        self.phrases: Dict[str, List[Tuple[Tuple[str, ...], int]]] = defaultdict(list)
        self.breadth: Dict[str, int] = {}
        groups_by_element: Dict[str, Set[str]] = defaultdict(set)
        self.skipped = 0
        for indicator in indicators:
            kind = classify(indicator.evidential_element)
            if scope == "case" and not case_wide(indicator, kind):
                self.skipped += 1
                continue
            text = usable(indicator.evidential_element, kind)
            if text is None or text in skip or (kind == "domain" and any(
                    text == d or text.endswith("." + d) for d in first_party)):
                self.skipped += 1
                continue
            number = len(self.indicators)
            self.indicators.append(indicator)
            self.kinds.append(kind)
            groups_by_element[text].add(indicator.threat_group.lower() or indicator.source_type.lower())
            key = os.path.basename(text.replace("\\", "/")) if kind == "file" else text
            if kind in ("ip", "hash", "url", "domain", "file", "software") and (
                    kind == "url" or TOKEN.fullmatch(key)):
                self.exact[key].append(number)
            else:
                parts = tuple(p.strip() for p in text.split(GAP) if p.strip())
                anchor = self._anchor(parts)
                if anchor:
                    self.phrases[anchor].append((parts, number))
                else:
                    self.skipped += 1
        self.breadth = {element: len(groups) for element, groups in groups_by_element.items()}

    @staticmethod
    def _anchor(parts: Tuple[str, ...]) -> str:
        """The rarest-looking token of a phrase (the longest), which a text must contain to match."""
        tokens = [t for p in parts for t in TOKEN.findall(p) if t not in GENERIC and len(t) >= 3]
        return max(tokens, key=len) if tokens else ""

    def __len__(self) -> int:
        return len(self.indicators)

    def match(self, text: str) -> List[Tuple[Indicator, str, int]]:
        """(indicator, kind, breadth) for each indicator found in the text, each indicator once."""
        if not text or len(text) < 3:
            return []
        lowered = normalise(text)
        tokens = set(TOKEN.findall(lowered))
        for path_like in re.split(r"[\s\"'|,;]+", lowered):
            if "\\" in path_like or "/" in path_like:
                tokens.add(path_like.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1])
        tokens.update(URL.findall(lowered))
        tokens.update(token.rsplit(".", 1)[0] for token in list(tokens) if token.endswith(PROGRAM_SUFFIXES))
        found: Dict[int, None] = {}
        for token in tokens:
            for number in self.exact.get(token, ()):
                found[number] = None
            for parts, number in self.phrases.get(token, ()):
                if number in found:
                    continue
                position = 0
                for part in parts:
                    position = lowered.find(part, position)
                    if position < 0:
                        break
                    position += len(part)
                else:
                    found[number] = None
        out = []
        for number in found:
            indicator = self.indicators[number]
            element = usable(indicator.evidential_element, self.kinds[number]) or ""
            out.append((indicator, self.kinds[number], self.breadth.get(element, 1)))
        return out


def by_element(matches: List[Tuple[Indicator, str, int]]) -> List[Dict[str, object]]:
    """Matches gathered per evidential element: an element MITRESaw names for a hundred groups is
    one finding with a hundred groups behind it, not a hundred findings."""
    grouped: Dict[str, Dict[str, object]] = {}
    for indicator, kind, breadth in matches:
        entry = grouped.setdefault(indicator.evidential_element.lower(), {
            "element": indicator.evidential_element, "kind": kind, "breadth": breadth,
            "groups": [], "techniques": [], "sources": [], "indicators": []})
        for key, value in (("groups", indicator.threat_group), ("techniques", indicator.technique_id),
                           ("sources", indicator.source_type)):
            if value and value not in entry[key]:
                entry[key].append(value)
        entry["indicators"].append(indicator)
    entries = list(grouped.values())
    # A truncated copy of a longer match ("net user /dom" inside "net user /domain") that fewer groups
    # (or as many) stand behind is an extraction artefact; a shorter match more groups use ("net user") is real
    entries = [e for e in entries if not any(
        o is not e and o["breadth"] >= e["breadth"] and len(str(o["element"])) > len(str(e["element"]))
        and str(o["element"]).lower().startswith(str(e["element"]).lower())
        for o in entries)]
    return sorted(entries, key=lambda e: (e["breadth"], e["element"].lower()))


def enrich_artefact(value: str, index: ThreatIntelIndex) -> List[Dict[str, object]]:
    """What threat intelligence says about one process name, command line or file path (or any IP,
    domain, hash or URL in it): one entry per matching evidential element, the most specific first,
    each with the groups, techniques and sources behind it and the indicator rows themselves
    (schema display names). This is the function Eru calls."""
    out = []
    for entry in by_element(index.match(value)):
        rows = [i.row() for i in entry.pop("indicators")]
        out.append({**entry, "common": entry["breadth"] > COMMON_BREADTH, "rows": rows})
    return out
