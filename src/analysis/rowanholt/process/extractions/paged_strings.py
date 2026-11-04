"""Evidence strings in Windows paging files: pagefile.sys, swapfile.sys, hiberfil.sys.

Paged-out memory keeps command lines, URLs and paths long after the process that
held them has gone, and it's there even when no memory image was taken. Without
Volatility (no --Memory, or hiberfil.sys, which Volatility can't read here), this
pulls ASCII and UTF-16LE strings and keeps those that look like evidence:
URLs, IPv4 addresses, e-mail addresses, executable and script paths, command lines
and Run-key paths. Each distinct string is reported once, with where it was first
seen and how often. hiberfil.sys on Windows 8 and later is mostly compressed, so it
gives far fewer strings than a pagefile.
"""

import mmap
import os
import re
from typing import Dict, List, Tuple

ASCII = re.compile(rb"[\x20-\x7e]{6,512}")
UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,512}")
CHUNK = 64 << 20
OVERLAP = 2048
MAX_ROWS = 200000

KINDS: Tuple[Tuple[str, "re.Pattern"], ...] = (
    ("url", re.compile(r"\b(?:https?|ftp)://[\w.\-]+(?::\d+)?(?:/[^\s\"'<>]*)?", re.I)),
    ("command", re.compile(
        r"\b(?:powershell(?:\.exe)?\s+[-/]\w|cmd(?:\.exe)?\s+/[ck]\s|mshta\s|rundll32(?:\.exe)?\s+\S|regsvr32\s|"
        r"certutil(?:\.exe)?\s+-|bitsadmin\s+/|wmic\s+\S|schtasks(?:\.exe)?\s+/create|net\s+user\s|"
        r"invoke-webrequest|downloadstring|iex\s*\(|-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{16,})", re.I)),
    ("run key", re.compile(r"\\(?:Software\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce)|"
                           r"CurrentControlSet\\Services)\\[^\x00]{1,200}", re.I)),
    ("email", re.compile(r"\b[\w.+\-]{1,64}@[\w\-]{1,63}(?:\.[\w\-]{1,63})*\.[a-z]{2,24}\b", re.I)),
    ("path", re.compile(r"\b[A-Z]:\\[^\x00\"<>|*?\r\n]{1,260}\.(?:exe|dll|ps1|psm1|bat|cmd|vbs|js|hta|scr|lnk|sys)\b",
                        re.I)),
    ("ipv4", re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")),
)
IGNORED_IPV4 = re.compile(r"^(?:0\.|127\.|255\.|224\.|1\.0\.0\.|2\.0\.0\.|\d+\.0\.0\.0$)")
HEADER = ["Source", "Kind", "String", "Encoding", "FirstOffset", "Count"]


def _classify(text: str):
    for kind, pattern in KINDS:
        match = pattern.search(text)
        if not match:
            continue
        value = match.group(0) if kind in ("url", "ipv4", "email", "path") else text.strip()
        if kind == "ipv4" and (IGNORED_IPV4.match(value) or len(text) > 64 and not re.search(r"[:/\\]", text)):
            continue
        return kind, value[:512]
    return None


def paged_strings(path: str) -> List[Dict[str, object]]:
    """Distinct evidence strings in a paging file, in the order first found."""
    found: Dict[Tuple[str, str], Dict[str, object]] = {}
    source = os.path.basename(path)
    size = os.path.getsize(path)
    if not size:
        return []
    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as view:
        for start in range(0, size, CHUNK):
            end = min(size, start + CHUNK + OVERLAP)
            block = view[start:end]
            for pattern, encoding in ((ASCII, "ascii"), (UTF16, "utf-16le")):
                for match in pattern.finditer(block):
                    if match.start() >= CHUNK:  # the overlap belongs to the next chunk
                        break
                    raw = match.group(0)
                    text = raw.decode("ascii") if encoding == "ascii" else raw.decode("utf-16-le")
                    hit = _classify(text)
                    if not hit:
                        continue
                    key = hit
                    if key in found:
                        found[key]["Count"] += 1
                    elif len(found) < MAX_ROWS:
                        found[key] = {"Source": source, "Kind": hit[0], "String": hit[1], "Encoding": encoding,
                                      "FirstOffset": start + match.start(), "Count": 1}
    return list(found.values())
