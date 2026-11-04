"""The memory-image ATT&CK patterns (post/mitre/patterns.py): a clean Windows host's processes,
connections and privileges tag nothing; the commands of an intrusion still do."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.post.mitre.patterns import MitrePatternMatcher, whole_words  # noqa: E402

CLEAN = [
    {"PID": 4, "ImageFileName": "System"},
    {"PID": 640, "ImageFileName": "lsass.exe"},
    {"PID": 700, "ImageFileName": "services.exe"},
    {"PID": 900, "ImageFileName": "svchost.exe", "Args": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule"},
    {"PID": 1200, "ImageFileName": "explorer.exe", "Path": "C:\\Windows\\explorer.exe"},
    {"PID": 1300, "ImageFileName": "vmtoolsd.exe", "Path": "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe"},
    {"LocalPort": "443", "ForeignPort": "53", "Owner": "svchost.exe"},
    {"Process": "rundll32.exe", "Args": "rundll32.exe shell32.dll,SHCreateLocalServerRunDll {9aa46009}"},
    {"Name": "SeDebugPrivilege", "Process": "lsass.exe"},
    {"Path": "C:\\Users\\a\\AppData\\Local\\Temp\\directory\\startup.log"},
    {"PID": 14634, "EventID": "4612"},
]


def tags(records) -> set:
    matcher = MitrePatternMatcher()
    return set().union(*(matcher.scan_record(r) for r in records))


def test_whole_words_keeps_extensions_and_spaces() -> None:
    import re
    matches = re.compile(whole_words(r"tar|\.lnk|reg |schtask|setwindowshookex|regsvr"), re.I).search
    assert not matches("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp")
    assert all(matches(s) for s in ("tar -czf a.tgz", "x.LNK", "reg add HKCU", "schtasks /create",
                                     "SetWindowsHookExA", "regsvr32 /s /i:http://x scrobj.dll"))
    assert whole_words(r"at\.(?:exe|allow|deny)") == r"(?<![a-z0-9])at\.(?:exe|allow|deny)"


def test_a_clean_host_tags_nothing() -> None:
    assert tags(CLEAN) == set()


def test_an_intrusion_still_tags() -> None:
    found = tags([{"Process": "powershell.exe", "Args": "powershell.exe -w hidden -enc AAAA"},
                  {"Args": "mimikatz.exe sekurlsa::logonpasswords"},
                  {"Args": "vssadmin delete shadows /all /quiet"},
                  {"Args": "schtasks /create /tn x /tr c:\\x.exe"}])
    assert {"T1059.001", "T1564.003", "T1003.001", "T1490", "T1053.005"} <= found
