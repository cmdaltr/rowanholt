"""ATT&CK tags in mitre_techniques.txt come from what the records show: an artefact being there
tags only a persistence mechanism or interpreter, and keywords don't match what a clean OS ships."""

import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.process.extractions.artemis import enrich_with_mitre  # noqa: E402
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
