"""Lab recording → dataset Elrond reads (src/mordor/lab/dataset.py), and Elrond reading it."""
import json
import os
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
# Appended, not prepended, as it always was (src/analysis/platform shadowed the stdlib module until it became platform_adapters).
sys.path.append(str(ROOT / "src" / "analysis"))

from src.mordor.lab import dataset  # noqa: E402
from src.mordor.lab.runner import LabError  # noqa: E402

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
SYSMON_1 = f"""<Event xmlns='{NS}'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{{x}}'/>
<EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode>
<Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-10-26T20:01:02.1234567Z'/>
<EventRecordID>881</EventRecordID><Execution ProcessID='2840' ThreadID='3900'/>
<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>lab-win11</Computer>
<Security UserID='S-1-5-18'/></System><EventData><Data Name='Image'>C:\\Windows\\System32\\reg.exe</Data>
<Data Name='CommandLine'>reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d c:\\x.exe</Data>
</EventData></Event>"""
PS_4104 = f"""<Event xmlns='{NS}'><System><Provider Name='Microsoft-Windows-PowerShell'/><EventID>4104</EventID>
<TimeCreated SystemTime='2026-10-26T20:01:05Z'/><EventRecordID>12</EventRecordID>
<Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>lab-win11</Computer></System>
<EventData><Data Name='ScriptBlockText'>Invoke-AtomicTest T1547.001</Data><Data>unnamed</Data></EventData></Event>"""


def recording(tmp_path, platform, tests, files):
    run = tmp_path / "telemetry" / f"lab-{platform}-persistence-20261026-2000"
    for folder, contents in files.items():
        (run / folder).mkdir(parents=True)
        for name, body in contents.items():
            (run / folder / name).write_text(body)
    manifest = {"run": run.name, "host": f"lab-{platform}", "platform": platform,
                "started": "2026-10-26T20:00:00Z", "tests": tests}
    (run / "manifest.json").write_text(json.dumps(manifest))
    return run


def test_flatten_event_reads_system_and_event_data():
    rec = dataset.flatten_event(SYSMON_1)
    assert rec["EventID"] == 1
    assert rec["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert rec["Hostname"] == "lab-win11"
    assert rec["SourceName"] == "Microsoft-Windows-Sysmon"
    assert rec["@timestamp"] == "2026-10-26T20:01:02.1234567Z"
    assert rec["RecordNumber"] == "881" and rec["ProcessID"] == "2840" and rec["UserID"] == "S-1-5-18"
    assert rec["CommandLine"].startswith("reg add HKCU")


def test_unnamed_data_and_several_events_in_one_file():
    events = list(dataset.windows_events(SYSMON_1 + "\n" + PS_4104 + "\n<garbage/>"))
    assert [e["EventID"] for e in events] == [1, 4104]
    assert events[1]["Data"] == "unnamed"


def test_windows_recording_becomes_an_event_dataset_zip(tmp_path):
    tests = [{"technique": "T1547.001", "test": 1, "name": "Reg Key Run", "folder": "T1547.001-1",
              "start": "2026-10-26T20:01:00Z", "end": "2026-10-26T20:01:30Z"},
             {"technique": "T1547.001", "test": 2, "name": "no events", "folder": "T1547.001-2",
              "start": "2026-10-26T20:02:00Z", "end": "2026-10-26T20:02:30Z"}]
    run = recording(tmp_path, "windows", tests, {"T1547.001-1": {"events.xml": SYSMON_1 + "\n" + PS_4104},
                                                 "T1547.001-2": {}})
    result = dataset.convert(str(run), str(tmp_path / "mordor" / "lab"))
    assert result["events"] == 2 and result["tests"] == 2
    acq = tmp_path / "mordor" / "lab" / run.name / "acquisitions"
    assert result["acquisitions"] == str(acq) + os.sep
    with zipfile.ZipFile(acq / f"{run.name}.zip") as z:
        lines = z.read(f"{run.name}.json").decode().splitlines()
    assert [json.loads(l)["EventID"] for l in lines] == [1, 4104]
    truth = json.loads((acq.parent / "expected.json").read_text())
    assert truth["techniques"] == ["T1547.001"] and len(truth["tests"]) == 2
    # The ground truth stays out of the events
    assert all("T1547.001" not in json.loads(l).get("technique", "") for l in lines)


def test_each_tests_capture_goes_to_a_network_folder_of_its_own(tmp_path):
    """FR-06: the recorder's captures, for --Network, apart from the acquisition."""
    tests = [{"technique": "T1105", "test": n, "name": f"t{n}", "folder": f"T1105-{n}"} for n in (1, 2, 3)]
    run = recording(tmp_path, "windows", tests, {"T1105-1": {"events.xml": SYSMON_1, "capture.pcapng": "\n\r\r\n"},
                                                 "T1105-2": {"capture.pcapng": ""}, "T1105-3": {}})
    result = dataset.convert(str(run), str(tmp_path / "mordor" / "lab"))
    network = tmp_path / "mordor" / "lab" / run.name / "network"
    assert result["captures"] == 1 and result["network"] == str(network) + os.sep
    assert sorted(p.name for p in network.iterdir()) == ["T1105-1.pcapng"]  # an empty capture isn't one
    assert not list((network.parent / "acquisitions").glob("*.pcap*"))
    assert "network" not in dataset.convert(str(recording(tmp_path / "b", "windows", tests[:1], {"T1105-1": {}})),
                                            str(tmp_path / "b" / "out"))


def test_linux_recording_becomes_a_gandalf_archive(tmp_path):
    tests = [{"technique": "T1053.003", "test": 1, "name": "Cron", "folder": "T1053.003-1"},
             {"technique": "T1053.003", "test": 2, "name": "Cron 2", "folder": "T1053.003-2"}]
    run = recording(tmp_path, "linux", tests, {
        "T1053.003-1": {"audit.log": "type=EXECVE msg=audit(1729100000.1:1): a0=\"crontab\"\n", "journal.log": "cron[1]: x\n"},
        "T1053.003-2": {"audit.log": "type=EXECVE msg=audit(1729100060.1:2): a0=\"echo\"\n"}})
    result = dataset.convert(str(run), str(tmp_path / "out"))
    with tarfile.open(result["archive"]) as tar:
        names = tar.getnames()
        assert tar.extractfile("artefacts/host.info").read() == b"lab-linux::Linux\n"
        audit = tar.extractfile("artefacts/logs/audit.log").read().decode()
    assert names == ["artefacts/host.info", "artefacts/logs/audit.log", "artefacts/logs/journal.log"]
    assert "crontab" in audit and "echo" in audit


def test_not_a_recording_is_refused(tmp_path):
    (tmp_path / "x").mkdir()
    with pytest.raises(LabError):
        dataset.convert(str(tmp_path / "x"), str(tmp_path / "out"))


def test_elrond_reads_both_kinds(tmp_path):
    from rowanholt.core import gandalf
    win = recording(tmp_path / "w", "windows", [{"technique": "T1547.001", "test": 1, "folder": "T-1"}],
                    {"T-1": {"events.xml": SYSMON_1}})
    lin = recording(tmp_path / "l", "linux", [{"technique": "T1053.003", "test": 1, "folder": "T-1"}],
                    {"T-1": {"audit.log": "type=EXECVE msg=audit(1729100000.1:1): a0=\"crontab\"\n"}})
    for run in (win, lin):
        result = dataset.convert(str(run), str(tmp_path / "datasets"))
        out = tmp_path / "elrond" / run.parent.parent.name
        out.mkdir(parents=True)
        allimgs = {}
        gandalf.assess_gandalf(False, True, False, False, False, False, {}, result["acquisitions"], os.getcwd(),
                               False, [], str(out) + "/", "", allimgs, {}, "", False, False)
        assert list(allimgs.values()) == (["lab-win11::Windows"] if run is win else ["lab-linux::Linux"])
