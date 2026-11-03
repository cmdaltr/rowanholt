"""Gandalf's extra Windows artefacts (process/windows_artefacts.py)."""
import csv
import sys
from pathlib import Path

# Appended, not prepended: src/analysis/platform would shadow the stdlib module.
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from dernvale.process import windows_artefacts as wa  # noqa: E402
from dernvale.process.select import WINDOWS_RAW_FOLDERS  # noqa: E402


def host(tmp_path):
    raw = tmp_path / "out" / "HOST" / "artefacts" / "raw"
    raw.mkdir(parents=True)
    return str(tmp_path / "out") + "/", raw


def run(out, artefact):
    return wa.process_windows_artefact("", "'HOST'", out, "HOST::Windows", "/", "processing", str(artefact))


def rows(out, name):
    with open(Path(out) / "HOST" / "artefacts" / "cooked" / name, newline="") as fh:
        return list(csv.DictReader(fh))


def test_folders_are_selected_and_routed():
    assert WINDOWS_RAW_FOLDERS.search("/x/HOST/artefacts/raw/defender/support/")
    assert WINDOWS_RAW_FOLDERS.search("/x/HOST/artefacts/raw/vss2/lnk/")
    assert not WINDOWS_RAW_FOLDERS.search("/x/HOST/artefacts/raw/registry/")
    assert wa.raw_folder("/x/HOST/artefacts/raw/pca/PcaAppLaunchDic.txt") == "pca"
    assert wa.raw_folder("/x/HOST/artefacts/raw/evt/Security.evtx") is None


def test_pca_both_files(tmp_path):
    out, raw = host(tmp_path)
    (raw / "pca").mkdir()
    (raw / "pca" / "PcaAppLaunchDic.txt").write_bytes(
        "C:\\Users\\a\\Downloads\\x.exe|2026-10-01 10:11:12.123\r\n".encode("utf-16-le"))
    (raw / "pca" / "PcaGeneralDb0.txt").write_bytes(
        "2|2026-10-02 08:00:00.000|2|%programfiles%\\tool\\t.exe|Tool|Acme|1.0|0006abc|Abnormal process exit\r\n".encode("utf-16-le"))
    run(out, raw / "pca" / "PcaAppLaunchDic.txt")
    run(out, raw / "pca" / "PcaGeneralDb0.txt")
    found = rows(out, "pca.csv")
    assert found[0]["Path"].endswith("x.exe") and found[0]["LastWriteTime"] == "2026-10-01T10:11:12.123"
    assert found[1]["CompanyName"] == "Acme" and found[1]["ExitMessage"] == "Abnormal process exit"


def test_wer_report(tmp_path):
    out, raw = host(tmp_path)
    (raw / "wer").mkdir()
    report = ("Version=1\r\nEventType=APPCRASH\r\nEventTime=133733000000000000\r\nAppName=evil.exe\r\n"
              "AppPath=C:\\Temp\\evil.exe\r\nSig[0].Name=Application Name\r\nSig[0].Value=evil.exe\r\n"
              "Sig[3].Name=Fault Module Name\r\nSig[3].Value=ntdll.dll\r\n")
    path = raw / "wer" / "System+ReportArchive+AppCrash_evil+Report.wer"
    path.write_bytes(b"\xff\xfe" + report.encode("utf-16-le"))
    run(out, path)
    (row,) = rows(out, "wer.csv")
    assert row["EventType"] == "APPCRASH" and row["FaultModule"] == "ntdll.dll"
    assert row["LastWriteTime"].startswith("2024-10-")


def test_hosts_flags_extra_entries(tmp_path):
    out, raw = host(tmp_path)
    (raw / "hosts").write_text("# comment\n127.0.0.1 localhost\n10.9.9.9 login.microsoftonline.com  # hijack\n")
    run(out, raw / "hosts")
    found = rows(out, "hosts.csv")
    assert [r["NonDefault"] for r in found] == ["", "yes"]


def test_startup_items_tag_t1547_001(tmp_path):
    out, raw = host(tmp_path)
    (raw / "startup").mkdir()
    (raw / "startup" / "bob+updater.bat").write_text("powershell -enc AAAA")
    (raw / "startup" / "bob+desktop.ini").write_text("[.ShellClassInfo]")
    run(out, raw / "startup" / "bob+updater.bat")
    run(out, raw / "startup" / "bob+desktop.ini")
    (row,) = rows(out, "startup_items.csv")
    assert row["User"] == "bob" and row["Item"] == "updater.bat" and row["Technique"] == "T1547.001"
    assert "T1547.001" in (Path(out) / "mitre_techniques.txt").read_text()


def test_defender_mplog_and_detection(tmp_path):
    out, raw = host(tmp_path)
    (raw / "defender" / "support").mkdir(parents=True)
    (raw / "defender" / "detectionhistory" / "1").mkdir(parents=True)
    mplog = raw / "defender" / "support" / "MPLog-20261001-101010.log"
    mplog.write_bytes(("2026-10-01T10:10:10.000Z Engine:Signature version 1.2\r\n"
                       "2026-10-01T10:11:00.000Z DETECTION Trojan:Win32/Fake!MTB file:_C:\\Temp\\evil.exe\r\n"
                       "no timestamp here\r\n").encode("utf-16-le"))
    record = raw / "defender" / "detectionhistory" / "1" / "ABCD-1234"
    record.write_bytes(b"\x00\x01" + "Trojan:Win32/Fake!MTB".encode("utf-16-le") + b"\x00\x00\x07"
                       + "file:_C:\\Temp\\evil.exe".encode("utf-16-le") + b"\x00\x00")
    run(out, mplog)
    run(out, record)
    (line,) = rows(out, "defender_mplog.csv")
    assert line["Category"] == "detection" and line["LastWriteTime"] == "2026-10-01T10:11:00.000Z"
    (det,) = rows(out, "defender_detections.csv")
    assert det["ThreatName"] == "Trojan:Win32/Fake!MTB" and "evil.exe" in det["Resources"]


def test_notepad_tab_text(tmp_path):
    out, raw = host(tmp_path)
    (raw / "notepad").mkdir()
    tab = raw / "notepad" / "bob+{1234}.bin"
    tab.write_bytes(b"NP\x00\x01\x05" + "net user backdoor P@ss /add".encode("utf-16-le") + b"\x00\x00\x9a")
    run(out, tab)
    (row,) = rows(out, "notepad_tabs.csv")
    assert row["User"] == "bob" and "net user backdoor" in row["Text"]


def test_other_raw_files_are_left_alone(tmp_path):
    out, raw = host(tmp_path)
    assert not run(out, raw / "evt" / "Security.evtx")
