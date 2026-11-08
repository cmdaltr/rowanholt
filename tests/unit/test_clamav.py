"""ClamAV in Elrond (post/clam.py): what's scanned, how clamscan's output is read, where it lands."""

import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.core.records import check_file, read_records  # noqa: E402
from rowanholt.post import clam  # noqa: E402


def test_detections_from_clamscan_lines() -> None:
    out = ("/mnt/x/Users/a/Downloads/mimi.exe: Win.Tool.Mimikatz-6338032-0 FOUND\n"
           "/mnt/x/Users/a/odd: name.txt: Eicar-Signature FOUND\n"
           "/mnt/x/Users/a/clean.txt: OK\n")
    assert clam.detections(out) == [("/mnt/x/Users/a/Downloads/mimi.exe", "Win.Tool.Mimikatz-6338032-0"),
                                    ("/mnt/x/Users/a/odd: name.txt", "Eicar-Signature")]


def test_user_writable_folders_or_the_whole_collection(tmp_path) -> None:
    image = tmp_path / "mnt"
    for d in ("Users", "ProgramData", "Windows/System32"):
        (image / d).mkdir(parents=True)
    collected = tmp_path / "files"
    collected.mkdir()
    assert clam.scan_targets(str(image), str(collected)) == [str(image / "Users"), str(image / "ProgramData"),
                                                             str(collected)]
    gandalf = tmp_path / "gandalf"
    (gandalf / "artefacts").mkdir(parents=True)
    assert clam.scan_targets(str(gandalf), str(tmp_path / "none")) == [str(gandalf)]


def test_detections_land_in_the_analysis_table(tmp_path, monkeypatch) -> None:
    image = tmp_path / "mnt"
    (image / "Users" / "a").mkdir(parents=True)
    out_dir = str(tmp_path / "case") + "/"
    stdout = f"{image}/Users/a/x,y.exe: Win.Tool.Mimikatz-1 FOUND\n".encode()
    monkeypatch.delenv("ROWANHOLT_ONLINE_LOOKUPS", raising=False)
    with mock.patch.object(clam.subprocess, "run") as run, mock.patch.object(clam, "write_audit_log_entry"):
        run.return_value = mock.Mock(stdout=stdout, stderr=b"", returncode=1)
        assert clam.run_clamscan("", out_dir, str(image), "HOST::Windows") == 1
    [call] = run.call_args_list  # no freshclam: the signatures are the image's own
    assert call.args[0][0] == "clamscan" and "--follow-file-symlinks=0" in call.args[0]
    table = tmp_path / "case" / "HOST" / "analysis" / "analysis.jsonl"
    assert check_file(table) == []
    [(_, row)] = list(read_records(table))
    assert (row["host"], row["artefact"], row["techniques"]) == ("HOST", "analysis", [])
    assert row["timestamp"].endswith("Z")
    assert (row["Filename"], row["analysis_type"], row["analysis_value"]) == ("/Users/a/x,y.exe", "ClamAV",
                                                                             "Win.Tool.Mimikatz-1")


def test_freshclam_only_when_listed(monkeypatch) -> None:
    monkeypatch.setenv("ROWANHOLT_ONLINE_LOOKUPS", "virustotal")
    assert not clam.freshclam_enabled()
    monkeypatch.setenv("ROWANHOLT_ONLINE_LOOKUPS", "dns, freshclam")
    assert clam.freshclam_enabled()
