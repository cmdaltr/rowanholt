"""Artemis MFT JSON analysis: streaming parse, EA and timestomp rules."""

import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.analysis.analysis import SETUP_COPIED_NOTE, iter_json_records, mft_findings  # noqa: E402


SAME = "2025-01-01T00:00:00.000Z"


def record(path: str, created: str = SAME, fn_created: str = SAME, eas=(), modified: str = SAME,
           fn_modified: str = SAME) -> dict:
    return {
        "filename": path.split("\\")[-1], "full_path": path, "is_file": True,
        "created": created, "filename_created": fn_created, "modified": modified, "filename_modified": fn_modified,
        "attribute_list": [{"offset": 0, "flags": 0, "name_size": len(n), "data_size": 4, "name": n, "data": "AAAA"} for n in eas],
    }


def test_streams_json_array_across_chunks() -> None:
    records = [record(f".\\Users\\a\\{i}.txt") for i in range(500)]
    parsed = list(iter_json_records(io.StringIO(json.dumps(records)), chunk=256))
    assert parsed == records


def test_streams_json_lines() -> None:
    records = [record(f".\\Users\\a\\{i}.txt") for i in range(50)]
    text = "\n".join(json.dumps(r) for r in records) + "\n"
    assert list(iter_json_records(io.StringIO(text), chunk=100)) == records


def test_windows_extended_attributes_are_ignored() -> None:
    eas = ("$CI.CATALOGHINT", "$KERNEL.PURGE.ESBCACHE", "APPLICENSING", "$LXUID")
    assert mft_findings(record(".\\Windows\\System32\\x.dll", eas=eas)) == []


def test_unexpected_extended_attribute_is_reported() -> None:
    assert mft_findings(record(".\\Users\\a\\x.txt", eas=("PAYLOAD",))) == [("ExtendedAttributes", "PAYLOAD")]


def test_timestomped_script_in_user_writable_path_is_reported() -> None:
    findings = mft_findings(record(".\\ProgramData\\RivendellLab\\sync.ps1", created="2019-03-01T00:00:00.000Z"))
    assert [kind for kind, _ in findings] == ["Timestomp"]


def test_timestomp_ignored_outside_user_writable_paths_and_for_documents() -> None:
    old = "2019-03-01T00:00:00.000Z"
    assert mft_findings(record(".\\Windows\\System32\\x.dll", created=old)) == []
    assert mft_findings(record(".\\Users\\a\\notes.txt", created=old)) == []


def test_setup_copied_paths_are_reported_as_likely_benign() -> None:
    for path in (
        ".\\Users\\Default\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Accessibility\\Magnify.lnk",
        ".\\ProgramData\\Microsoft\\Windows\\x.dll",
    ):
        [(kind, value)] = mft_findings(record(path, created="2024-04-01T08:43:23.000Z", fn_created="2026-10-25T18:04:50.000Z"))
        assert kind == "Timestomp" and value.endswith(SETUP_COPIED_NOTE)


def test_seeded_timestomp_is_not_marked_benign() -> None:
    [(_, value)] = mft_findings(record(".\\ProgramData\\RivendellLab\\helper.ps1", created="2019-03-14T09:26:53.000Z"))
    assert SETUP_COPIED_NOTE not in value


def test_backdated_modified_time_alone_is_reported() -> None:
    # Some tools set only the modified time, leaving $SI's created as it was
    [(kind, value)] = mft_findings(record(".\\Users\\a\\AppData\\Local\\Temp\\x.dll", modified="2019-03-01T00:00:00.000Z"))
    assert kind == "Timestomp" and value == "$SI: 2019-03-01T00:00:00.000Z|$FN: " + SAME


def test_both_backdated_times_are_in_one_finding() -> None:
    old = "2019-03-01T00:00:00.000Z"
    [(_, value)] = mft_findings(record(".\\Users\\a\\Downloads\\run.exe", created=old, modified=old))
    assert value.count("$SI: " + old) == 2


def test_archives_and_disk_images_are_checked() -> None:
    old = "2019-03-01T00:00:00.000Z"
    for name in ("stage.zip", "payload.iso", "tool.jar", "loader.py"):
        assert [k for k, _ in mft_findings(record(".\\Users\\a\\Downloads\\" + name, created=old))] == ["Timestomp"]


def test_later_si_times_are_not_timestomping() -> None:
    # $SI moves on with every write; only $SI before $FN says it was set back
    assert mft_findings(record(".\\Users\\a\\Downloads\\run.exe", modified="2026-01-01T00:00:00.000Z")) == []


def test_nothing_reads_mft_csv_any_more() -> None:
    source = (Path(__file__).resolve().parents[2] / "src" / "analysis" / "rowanholt" / "analysis" / "analysis.py").read_text()
    assert "MFT.csv" not in source
