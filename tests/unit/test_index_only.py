"""elrond.py --Index: a processed case into Splunk, Elastic and the Navigator without processing
it again; and the case audit log, which every Gandalf archive used to start afresh."""

import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.audit import HEADER, write_audit_log_entry  # noqa: E402
from rowanholt.post import index_only  # noqa: E402


def make_case(root: Path) -> Path:
    case = root / "WINSTACK"
    for host in ("LAB-WIN11", "LAB-WINCLEAN1", "WIN10-DISK", "MYSTERY"):
        (case / host / "artefacts" / "cooked").mkdir(parents=True)
    (case / "LAB-WIN11" / "artefacts" / "host.info").write_text("LAB-WIN11::Windows10\n")
    (case / "LAB-WINCLEAN1" / "artefacts" / "host.info").write_text("LAB-WINCLEAN1::Windows10\n")
    (case / ".previous" / "LAB-WIN11-20261107-150000" / "artefacts" / "cooked").mkdir(parents=True)
    (case / "not-a-host").mkdir()
    (case / "rowanholt_audit.log").write_text(
        HEADER + "2026-11-07T16:35:09,WIN10-DISK,identified platform,Windows10\n"
        "2026-11-07T16:35:10,LAB-WINCLEAN1,identified platform,Windows11\n")
    return case


def test_hosts_and_platforms_come_from_the_case(tmp_path):
    case = make_case(tmp_path)
    allimgs, unknown = index_only.case_hosts(str(case))
    assert allimgs == {
        str(case / "LAB-WIN11" / "artefacts" / "raw"): "LAB-WIN11::Windows10",  # host.info
        str(case / "LAB-WINCLEAN1" / "artefacts" / "raw"): "LAB-WINCLEAN1::Windows11",  # the audit log first
        str(case / "WIN10-DISK" / "artefacts" / "raw"): "WIN10-DISK::Windows10",  # a disk image: the audit log
    }
    assert unknown == ["MYSTERY"]  # .previous/ and folders without cooked/ aren't hosts


def test_index_case_indexes_each_target_and_goes_on_after_a_failure(tmp_path):
    case = make_case(tmp_path)
    with mock.patch("rowanholt.post.splunk.config.configure_splunk_stack", side_effect=RuntimeError("down")) as splunk, \
            mock.patch("rowanholt.post.elastic.config.configure_elastic_stack") as elastic, \
            mock.patch("rowanholt.post.mitre.nav_config.configure_navigator") as navigator:
        failed = index_only.index_case(str(case), "WINSTACK", "veryverbose", True, True, True)
    assert failed == ["Splunk"]
    directory, allimgs = elastic.call_args.args[1], elastic.call_args.args[4]
    assert directory == str(case) + "/" and len(allimgs) == 3
    assert splunk.call_args.args[4] == allimgs and navigator.called
    log = (case / "rowanholt_audit.log").read_text()
    assert "index only,indexed into Splunk; Elastic; Navigator; Splunk failed" in log
    assert log.startswith(HEADER) and "WIN10-DISK,identified platform" in log  # appended, not replaced


def test_index_case_only_runs_what_was_asked(tmp_path):
    case = make_case(tmp_path)
    with mock.patch("rowanholt.post.splunk.config.configure_splunk_stack") as splunk, \
            mock.patch("rowanholt.post.elastic.config.configure_elastic_stack") as elastic, \
            mock.patch("rowanholt.post.mitre.nav_config.configure_navigator") as navigator:
        assert index_only.index_case(str(case), "WINSTACK", "", False, True, False) == []
    assert elastic.called and not splunk.called and not navigator.called


def test_a_folder_with_no_processed_hosts_is_refused(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(index_only.IndexOnlyError):
        index_only.index_case(str(tmp_path / "empty"), "WINSTACK", "", True, False, False)


def test_the_audit_log_header_starts_a_log_but_never_restarts_one(tmp_path):
    """Each Gandalf archive's ingest writes the header; opening the log for writing each time left
    only the last host's entries (the Windows stacking eval, 7 November 2026)."""
    out = str(tmp_path) + "/"
    for host in ("LAB-WIN11", "LAB-WINCLEAN1", "LAB-WINCLEAN2"):
        write_audit_log_entry("", out, HEADER, "")
        write_audit_log_entry("", out, f"2026-11-07T16:00:00,{host},identified platform,Windows10\n", "")
    lines = (tmp_path / "rowanholt_audit.log").read_text().splitlines()
    assert lines[0] == HEADER.strip() and lines.count(HEADER.strip()) == 1
    assert [line.split(",")[1] for line in lines[1:]] == ["LAB-WIN11", "LAB-WINCLEAN1", "LAB-WINCLEAN2"]
