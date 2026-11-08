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


def requests(statuses):
    """A stand-in for index_only._request answering with ``statuses`` in turn; the calls made."""
    calls = []

    def request(url, user, password, method, data=None):
        calls.append((method, url))
        return statuses.pop(0)
    return request, calls


def test_elastic_index_is_deleted_to_be_made_afresh(monkeypatch):
    monkeypatch.setenv("ELASTICSEARCH_HOST", "elastic")
    request, calls = requests([200])
    assert index_only.replace_elastic_index("WINSTACK-jsonl", request) == "replaced"
    assert calls == [("DELETE", "http://elastic:9200/winstack-jsonl")]
    assert index_only.replace_elastic_index("WINSTACK-jsonl", requests([404])[0]) == "new"
    with pytest.raises(index_only.IndexOnlyError, match="wouldn't delete"):
        index_only.replace_elastic_index("WINSTACK-jsonl", requests([403])[0])
    monkeypatch.delenv("ELASTICSEARCH_HOST")
    assert index_only.replace_elastic_index("WINSTACK-jsonl", requests([])[0]) is None  # local: not touched


def test_splunk_index_is_recreated_only_once_its_removal_has_finished(monkeypatch):
    """Splunk's listing says 404 before the removal has taken the stanza out of indexes.conf: an
    index created then was erased 43 ms later (7 November 2026)."""
    monkeypatch.setenv("SPLUNK_HOST", "splunk")
    # DELETE, GET (still there), GET 404, POST, GET 404 (erased by the removal), POST again, GET 200
    request, calls = requests([200, 200, 404, 201, 404, 201, 200])
    assert index_only.replace_splunk_index("WINSTACK-jsonl", request, sleep=lambda _: None) == "replaced"
    assert [m for m, _ in calls] == ["DELETE", "GET", "GET", "POST", "GET", "POST", "GET"]
    assert calls[0][1] == "https://splunk:8089/services/data/indexes/winstack-jsonl"  # Splunk's lowercase name
    assert calls[3][1] == "https://splunk:8089/services/data/indexes"
    with pytest.raises(index_only.IndexOnlyError, match="still removing"):
        index_only.replace_splunk_index("WINSTACK-jsonl", requests([200] + [200] * 5)[0], wait=4, sleep=lambda _: None)
    with pytest.raises(index_only.IndexOnlyError, match="kept losing"):
        index_only.replace_splunk_index("WINSTACK-jsonl", requests([404] + [201, 404] * 3)[0], sleep=lambda _: None)
    assert index_only.replace_splunk_index("WINSTACK-jsonl", requests([404, 201, 200])[0], sleep=lambda _: None) == "new"


def test_a_restart_without_the_index_fails_the_run(monkeypatch):
    monkeypatch.setenv("SPLUNK_HOST", "splunk")

    def down_then(statuses):
        def request(url, user, password, method, data=None):
            status = statuses.pop(0)
            if status == 0:
                raise ConnectionRefusedError()
            return status
        return request
    index_only.confirm_splunk_index("WINSTACK-jsonl", down_then([0, 503, 200]), sleep=lambda _: None)
    with pytest.raises(index_only.IndexOnlyError, match="restarted without index 'winstack-jsonl'"):
        index_only.confirm_splunk_index("WINSTACK-jsonl", down_then([0, 404]), sleep=lambda _: None)


def test_index_case_replaces_before_indexing_and_warns(tmp_path, monkeypatch, capsys):
    case = make_case(tmp_path)
    order = []
    monkeypatch.setattr(index_only, "replace_elastic_index", lambda c: order.append("replace") or "replaced")
    with mock.patch("rowanholt.post.elastic.config.configure_elastic_stack", side_effect=lambda *a: order.append("index")):
        assert index_only.index_case(str(case), "WINSTACK", "", False, True, False) == []
    assert order == ["replace", "index"]
    assert "may need re-pointing" in capsys.readouterr().out


def test_a_failed_replacement_indexes_nothing(tmp_path, monkeypatch):
    case = make_case(tmp_path)

    def refuse(case):
        raise index_only.IndexOnlyError("no")
    monkeypatch.setattr(index_only, "replace_elastic_index", refuse)
    with mock.patch("rowanholt.post.elastic.config.configure_elastic_stack") as elastic:
        assert index_only.index_case(str(case), "WINSTACK", "", False, True, False) == ["Elastic"]
    assert not elastic.called  # not into an index that still holds the old records


def test_splunk_reads_the_files_again_and_old_inputs_go():
    from rowanholt.post.splunk import ingest as splunk
    stanza = splunk.monitor_stanza("/c/h/analysis", "h", "WINSTACK", "elrond", salt=":20261107T200000")
    assert "crcSalt = <SOURCE>:20261107T200000" in stanza
    inputs = ("[default]\n" + splunk.INPUTS_HEADER.format("WINSTACK") + "[monitor:///c/h/a]\n\n"
              + splunk.INPUTS_HEADER.format("OTHER") + "[monitor:///o]\n\n"
              + splunk.INPUTS_HEADER.format("WINSTACK") + "[monitor:///c/h/b]\n\n")
    kept = splunk.drop_case_inputs(inputs, "WINSTACK")
    assert "/c/h/" not in kept and "[default]" in kept and "[monitor:///o]" in kept
