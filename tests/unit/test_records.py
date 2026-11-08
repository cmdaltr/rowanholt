"""Rowanholt's one output format (rowanholt/core/records.py): JSON Lines with the envelope, old
cases' CSV and JSON still read, timestamps as ISO 8601 UTC."""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.append(str(REPO / "src" / "analysis"))

from rowanholt.core.records import (ENVELOPE, check_file, envelope, iso_timestamp,  # noqa: E402
                                    read_records, table_path, write_records)


def test_written_lines_carry_the_envelope_then_the_row(tmp_path):
    path = tmp_path / "cooked" / "startup_items.jsonl"
    rows = [{"Item": "Updater", "Command": 'C:\\Users\\Public\\upd.exe "-q"\n2nd', "LastWriteTime": "2026-10-29 14:03:11"}]
    assert write_records(path, rows, host="LAB-WIN11", artefact="startup_items", source_path="raw/registry/NTUSER.DAT",
                         time_field="LastWriteTime", techniques=["T1547.001"]) == 1
    lines = path.read_text().splitlines()
    assert len(lines) == 1  # the newline inside the command stays inside the record
    record = json.loads(lines[0])
    assert list(record)[:5] == list(ENVELOPE)
    assert record["timestamp"] == "2026-10-29T14:03:11Z"
    assert record["techniques"] == ["T1547.001"]
    assert record["Command"] == rows[0]["Command"]
    assert check_file(path) == []


def test_appends_and_takes_techniques_per_row(tmp_path):
    path = tmp_path / "btm_items.jsonl"
    write_records(path, [{"Name": "a", "Technique": "T1543.001"}], host="mac", artefact="btm_items",
                  techniques=lambda row: [row.get("Technique", "")])
    write_records(path, [{"Name": "b"}], host="mac", artefact="btm_items", techniques=lambda row: [row.get("Technique", "")])
    records = [r for _, r in read_records(path)]
    assert [r["techniques"] for r in records] == [["T1543.001"], []]
    assert [r["timestamp"] for r in records] == [None, None]


def test_nothing_written_makes_no_file(tmp_path):
    path = tmp_path / "x" / "empty.jsonl"
    assert write_records(path, [], host="h", artefact="empty") == 0
    assert not path.exists()


def test_envelope_names_in_a_row_are_kept_aside():
    record = envelope({"host": "other", "timestamp": "2026-01-02T03:04:05Z", "x": 1}, host="h", artefact="a")
    assert record["host"] == "h" and record["orig_host"] == "other"
    assert record["timestamp"] == "2026-01-02T03:04:05Z" and "orig_timestamp" not in record
    record = envelope({"timestamp": "boot +3s"}, host="h", artefact="a")
    assert record["timestamp"] is None and record["orig_timestamp"] == "boot +3s"  # not a time: kept, not lost
    record = envelope({"timestamp": "junk", "When": 1793990000}, host="h", artefact="a", time_field="When")
    assert record["timestamp"] == "2026-11-06T18:33:20Z" and record["orig_timestamp"] == "junk"


def test_timestamps():
    assert iso_timestamp("2026-10-29T14:03:11.1234567Z") == "2026-10-29T14:03:11.123456Z"
    assert iso_timestamp("2026-10-29T15:03:11+01:00") == "2026-10-29T14:03:11Z"
    assert iso_timestamp("Thu Oct 29 14:03:11 2026") == "2026-10-29T14:03:11Z"
    assert iso_timestamp("2026-10-29 14:03:11 UTC") == "2026-10-29T14:03:11Z"
    assert iso_timestamp("Thu, 29 Oct 2026 15:03:11 +0100") == "2026-10-29T14:03:11Z"
    assert iso_timestamp(1793990000) == iso_timestamp(1793990000000) == "2026-11-06T18:33:20Z"
    assert iso_timestamp({"#attributes": {"SystemTime": "2026-10-29T14:03:11.000000Z"}}) == "2026-10-29T14:03:11Z"
    for nothing in (None, "", "-", "0000-00-00T00:00:00", "1601-01-01 00:00:00", "not a time", 7, True):
        assert iso_timestamp(nothing) is None


def test_long_fractions_keep_their_zone():
    # The fallback Python 3.10 reaches for Artemis's nine-digit event times (3.11 on parses them itself)
    from rowanholt.core.records import _long_fraction
    assert _long_fraction("2026-10-25T17:27:05.145549000+00:00").isoformat() == "2026-10-25T17:27:05.145549+00:00"
    assert _long_fraction("2026-10-25T18:27:05.1455490+01:00").isoformat() == "2026-10-25T18:27:05.145549+01:00"
    assert _long_fraction("2026-10-25T17:27:05.1455490").isoformat() == "2026-10-25T17:27:05.145549"


def test_reads_old_cases_too(tmp_path):
    (tmp_path / "old.csv").write_text("Name,Command\nsshd,/usr/sbin/sshd\n")
    (tmp_path / "old.json").write_text(json.dumps([{"a": 1}, {"a": 2}]))
    assert list(read_records(tmp_path / "old.csv")) == [("2", {"Name": "sshd", "Command": "/usr/sbin/sshd"})]
    assert [ref for ref, _ in read_records(tmp_path / "old.json")] == ["#0", "#1"]


def test_a_broken_line_costs_only_that_record(tmp_path):
    path = tmp_path / "t.jsonl"
    path.write_text('{"a": 1}\n{"a": \n\n{"a": 3}\n')
    assert list(read_records(path)) == [("1", {"a": 1}), ("2", {"unparsed": '{"a": '}), ("4", {"a": 3})]
    assert any("line 2" in p for p in check_file(path))
    assert any("no host" in p for p in check_file(path))


def test_table_path_prefers_this_format(tmp_path):
    assert table_path(tmp_path, "iocs.csv") == tmp_path / "iocs.jsonl"
    (tmp_path / "iocs.csv").write_text("x\n")
    assert table_path(tmp_path, "iocs") == tmp_path / "iocs.csv"
    (tmp_path / "iocs.jsonl").write_text("")
    assert table_path(tmp_path, "iocs.csv") == tmp_path / "iocs.jsonl"
