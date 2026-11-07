"""The tables Elrond's analysis phase writes to <host>/analysis/: JSON Lines with the envelope,
each table's own fields under their old CSV names."""

import json
import sys
from pathlib import Path
from unittest import mock

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.analysis import analysis as an  # noqa: E402
from rowanholt.analysis import iocs, masquerading, misplaced  # noqa: E402
from rowanholt.core.records import ENVELOPE, check_file, own_fields, read_records  # noqa: E402
from rowanholt.post import yara as yara_post  # noqa: E402


def records(path: Path) -> list:
    assert check_file(path) == []
    return [record for _, record in read_records(path)]


def test_magic_bytes_and_timestomping_land_in_the_analysis_table(tmp_path) -> None:
    out = str(tmp_path / "case") + "/"
    mnt = tmp_path / "mnt"
    (mnt / "Users" / "a").mkdir(parents=True)
    (mnt / "Users" / "a" / "report, final.pdf").write_bytes(b"MZ\x90\x00" + b"\0" * 60)
    cooked = tmp_path / "case" / "HOST" / "artefacts" / "cooked"
    cooked.mkdir(parents=True)
    (cooked / "mft.json").write_text(json.dumps([{
        "full_path": "/Users/a/evil.exe", "is_file": True,
        "created": "2020-01-01T00:00:00.000Z", "filename_created": "2026-01-01T00:00:00.000Z",
    }]))
    with mock.patch.object(an, "write_audit_log_entry"):
        an.analyse_artefacts("", out, "HOST::Windows", str(mnt), True, True, False, None, "'HOST'")
    analysis_dir = tmp_path / "case" / "HOST" / "analysis"
    assert not (analysis_dir / "analysis.csv").exists()
    rows = records(analysis_dir / "analysis.jsonl")
    by_type = {r["analysis_type"]: r for r in rows}
    signature = by_type["File-signature (magic-byte) Discrepency"]
    assert list(signature)[: len(ENVELOPE)] == list(ENVELOPE)
    assert list(own_fields(signature)) == list(an.ANALYSIS_FIELDS)
    assert (signature["host"], signature["artefact"], signature["techniques"]) == ("HOST", "analysis", [])
    assert signature["Filename"] == "/Users/a/report, final.pdf"  # no %2C any more
    assert signature["timestamp"].endswith("Z")
    timestomp = by_type["Timestomp"]
    assert timestomp["Filename"] == "/Users/a/evil.exe" and timestomp["techniques"] == ["T1070.006"]


def test_likely_benign_timestomps_are_recorded_but_not_printed(tmp_path) -> None:
    # A wheel's files unpacked together keep their own times: recorded and audited, not on screen
    out = str(tmp_path / "case") + "/"
    cooked = tmp_path / "case" / "HOST" / "artefacts" / "cooked"
    cooked.mkdir(parents=True)
    times = {"is_file": True, "created": "2020-01-01T00:00:00.000Z", "filename_created": "2026-01-01T00:00:00.000Z"}
    batch = [{"full_path": f"/Users/a/AppData/Local/Programs/Python/numpy/{n}.py", **times} for n in "abcd"]
    lone = {"full_path": "/Users/a/Downloads/evil.exe", "is_file": True,
            "created": "2021-05-05T00:00:00.000Z", "filename_created": "2026-01-01T00:00:00.000Z"}
    (cooked / "mft.json").write_text(json.dumps(batch + [lone]))
    with mock.patch.object(an, "write_audit_log_entry") as audit:
        an.analyse_artefacts("", out, "HOST::Windows", str(tmp_path / "mnt"), True, False, False, None, "'HOST'")
    stomps = [c.args for c in audit.call_args_list if "evidence of timestomping" in c.args[2]]
    assert len(stomps) == 5  # every one is in the audit log
    printed = [p for *_, p in stomps if p]
    assert len(printed) == 1 and "evil.exe" in printed[0]  # only the lone one on screen
    rows = records(tmp_path / "case" / "HOST" / "analysis" / "analysis.jsonl")
    assert sum(r["analysis_type"] == "Timestomp" for r in rows) == 5


def test_likely_benign_findings_carry_no_technique() -> None:
    row = an.analysis_row("HOST", "/x", "AlternateDataStream", "Zone.Identifier (26 bytes)|likely benign: MotW")
    assert an._finding_techniques(row) == []
    assert an._finding_techniques(an.analysis_row("HOST", "/x", "AlternateDataStream", "payload (9 bytes)")) == ["T1564.004"]


def test_iocs_table_keeps_its_fields_and_watchlist_match(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("ROWANHOLT_ONLINE_LOOKUPS", raising=False)
    out = str(tmp_path) + "/"
    (tmp_path / "HOST" / "analysis").mkdir(parents=True)
    source = tmp_path / "notes, today.txt"
    source.write_text("beacon to 8.8.4.4 every hour\n")
    watchlist = tmp_path / "watch.txt"
    watchlist.write_text("8.8.4.4\n")
    with mock.patch.object(iocs, "write_audit_log_entry"):
        iocs.compare_iocs(out, "", "HOST::Linux", "analysing", "'HOST'", [str(source)], 0, 0.0,
                          watchlist_file=str(watchlist))
    [row] = records(tmp_path / "HOST" / "analysis" / "iocs.jsonl")
    assert list(own_fields(row)) == list(an.IOC_FIELDS)
    assert (row["host"], row["artefact"], row["ioc"], row["indicator_type"]) == ("HOST", "iocs", "8.8.4.4", "IPv4 address")
    assert (row["Filename"], row["line_number"], row["resolvable"], row["watchlist_match"]) == (
        str(source), 1, "not checked", "YES")
    assert row["timestamp"].endswith("Z")


def test_misplaced_and_masquerading_tables_carry_their_techniques(tmp_path) -> None:
    out = str(tmp_path / "case")
    mnt = tmp_path / "mnt"
    (mnt / "Users" / "Public").mkdir(parents=True)
    (mnt / "Users" / "Public" / "cmd.exe").write_bytes(b"MZ")
    (mnt / "Users" / "Public" / "invoice.pdf.exe").write_bytes(b"MZ")
    misplaced.detect_misplaced_binaries(str(mnt), out, "", "HOST::Windows", "'HOST'")
    masquerading.detect_masquerading(str(mnt), out, "", "HOST::Windows", "'HOST'")
    analysis_dir = tmp_path / "case" / "HOST" / "analysis"
    [placed] = records(analysis_dir / "misplaced_binaries.jsonl")
    assert (placed["artefact"], placed["binary_name"], placed["techniques"]) == ("misplaced_binaries", "cmd.exe", ["T1036.005"])
    assert placed["timestamp"].endswith("Z")
    masked = records(analysis_dir / "masquerading.jsonl")
    double = next(r for r in masked if r["filename"] == "invoice.pdf.exe" and r["technique_id"] == "T1036.007")
    assert (double["host"], double["artefact"], double["techniques"]) == ("HOST", "masquerading", ["T1036.007"])


def test_yara_table_with_rule_and_web_shell_techniques(tmp_path) -> None:
    rules = tmp_path / "rules.yar"
    rules.write_text('rule A {\n  meta:\n    attack = "T1059.001"\n  strings:\n    $a = "x"\n  condition:\n    $a\n}\n')
    stdout = "A /mnt/x/var/www/html/up, load.php\n0x1a:$a: x, \"y\"\n"
    with mock.patch.object(yara_post.subprocess, "run") as run, \
            mock.patch.object(yara_post, "write_audit_log_entry"), mock.patch.object(yara_post, "_record_techniques"):
        run.return_value = mock.Mock(stdout=stdout)
        yara_post.invoke_yara("", str(tmp_path / "case"), "HOST::Linux", str(rules), "/mnt/x")
    [row] = records(tmp_path / "case" / "HOST" / "analysis" / "yara.jsonl")
    assert list(own_fields(row)) == list(yara_post.YARA_FIELDS)
    assert (row["file"], row["path"], row["signature_name"], row["matched_data"]) == (
        "up, load.php", "/mnt/x/var/www/html", "a", 'x, "y"')
    assert (row["host"], row["artefact"], row["timestamp"], row["techniques"]) == (
        "HOST", "yara", None, ["T1059.001", "T1505.003"])
