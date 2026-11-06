"""The SIEMs and post-processing over JSON Lines tables (docs/OUTPUT_FORMAT.md step 4): Splunk's
monitors and sourcetype, Elastic's documents, ATT&CK enrichment rewriting line by line."""
import io
import json
import re
import sys
from pathlib import Path

# Appended, not prepended: src/analysis/platform would shadow the stdlib module.
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.core.records import check_file, write_records  # noqa: E402
from rowanholt.post.elastic import ingest as elastic  # noqa: E402
from rowanholt.post.mitre.enrichment import (  # noqa: E402
    MitreEnrichment, record_technique_ids, scannable)
from rowanholt.post.splunk import ingest as splunk  # noqa: E402


def table(path: Path, rows, artefact="startup_items", time_field="LastWriteTime", techniques=None) -> Path:
    write_records(path, rows, host="LAB-WIN11", artefact=artefact, source_path="raw/registry/NTUSER.DAT",
                  time_field=time_field, techniques=techniques)
    return path


def host(tmp_path: Path) -> Path:
    h = tmp_path / "LAB-WIN11"
    table(h / "artefacts" / "cooked" / "startup_items.jsonl", [{"Item": "Updater", "LastWriteTime": ""}])
    table(h / "artefacts" / "cooked" / "evt" / "Security.jsonl",
          [{"EventID": 4624, "LastWriteTime": "2026-10-29 14:03:11"}], artefact="evt/Security")
    table(h / "analysis" / "iocs.jsonl", [{"ioc": "203.0.113.5", "LastWriteTime": "2026-10-29T14:03:11.25Z"}],
          artefact="iocs")
    table(h / "artefacts" / "plaso_timeline.jsonl", [{"message": "x", "datetime": "2026-10-29T14:03:11Z"}],
          artefact="plaso_timeline", time_field="datetime")
    return h


# Splunk

def stanzas(text: str) -> dict:
    out = {}
    for block in text.strip().split("\n\n"):
        head, *body = block.strip().split("\n")
        out[head] = dict(line.split(" = ", 1) for line in body)
    return out


def test_one_recursive_monitor_each_for_cooked_and_analysis(tmp_path):
    h = host(tmp_path)
    found = stanzas("".join(splunk.host_monitors(str(h), "LAB-WIN11", "case1")))
    cooked = found[f"[monitor://{h}/artefacts/cooked]"]
    assert cooked["whitelist"] == r"\.jsonl$" and cooked["sourcetype"] == "rowanholt_jsonl"
    assert cooked["host"] == "LAB-WIN11" and cooked["index"] == "case1"
    assert f"[monitor://{h}/analysis]" in found
    assert found[f"[monitor://{h}/artefacts/plaso_timeline.jsonl]"]["sourcetype"] == "rowanholt_jsonl"
    # nothing per file any more, and none of the old CSV stanzas
    assert not any(".csv" in head or "evt" in head for head in found)


def test_memory_output_in_either_format(tmp_path):
    (tmp_path / "memory_pslist.jsonl").write_text('{"PID": 4}\n')
    found = stanzas("".join(splunk.host_monitors(str(tmp_path), "mem.raw", "c")))
    assert found[f"[monitor://{tmp_path}/memory_*.jsonl]"]["sourcetype"] == "rowanholt_jsonl"
    old = tmp_path / "old"
    old.mkdir()
    (old / "memory_pslist.json").write_text("[]")
    found = stanzas("".join(splunk.host_monitors(str(old), "mem.raw", "c")))
    assert found[f"[monitor://{old}/memory_*.json]"]["sourcetype"] == "json"


def test_the_sourcetype_reads_the_envelope_time():
    props = stanzas(splunk.PROPS.format(reports="REPORT-x = x"))["[rowanholt_jsonl]"]
    assert props["INDEXED_EXTRACTIONS"] == "json" and props["TIMESTAMP_FIELDS"] == "timestamp"
    assert "TIME_FORMAT" not in props  # Splunk parses ISO 8601 with or without a fraction itself
    assert props["TRANSFORMS-rowanholt_time"] == "rowanholt_time" and props["REPORT-x"] == "x"


def eval_regex() -> str:
    """The regex in TIME_TRANSFORM's match(), as Splunk's eval string unescapes it."""
    literal = re.search(r'match\(_raw, "((?:[^"\\]|\\.)*)"\)', splunk.TIME_TRANSFORM).group(1)
    return re.sub(r"\\(.)", r"\1", literal).replace("[[]", r"\[")  # the same class, unambiguous to Python


def test_records_with_no_time_are_found_by_the_time_transform(tmp_path):
    t = table(tmp_path / "t.jsonl", [{"Item": "a", "LastWriteTime": ""},
                                     {"Item": "b", "LastWriteTime": "2026-10-29 14:03:11",
                                      "nested": {"timestamp": None}}])
    timeless, timed = t.read_text().splitlines()
    assert re.search(eval_regex(), timeless)
    assert not re.search(eval_regex(), timed)


def test_local_ingest_writes_no_dead_sourcetypes(tmp_path):
    out = tmp_path / "out"
    h = host(out)
    (h / "artefacts" / "cooked" / "vss1").mkdir()
    conf = tmp_path / "splunk" / "etc" / "apps" / "elrond" / "default"
    conf.mkdir(parents=True)
    allimgs = {"/mnt/a": "LAB-WIN11::Windows", "/mnt/b": "LAB-WIN11::Windows_vss1"}
    splunk.ingest_splunk_data("", f"{out}/", "case1", "splunk", allimgs, str(tmp_path).lstrip("/") + "/")
    inputs = (conf / "inputs.conf").read_text()
    assert "json_noTime" not in inputs and "elrondCSV_noTime" not in inputs
    assert inputs.count(f"[monitor://{h.resolve()}/artefacts/cooked]") == 1  # the shadow copy's in it


# Elastic

def test_host_tables_are_the_host_s_own(tmp_path):
    h = host(tmp_path)
    (h / "artefacts" / "raw").mkdir()
    (h / "artefacts" / "raw" / "x.json").write_text("[]")
    (h / "artefacts" / "cooked" / "stray.csv").write_text("a\n1\n")
    names = [a for _, a in elastic.host_tables(str(h))]
    assert names == ["startup_items", "evt/Security", "iocs", "plaso_timeline"]


def test_an_old_case_is_still_indexed(tmp_path):
    cooked = tmp_path / "h" / "artefacts" / "cooked"
    cooked.mkdir(parents=True)
    (cooked / "prefetch.csv").write_text("Filename,LastWriteTime\nx.exe,2026-10-29 14:03:11\n")
    (cooked / "usb.json").write_text(json.dumps([{"Vendor": "a"}]))
    tables = elastic.host_tables(str(tmp_path / "h"))
    assert [a for _, a in tables] == ["prefetch", "usb"]
    docs = [elastic.to_document(r, "h", "prefetch") for r in elastic.table_records(tables[0][0])]
    assert docs[0]["@timestamp"] == "2026-10-29T14:03:11Z" and docs[0]["hostname"] == "h"


def test_documents_take_the_envelope_time_and_techniques(tmp_path):
    t = table(tmp_path / "t.jsonl", [{"Item": "a", "LastWriteTime": "2026-10-29 14:03:11"},
                                     {"Item": "b", "LastWriteTime": "Tue 29 Oct"}],
              techniques=["T1547.001", "T1059.001"])
    timed, untimed = [elastic.to_document(r, "x", "t") for r in elastic.table_records(str(t))]
    assert timed["@timestamp"] == "2026-10-29T14:03:11Z" and timed["hostname"] == "LAB-WIN11"
    assert timed["artefact"] == "startup_items"
    assert timed["mitre_technique_id"] == ["T1547.001", "T1059.001"]
    assert "@timestamp" not in untimed  # no guess, and nothing Elasticsearch would refuse
    enriched = elastic.to_document({**timed, "mitre_technique_id": "T1112"}, "x", "t")
    assert enriched["mitre_technique_id"] == "T1112"


def test_tables_are_posted_in_batches(tmp_path, monkeypatch):
    monkeypatch.setattr(elastic, "BATCH_SIZE", 2)
    t = table(tmp_path / "t.jsonl", [{"Item": str(i)} for i in range(5)])
    with t.open("a") as fh:
        fh.write("not json\n")
    batches = []
    sent, ok = elastic.index_table(str(t), "h", "t", "case1", lambda b: batches.append(b) or True)
    assert sent == 5 and ok and [len(b) for b in batches] == [4, 4, 2]
    assert json.loads(batches[0][0]) == {"index": {"_index": "case1"}}


def test_local_ingest_finds_the_host_s_tables(tmp_path, monkeypatch):
    out = tmp_path / "out"
    host(out)
    posted = []
    monkeypatch.setattr(elastic.subprocess, "Popen", lambda *a, **k: type(
        "P", (), {"communicate": lambda self: (b"", b"")})())
    monkeypatch.setattr(elastic.time, "sleep", lambda _: None)
    monkeypatch.setattr(elastic, "send_bulk_to_elastic", lambda batch, *a: posted.extend(batch) or True)
    elastic.ingest_elastic_data("", f"{out}/", "CASE1", "elastic", {"/mnt/a": "LAB-WIN11::Windows"})
    artefacts = {json.loads(line)["artefact"] for line in posted[1::2]}
    assert artefacts == {"startup_items", "evt/Security", "iocs", "plaso_timeline"}


# ATT&CK enrichment

def test_the_envelope_is_not_scanned():
    record = {"host": "h", "artefact": "a", "source_path": "raw/powershell.exe", "timestamp": None,
              "techniques": [], "Item": "x", "mitre_description": "powershell"}
    assert scannable(record) == {"Item": "x"}
    assert record_technique_ids({"techniques": ["T1"], "mitre_technique_id": "T2",
                                 "mitre_techniques": [{"mitre_technique_id": "T3"}]}) == {"T1", "T2", "T3"}


def test_jsonl_is_rewritten_line_by_line(tmp_path):
    t = table(tmp_path / "memory_cmdline.jsonl",
              [{"PID": 4, "Args": "powershell.exe -nop -w hidden -enc AAAA"},
               {"PID": 5, "Args": "C:\\Windows\\system32\\svchost.exe -k netsvcs"}],
              artefact="memory_cmdline", techniques=["T1000"])
    clean = t.read_text().splitlines()[1]
    written = io.StringIO()
    assert MitreEnrichment().enrich_json_file_streaming(str(t), written, "memory_cmdline")
    lines = t.read_text().splitlines()
    assert check_file(t) == [] and len(lines) == 2
    first = json.loads(lines[0])
    assert first["techniques"][0] == "T1000" and "T1059.001" in first["techniques"]
    assert first["mitre_technique_id"]
    assert lines[1] == clean  # a record nothing matched is left byte for byte
    assert {"T1000", "T1059.001"} <= set(written.getvalue().split())
    assert not list(tmp_path.glob("*.enriching"))


def test_a_large_jsonl_has_its_techniques_recorded_but_is_left_alone(tmp_path, monkeypatch):
    from rowanholt.post.mitre import enrichment
    monkeypatch.setattr(enrichment, "LARGE_FILE_BYTES", 2000)  # matching runs at ~10 s a megabyte
    t = tmp_path / "mft.jsonl"
    row = {"Filename": "C:\\Users\\a\\x.txt", "pad": "x" * 100}
    table(t, [row] * 30, artefact="mft", techniques=["T1070.006"])
    with t.open("a") as fh:
        fh.write(json.dumps({"host": "h", "artefact": "mft", "source_path": "raw/powershell.exe",
                             "timestamp": None, "techniques": [], "Args": "mimikatz.exe"}) + "\n")
    before = t.stat().st_size
    written = io.StringIO()
    assert MitreEnrichment().enrich_json_file_streaming(str(t), written, "mft")
    found = set(written.getvalue().split())
    assert "T1070.006" in found and any(t.startswith("T1003") for t in found)
    assert "T1059.001" not in found  # powershell is only in the envelope's source path
    assert t.stat().st_size == before


def test_techniques_are_collected_from_jsonl(tmp_path):
    table(tmp_path / "a" / "t.jsonl", [{"Item": "a"}], techniques=["T1547.001"])
    (tmp_path / "old.json").write_text(json.dumps([{"mitre_technique_id": "T1112"}]))
    assert MitreEnrichment().collect_techniques_from_directory(str(tmp_path)) == {"T1547.001", "T1112"}
