"""The case report (FR-07, src/analysis/rowanholt/report): read from the case directory without
reaching raw/, every technique and indicator cited by file, row and the row's hash as the case
browser computes it, Gandalf's integrity check, Elrond's method, Markdown and DOCX, the curated
version from the backend with confirmed findings first, and Elrond's --Report."""
import argparse
import importlib
import io
import json
import re
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace
from xml.dom import minidom

import pytest

REPO = Path(__file__).resolve().parents[2]
# The backend first, as test_case_browser has it: src/analysis has its own config module
sys.path.insert(0, str(REPO / "src" / "web" / "backend"))
sys.path.append(str(REPO / "src" / "analysis"))

from rowanholt.core.records import write_records  # noqa: E402
from rowanholt.report import build, document, method  # noqa: E402
from rowanholt.report.__main__ import main as report_cli  # noqa: E402

gathering = importlib.import_module("rowanholt.report.gather")  # the package exports gather(), the function

CASE = "CASE-FR07"
JOB = "77777777-2222-3333-4444-555555555555"


def make_case(root: Path) -> Path:
    """A two-host case as Elrond writes it now (JSON Lines), with one old-format table."""
    case = root / CASE
    win = case / "LAB-WIN11"
    cooked, analysis = win / "artefacts" / "cooked", win / "analysis"
    write_records(cooked / "evt" / "Security.jsonl", [
        {"EventID": 4625, "TargetUserName": "admin", "IpAddress": "198.51.100.23", "Time": "2026-10-25T10:00:00Z"},
        {"EventID": 4624, "TargetUserName": "admin", "IpAddress": "198.51.100.23", "Time": "2026-10-25T10:05:00Z"},
        {"EventID": 4688, "CommandLine": "powershell -enc SQBFAFgA | x", "Time": "2026-10-25T10:07:00Z"},
    ], host="LAB-WIN11", artefact="evt/Security", source_path="artefacts/raw/evt/Security.evtx", time_field="Time",
        techniques=lambda r: {4625: ["T1110.001"], 4688: ["T1059.001"]}.get(r["EventID"], []))
    # Artemis's own time beside a null envelope time (written by Python 3.10 before records.py's fix)
    (cooked / "evt" / "PowerShell.jsonl").write_text(json.dumps(
        {"host": "LAB-WIN11", "artefact": "evt/PowerShell", "source_path": "artefacts/raw/evt/PowerShell.evtx",
         "timestamp": None, "techniques": ["T1059.001"], "orig_timestamp": "2026-10-25T10:08:00.123456700Z",
         "data": {"Event": {"#attributes": {"xmlns": "http://x"}, "EventData": {"ScriptBlockText": "IEX (New-Object Net.WebClient)"}}}})
        + "\n")
    write_records(cooked / "journal_mft.jsonl", [{"Path": "C:\\Windows", "Created": "1601-01-01T00:00:00.000Z"},
                                                 {"Path": "C:\\Windows\\notepad.exe", "Created": "2021-06-05T12:00:00Z"}],
                  host="LAB-WIN11", artefact="journal_mft", time_field="Created")
    write_records(analysis / "iocs.jsonl", [
        {"Filename": "/x/a.log", "ioc": "198.51.100.23", "indicator_type": "IPv4 address", "line_number": 3,
         "watchlist_match": "YES", "LastWriteTime": "2026-10-25T10:00:00"},
        {"Filename": "/x/b.log", "ioc": "198.51.100.23", "indicator_type": "IPv4 address", "line_number": 9,
         "watchlist_match": "YES", "LastWriteTime": "2026-10-25T10:00:00"},
        {"Filename": "/x/b.log", "ioc": "evil.example", "indicator_type": "domain", "line_number": 10,
         "watchlist_match": "", "LastWriteTime": "2026-10-25T10:00:00"},
    ], host="LAB-WIN11", artefact="iocs")
    write_records(analysis / "threat_intel_matches.jsonl", [
        {"Artefact": "evt/Security", "Element": "198.51.100.23", "Kind": "ipv4", "Groups": "APT33",
         "Techniques": "T1566.001"}], host="LAB-WIN11", artefact="threat_intel_matches",
        techniques=lambda r: r["Techniques"].split(","))
    write_records(win / "gandalf_integrity.jsonl", [
        {"file_path": "artefacts/evt/Security.evtx", "expected_sha256": "a" * 64, "actual_sha256": "a" * 64,
         "status": "verified"},
        {"file_path": "artefacts/evt/System.evtx", "expected_sha256": "b" * 64, "actual_sha256": "c" * 64,
         "status": "MISMATCH"}], host="LAB-WIN11", artefact="gandalf_integrity", source_path="log.meta")
    (win / "gandalf_extracted.json").write_text(json.dumps({"archive": "LAB-WIN11.zip", "integrity": "1 verified, 1 MISMATCH"}))
    (win / "gandalf_log.audit").write_text("LastWriteTime,gandalf_host,gandalf_stage,gandalf_log_entry\n"
                                           "2026-11-07T03:06:39.3246475Z, LAB-WIN11, acquisition_commenced, collected\n"
                                           "2026-11-07T03:09:12.0000000Z, LAB-WIN11, Windows10, collected\n")
    (win / "gandalf_log.meta").write_text("hostname,file_path,sha256_hash\n")
    # raw/ is never read: a technique only here must not reach the report
    write_records(win / "artefacts" / "raw" / "secret.jsonl", [{"x": 1}], host="LAB-WIN11", artefact="secret",
                  techniques=["T1003.001"])

    linux = case / "lab-ubuntu"
    (linux / "artefacts" / "cooked").mkdir(parents=True)
    (linux / "artefacts" / "cooked" / "k8s_audit.csv").write_text(
        "LastWriteTime,User,Verb,Resource,Flag,Technique\n"
        "2026-10-20T09:11:00Z,lab-intruder,list,secrets,secrets read,T1552.007\n"
        "2026-10-20T09:12:00Z,kubelet,get,pods,,\n")
    (linux / "artefacts" / "host.info").write_text("lab-ubuntu::Linux\nuname...\n")

    (case / "mitre_techniques.txt").write_text("T1110.001\nT1059.001\nT1053.003\n")
    (case / "rowanholt_audit.log").write_text(
        "LastWriteTime,elrond_host,elrond_stage,elrond_log_entry\n"
        "2026-11-07T16:35:09.955052,LAB-WIN11,identified platform,Windows10\n"
        "2026-11-07T16:40:00.000000,LAB-WIN11,processing,Security.evtx\n"
        "2026-11-07T16:41:00.000000,LAB-WIN11,processing failed (artemis),'SRUDB.dat'\n")
    write_records(case / "threat_groups.jsonl", [{"Rank": "1", "Group": "APT33", "Basis": "atomic indicators",
                                                  "Techniques In Case": "T1110.001"}], host="", artefact="threat_groups")
    return case


@pytest.fixture
def case(tmp_path):
    return make_case(tmp_path)


def _md(report) -> str:
    return build.uncurated_report(report, "markdown").decode()


def test_techniques_are_cited_by_row_and_never_from_raw(case):
    report = gathering.gather(case)
    assert report.case == CASE  # the folder's name when Elrond recorded none
    techniques = report.techniques
    assert set(techniques) == {"T1110.001", "T1059.001", "T1053.003", "T1552.007"}
    assert "T1003.001" not in techniques  # only in raw/
    assert "T1566.001" not in techniques  # threat intelligence's group knowledge, not evidence
    powershell = techniques["T1059.001"]
    assert powershell.rows == 2 and powershell.recorded and powershell.name.endswith("PowerShell")
    cites = {(c.file, c.ref) for f in powershell.files.values() for c in f.cites}
    assert cites == {("artefacts/cooked/evt/Security.jsonl", "3"), ("artefacts/cooked/evt/PowerShell.jsonl", "1")}
    assert techniques["T1053.003"].rows == 0 and techniques["T1053.003"].recorded
    old = techniques["T1552.007"].files[("lab-ubuntu", "artefacts/cooked/k8s_audit.csv")].cites[0]
    assert old.ref == "2" and "lab-intruder" in old.excerpt
    brute = techniques["T1110.001"].files[("LAB-WIN11", "artefacts/cooked/evt/Security.jsonl")].cites[0]
    assert brute.source == "artefacts/raw/evt/Security.evtx" and brute.time == "2026-10-25T10:00:00Z"


def test_row_hashes_are_the_case_browsers(case):
    import case_files
    report = gathering.gather(case)
    for technique in report.techniques.values():
        for entry in technique.files.values():
            host_dir = case / entry.host
            for cite in entry.cites:
                row = case_files.find_row(case_files.resolve(case, entry.host, cite.file), cite.ref)
                assert row is not None and case_files.row_hash(row) == cite.row_hash, (entry.file, cite.ref)
                assert (host_dir / cite.file).is_file()


def test_the_fast_path_reads_what_decoding_reads(case):
    for line in (case / "LAB-WIN11" / "artefacts" / "cooked" / "evt" / "Security.jsonl").read_text().splitlines():
        techniques, moment = gathering._fast(line)
        record = json.loads(line)
        assert techniques == record["techniques"] and moment == record["timestamp"]
    techniques, moment = gathering._fast((case / "LAB-WIN11" / "artefacts" / "cooked" / "evt" / "PowerShell.jsonl")
                                         .read_text())
    assert techniques == ["T1059.001"] and moment == "2026-10-25T10:08:00.123456Z"
    assert gathering._fast('{"a": 1}') is None


def test_hosts_timespan_integrity_and_indicators(case):
    report = gathering.gather(case)
    win, linux = report.hosts[0], report.hosts[1]
    assert (win.name, win.os, linux.os) == ("LAB-WIN11", "Windows10", "Linux")
    assert win.earliest.time == "2021-06-05T12:00:00Z"  # the 1601 FILETIME zero is no time
    assert win.latest.time == "2026-10-25T10:08:00.123456Z" and win.latest.file == "artefacts/cooked/evt/PowerShell.jsonl"
    assert win.first_technique.time == "2026-10-25T10:00:00Z"
    assert win.collected_from.startswith("2026-11-07T03:06:39") and win.collected_to.startswith("2026-11-07T03:09:12")
    assert win.integrity.counts == {"verified": 1, "MISMATCH": 1} and win.integrity.problems[0].ref == "2"
    assert not linux.integrity.gandalf and linux.legacy_tables == 1 and not linux.timed
    assert win.ioc_rows == 3 and win.ioc_types == {"IPv4 address": 1, "domain": 1}
    ip = win.indicators["IPv4 address"][0]
    assert (ip.value, ip.count, ip.watchlist, ip.cite.ref) == ("198.51.100.23", 2, True, "1")
    assert [i.value for i in win.intel] == ["198.51.100.23"]
    assert report.failure_count == 1 and report.failures[0].line == 4
    assert report.threat_groups[0][0]["Group"] == "APT33"
    assert "missing" in report.method_problem


def test_markdown_says_everything_with_its_citation(case):
    text = _md(gathering.gather(case))
    for heading in ("# CASE-FR07: case report", "## Hosts and timespan", "## ATT&CK techniques",
                    "### T1059.001 Command and Scripting Interpreter: PowerShell", "### Recorded without a row",
                    "## Indicators", "## Evidence integrity", "## Method", "### Processing log"):
        assert heading in text, heading
    assert "| LAB-WIN11 | 2026-10-25 10:07:00Z | `artefacts/cooked/evt/Security.jsonl` | 3 |" in text
    assert "1 of 2 files don't verify" in text and "MISMATCH" in text
    assert "not a Gandalf acquisition" in text
    assert "processing failed (artemis)" in text
    assert "powershell -enc SQBFAFgA \\| x" in text  # a pipe in evidence doesn't break the table
    assert "T1003.001" not in text


def test_docx_is_valid_wordprocessingml_with_widths_in_dxa(case):
    data = build.uncurated_report(gathering.gather(case), "docx")
    archive = zipfile.ZipFile(io.BytesIO(data))
    assert {"[Content_Types].xml", "word/document.xml", "word/styles.xml", "word/numbering.xml"} <= set(archive.namelist())
    for name in archive.namelist():
        minidom.parseString(archive.read(name))
    body = archive.read("word/document.xml").decode()
    assert "T1059.001" in body and "198.51.100.23" in body
    assert 'w:type="pct"' not in body and 'w:w="9026" w:type="dxa"' in body
    for widths in re.findall(r"<w:tblGrid>(.*?)</w:tblGrid>", body):
        assert sum(int(w) for w in re.findall(r'w:w="(\d+)"', widths)) == document.TEXT_WIDTH


def test_control_characters_in_evidence_dont_break_the_docx():
    blocks = [document.Table(["a"], [["bad \x01\x1f byte"]]), document.Para([("<tag> & \x00", "code")])]
    minidom.parseString(zipfile.ZipFile(io.BytesIO(document.docx(blocks, "t"))).read("word/document.xml"))


def test_curated_report_puts_confirmed_findings_first(case):
    report = gathering.gather(case)
    findings = [
        {"id": 1, "host": "LAB-WIN11", "artefact": "artefacts/cooked/evt/Security.jsonl", "row_ref": "3",
         "row_hash": "f" * 64, "excerpt": "CommandLine: powershell -enc", "title": "Encoded PowerShell",
         "technique": "T1059.001", "status": "confirmed", "author": "frodo", "created_at": "2026-11-07T18:00:00",
         "updated_at": "2026-11-07T18:00:00", "intact": True},
        {"id": 2, "host": "LAB-WIN11", "artefact": "artefacts/cooked/evt/Security.jsonl", "row_ref": "1",
         "row_hash": "e" * 64, "excerpt": "", "title": "Password guessing", "technique": "", "status": "confirmed",
         "author": "sam", "created_at": "2026-11-07T18:01:00", "updated_at": "2026-11-07T18:01:00", "intact": False},
        {"id": 3, "host": "LAB-WIN11", "artefact": "artefacts/cooked/journal_mft.jsonl", "row_ref": "2",
         "row_hash": "d" * 64, "excerpt": "", "title": "Odd binary", "technique": "", "status": "lead",
         "author": "sam", "created_at": "2026-11-07T18:02:00", "updated_at": None, "intact": True},
    ]
    notes = [{"id": 1, "finding_id": None, "author": "frodo", "body": "Scoped to **one** host", "created_at": ""},
             {"id": 2, "finding_id": 1, "author": "sam", "body": "Same IP as the web shell", "created_at": ""}]
    text = build.curated_report(report, findings, notes, "markdown").decode()
    confirmed, appendix_a, appendix_b = (text.index("## Confirmed findings"), text.index("## Appendix A"),
                                         text.index("## Appendix B"))
    assert confirmed < appendix_a < appendix_b
    assert text.index("Encoded PowerShell") < appendix_a and text.index("Odd binary") > appendix_a
    assert "#1 Encoded PowerShell (T1059.001 Command and Scripting Interpreter: PowerShell)" in text
    assert "Scoped to **one** host" in text  # a note is the analyst's own Markdown
    assert "Warning:" in text and "#2" in text and "ROW CHANGED" in text
    assert "### ATT&CK techniques" in text  # Elrond's report, one level down
    minidom.parseString(zipfile.ZipFile(io.BytesIO(build.curated_report(report, findings, notes, "docx")))
                        .read("word/document.xml"))


def test_method_records_options_and_tool_versions(case):
    args = argparse.Namespace(case=[CASE], directory=["/evidence/LAB-WIN11.zip"], Gandalf=True, Analysis=True,
                              Splunk=False, Keywords=["/x/keywords.txt"], threatIntel=None, Report=True)
    found = method.tools([("Python", (sys.executable,), ("--version",)),
                          ("Not here", ("no-such-tool-fr07",), ("--version",))])
    assert found[0][0]["version"].startswith("Python 3") and found[1] == ["Not here"]
    method.record(case, CASE, args, ["/opt/elrond-src/elrond.py", CASE, "/evidence/LAB-WIN11.zip", "--Gandalf"],
                  ["/evidence/LAB-WIN11.zip"], started="2026-11-07T16:30:00+00:00", found=found)
    running = json.loads((case / method.METHOD_FILE).read_text())
    assert running["status"] == "running" and running["options"] == {
        "Gandalf": True, "Analysis": True, "Keywords": "/x/keywords.txt", "Report": True}
    method.record(case, CASE, args, ["elrond.py"], [], started=running["started"],
                  finished="2026-11-07T17:30:00+00:00", found=found)
    report = gathering.gather(case)
    assert report.method["status"] == "completed" and not report.method_problem
    text = _md(report)
    assert "`--Keywords` | /x/keywords.txt" in text and "| Python | Python 3" in text and "Not here" in text


def test_cli_writes_both_formats(case, tmp_path):
    out = tmp_path / "out"
    assert report_cli([str(case), "--out", str(out)]) == 0
    assert sorted(p.name for p in out.iterdir()) == [f"{CASE}_report.docx", f"{CASE}_report.md"]
    assert report_cli([str(tmp_path / "nothing-here"), "--out", str(out)]) == 1


def test_elrond_has_report_and_records_its_method():
    source = (REPO / "src" / "analysis" / "elrond.py").read_text()
    assert '"--Report"' in source and "write_reports(folder" in source and "run_method.record(" in source


# ---- the backend: the curated report as the case browser downloads it ----

sqlalchemy = pytest.importorskip("sqlalchemy")
pytest.importorskip("fastapi")
pytest.importorskip("httpx")


@pytest.fixture
def client(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import case_routes
    import storage
    case = make_case(tmp_path)
    engine = sqlalchemy.create_engine(f"sqlite:///{tmp_path / 'db.sqlite'}")
    storage.Base.metadata.create_all(engine)
    job = SimpleNamespace(id=JOB, case_number=CASE, destination_path=str(tmp_path))
    jobs = SimpleNamespace(Session=sqlalchemy.orm.sessionmaker(bind=engine),
                           get_job=lambda job_id: job if job_id == JOB else None, list_jobs=lambda limit=0: [job])
    case_routes.configure(jobs)
    case_routes._gathered.clear()
    app = FastAPI()

    @app.middleware("http")
    async def user(request, call_next):
        request.state.user = {"id": "u1", "username": "frodo", "role": "analyst"}
        return await call_next(request)

    app.include_router(case_routes.router)
    yield TestClient(app), case


def test_backend_report_download(client):
    api, case = client
    base = f"/api/jobs/{JOB}/case"
    finding = api.post(f"{base}/findings", json={"host": "LAB-WIN11", "artefact": "artefacts/cooked/evt/Security.jsonl",
                                                 "row_ref": "3", "title": "Encoded PowerShell", "technique": "T1059.001",
                                                 "status": "confirmed"}).json()
    api.post(f"{base}/findings", json={"host": "lab-ubuntu", "artefact": "artefacts/cooked/k8s_audit.csv",
                                       "row_ref": "3", "title": "kubelet read pods"})
    got = api.get(f"{base}/full-report", params={"format": "markdown"})
    assert got.status_code == 200 and f'filename="{CASE}_report.md"' in got.headers["content-disposition"]
    text = got.text
    assert text.index("Encoded PowerShell") < text.index("## Appendix A") < text.index("kubelet read pods")
    assert f"`{finding['row_hash'][:12]}`; unchanged since it was flagged" in text
    assert "### Evidence integrity" in text
    docx = api.get(f"{base}/full-report")  # DOCX by default
    assert docx.status_code == 200 and docx.headers["content-type"].startswith(
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    minidom.parseString(zipfile.ZipFile(io.BytesIO(docx.content)).read("word/document.xml"))
    assert api.get(f"{base}/full-report", params={"format": "pdf"}).status_code == 422
    activity = [a["detail"] for a in api.get(f"{base}/activity").json() if a["action"] == "exported"]
    assert activity == ["the case report (docx)", "the case report (markdown)"]


def test_backend_report_rereads_a_case_that_changed(client):
    import case_routes
    api, case = client
    base = f"/api/jobs/{JOB}/case"
    assert "T1552.007" in api.get(f"{base}/full-report", params={"format": "markdown"}).text
    first = next(iter(case_routes._gathered.values()))[1]
    assert api.get(f"{base}/full-report", params={"format": "markdown"}).status_code == 200
    assert next(iter(case_routes._gathered.values()))[1] is first  # kept while the case is unchanged
    k8s = case / "lab-ubuntu" / "artefacts" / "cooked" / "k8s_audit.csv"
    k8s.write_text(k8s.read_text().replace("T1552.007", "T1613") + "\n")
    text = api.get(f"{base}/full-report", params={"format": "markdown"}).text
    assert "T1613" in text and "T1552.007" not in text
