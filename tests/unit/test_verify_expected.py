"""The lab's check of a case against what was seeded (lab/verify-expected.py): cooked tables by
name whatever their suffix, expected text matched against decoded values, and the format check."""
import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("verify_expected", REPO / "lab" / "verify-expected.py")
verify_expected = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_expected)
sys.path.append(str(REPO / "src" / "analysis"))

from rowanholt.core.records import write_records  # noqa: E402


def test_tables_values_and_format(tmp_path):
    host = tmp_path / "out" / "lab-win"
    cooked = host / "artefacts" / "cooked"
    cooked.mkdir(parents=True)
    (host / "analysis").mkdir()
    write_records(cooked / "startup_items.jsonl", [{"Command": 'C:\\Users\\Public\\upd.exe "-q"'}],
                  host="lab-win", artefact="startup_items")
    (cooked / "broken.jsonl").write_text('{"a": 1}\n')
    (host / "analysis" / "iocs.csv").write_text("Indicator\n198.51.100.23\n")
    target = tmp_path / "acq" / "lab-win"
    target.mkdir(parents=True)
    (target / "expected.json").write_text(json.dumps({
        "seeded": [{"artefact": "Run key", "cooked": "startup_items.csv", "expect": ['public\\upd.exe "-q"']},
                   {"artefact": "absent", "cooked": "services"}],
        "iocs": ["198.51.100.23"]}))
    rows = {r["item"]: r for r in verify_expected.verify(host, target, set())}
    assert rows["Run key"]["cooked"] is True and rows["Run key"]["expect"] == []
    assert rows["absent"]["cooked"] is False
    assert rows["IOCs"]["expect"] == []
    assert [p.split(":")[0] for p in rows["JSON Lines format"]["format"]] == ["artefacts/cooked/broken.jsonl"]


def test_attack_ids_match_through_the_releases_revoked_map(tmp_path):
    """An Atomic test's folder name (T1070.001) matches Elrond's v20.1 tag (T1685.005), and an older
    case's revoked tag matches an expected.json naming the v20.1 ID."""
    host = tmp_path / "out" / "lab-win"
    (host / "artefacts" / "cooked").mkdir(parents=True)
    (host / "analysis").mkdir()
    target = tmp_path / "acq" / "lab-win"
    target.mkdir(parents=True)
    (target / "expected.json").write_text(json.dumps({"seeded": [
        {"artefact": "log clear", "attack": "T1070.001"},
        {"artefact": "defender off", "attack": "T1685"},
        {"artefact": "audit off", "attack": "T1562.012"}]}))
    tags = {verify_expected.current_id(t) for t in ("T1685.005", "T1562.001", "T1685")}
    rows = {r["item"]: r for r in verify_expected.verify(host, target, tags)}
    assert rows["log clear"]["attack"] is True
    assert rows["defender off"]["attack"] is True
    assert rows["audit off"]["attack"] == "parent"
