"""Recorded attack telemetry (src/mordor/telemetry, ported from Shikari): the shipped data and the lab source."""

import gzip
import io
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.mordor.telemetry import __main__ as cli  # noqa: E402
from src.mordor.telemetry import check, datasets as ds, lab  # noqa: E402

EVENTS = (
    "\ufeff<Event><System><EventID>1</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>"
    "<EventData><Data Name='Image'>C:\\Windows\\System32\\schtasks.exe</Data>"
    "<Data Name='CommandLine'>schtasks /create /tn RivendellLabTask /sc onlogon</Data></EventData></Event>\r\n"
    "<Event><System><EventID>4698</EventID><Channel>Security</Channel></System>"
    "<EventData><Data Name='TaskName'>\\RivendellLabTask</Data></EventData></Event>\r\n"
)


def test_shipped_data_loads():
    summary = ds.load()
    assert {"otrf", "splunk", "evtx"} <= set(summary["sources"])
    assert len(summary["datasets"]) >= 1600
    assert ds.values() is not None
    assert ds.describe("Microsoft-Windows-Sysmon/Operational 1")["mde"] == "DeviceProcessEvents"
    assert check.technique("T1053.005")["recordings"]


def test_telemetry_needs_no_pydantic():
    # src.mordor loads its catalog (pydantic, requests) on first use, not on import
    assert "src.mordor.catalog" not in sys.modules


def test_lab_recording_is_built_locally(tmp_path, monkeypatch):
    data = tmp_path / "data"
    (data / "cache").mkdir(parents=True)
    shutil.copy(ds.SUMMARY_PATH, data / "telemetry_datasets.json")
    shutil.copy(ds.VALUES_PATH, data / "telemetry_values.json.gz")
    for name, path in {"SUMMARY_PATH": "telemetry_datasets.json", "VALUES_PATH": "telemetry_values.json.gz",
                       "LOCAL_SUMMARY_PATH": "cache/telemetry_local.json",
                       "LOCAL_VALUES_PATH": "cache/telemetry_local_values.json.gz",
                       "STATE_PATH": "cache/telemetry_state.json"}.items():
        monkeypatch.setattr(ds, name, str(data / path))
    run = tmp_path / "lab" / "lab-win11-test"
    (run / "T1053.005-1").mkdir(parents=True)
    (run / "T1053.005-1" / "events.xml").write_text(EVENTS, encoding="utf-8")
    (run / "manifest.json").write_text(json.dumps({"run": run.name, "platform": "windows", "tests": [
        {"technique": "T1053.005", "test": 1, "name": "Scheduled task", "folder": "T1053.005-1"}]}))
    monkeypatch.setattr(lab, "LAB_DIR", str(tmp_path / "lab"))
    shipped = (data / "telemetry_values.json.gz").read_bytes()
    ds._cache.clear()

    cli.build(("lab",), log=lambda *_: None)

    recorded = [d for d in ds.for_technique("T1053.005") if d["source"] == "lab"]
    assert recorded and recorded[0]["events"] == {"Microsoft-Windows-Sysmon/Operational 1": 1, "Security 4698": 1}
    assert "T1053.005" in check.search("RivendellLabTask")
    # The recording holds host names: it goes to the local files, never the shipped ones
    assert "lab" not in json.loads((data / "telemetry_datasets.json").read_text())["sources"]
    with gzip.open(data / "telemetry_values.json.gz", "rt") as fh, gzip.open(io.BytesIO(shipped), "rt") as before:
        assert json.load(fh) == json.load(before)
    ds._cache.clear()
