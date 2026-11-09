"""ATT&CK's two domains at one pinned release: Enterprise (cloud platforms included) and Mobile,
from post/mitre/attack_techniques.csv (scripts/attack/build_attack_data.py), through the
Navigator layers, the report's names, the cloud analysers and Splunk's lookup."""
import csv
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.append(str(REPO / "src" / "analysis"))

from rowanholt.post.mitre import attack_lookup, layers, nav_config  # noqa: E402


class TheRelease(unittest.TestCase):
    def test_both_domains_one_release(self):
        release = attack_lookup.release()
        self.assertRegex(attack_lookup.version(), r"^\d+\.\d+$")
        self.assertEqual(set(release["domains"]), {"enterprise-attack", "mobile-attack"})
        self.assertGreater(release["domains"]["enterprise-attack"], 600)
        self.assertGreater(release["domains"]["mobile-attack"], 100)

    def test_ids_tell_the_domain(self):
        self.assertEqual(attack_lookup.domain_of("T1059.001"), "enterprise-attack")
        self.assertEqual(attack_lookup.domain_of("t1632.001"), "mobile-attack")
        self.assertIsNone(attack_lookup.domain_of("T9999"))
        self.assertEqual(attack_lookup.full_name("T1003.001"), "OS Credential Dumping: LSASS Memory")
        self.assertEqual(attack_lookup.technique("T1626.001").platforms, ["Android"])

    def test_cloud_is_enterprise_platforms(self):
        self.assertEqual(attack_lookup.technique("T1580").platforms, ["IaaS"])
        platforms = attack_lookup.platforms("enterprise-attack")
        for cloud in ("IaaS", "SaaS", "Office Suite", "Identity Provider", "Containers"):
            self.assertIn(cloud, platforms)
        self.assertEqual(attack_lookup.platforms("mobile-attack"), ["Android", "iOS"])

    def test_a_revoked_id_resolves_to_its_replacement(self):
        revoked = attack_lookup.release()["revoked"]
        self.assertTrue(revoked)
        old, new = next(iter(revoked.items()))
        self.assertIsNotNone(attack_lookup.technique(old))
        self.assertEqual(attack_lookup.current_id(old), new)
        self.assertEqual(attack_lookup.by_domain([old]), {attack_lookup.domain_of(new): [new]})

    def test_every_tagged_technique_is_in_the_release(self):
        # A typo (T1337.002 for T1137.002) or a technique MITRE dropped with no replacement
        # would be silently left out of every layer
        source = REPO / "src" / "analysis" / "rowanholt"
        skip = ("post/splunk/app/views", "post/elastic/dashboards", "post/mitre/attack_data.py")
        unknown = set()
        for path in source.rglob("*.py"):
            if any(part in path.as_posix() for part in skip):
                continue
            for tid in re.findall(r'"(T\d{4}(?:\.\d{3})?)"', path.read_text(errors="ignore")):
                if attack_lookup.technique(tid) is None:
                    unknown.add(f"{tid} ({path.relative_to(source)})")
        self.assertEqual(sorted(unknown), [])


class NavigatorLayers(unittest.TestCase):
    def test_one_layer_per_domain(self):
        with tempfile.TemporaryDirectory() as assets, tempfile.TemporaryDirectory() as out, \
                mock.patch.object(nav_config, "NAV_ASSETS_DIR", assets):
            self.assertTrue(nav_config.write_navigator_layer(
                "CASE-1", ["T1059", "T1059.001", "T1580", "T1632.001", "T9999"], out))
            enterprise = json.loads(Path(assets, "CASE-1.json").read_text())
            mobile = json.loads(Path(assets, "CASE-1.mobile.json").read_text())
            config = json.loads(Path(assets, "config.json").read_text())
            self.assertTrue(Path(out, "CASE-1_navigator.json").is_file())
            self.assertTrue(Path(out, "CASE-1_mobile_navigator.json").is_file())

        self.assertEqual(enterprise["domain"], "enterprise-attack")
        self.assertEqual([t["techniqueID"] for t in enterprise["techniques"]], ["T1059", "T1059.001", "T1580"])
        self.assertTrue(enterprise["techniques"][0]["showSubtechniques"])
        self.assertIn("IaaS", enterprise["filters"]["platforms"])  # T1580 is IaaS only
        self.assertEqual(mobile["domain"], "mobile-attack")
        self.assertEqual([t["techniqueID"] for t in mobile["techniques"]], ["T1632.001"])
        self.assertEqual(mobile["filters"]["platforms"], ["Android", "iOS"])

        major = attack_lookup.version().split(".")[0]
        self.assertEqual(enterprise["versions"]["attack"], major)
        entry, = config["versions"]["entries"]
        self.assertEqual(entry["version"], major)
        self.assertEqual([d["identifier"] for d in entry["domains"]], ["enterprise-attack", "mobile-attack"])
        self.assertEqual(config["default_layers"]["urls"], ["assets/CASE-1.json", "assets/CASE-1.mobile.json"])

    def test_a_phone_case_has_only_a_mobile_layer(self):
        with tempfile.TemporaryDirectory() as assets, mock.patch.object(nav_config, "NAV_ASSETS_DIR", assets):
            self.assertTrue(nav_config.write_navigator_layer("PHONE", ["T1626.001"]))
            self.assertEqual(sorted(p.name for p in Path(assets).iterdir()), ["PHONE.mobile.json", "config.json"])

    def test_nothing_known_writes_nothing(self):
        with tempfile.TemporaryDirectory() as assets, mock.patch.object(nav_config, "NAV_ASSETS_DIR", assets):
            self.assertFalse(nav_config.write_navigator_layer("NONE", ["T9999"]))

    def test_compose_serves_the_same_release_and_navigator(self):
        compose = (REPO / "docker-compose.yml").read_text()
        version = attack_lookup.version()
        self.assertIn(f"--branch v{layers.NAVIGATOR_VERSION} ", compose)
        self.assertIn(f"-attack-{version}.json", compose)
        self.assertIn(f"!= '{version}'", compose)


class ReportAndCloud(unittest.TestCase):
    def test_report_names_both_domains(self):
        from rowanholt.report.gather import attack_names

        names = attack_names(["T1003.001", "T1632.001", "T9999"])
        self.assertEqual(names["T1003.001"][0], "OS Credential Dumping: LSASS Memory")
        self.assertTrue(names["T1632.001"][1].endswith("(Mobile)"))
        self.assertNotIn("T9999", names)

    def test_cloud_analysis_records_its_techniques_in_the_case(self):
        from rowanholt.cloud import cli

        with tempfile.TemporaryDirectory() as case:
            cli.record_case_techniques(case, {"T1580": [], "T1078.004": []})
            cli.record_case_techniques(case, ["T1580"])
            lines = Path(case, "mitre_techniques.txt").read_text().split()
        self.assertEqual(sorted(lines), ["T1078.004", "T1580"])


class SplunkLookup(unittest.TestCase):
    def test_mitre_csv_has_both_domains(self):
        from rowanholt.post.splunk.app import app

        with tempfile.TemporaryDirectory() as lookups:
            app.write_attack_lookups(lookups)
            with open(Path(lookups, "mitre.csv"), newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertTrue(Path(lookups, "enterprise_attack.csv").is_file())  # the ATT&CK dashboard's
        by_id = {r["id"]: r for r in rows}
        self.assertEqual(len(rows), sum(attack_lookup.release()["domains"].values()))
        self.assertEqual(by_id["T1632.001"]["domain"], "mobile-attack")
        self.assertIn("IaaS", by_id["T1580"]["platform"])
        # ATT&CK's current platform names, not the old ones (Office 365, Azure AD)
        self.assertNotIn("Office 365", {p.strip() for r in rows for p in r["platform"].split(";")})


if __name__ == "__main__":
    unittest.main()
