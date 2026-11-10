"""Elrond tags with the pinned ATT&CK release's IDs: none of its tag tables names a technique the
release revoked (T1562.001 is T1685 since v20), and a YARA rule's revoked ID is given as its
replacement. Lookups still resolve an older case's revoked IDs (attack_lookup.current_id)."""

import re
import sys
from pathlib import Path
from typing import Dict, List

REPO = Path(__file__).resolve().parents[2]
ANALYSIS = REPO / "src" / "analysis"
sys.path.append(str(ANALYSIS))

from rowanholt.post import yara as yara_post  # noqa: E402
from rowanholt.post.mitre import attack_lookup  # noqa: E402
from rowanholt.post.mitre.patterns import PATTERN_MAPPINGS  # noqa: E402

TECHNIQUE = re.compile(r"(?<![\w.])(T\d{4}(?:\.\d{3})?)(?!\d|\.\d)")

# Every static table Elrond (and Mordor's labels for Elrond's datasets) tags from
TAG_TABLES = [
    ANALYSIS / "rowanholt" / "post" / "mitre" / "patterns.py",
    ANALYSIS / "rowanholt" / "post" / "mitre" / "enrichment.py",
    ANALYSIS / "rowanholt" / "post" / "mitre" / "attack_data.py",
    ANALYSIS / "rowanholt" / "post" / "mitre" / "mitre_integration.py",
    ANALYSIS / "rowanholt" / "process" / "extractions" / "artemis.py",
    ANALYSIS / "rowanholt" / "process" / "extractions" / "mitre_tagger.py",
    ANALYSIS / "rowanholt" / "process" / "extractions" / "powershell_history.py",
    ANALYSIS / "rowanholt" / "cloud" / "aws" / "cloudtrail.py",
    ANALYSIS / "rowanholt" / "cloud" / "azure" / "activity_log.py",
    ANALYSIS / "rowanholt" / "cloud" / "gcp" / "logging.py",
    ANALYSIS / "mitre" / "technique_mapper.py",
    ANALYSIS / "rowanholt" / "post" / "splunk" / "app" / "transforms.py",
    ANALYSIS / "rowanholt" / "post" / "splunk" / "app" / "views" / "xml" / "techniques.py",
    ANALYSIS / "rowanholt" / "post" / "elastic" / "dashboards" / "techniques.py",
    REPO / "src" / "web" / "backend" / "aule_offline.py",
    REPO / "src" / "mordor" / "telemetry" / "macos_attack.py",
]


def revoked() -> Dict[str, str]:
    return attack_lookup.release()["revoked"]


def revoked_in(path: Path) -> List[str]:
    """Each line naming a revoked ID, as "line: old -> new"."""
    found = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        for tid in TECHNIQUE.findall(line):
            if tid in revoked():
                found.append(f"{number}: {tid} -> {revoked()[tid]}")
    return found


def test_the_release_maps_revoked_ids() -> None:
    assert revoked().get("T1562.001") == "T1685"
    assert revoked().get("T1070.001") == "T1685.005"


def test_no_tag_table_names_a_revoked_technique() -> None:
    bad = {str(p.relative_to(REPO)): revoked_in(p) for p in TAG_TABLES if p.exists()}
    assert {p: lines for p, lines in bad.items() if lines} == {}


def test_every_pattern_tags_a_technique_the_release_has() -> None:
    for category, patterns in PATTERN_MAPPINGS.items():
        for pattern, techniques in patterns.items():
            for tid in techniques:
                assert tid not in revoked(), (category, pattern, tid)
                assert attack_lookup.technique(tid), (category, pattern, tid)


def test_a_yara_rules_revoked_id_is_its_replacement(tmp_path: Path) -> None:
    rules = tmp_path / "old.yar"
    rules.write_text('rule A {\n meta:\n  attack = "T1562.001, T1685, T1105"\n condition:\n  true\n}\n')
    assert yara_post.rule_techniques(str(rules)) == {"A": ["T1685", "T1105"]}
