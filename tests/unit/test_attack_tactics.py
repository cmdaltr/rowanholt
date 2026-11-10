"""Elrond files techniques under the pinned ATT&CK release's tactics. v20 split Enterprise's
Defense Evasion into Stealth and Defense Impairment: none of Elrond's tactic tables, dashboards
or tactic orderings names a tactic v20.1 doesn't have, and every technique a table or dashboard
lists sits under a tactic attack_techniques.csv gives it. Mobile kept Defense Evasion."""

import ast
import re
import sys
import warnings
from pathlib import Path
from typing import Dict, Iterator, List, Set, Tuple

REPO = Path(__file__).resolve().parents[2]
ANALYSIS = REPO / "src" / "analysis"
sys.path.append(str(ANALYSIS))

from rowanholt.post.elastic.dashboards import techniques as kibana  # noqa: E402
from rowanholt.post.mitre import attack_lookup  # noqa: E402
from rowanholt.post.mitre.attack_data import ATTACK_TECHNIQUES, get_techniques_for_tactic  # noqa: E402
from rowanholt.post.splunk.app import nav  # noqa: E402
from rowanholt.post.splunk.app.lookups.mitre_csv_generator import generate_embedded_mitre_csv  # noqa: E402
from rowanholt.post.splunk.app.views.xml import techniques as splunk  # noqa: E402

SPLUNK_APP = ANALYSIS / "rowanholt" / "post" / "splunk" / "app"

# Every static table that gives techniques their tactics ("tactics": [...] beside the IDs)
TACTIC_TABLES = [
    ANALYSIS / "rowanholt" / "post" / "mitre" / "attack_data.py",
    ANALYSIS / "rowanholt" / "post" / "mitre" / "enrichment.py",
    ANALYSIS / "rowanholt" / "process" / "extractions" / "artemis.py",
    ANALYSIS / "rowanholt" / "process" / "extractions" / "mitre_tagger.py",
    ANALYSIS / "rowanholt" / "post" / "splunk" / "app" / "views" / "xml" / "techniques.py",
    ANALYSIS / "rowanholt" / "post" / "elastic" / "dashboards" / "techniques.py",
    ANALYSIS / "rowanholt" / "post" / "splunk" / "app" / "lookups" / "mitre_csv_generator.py",
]

TACTICS_LIST = re.compile(r'"tactics":\s*\[([^\]]*)\]')
ONE_ID = re.compile(r'"technique_id":\s*"(T[\d.]+)"')
MANY_IDS = re.compile(r'"technique_ids":\s*\[([^\]]*)\]')
DICT_KEY = re.compile(r'"(T\d{4}(?:\.\d{3})?)"\s*:\s*$')


def enterprise() -> Set[str]:
    return set(attack_lookup.tactic_names(attack_lookup.ENTERPRISE))


def every_tactic() -> Set[str]:
    return enterprise() | set(attack_lookup.tactic_names(attack_lookup.MOBILE))


def tactic_lists(path: Path) -> Iterator[Tuple[List[str], List[str]]]:
    """(technique IDs, tactics) for each "tactics": [...] list in the file, the IDs from the
    dict it sits in (technique_id, technique_ids, or the dict's own key)."""
    text = path.read_text(encoding="utf-8")
    for match in TACTICS_LIST.finditer(text):
        start = text.rfind("{", 0, match.start())
        head = text[start:match.start()]
        one, many = ONE_ID.search(head), MANY_IDS.search(head)
        if one:
            ids = [one.group(1)]
        elif many:
            ids = ast.literal_eval(f"[{many.group(1)}]")
        else:
            key = DICT_KEY.search(text[:start])
            ids = [key.group(1)] if key else []
        yield ids, ast.literal_eval(f"[{match.group(1)}]")


def test_the_release_split_defense_evasion() -> None:
    assert "Defense Evasion" not in enterprise()
    assert {"Stealth", "Defense Impairment"} <= enterprise()
    assert attack_lookup.tactic_shortnames()["Stealth"] == "stealth"
    assert attack_lookup.tactic_shortnames()["Defense Impairment"] == "defense-impairment"
    assert attack_lookup.tactics_of("T1685.005") == ["Defense Impairment"]
    assert attack_lookup.tactics_of("T1070.004") == ["Stealth"]
    # Mobile kept it
    assert "Defense Evasion" in attack_lookup.tactic_names(attack_lookup.MOBILE)


def test_the_kill_chain_is_enterprises_tactics() -> None:
    order = attack_lookup.ENTERPRISE_TACTICS
    assert set(order) == enterprise() and len(order) == len(enterprise())
    assert order.index("Stealth") == order.index("Privilege Escalation") + 1
    assert order.index("Defense Impairment") == order.index("Stealth") + 1
    assert order.index("Credential Access") == order.index("Defense Impairment") + 1


def test_every_tactic_table_names_v20_tactics_its_techniques_have() -> None:
    bad = []
    for path in TACTIC_TABLES:
        for ids, tactics in tactic_lists(path):
            where = f"{path.relative_to(REPO)} {ids}"
            assert ids, f"{path.relative_to(REPO)}: a tactics list with no technique: {tactics}"
            given = {t for tid in ids for t in attack_lookup.tactics_of(tid)}
            unknown = set(tactics) - every_tactic()
            if unknown or not set(tactics) <= given:
                bad.append(f"{where}: {tactics}, v20.1 gives {sorted(given)}")
    assert bad == []


def test_no_enterprise_table_names_defense_evasion() -> None:
    for path in TACTIC_TABLES + [SPLUNK_APP / "nav.py", SPLUNK_APP / "app.py",
                                 ANALYSIS / "tools" / "config" / "mitre.py"]:
        text = path.read_text(encoding="utf-8")
        assert '"Defense Evasion"' not in text, path.relative_to(REPO)
        assert "Defense%20Evasion" not in text, path.relative_to(REPO)


def test_curated_techniques_carry_their_v20_tactics() -> None:
    for tid, data in ATTACK_TECHNIQUES.items():
        assert set(data["tactics"]) <= set(attack_lookup.tactics_of(tid)), tid
    found = {t["technique_id"] for t in get_techniques_for_tactic("Defense Impairment")}
    assert "T1685.005" in found
    assert get_techniques_for_tactic("Defense Evasion") == []


def test_every_splunk_dashboard_sits_under_a_tactic_the_release_gives_it() -> None:
    for tid, (_name, tactic, _desc) in splunk.TECHNIQUES.items():
        given = attack_lookup.tactics_of(tid)
        assert given, f"{tid} is not in ATT&CK v20.1"
        assert tactic in given, (tid, tactic, given)
        assert splunk.technique_tactics(tid) == given, tid


def test_the_splunk_tactic_views_drop_no_dashboard() -> None:
    views = [
        splunk.create_reconnaissance_xml, splunk.create_resource_development_xml,
        splunk.create_initial_access_xml, splunk.create_execution_xml,
        splunk.create_persistence_xml, splunk.create_privilege_escalation_xml,
        splunk.create_stealth_xml, splunk.create_defense_impairment_xml,
        splunk.create_credential_access_xml, splunk.create_discovery_xml,
        splunk.create_lateral_movement_xml, splunk.create_collection_xml,
        splunk.create_command_and_control_xml, splunk.create_exfiltration_xml,
        splunk.create_impact_xml,
    ]
    assert not hasattr(splunk, "create_defense_evasion_xml")
    covered = sum(len(splunk.techniques_for_tactic(t)) for t in attack_lookup.ENTERPRISE_TACTICS)
    assert covered == len(splunk.TECHNIQUES)
    assert len(views) == len(attack_lookup.ENTERPRISE_TACTICS)
    assert len(splunk.techniques_for_tactic("Stealth")) > 0
    assert len(splunk.techniques_for_tactic("Defense Impairment")) > 0


def test_the_splunk_tactic_views_write_every_dashboard(tmp_path: Path) -> None:
    written = sum(
        getattr(splunk, f"create_{t.lower().replace(' ', '_')}_xml")(f"{tmp_path}/")
        for t in attack_lookup.ENTERPRISE_TACTICS
    )
    assert written == len(splunk.TECHNIQUES) == len(list(tmp_path.glob("*.xml")))
    page = (tmp_path / "t1685_005.xml").read_text()
    assert ">Defense Impairment</span>" in page and "Defense Evasion</span>" not in page


def test_the_splunk_nav_files_every_technique_under_its_v20_tactics() -> None:
    by_tactic: Dict[str, List[str]] = nav.TECHNIQUES_BY_TACTIC
    assert list(by_tactic) == [t for t in attack_lookup.ENTERPRISE_TACTICS if t in by_tactic]
    assert {"Stealth", "Defense Impairment"} <= set(by_tactic)
    views = {tid.lower() for tid in splunk.TECHNIQUES}
    for tactic, ids in by_tactic.items():
        for view in ids:
            assert view in views, (tactic, view)
            assert tactic in attack_lookup.tactics_of(view.upper()), (tactic, view)
    listed = {v for ids in by_tactic.values() for v in ids}
    assert listed == {tid.lower() for tid in splunk.TECHNIQUES if "." not in tid}


def test_the_splunk_badges_and_overview_name_v20_tactics() -> None:
    source = (SPLUNK_APP / "views" / "xml" / "techniques.py").read_text(encoding="utf-8")
    colours = re.search(r"TACTIC_COLORS = \{(.*?)\}", source, re.S).group(1)
    assert set(re.findall(r'"([^"]+)":', colours)) == enterprise()
    overview = (SPLUNK_APP / "app.py").read_text(encoding="utf-8")
    panels = set(re.findall(r'mitre_tactics\{\}="([^"]+)"', overview))
    assert panels <= enterprise()
    assert {"Stealth", "Defense Impairment"} <= panels


def test_the_splunk_lookups_tactics_are_v20s() -> None:
    for row in generate_embedded_mitre_csv():
        assert {t.strip() for t in row["tactic"].split(";")} <= set(attack_lookup.tactics_of(row["id"])), row["id"]


def test_every_kibana_dashboard_sits_under_a_tactic_the_release_gives_it() -> None:
    for tid, info in kibana.TECHNIQUES.items():
        assert info["tactic"] in attack_lookup.tactics_of(tid), (tid, info["tactic"])
    assert kibana.get_all_tactics() == [t for t in attack_lookup.ENTERPRISE_TACTICS
                                        if t in {i["tactic"] for i in kibana.TECHNIQUES.values()}]


def test_the_legacy_page_generator_uses_v20_tactics() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)  # the script's own "\ " escapes
        tree = ast.parse((ANALYSIS / "tools" / "config" / "mitre.py").read_text(encoding="utf-8"))
    pages = next(ast.literal_eval(n.value) for n in tree.body
                 if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "PAGE_TACTICS")
    assert list(pages) == [t for t in attack_lookup.ENTERPRISE_TACTICS
                           if t not in ("Reconnaissance", "Resource Development")]


def test_the_journey_lights_a_beacon_per_v20_tactic() -> None:
    page = (REPO / "src" / "web" / "frontend" / "public" / "architecture" / "rowanholt-journey.html").read_text(
        encoding="utf-8")
    listed = re.search(r"const TACTICS = \[(.*?)\];", page, re.S).group(1)
    assert tuple(re.findall(r"'([^']+)'", listed)) == attack_lookup.ENTERPRISE_TACTICS
    for hits in re.findall(r"hits:\[([\d,]*)\]", page):
        assert all(int(i) < len(attack_lookup.ENTERPRISE_TACTICS) for i in hits.split(",") if i)
