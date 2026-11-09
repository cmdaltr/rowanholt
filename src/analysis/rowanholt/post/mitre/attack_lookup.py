#!/usr/bin/env python3 -tt
"""
ATT&CK techniques, Enterprise and Mobile, at the one release Rowanholt pins.

attack_techniques.csv and attack_release.json are generated from MITRE's STIX bundles by
scripts/attack/build_attack_data.py; nothing here is written by hand. Cloud is not a domain of
its own: IaaS, SaaS, Office Suite and Identity Provider are Enterprise platforms. Technique IDs
are unique across the two domains, so an ID says which domain it belongs to.
"""

import csv
import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional

HERE = Path(__file__).resolve().parent
TECHNIQUES_CSV = HERE / "attack_techniques.csv"
RELEASE_JSON = HERE / "attack_release.json"

ENTERPRISE = "enterprise-attack"
MOBILE = "mobile-attack"
DOMAINS = (ENTERPRISE, MOBILE)
DOMAIN_NAMES = {ENTERPRISE: "Enterprise", MOBILE: "Mobile"}


class Technique(NamedTuple):
    """One technique or sub-technique as ATT&CK publishes it."""
    domain: str
    technique_id: str
    name: str
    tactics: List[str]
    tactic_ids: List[str]
    platforms: List[str]
    url: str


def _split(value: str, sep: str) -> List[str]:
    return [v.strip() for v in value.split(sep) if v.strip()]


@lru_cache(maxsize=1)
def _techniques() -> Dict[str, Technique]:
    with open(TECHNIQUES_CSV, newline="", encoding="utf-8") as fh:
        return {
            row["technique_id"]: Technique(
                row["domain"], row["technique_id"], row["name"], _split(row["tactics"], ";"),
                _split(row["tactic_ids"], ";"), _split(row["platforms"], ";"), row["url"])
            for row in csv.DictReader(fh)
        }


@lru_cache(maxsize=1)
def release() -> Dict:
    """The pinned release: {"version": "20.1", "domains": {domain: count}, ...}."""
    return json.loads(RELEASE_JSON.read_text(encoding="utf-8"))


def version() -> str:
    """The pinned ATT&CK release, e.g. "20.1"."""
    return str(release()["version"])


def normalise(technique_id: str) -> str:
    """T1059.001 from t1059.001 or 1059.001."""
    tid = technique_id.strip().upper()
    return tid if tid.startswith("T") else f"T{tid}"


def current_id(technique_id: str) -> str:
    """The ID the pinned release uses: a revoked technique's replacement (T1562.001, Disable or
    Modify Tools, became T1685 in v20), or the ID itself. Cases recorded before keep the old IDs."""
    tid = normalise(technique_id)
    return release().get("revoked", {}).get(tid, tid)


def technique(technique_id: str) -> Optional[Technique]:
    """The technique (a revoked one's replacement), or None when the release has no such ID."""
    return _techniques().get(current_id(technique_id))


def domain_of(technique_id: str) -> Optional[str]:
    """enterprise-attack, mobile-attack, or None for an ID neither has."""
    found = technique(technique_id)
    return found.domain if found else None


def full_name(technique_id: str) -> str:
    """A sub-technique's name with its parent's, as ATT&CK writes it ("OS Credential Dumping:
    LSASS Memory"); "" for an unknown ID."""
    found = technique(technique_id)
    if not found:
        return ""
    if "." not in found.technique_id:
        return found.name
    parent = _techniques().get(found.technique_id.split(".")[0])
    return f"{parent.name}: {found.name}" if parent else found.name


def all_techniques() -> List[Technique]:
    """Every technique of both domains, by domain then ID."""
    return sorted(_techniques().values(), key=lambda t: (t.domain, t.technique_id))


def platforms(domain: str) -> List[str]:
    """Every platform the domain's techniques name, sorted (Enterprise's include the cloud ones)."""
    return sorted({p for t in _techniques().values() if t.domain == domain for p in t.platforms})


def by_domain(technique_ids) -> Dict[str, List[str]]:
    """The IDs grouped by domain, each list sorted; IDs no domain has go under None. A revoked
    ID is given as its replacement, the one the Navigator's ATT&CK data has."""
    grouped: Dict[Optional[str], List[str]] = {}
    for tid in sorted({current_id(t) for t in technique_ids if t and t.strip()}):
        grouped.setdefault(domain_of(tid), []).append(tid)
    return grouped
