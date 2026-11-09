#!/usr/bin/env python3
"""Rowanholt's ATT&CK techniques, both domains at one release, from MITRE's STIX bundles.

    python3 scripts/attack/build_attack_data.py enterprise-attack-20.1.json mobile-attack-20.1.json

The bundles come from https://github.com/mitre-attack/attack-stix-data (<domain>-attack/
<domain>-attack-<version>.json). Writes src/analysis/rowanholt/post/mitre/attack_techniques.csv
(one row per technique and sub-technique: domain, ID, name, tactics, platforms, URL) and
attack_release.json (the release, and the counts). Revoked and deprecated techniques are left
out. Both bundles must be the same release: the Navigator serves them as one version.
"""
import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

OUT = Path(__file__).resolve().parents[2] / "src" / "analysis" / "rowanholt" / "post" / "mitre"
DOMAINS = ("enterprise-attack", "mobile-attack")
# Technique references and kill chains name either (Mobile mostly uses mitre-attack)
ATTACK_SOURCES = {"mitre-attack", "mitre-mobile-attack"}
FIELDS = ["domain", "technique_id", "name", "tactics", "tactic_ids", "platforms", "url"]


def read_bundle(path: Path) -> Tuple[str, str, List[Dict[str, str]], Dict[str, str]]:
    """(domain, release, rows, revoked) from one STIX bundle; revoked maps each revoked
    technique's ID to its replacement's, as MITRE's revoked-by relationships give them."""
    objects = json.loads(path.read_text(encoding="utf-8"))["objects"]
    collections = [o for o in objects if o.get("type") == "x-mitre-collection"]
    if not collections:
        sys.exit(f"{path}: no x-mitre-collection object, so no release to pin (use attack-stix-data's versioned files)")
    release = collections[0]["x_mitre_version"]
    domains = {d for o in objects if o.get("type") == "attack-pattern" for d in o.get("x_mitre_domains", [])}
    domains &= set(DOMAINS)
    if len(domains) != 1:
        sys.exit(f"{path}: not one of {', '.join(DOMAINS)}")
    domain = domains.pop()
    tactic_names = {o["x_mitre_shortname"]: o["name"] for o in objects
                    if o.get("type") == "x-mitre-tactic" and not o.get("revoked") and not o.get("x_mitre_deprecated")}
    rows = []
    for o in objects:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        if domain not in o.get("x_mitre_domains", [domain]):
            continue
        ref = next((r for r in o.get("external_references", []) if r.get("source_name") in ATTACK_SOURCES
                    and r.get("external_id", "").startswith("T")), None)
        if not ref:
            continue
        tactic_ids = [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") in ATTACK_SOURCES]
        rows.append({
            "domain": domain,
            "technique_id": ref["external_id"],
            "name": o["name"],
            "tactics": "; ".join(tactic_names.get(t, t) for t in tactic_ids),
            "tactic_ids": ";".join(tactic_ids),
            "platforms": "; ".join(o.get("x_mitre_platforms", [])),
            "url": ref.get("url", ""),
        })
    by_ref = {o["id"]: o for o in objects if o.get("type") == "attack-pattern"}

    def technique_id(o: Dict) -> str:
        return next((r["external_id"] for r in o.get("external_references", [])
                     if r.get("source_name") in ATTACK_SOURCES and r.get("external_id", "").startswith("T")), "")

    revoked = {}
    for rel in objects:
        if rel.get("type") == "relationship" and rel.get("relationship_type") == "revoked-by":
            old, new = by_ref.get(rel["source_ref"]), by_ref.get(rel["target_ref"])
            if old and new and domain in old.get("x_mitre_domains", [domain]) and technique_id(old) and technique_id(new):
                revoked[technique_id(old)] = technique_id(new)
    return domain, release, rows, revoked


def main() -> None:
    """Read the bundles, check they're one release with no ID in both, write the two files."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("bundles", nargs="+", type=Path, help="enterprise-attack and mobile-attack STIX bundles")
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()

    read = [read_bundle(p) for p in args.bundles]
    domains = [d for d, _, _, _ in read]
    if sorted(domains) != sorted(DOMAINS):
        sys.exit(f"Need one bundle of each of {', '.join(DOMAINS)} (got {', '.join(domains)})")
    releases = {d: r for d, r, _, _ in read}
    if len(set(releases.values())) != 1:
        sys.exit(f"The bundles are different releases ({releases}): download both at the same version")
    rows = sorted((row for _, _, rs, _ in read for row in rs), key=lambda r: (r["domain"], r["technique_id"]))
    current = {r["technique_id"] for r in rows}
    # Follow chains (A revoked by B, B since revoked by C) to a technique the release still has
    revoked: Dict[str, str] = {}
    chain = {old: new for _, _, _, rv in read for old, new in rv.items()}
    for old in chain:
        new, hops = chain[old], 0
        while new not in current and new in chain and hops < 10:
            new, hops = chain[new], hops + 1
        if new in current and old not in current:
            revoked[old] = new
    seen: Dict[str, str] = {}
    for row in rows:
        if row["technique_id"] in seen:
            sys.exit(f"{row['technique_id']} is in both {seen[row['technique_id']]} and {row['domain']}: IDs no longer tell the domain")
        seen[row["technique_id"]] = row["domain"]

    with open(args.out / "attack_techniques.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    release = {
        "version": next(iter(releases.values())),
        "source": "https://github.com/mitre-attack/attack-stix-data",
        "domains": {d: sum(1 for r in rows if r["domain"] == d) for d in DOMAINS},
        # A revoked technique's ID still resolves, to the one that replaced it
        "revoked": dict(sorted(revoked.items())),
    }
    (args.out / "attack_release.json").write_text(json.dumps(release, indent=2) + "\n", encoding="utf-8")
    print(f"ATT&CK v{release['version']}: " + ", ".join(f"{n} {d}" for d, n in release["domains"].items())
          + f"; {len(revoked)} revoked IDs mapped to their replacements")


if __name__ == "__main__":
    main()
