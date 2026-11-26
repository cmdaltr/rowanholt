"""
Microsoft's GUIDE dataset (CDLA-Permissive-2.0): Defender XDR alerts and their evidence from over
5,000 organisations over two weeks, each alert with its ATT&CK techniques and the customer's
triage grade. Identifying values are anonymised, so it says nothing about what an attack looks
like in the logs. What it does say, per technique: whether Defender XDR alerts on it out of the
box, how widely, and how often those alerts are true positives. Where Defender is already good,
custom detections matter less; where it rarely alerts, or is mostly wrong, they matter more.

GUIDE needs a Kaggle login, so it's downloaded by hand and summarised here:

    python -m src.mordor.telemetry --guide ~/Downloads/microsoft-security-incident-prediction.zip

The summary (src/mordor/data/telemetry_guide.json, a few hundred KB) is all that's kept.
Ported from Shikari.
"""

import csv
import io
import json
import os
import re
import time
import zipfile
from collections import Counter, defaultdict
from typing import Dict, Iterable, Optional

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUMMARY_PATH = os.path.join(HERE, "data", "telemetry_guide.json")
INFO = {"name": "Microsoft GUIDE", "licence": "CDLA-Permissive-2.0",
        "url": "https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction",
        "note": "Defender XDR alerts over two weeks, with customers' triage grades"}
_TID = re.compile(r"T\d{4}(?:\.\d{3})?")
GRADES = {"TruePositive": "tp", "BenignPositive": "bp", "FalsePositive": "fp"}


def _rows(path: str) -> Iterable[Dict[str, str]]:
    """GUIDE_Train.csv and GUIDE_Test.csv rows from the Kaggle zip, a folder or one CSV."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for name in sorted(n for n in z.namelist() if n.lower().endswith(".csv")):
                with z.open(name) as fh:
                    yield from csv.DictReader(io.TextIOWrapper(fh, encoding="utf-8", newline=""))
    elif os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            if name.lower().endswith(".csv"):
                with open(os.path.join(path, name), encoding="utf-8", newline="") as fh:
                    yield from csv.DictReader(fh)
    else:
        with open(path, encoding="utf-8", newline="") as fh:
            yield from csv.DictReader(fh)


def build(path: str, log=print) -> Dict:
    """Summarise GUIDE per technique: alerts, organisations, detectors, triage grades, alert
    categories and evidence types. An alert's grade is its incident's."""
    alerts, orgs, detectors = defaultdict(set), defaultdict(set), defaultdict(set)
    grades, categories, evidence = defaultdict(Counter), defaultdict(Counter), defaultdict(Counter)
    rows = 0
    for r in _rows(path):
        rows += 1
        if rows % 1_000_000 == 0:
            log(f"  {rows:,} rows")
        techniques = set(_TID.findall(r.get("MitreTechniques") or ""))
        if not techniques:
            continue
        alert = (r.get("OrgId"), r.get("AlertId"))
        grade = GRADES.get(r.get("IncidentGrade") or "")
        for t in techniques:
            if alert not in alerts[t]:
                alerts[t].add(alert)
                if r.get("Category"):
                    categories[t][r["Category"]] += 1
                if grade:  # an incident's grade, so the same on all its alert's rows
                    grades[t][grade] += 1
            orgs[t].add(r.get("OrgId"))
            detectors[t].add(r.get("DetectorId"))
            if r.get("EntityType"):
                evidence[t][r["EntityType"]] += 1
    out = {}
    for t in sorted(alerts):
        g = grades[t]
        total = sum(g.values())
        out[t] = {"alerts": len(alerts[t]), "orgs": len(orgs[t]), "detectors": len(detectors[t]),
                  "grades": dict(g), "tp_rate": round(g["tp"] / total, 3) if total else None,
                  "categories": [c for c, _ in categories[t].most_common(4)],
                  "evidence": [e for e, _ in evidence[t].most_common(6)]}
    every = set().union(*orgs.values()) if orgs else set()
    summary = {"source": {**INFO, "note": f"{INFO['note']}, from {len(every):,} organisations",
                          "built": time.strftime("%Y-%m-%d"), "rows": rows, "orgs": len(every)},
               "techniques": out}
    os.makedirs(os.path.dirname(SUMMARY_PATH), exist_ok=True)
    with open(SUMMARY_PATH, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    _cache.clear()
    log(f"GUIDE: {rows:,} rows, {len(out)} techniques with Defender XDR alerts")
    return summary


_cache: Dict = {}


def load() -> Optional[Dict]:
    if "summary" not in _cache:
        try:
            with open(SUMMARY_PATH, encoding="utf-8") as fh:
                _cache["summary"] = json.load(fh)
        except (OSError, ValueError):
            _cache["summary"] = None
    return _cache["summary"]


def for_technique(tid: str) -> Optional[Dict]:
    """GUIDE's figures for a technique, else its parent's (marked "family"), or None (not built,
    or no Defender XDR alert maps to it)."""
    s = load()
    if not s:
        return None
    tid = tid.upper()
    own = s["techniques"].get(tid)
    if own:
        return own
    parent = s["techniques"].get(tid.split(".")[0])
    return {**parent, "family": True} if parent and "." in tid else None
