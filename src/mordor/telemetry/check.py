"""
A detection's indicators against recorded attack telemetry (src.mordor.telemetry.datasets).

For each indicator: the recordings of its technique whose events contain it (the event type
and field: "Sysmon 1, CommandLine"), and how many recordings of other techniques contain it
too. Found in its own technique's recordings means the detection would have matched real
events of the attack, and says which log it needs. Found in many unrelated recordings means
it also matches the lab's ordinary activity: likely noisy. Neither proves anything about
another estate; it's a cheap first look before hit counts against a real SIEM (#16).
"""

import os
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Optional

from . import datasets as ds

# Archer writes indicators that contain a variable span (a user name, a random path segment)
# with this ellipsis standing in for the gap, so "C:\Users\…\AppData" matches any user's. If a
# detection source doesn't use gap indicators, leave it as-is: a value with no GAP is matched whole.
GAP = "\u2026"

MIN_LEN = 3
NOISY = 5  # recordings of other techniques containing an indicator before it's called noisy
_haystack: Dict = {}


def _index() -> Optional[Dict[str, Dict[str, List[tuple]]]]:
    """{dataset: {field group: [(event type, field, lowercased values joined)]}}, built once."""
    vals = ds.values()
    if vals is None:
        return None
    if _haystack.get("for") is not vals:
        group_of = {f: g for g, fs in ds.FIELDS.items() for f in fs}
        index = {}
        for did, by_type in vals.items():
            groups = defaultdict(list)
            for etype, fields in by_type.items():
                for field, values in fields.items():
                    groups[group_of.get(field, "other")].append((etype, field, "\n".join(values).lower(), values))
            index[did] = groups
        _haystack.update({"for": vals, "index": index})
    return _haystack["index"]


def _found(indicator: str, haystack: str) -> bool:
    parts = [p for p in indicator.lower().split(GAP) if p]
    if len(parts) == 1:
        return parts[0] in haystack
    pos = 0
    for p in parts:  # in order: "C:\Users\…\AppData" matches any user's
        pos = haystack.find(p, pos)
        if pos < 0:
            return False
        pos += len(p)
    return True


def _example(indicator: str, values: List[str]) -> str:
    first = indicator.lower().split(GAP)[0]
    return next((v for v in values if first in v.lower()), "")[:240]


def indicators_of(doc: Dict) -> List[tuple]:
    """(kind, value) for a detection YAML's indicators."""
    out = []
    for kind, items in (doc.get("indicators") or {}).items():
        for v in items if isinstance(items, list) else [items]:
            v = str(v).strip()
            if len(v.replace(GAP, "")) >= MIN_LEN:
                out.append((kind, v))
    return out


def check(doc: Dict) -> Dict:
    """The detection's indicators against its technique's recordings and everyone else's."""
    tid = str(doc.get("technique_id") or "")
    own = ds.for_technique(tid) if tid else []
    result = {"technique": tid, "name": doc.get("name"), "datasets": len(own), "indicators": []}
    index = _index()
    if not own:
        return {**result, "status": "no_recordings"}
    if index is None:
        return {**result, "status": "no_values"}
    own_ids = {d["id"] for d in own}
    titles = {d["id"]: d["title"] for d in own}
    for kind, value in indicators_of(doc):
        groups = ds.KIND_FIELDS.get(kind, ("cmd", "file", "other"))
        seen, elsewhere = [], 0
        for did, by_group in index.items():
            hits = [(e, f, vals) for g in groups for e, f, text, vals in by_group.get(g, []) if _found(value, text)]
            if not hits:
                continue
            if did in own_ids:
                for etype, field, vals in hits[:3]:
                    seen.append({"dataset": did, "source": did.split(":", 1)[0], "title": titles[did], "event": etype,
                                 "collection": ds.collection(etype),
                                 "label": ds.describe(etype)["label"], "field": field, "example": _example(value, vals)})
            else:
                elsewhere += 1
        result["indicators"].append({"kind": kind, "value": value, "seen": seen, "elsewhere": elsewhere,
                                     "noisy": elsewhere >= NOISY})
    any_seen = any(i["seen"] for i in result["indicators"])
    result["status"] = "seen" if any_seen else ("no_indicators" if not result["indicators"] else "not_seen")
    result["events"] = sorted({s["label"] for i in result["indicators"] for s in i["seen"]})
    described = [ds.describe(s["event"]) for i in result["indicators"] for s in i["seen"]]
    result["mde"] = sorted({d["mde"].split(" (")[0] for d in described if d.get("mde")})
    result["udm"] = sorted({d["udm"] for d in described if d.get("udm")})
    return result


def technique(tid: str, collections: Optional[Iterable[str]] = None, platforms: Optional[Iterable[str]] = None) -> Dict:
    """What recorded telemetry shows for a technique: its recordings, and the event types (of the
    chosen kinds of collection) they hold."""
    allowed, on = _allowed(collections), _allowed(platforms)
    recs = [d for d in ds.for_technique(tid) if _on(d, on)]
    by_type: Counter = Counter()
    events: Counter = Counter()
    common = set()
    visible = 0
    for d in recs:
        held = _held(d, allowed, on)
        visible += bool(held)
        by_type.update(held)
        events.update({e: d["events"][e] for e in held})
        common |= set(d.get("background") or [])
    rows = []
    for etype, n in by_type.most_common():
        info = ds.describe(etype)
        rows.append({"event": etype, "label": info["label"], "mde": info.get("mde", ""), "udm": info.get("udm", ""),
                     "collection": ds.collection(etype), "recordings": n, "events": events[etype], "common": etype in common})
    exact = any(tid.upper() in d["techniques"] for d in recs)
    # What most of its recordings hold: Sysmon 1 is in nearly every recording because nearly
    # every attack starts processes, so how common an event type is elsewhere doesn't exclude it
    usual = [r for r in rows if r["recordings"] * 2 >= visible]
    need = {"mde": Counter(r["mde"].split(" (")[0] for r in usual if r["mde"]),
            "udm": Counter(r["udm"] for r in usual if r["udm"])}
    return {"technique": tid.upper(), "exact": exact, "visible": visible,
            "recordings": [{k: d.get(k) for k in ("id", "source", "title", "techniques", "tools", "url", "date")}
                           | {"events": sum(d["events"].values()), "platforms": ds.platforms(d),
                              "visible": bool(_held(d, allowed, on))} for d in recs],
            "event_types": rows,
            "need": {k: [{"name": n, "recordings": c} for n, c in v.most_common()] for k, v in need.items()}}


def group(group_name: str, generate_dir: str, list_files=None) -> Dict:
    """Every detection of a group's latest run against recorded telemetry.

    `list_files(group_name, generate_dir) -> list[path]` names the detection YAMLs for the group;
    inject your own (Dernvale's detection store). Each YAML needs `technique_id`, `name` and an
    `indicators:` map ({kind: [values]}); `requiredDataConnectors` is optional (used to label the SIEM).
    """
    import yaml

    if list_files is None:
        raise ValueError("pass list_files(group_name, generate_dir) -> [yaml paths]")

    rows = []
    for name in list_files(group_name, generate_dir):
        try:
            with open(os.path.join(generate_dir, os.path.basename(name)), encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
        except (OSError, ValueError, yaml.YAMLError):
            continue
        if not doc.get("technique_id"):
            continue
        connector = ((doc.get("requiredDataConnectors") or [{}])[0] or {}).get("connectorId", "")
        rows.append({**check(doc), "file": os.path.basename(name), "connector": connector, "group": group_name,
                     "siem": "secops" if connector == "GoogleSecOps" else "mde" if connector == "MicrosoftThreatProtection" else ""})
    counts = Counter(r["status"] for r in rows)
    return {"group": group_name, "detections": rows, "counts": dict(counts), "values": ds.values() is not None}


def _allowed(collections: Optional[Iterable[str]]) -> Optional[frozenset]:
    return frozenset(collections) if collections else None


def _held(d: Dict, allowed: Optional[frozenset], on: Optional[frozenset] = None) -> List[str]:
    """A recording's event types from the chosen kinds of collection, on the chosen platforms."""
    given = None
    out = []
    for e in d["events"]:
        if allowed is not None and ds.collection(e) not in allowed:
            continue
        if on is not None:
            p = ds.event_platform(e, d)
            if p is None:
                given = ds._given(d) if given is None else given
                if not given & on:
                    continue
            elif p not in on:
                continue
        out.append(e)
    return out


def _on(d: Dict, platforms: Optional[frozenset]) -> bool:
    return platforms is None or bool(platforms & set(ds.platforms(d)))


def _usual(collections: Optional[Iterable[str]] = None, platforms: Optional[Iterable[str]] = None) -> Dict[str, Dict]:
    """{technique: {recordings, visible, sources, platforms, usual}}: the event types (of the chosen
    collections) in at least half the recordings that hold any of them."""
    allowed, on = _allowed(collections), _allowed(platforms)
    key = ("usual", allowed, on, id(ds.load()))
    if key in _haystack:
        return _haystack[key]
    recs, visible, holding = Counter(), Counter(), defaultdict(Counter)
    sources, plats = defaultdict(Counter), defaultdict(set)
    for d in ds.load()["datasets"]:
        if not _on(d, on):
            continue
        held = _held(d, allowed, on)
        for t in d["techniques"]:
            if t == "T0000":  # Security-Datasets' placeholder for a recording with no technique
                continue
            recs[t] += 1
            sources[t][d["source"]] += 1
            plats[t].update(p for p in ds.platforms(d) if on is None or p in on)
            if held:
                visible[t] += 1
                holding[t].update(held)
    out = {t: {"recordings": recs[t], "visible": visible[t], "sources": dict(sources[t]), "platforms": sorted(plats[t]),
               "usual": [e for e, n in holding[t].most_common() if visible[t] and n * 2 >= visible[t]]} for t in recs}
    _haystack[key] = out
    return out


def overview(collections: Optional[Iterable[str]] = None, platforms: Optional[Iterable[str]] = None) -> List[Dict]:
    """Every recorded technique: its recordings per source, how many hold the chosen kinds of log,
    the logs most of those hold, and their Defender XDR tables and UDM event types."""
    rows = []
    for t, u in sorted(_usual(collections, platforms).items()):
        infos = [ds.describe(e) for e in u["usual"]]
        rows.append({"technique": t, "recordings": u["recordings"], "visible": u["visible"], "sources": u["sources"],
                     "platforms": u["platforms"], "logs": [i["label"] for i in infos],
                     "collections": sorted({ds.collection(e) for e in u["usual"]}),
                     "mde": sorted({i["mde"].split(" (")[0] for i in infos if i.get("mde")}),
                     "udm": sorted({i["udm"] for i in infos if i.get("udm")})})
    return rows


def by_data_source(collections: Optional[Iterable[str]] = None, platforms: Optional[Iterable[str]] = None) -> Dict[str, List[Dict]]:
    """For each Defender XDR table and UDM event type: the techniques at least half of whose
    recordings hold it (from the chosen kinds of log), and the logs it comes from."""
    mde, udm = defaultdict(lambda: (set(), Counter())), defaultdict(lambda: (set(), Counter()))
    for t, u in _usual(collections, platforms).items():
        for etype in u["usual"]:
            info = ds.describe(etype)
            for m, name in ((mde, info.get("mde", "").split(" (")[0]), (udm, info.get("udm", ""))):
                if name:
                    m[name][0].add(t)
                    m[name][1][info["label"]] += 1
    # Logs by how many of the source's techniques they record
    rank = lambda m: [{"name": k, "techniques": len(v[0]), "technique_ids": sorted(v[0]), "logs": [l for l, _ in v[1].most_common()]}
                      for k, v in sorted(m.items(), key=lambda kv: (-len(kv[1][0]), kv[0]))]
    return {"mde": rank(mde), "udm": rank(udm)}


def search(text: str, limit: int = 400) -> Optional[Dict[str, List[str]]]:
    """{technique: [logs]} whose recordings hold a field value containing the text (… gaps allowed)."""
    index = _index()
    if index is None:
        return None
    text = text.strip()
    if len(text.replace(GAP, "")) < MIN_LEN:
        return {}
    techniques = {d["id"]: d["techniques"] for d in ds.load()["datasets"]}
    out = defaultdict(set)
    for did, by_group in index.items():
        for entries in by_group.values():
            for etype, _field, hay, _vals in entries:
                if _found(text, hay):
                    for t in techniques.get(did, []):
                        out[t].add(ds.describe(etype)["label"])
        if len(out) >= limit:
            break
    return {t: sorted(v) for t, v in sorted(out.items())}


def _recorded_values(tid: str, cap: int = 40) -> List[str]:
    """Distinct field values from a technique's own recordings — candidate indicators to vet."""
    vals = ds.values() or {}
    own_ids = {d["id"] for d in ds.for_technique(tid)}
    out: List[str] = []
    for did in own_ids:
        for fields in (vals.get(did) or {}).values():
            for values in fields.values():
                for v in values:
                    v = str(v).strip()
                    if len(v) >= 4 and not v.isdigit():
                        out.append(v)
    return list(dict.fromkeys(out))[:cap]


def noisy(indicators: Optional[Iterable[str]] = None, technique_id: str = "",
          min_techniques: int = NOISY) -> Dict:
    """Which indicator strings are poor discriminators: recorded while many unrelated techniques ran.

    For each indicator, the distinct techniques whose recorded telemetry contains it (found via
    ``search``). With a technique_id, its own family is set aside so the count is of *other*
    techniques, and the indicator is marked for whether its own technique recorded it at all; an
    indicator in ``min_techniques`` or more other techniques is noisy. Given no indicators but a
    technique_id, the technique's own recorded field values are vetted — the artefacts too common to
    key a detection on. A cheap false-positive signal before hit counts against a real SIEM.
    """
    base = {"min_techniques": min_techniques,
            "technique": technique_id.upper() if technique_id else "", "noisy": [], "checked": 0}
    if _index() is None:
        return {**base, "status": "no_values"}
    tid = str(technique_id or "").upper()
    family = tid.split(".")[0]

    def is_own(t: str) -> bool:
        return bool(tid) and (t == tid or t == family or t.startswith(family + "."))

    cands = [str(v).strip() for v in (indicators or []) if str(v).strip()]
    derived = not cands and bool(tid)
    if derived:
        cands = _recorded_values(tid)
    rows = []
    for value in dict.fromkeys(cands):
        if len(value.replace(GAP, "")) < MIN_LEN:
            continue
        hits = {t for t in (search(value) or {}) if t != "T0000"}
        others = sorted(t for t in hits if not is_own(t))
        rows.append({"indicator": value, "techniques": len(hits), "other_techniques": len(others),
                     "in_own_technique": any(is_own(t) for t in hits), "examples": others[:12],
                     "noisy": len(others) >= min_techniques})
    rows.sort(key=lambda r: -r["other_techniques"])
    status = "no_recordings" if (derived and not rows) else "ok"
    return {**base, "status": status, "derived_from_technique": derived, "checked": len(rows),
            "noisy": [r for r in rows if r["noisy"]],
            "specific": [r["indicator"] for r in rows if not r["noisy"]][:40]}
