"""STIX 2.1 bundles and TAXII 2.1 collections as indicator rows.

Bundles are read by samarkand.stix, the suite's shared reader (hand-written JSON rather than
python-stix2's loaders, because vendor exports carry custom properties the strict loaders reject).
It gives each value with the groups and techniques its own STIX relationships ('indicates',
'related-to', 'uses') link it to; here those become the ten columns, an indicator falling back to the
bundle's only intrusion set when it has exactly one, and never to every technique in the bundle. Only
objects with an id are read: one without can't be referred to, so it gives no row and links nothing.

An indicator's valid_until and confidence (and valid_from or created, as first seen) come back
beside the rows, keyed by Indicator.key(), for the backend's threat_intel_validity
(parse_stix_bundle_with_validity); the ten columns don't carry them.
"""

import base64
import json
import urllib.request
from datetime import datetime
from itertools import groupby
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlencode

from samarkand import stix as shared

from rowanholt.threat_intel.schema import Indicator, unique
from rowanholt.threat_intel.validity import Validity

# The cyber observables a row can come from; an indicator's pattern may name any of these and software
OBSERVABLES = ("ipv4-addr", "ipv6-addr", "domain-name", "url", "file", "process", "windows-registry-key")
TAXII_ACCEPT = "application/taxii+json;version=2.1"


class IntelFormatError(ValueError):
    """The document isn't the format it was read as."""


def _load(data: Union[str, bytes, dict, list]):
    if isinstance(data, (str, bytes)):
        try:
            return json.loads(data)
        except ValueError as exc:
            raise IntelFormatError(f"not JSON: {exc}") from exc
    return data


def _kind(item: shared.Indicator) -> str:
    """The value's kind as Rowanholt names it (ip, domain, url, hash, file, cmd, software, reg), or ""
    for one it doesn't read."""
    stix_type, path = item.stix_type, item.stix_path.lower()
    if stix_type in ("ipv4-addr", "ipv6-addr"):
        return "ip"
    if stix_type in ("domain-name", "url"):
        return "domain" if stix_type == "domain-name" else "url"
    if stix_type == "file":
        return "hash" if "hashes" in path else "file"
    if stix_type == "process":
        return "cmd" if "command_line" in path else "software"
    if stix_type == "windows-registry-key":
        return "reg"
    if stix_type == "software" and item.object_type == "indicator":
        return "software"
    return ""


def _naive(at: Optional[datetime]) -> Optional[datetime]:
    """samarkand's aware UTC as the naive UTC the database stores."""
    return at.replace(tzinfo=None) if at else None


def _tactics(phases: Tuple[str, ...]) -> str:
    return ", ".join(p.replace("-", " ").title() for p in phases)


def parse_stix_bundle(data: Union[str, bytes, dict, list], source: str = "") -> List[Indicator]:
    """A STIX 2.1 bundle (or a bare list of objects) as indicators."""
    return parse_stix_bundle_with_validity(data, source)[0]


def parse_stix_bundle_with_validity(data: Union[str, bytes, dict, list],
                                    source: str = "") -> Tuple[List[Indicator], Dict[tuple, Validity]]:
    """The bundle's indicators, and the validity of those whose STIX object gives one (by key)."""
    data = _load(data)
    objects = data.get("objects") if isinstance(data, dict) else data
    if not isinstance(objects, list):
        raise IntelFormatError("not a STIX bundle: no 'objects' list")
    try:
        parsed = shared.parse([o for o in objects if isinstance(o, dict) and isinstance(o.get("id"), str) and o["id"]])
    except shared.NotABundle as exc:
        raise IntelFormatError(str(exc)) from exc
    report = parsed.reports[0] if parsed.reports else None
    bundle_id = data.get("id", "bundle") if isinstance(data, dict) else "bundle"
    source = source or ("STIX: " + ((report.name if report else "") or parsed.only_group or bundle_id))
    report_url = report.references[0] if report and report.references else ""

    indicators = []
    validity: Dict[tuple, Validity] = {}
    # One STIX object's values are consecutive: each object is a run, as Rowanholt has always read it
    for _, run in groupby(parsed.indicators, key=lambda item: item.object_id):
        values = [(item, _kind(item)) for item in run
                  if item.object_type == "indicator" or item.object_type in OBSERVABLES]
        values = [(item, kind) for item, kind in values if kind]
        if not values:
            continue
        obj = values[0][0]  # what the object says is the same for each of its values
        group = obj.groups[0] if obj.groups else parsed.only_group
        own = Validity(valid_until=_naive(obj.valid_until), confidence=obj.confidence,
                       first_seen=_naive(obj.valid_from or obj.created))
        timed = own.valid_until is not None or own.confidence is not None
        for technique in obj.techniques or (None,):
            technique_id = technique.id if technique else (obj.named_techniques or ("",))[0]
            for item, kind in values:
                indicators.append(Indicator(
                    evidential_element=item.value, threat_group=group,
                    procedure_example=(obj.description or obj.name or "")[:1000],
                    technique_id=technique_id, technique_name=technique.name if technique else "",
                    tactic=_tactics(technique.tactics if technique else obj.tactics),
                    contextual_evidence=f"{kind}: {obj.name or obj.object_type}"[:500],
                    reference_url=(obj.references or (report_url,))[0], source_type=source,
                ))
                if timed:
                    key = indicators[-1].key()
                    validity[key] = validity[key].merge(own) if key in validity else own
    return unique(indicators), validity


def fetch_taxii(collection_url: str, username: str = "", password: str = "", added_after: str = "",
                limit: int = 5000, timeout: int = 60) -> List[Dict]:
    """Every STIX object in a TAXII 2.1 collection, following its pagination. collection_url is the
    collection's base (.../collections/<id>/); added_after (ISO 8601) fetches only what's new."""
    base = collection_url if collection_url.endswith("/") else collection_url + "/"
    headers = {"Accept": TAXII_ACCEPT, "User-Agent": "Rowanholt (TAXII 2.1 client)"}
    if username:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
    params: Dict[str, object] = {"limit": min(limit, 1000)}
    if added_after:
        params["added_after"] = added_after
    objects: List[Dict] = []
    seen = set()
    while len(objects) < limit:
        request = urllib.request.Request(f"{base}objects/?{urlencode(params)}", headers=headers)
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (an analyst-given URL)
            envelope = json.load(response)
        objects.extend(envelope.get("objects") or [])
        following = envelope.get("next")
        if not envelope.get("more") or not following or following in seen:
            break
        seen.add(following)
        params["next"] = following
    return objects[:limit]


def import_taxii(collection_url: str, username: str = "", password: str = "", added_after: str = "",
                 limit: int = 5000) -> List[Indicator]:
    return import_taxii_with_validity(collection_url, username, password, added_after, limit)[0]


def import_taxii_with_validity(collection_url: str, username: str = "", password: str = "", added_after: str = "",
                               limit: int = 5000) -> Tuple[List[Indicator], Dict[tuple, Validity]]:
    objects = fetch_taxii(collection_url, username, password, added_after, limit)
    return parse_stix_bundle_with_validity({"type": "bundle", "objects": objects}, source=f"TAXII: {collection_url}")
