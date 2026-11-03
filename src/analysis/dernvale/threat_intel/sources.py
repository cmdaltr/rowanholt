"""Any threat intelligence file Dernvale reads, by what it is rather than what it's called."""

import json
import os
from typing import Dict, List, Tuple

from dernvale.threat_intel import iran_apt_loader, mitresaw, stix
from dernvale.threat_intel.schema import COLUMNS, Indicator, read_csv, unique
from dernvale.threat_intel.validity import Validity


class UnsupportedIntel(ValueError):
    """A file none of the loaders reads."""


def load(path: str) -> List[Indicator]:
    """Indicators from one file (load_with_validity for what's below)."""
    return load_with_validity(path)[0]


def load_with_validity(path: str) -> Tuple[List[Indicator], Dict[tuple, Validity]]:
    """Indicators from one file, and the validity a STIX bundle gives some of them (by key):
    - XLSX: the Iran APT workbook (the ten columns, on any sheet)
    - CSV: Dernvale's own export (the ten columns) or MITRESaw's mitre_procedures.csv
    - JSON: a STIX 2.1 bundle
    - text: one indicator per line, '#' for comments (the --iocsFile watchlist format)
    """
    name = os.path.basename(path)
    lower = name.lower()
    if lower.endswith((".xlsx", ".xlsm")):
        return iran_apt_loader.load_workbook(path), {}
    if lower.endswith(".csv"):
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            header = fh.readline()
        if all(column in header for column in COLUMNS):
            return read_csv(path), {}
        if "group_sw_name" in header and "evidence" in header:
            return mitresaw.load_procedures(path), {}
        raise UnsupportedIntel(f"{name}: a CSV without the ten threat intelligence columns or MITRESaw's")
    if lower.endswith(".json"):
        with open(path, encoding="utf-8", errors="replace") as fh:
            try:
                data = json.load(fh)
            except ValueError as exc:
                raise UnsupportedIntel(f"{name}: not JSON ({exc})") from exc
        if isinstance(data, dict) and ("objects" in data or data.get("type") == "bundle"):
            return stix.parse_stix_bundle_with_validity(data)
        if isinstance(data, list) and data and all(isinstance(o, dict) and "type" in o for o in data):
            return stix.parse_stix_bundle_with_validity(data)
        raise UnsupportedIntel(f"{name}: JSON that's not a STIX bundle")
    if lower.endswith((".txt", ".ioc", ".iocs", ".list")) or "." not in name:
        with open(path, encoding="utf-8", errors="replace") as fh:
            values = [line.strip() for line in fh if line.strip() and not line.lstrip().startswith("#")]
        return unique(Indicator(evidential_element=v, source_type=f"Watchlist: {name}") for v in values), {}
    raise UnsupportedIntel(f"{name}: not XLSX, CSV, JSON or a text watchlist")


def load_all(paths: List[str]) -> List[Indicator]:
    return unique(i for path in paths for i in load(path))
