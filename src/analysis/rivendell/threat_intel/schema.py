"""The threat intelligence indicator: one row of the fixed 10-column schema.

Every source (the Iran APT workbook, STIX bundles, TAXII collections, MITRESaw's
procedures) is loaded into these rows, the web backend stores them in threat_intel_indicators
(Alembic revision 7c41d2e9a0b3), and Elrond matches a case against them. The columns are fixed:
adding one means changing this dataclass, COLUMNS, the table's migration and
tests/unit/test_threat_intel.py together.
"""

import csv
from dataclasses import asdict, dataclass, fields
from typing import Dict, Iterable, List

# Display name (the workbook's header and the CSV's) -> field name
COLUMNS = {
    "Evidential Element": "evidential_element",
    "Threat Group": "threat_group",
    "Procedure Example": "procedure_example",
    "Technique ID": "technique_id",
    "Technique Name": "technique_name",
    "Tactic": "tactic",
    "Contextual Evidence": "contextual_evidence",
    "Reference URL": "reference_url",
    "Navigation Layer URL": "navigation_layer_url",
    "Source Type": "source_type",
}


@dataclass(frozen=True)
class Indicator:
    """One evidential element (an IP, a domain, a hash, a command, a path, a registry key or a
    tool's name) and what it's evidence of: the group, the procedure and the technique."""

    evidential_element: str
    threat_group: str = ""
    procedure_example: str = ""
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    contextual_evidence: str = ""
    reference_url: str = ""
    navigation_layer_url: str = ""
    source_type: str = ""

    def key(self) -> tuple:
        """What makes two rows the same indicator: the element, for the same group and technique
        from the same source. Loaders deduplicate on it, and so does the table's unique index."""
        return (self.evidential_element.lower(), self.threat_group.lower(), self.technique_id.upper(),
                self.source_type.lower())

    def row(self) -> Dict[str, str]:
        """The row under the display names."""
        values = asdict(self)
        return {display: values[name] for display, name in COLUMNS.items()}


FIELD_NAMES = [f.name for f in fields(Indicator)]
assert FIELD_NAMES == list(COLUMNS.values()), "COLUMNS and Indicator must list the same fields in order"


def from_row(row: Dict[str, str]) -> Indicator:
    """An Indicator from a row keyed by display names or by field names."""
    values = {}
    for display, name in COLUMNS.items():
        value = row.get(display, row.get(name, ""))
        values[name] = "" if value is None else str(value).strip()
    return Indicator(**values)


def unique(indicators: Iterable[Indicator]) -> List[Indicator]:
    """Indicators without repeats, in first-seen order, and without empty elements."""
    seen, out = set(), []
    for indicator in indicators:
        if not indicator.evidential_element or indicator.key() in seen:
            continue
        seen.add(indicator.key())
        out.append(indicator)
    return out


def write_csv(path: str, indicators: Iterable[Indicator]) -> int:
    """Indicators as a CSV under the display names: what the backend hands Elrond."""
    rows = [i.row() for i in indicators]
    with open(path, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=list(COLUMNS))
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def read_csv(path: str) -> List[Indicator]:
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        return unique(from_row(row) for row in csv.DictReader(fh))
