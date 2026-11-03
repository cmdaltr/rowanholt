"""MITRESaw's procedures (mitre_procedures.csv, from `MITRESaw.py -E`, or Archer's
data/mitre_procedures.csv): every ATT&CK group's and software's procedures with the evidence
named in each, one indicator per piece of evidence.

Ports, CVEs and event IDs are left out: they say what to look for in a SIEM, not what to find in
a case's artefacts. Generic evidence (net, cmd.exe) is kept here and left out at matching time
(threat_intel/index.py), so the rows stay a faithful copy of MITRESaw's.
"""

import csv
import json
from typing import List

from rivendell.threat_intel.schema import Indicator, unique

SOURCE = "MITRESaw"
EVIDENCE_KINDS = {"software": "software", "cmd": "cmd", "filepath": "file", "reg": "reg"}
MAX_FIELD = 1000


class ProceduresError(ValueError):
    """The CSV isn't MITRESaw's procedures."""


def _reference(entity_id: str) -> str:
    if entity_id.startswith("G"):
        return f"https://attack.mitre.org/groups/{entity_id}/"
    if entity_id.startswith("S"):
        return f"https://attack.mitre.org/software/{entity_id}/"
    if entity_id.startswith("C"):
        return f"https://attack.mitre.org/campaigns/{entity_id}/"
    return ""


def load_procedures(path: str) -> List[Indicator]:
    indicators = []
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        if not {"group_sw_name", "technique_id", "evidence"} <= set(reader.fieldnames or []):
            raise ProceduresError("not MITRESaw's procedures: needs group_sw_name, technique_id and evidence columns")
        for row in reader:
            try:
                evidence = json.loads(row.get("evidence") or "{}")
            except ValueError:
                continue
            if not isinstance(evidence, dict):
                continue
            for key, kind in EVIDENCE_KINDS.items():
                for value in evidence.get(key) or []:
                    if not isinstance(value, str) or not value.strip():
                        continue
                    context = f"{kind}"
                    if row.get("detectable_via"):
                        context += f"; detectable via {row['detectable_via']}"
                    indicators.append(Indicator(
                        evidential_element=value.strip(), threat_group=row.get("group_sw_name", ""),
                        procedure_example=(row.get("procedure_example") or "")[:MAX_FIELD],
                        technique_id=row.get("technique_id", ""), technique_name=row.get("technique_name", ""),
                        tactic=row.get("tactic", ""), contextual_evidence=context[:MAX_FIELD],
                        reference_url=_reference(row.get("group_sw_id", "")), source_type=SOURCE,
                    ))
    return unique(indicators)
