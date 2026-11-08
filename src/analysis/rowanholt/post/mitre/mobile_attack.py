"""The MITRE ATT&CK Mobile techniques Elrond tags, with their names and tactics.

Mobile techniques share the T-number space with Enterprise without overlapping it, so they're
recorded the same way (each record's envelope techniques, the case's mitre_techniques.txt) and
looked up here when attack_data.py (Enterprise) doesn't know them. Only the techniques a rule in
process/mobile.py can tag are listed: the Mobile matrix isn't loaded whole.

Checked against attack.mitre.org on 8 November 2026.
"""

from typing import Dict, Optional

DOMAIN = "mobile-attack"

MOBILE_TECHNIQUES: Dict[str, Dict] = {
    "T1632": {
        "name": "Subvert Trust Controls",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may undermine security controls that will either warn users of untrusted "
                       "activity or prevent execution of untrusted applications.",
        "platforms": ["Android", "iOS"],
    },
    "T1632.001": {
        "name": "Subvert Trust Controls: Code Signing Policy Modification",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may modify code signing policies to enable execution of applications signed "
                       "with unofficial or unknown keys, for example with malicious configuration profiles.",
        "platforms": ["Android", "iOS"],
        "procedure_examples": ["Windshift has installed malicious MDM profiles on iOS devices as part of "
                               "Operation ROCK.", "XLoader for iOS has been installed via a malicious "
                               "configuration profile."],
    },
    "T1626": {
        "name": "Abuse Elevation Control Mechanism",
        "tactics": ["Privilege Escalation"],
        "description": "Adversaries may circumvent mechanisms designed to control elevated privileges to gain "
                       "higher-level permissions.",
        "platforms": ["Android"],
    },
    "T1626.001": {
        "name": "Abuse Elevation Control Mechanism: Device Administrator Permissions",
        "tactics": ["Privilege Escalation"],
        "description": "Adversaries may abuse Android's device administration API to obtain a higher degree of "
                       "control over the device: resetting its password, wiping it, disabling its cameras or "
                       "making an app harder to uninstall.",
        "platforms": ["Android"],
    },
}


def get_mobile_technique(technique_id: str) -> Optional[Dict]:
    """A Mobile technique's metadata (with its domain), or None when it isn't one listed here."""
    data = MOBILE_TECHNIQUES.get(str(technique_id).strip().upper())
    if data is None:
        return None
    return {"groups": [], "software": [], "procedure_examples": [], **data, "domain": DOMAIN}


def is_mobile_technique(technique_id: str) -> bool:
    """Whether a technique ID is one of the Mobile techniques listed here."""
    return str(technique_id).strip().upper() in MOBILE_TECHNIQUES
