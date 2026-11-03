#!/usr/bin/env python3 -tt
"""
Navigation Menu Generator for Elrond Splunk App

Generates the navigation menu structure including all MITRE ATT&CK techniques
organized by tactic. Updated for MITRE ATT&CK v18.1.
"""


# All MITRE ATT&CK techniques organized by tactic (v18.1)
TECHNIQUES_BY_TACTIC = {
    "Reconnaissance": [
        "t1595", "t1592", "t1589", "t1590", "t1591", "t1598", "t1597", "t1596", "t1593", "t1594"
    ],
    "Resource Development": [
        "t1583", "t1586", "t1584", "t1587", "t1585", "t1588", "t1608", "t1650"
    ],
    "Initial Access": [
        "t1659", "t1189", "t1190", "t1133", "t1200", "t1566", "t1091", "t1195", "t1199", "t1078"
    ],
    "Execution": [
        "t1651", "t1059", "t1609", "t1610", "t1203", "t1559", "t1106", "t1053", "t1129", "t1072", "t1569", "t1204", "t1047"
    ],
    "Persistence": [
        "t1098", "t1197", "t1547", "t1037", "t1176", "t1554", "t1136", "t1543", "t1546", "t1133",
        "t1574", "t1525", "t1556", "t1137", "t1653", "t1542", "t1053", "t1505", "t1205", "t1078"
    ],
    "Privilege Escalation": [
        "t1548", "t1134", "t1547", "t1037", "t1543", "t1484", "t1611", "t1546", "t1068", "t1574", "t1055", "t1053", "t1078"
    ],
    "Defense Evasion": [
        "t1548", "t1134", "t1197", "t1612", "t1622", "t1140", "t1610", "t1006", "t1480", "t1211",
        "t1222", "t1484", "t1564", "t1574", "t1562", "t1656", "t1070", "t1202", "t1036", "t1556",
        "t1578", "t1112", "t1601", "t1599", "t1027", "t1647", "t1542", "t1055", "t1620", "t1207",
        "t1014", "t1218", "t1216", "t1553", "t1221", "t1205", "t1127", "t1535", "t1550", "t1078",
        "t1497", "t1600", "t1220"
    ],
    "Credential Access": [
        "t1557", "t1110", "t1555", "t1212", "t1187", "t1606", "t1056", "t1556", "t1040", "t1003",
        "t1528", "t1649", "t1539", "t1111", "t1621", "t1552"
    ],
    "Discovery": [
        "t1087", "t1010", "t1217", "t1580", "t1538", "t1526", "t1613", "t1622", "t1652", "t1482",
        "t1083", "t1615", "t1654", "t1046", "t1135", "t1040", "t1201", "t1120", "t1069", "t1057",
        "t1012", "t1018", "t1518", "t1082", "t1614", "t1016", "t1049", "t1033", "t1007", "t1124", "t1497"
    ],
    "Lateral Movement": [
        "t1210", "t1534", "t1570", "t1563", "t1021", "t1091", "t1072", "t1080", "t1550"
    ],
    "Collection": [
        "t1560", "t1123", "t1119", "t1115", "t1530", "t1602", "t1213", "t1005", "t1039", "t1025",
        "t1074", "t1114", "t1056", "t1185", "t1557", "t1113", "t1125"
    ],
    "Command and Control": [
        "t1071", "t1092", "t1659", "t1132", "t1001", "t1568", "t1573", "t1008", "t1105", "t1104",
        "t1095", "t1571", "t1572", "t1090", "t1219", "t1205", "t1102"
    ],
    "Exfiltration": [
        "t1020", "t1030", "t1048", "t1041", "t1011", "t1052", "t1567", "t1029", "t1537"
    ],
    "Impact": [
        "t1531", "t1485", "t1486", "t1565", "t1491", "t1561", "t1499", "t1657", "t1495", "t1490",
        "t1498", "t1496", "t1489", "t1529"
    ]
}


def create_nav_menu(defaultnav):
    """Create the ATT&CK navigation menu with all techniques organized by tactic."""

    # Techniques collection containing tactics with techniques under each
    defaultnav.write('<collection label="Techniques">\n\t\t')

    # Each tactic as a sub-collection with techniques under it
    for tactic, techniques in TECHNIQUES_BY_TACTIC.items():
        # HTML escape the ampersand in "Command and Control"
        tactic_label = tactic.replace("&", "&amp;")
        defaultnav.write(f'<collection label="{tactic_label}">\n\t\t\t')

        for technique_id in techniques:
            defaultnav.write(f'<view name="{technique_id}" />\n\t\t\t')

        defaultnav.write('</collection>\n\t\t')

    defaultnav.write('</collection>\n\t')


def get_all_technique_ids():
    """Return a flat list of all technique IDs for XML generation."""
    all_techniques = []
    for techniques in TECHNIQUES_BY_TACTIC.values():
        all_techniques.extend(techniques)
    # Remove duplicates while preserving order
    seen = set()
    unique_techniques = []
    for t in all_techniques:
        if t not in seen:
            seen.add(t)
            unique_techniques.append(t)
    return unique_techniques
