"""Device management on phones: iOS configuration profiles and MDM enrolment, Android device
administrators and device/profile owners. iLEAPP and ALEAPP don't report either, and both are
how a phone is taken over without an exploit, so Elrond reads them itself.

  iOS      .../Library/ConfigurationProfiles/profile-*.stub   an installed profile (plist, or the
                                                               signed .mobileconfig holding one)
           .../Library/ConfigurationProfiles/MDM.plist        the MDM server it's enrolled in
           .../Library/ConfigurationProfiles/CloudConfigurationDetails.plist   automated (DEP) enrolment
  Android  data/system/device_policies.xml (and users/<n>/)   active device administrators
           data/system/device_owner_2.xml                     device owner and profile owners

Techniques (MITRE ATT&CK Mobile), only where the setting itself is the technique's mechanism:
an MDM enrolment, or a profile that enrols in MDM or installs a root certificate, is
**T1632.001** (Code Signing Policy Modification: "malicious configuration profiles"); an Android
device administrator, device owner or profile owner is **T1626.001** (Device Administrator
Permissions). A company's own MDM looks the same: the Flag says what it is, the analyst decides.

Stdlib only.
"""

import logging
import plistlib
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

PROFILE_HEADER = ["Source", "Kind", "Name", "Identifier", "Organisation", "PayloadTypes", "Server", "Installed", "Flag",
                  "Technique"]
ADMIN_HEADER = ["Source", "Kind", "Package", "Component", "User", "Policies", "Flag", "Technique"]

IOS_PROFILE_DIR = "/Library/ConfigurationProfiles/"
MDM_PAYLOAD = "com.apple.mdm"
CERTIFICATE_PAYLOADS = ("com.apple.security.root",)
REDIRECTING_PAYLOADS = ("com.apple.vpn.managed", "com.apple.proxy.http.global", "com.apple.dnsSettings.managed")
CODE_SIGNING = "T1632.001"
DEVICE_ADMIN = "T1626.001"
ABX_MAGIC = b"ABX\x00"


def is_ios_config_file(path: str) -> bool:
    """Whether a path in an iOS extraction or backup is one this module reads."""
    path = "/" + path.replace("\\", "/").lstrip("/")
    if IOS_PROFILE_DIR not in path:
        return False
    name = path.rsplit("/", 1)[-1]
    return bool(re.match(r"^profile-.+\.stub$", name)) or name in ("MDM.plist", "CloudConfigurationDetails.plist")


def is_android_config_file(path: str) -> bool:
    """Whether a path in an Android extraction is one this module reads."""
    path = "/" + path.replace("\\", "/").lstrip("/")
    return bool(re.search(r"/data/system/(?:users/\d+/)?device_policies\.xml$", path)) or \
        path.endswith("/data/system/device_owner_2.xml")


def _plist(data: bytes) -> Dict:
    """A plist, or the XML plist inside a signed (CMS) profile; {} when there's none."""
    for candidate in (data, _embedded_plist(data)):
        if not candidate:
            continue
        try:
            value = plistlib.loads(candidate)
        except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError):
            continue
        if isinstance(value, dict):
            return value
    return {}


def _embedded_plist(data: bytes) -> Optional[bytes]:
    start, end = data.find(b"<?xml"), data.rfind(b"</plist>")
    return data[start:end + len(b"</plist>")] if 0 <= start < end else None


def _time(value: object, fallback: str = "") -> str:
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return fallback


def ios_config_rows(path: str, data: bytes, modified: str = "") -> List[Dict]:
    """Rows for one iOS configuration-profile file (path as it was on the phone)."""
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    plist = _plist(data)
    if not plist:
        logger.warning("%s isn't a readable plist; skipped", path)
        return []
    if name == "MDM.plist":
        server = str(plist.get("ServerURL") or "")
        return [{"Source": path, "Kind": "MDM enrolment", "Name": str(plist.get("ManagingProfileIdentifier") or ""),
                 "Identifier": str(plist.get("Topic") or ""), "Organisation": "",
                 "PayloadTypes": MDM_PAYLOAD, "Server": server, "Installed": modified,
                 "Flag": f"enrolled in MDM ({server or 'server not recorded'})", "Technique": CODE_SIGNING}]
    if name == "CloudConfigurationDetails.plist":
        flags = ["automated (DEP) enrolment"]
        if plist.get("IsSupervised"):
            flags.append("supervised")
        if plist.get("IsMDMUnremovable"):
            flags.append("MDM can't be removed")
        return [{"Source": path, "Kind": "cloud configuration", "Name": str(plist.get("OrganizationName") or ""),
                 "Identifier": "", "Organisation": str(plist.get("OrganizationName") or ""), "PayloadTypes": "",
                 "Server": str(plist.get("ConfigurationURL") or ""), "Installed": modified,
                 "Flag": "; ".join(flags), "Technique": ""}]
    content = plist.get("PayloadContent")
    types = sorted({str(p.get("PayloadType")) for p in content if isinstance(p, dict) and p.get("PayloadType")}) \
        if isinstance(content, list) else []
    flags, technique, server = [], "", ""
    if MDM_PAYLOAD in types:
        flags.append("enrols in MDM")
        technique = CODE_SIGNING
        server = next((str(p.get("ServerURL") or "") for p in content
                       if isinstance(p, dict) and p.get("PayloadType") == MDM_PAYLOAD), "")
    if any(t in types for t in CERTIFICATE_PAYLOADS):
        flags.append("installs a root certificate")
        technique = CODE_SIGNING
    if any(t in types for t in REDIRECTING_PAYLOADS):
        flags.append("routes traffic (VPN, proxy or DNS)")
    return [{"Source": path, "Kind": "configuration profile", "Name": str(plist.get("PayloadDisplayName") or ""),
             "Identifier": str(plist.get("PayloadIdentifier") or ""),
             "Organisation": str(plist.get("PayloadOrganization") or ""), "PayloadTypes": "; ".join(types),
             "Server": server, "Installed": _time(plist.get("InstallDate"), modified),
             "Flag": "; ".join(flags), "Technique": technique}]


def _component_package(component: str) -> str:
    return component.split("/", 1)[0] if component else ""


def android_config_rows(path: str, data: bytes) -> List[Dict]:
    """Rows for one Android device-policy file (path as it was on the phone)."""
    if data.startswith(ABX_MAGIC):
        logger.warning("%s is Android binary XML (ABX), which Elrond doesn't read; skipped", path)
        return []
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        logger.warning("%s isn't readable XML (%s); skipped", path, e)
        return []
    user = (re.search(r"/users/(\d+)/", path) or [None, "0"])[1]
    rows = []
    if path.endswith("device_policies.xml"):
        for admin in root.iter("admin"):
            component = admin.get("name") or ""
            policies = sorted({child.tag for child in admin if child.tag != "policies"})
            rows.append({"Source": path, "Kind": "device administrator", "Package": _component_package(component),
                         "Component": component, "User": user, "Policies": "; ".join(policies),
                         "Flag": "active device administrator", "Technique": DEVICE_ADMIN})
        return rows
    for tag, kind in (("device-owner", "device owner"), ("profile-owner", "profile owner")):
        for owner in root.iter(tag):
            component = owner.get("component") or ""
            rows.append({"Source": path, "Kind": kind, "Package": owner.get("package") or _component_package(component),
                         "Component": component, "User": owner.get("userId") or ("0" if tag == "device-owner" else ""),
                         "Policies": "", "Flag": f"{kind}: the device is managed by this app (MDM or DPC)",
                         "Technique": DEVICE_ADMIN})
    return rows
