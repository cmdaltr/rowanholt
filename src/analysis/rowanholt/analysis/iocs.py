#!/usr/bin/env python3 -tt
import ipaddress
import os
import re
import subprocess
from datetime import datetime
from functools import lru_cache
from urllib.parse import urlsplit

from rowanholt.audit import write_audit_log_entry


# How reports defang an indicator (evil[.]com, hxxps://, 10[:]...)
DEFANG = [("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."), ("[:]", ":"),
          ("hxxp", "http"), ("fxp", "ftp")]


def refang(ioc):
    """An indicator as it would appear in evidence: lowercase, refanged, and a URL's host
    (extraction finds domains and addresses, never whole URLs)."""
    ioc = ioc.strip().lower()
    for defanged, plain in DEFANG:
        ioc = ioc.replace(defanged, plain)
    if "://" in ioc:
        ioc = urlsplit(ioc).hostname or ioc
    return ioc.rstrip(".")


def watchlist_match(value, watchlist):
    """The value, or for a domain any parent of it (watchlisted evil.com matches cdn.evil.com)."""
    value = value.lower()
    if value in watchlist:
        return True
    labels = value.split(".")
    return any(".".join(labels[i:]) in watchlist for i in range(1, len(labels) - 1))


def load_ioc_watchlist(watchlist_file):
    """Load IOCs from a watchlist file (one IOC per line), refanged and lowercase."""
    from utils.file_limits import safe_open

    watchlist = set()
    if watchlist_file and os.path.exists(watchlist_file):
        try:
            with safe_open(watchlist_file, "r") as f:
                for line in f:
                    # Skip empty lines and comments
                    if line.strip() and not line.strip().startswith("#"):
                        watchlist.add(refang(line))
            if watchlist:
                print(f"      Loaded {len(watchlist)} IOCs from watchlist: {watchlist_file}")
        except Exception as e:
            print(f"      WARNING: Could not load IOC watchlist: {e}")
    return watchlist


HERE = os.path.dirname(__file__)

# Reserved and internal-use suffixes seen in real intrusions and in the lab
# (RFC 2606/6761, common AD and home-network suffixes), on top of IANA's list.
EXTRA_TLDS = {"test", "local", "internal", "lan", "corp", "home", "onion", "localdomain", "intranet"}
# TLDs that are also everyday file extensions: a bare "name.ext" ending in one of
# these is treated as a file name unless it's part of a URL.
FILE_EXTENSION_TLDS = {"sh", "py", "pl", "ps", "rs", "so", "js", "ts", "rb", "cs", "cc", "md", "pm", "mk", "am", "zip", "mov", "log", "app", "cat"}
# First labels of reverse-DNS identifiers (com.apple.foo, org.mozilla.firefox)
REVERSE_DNS_PREFIXES = {"com", "org", "net", "edu", "gov", "io", "de", "uk", "fr", "jp", "us"}
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
UNIQUE_LOCAL = ipaddress.ip_network("fc00::/7")
# Longer TLDs seen in phishing and C2; other long TLDs (.data, .software, .apple)
# mostly turn up as the last word of dotted identifiers, so need a URL to count
ABUSED_LONG_TLDS = {"info", "online", "site", "shop", "live", "cloud", "tech", "space", "website", "club", "life", "world", "today", "digital", "email", "link", "click", "monster", "rest", "quest", "buzz", "mobi", "asia", "work", "host", "network", "support", "group", "finance"}
# Encoded public keys and certificates: base64, but not something to chase
KEY_PREFIXES = ("AAAAB3NzaC1", "AAAAC3NzaC1", "AAAAE2VjZHNh", "MII", "MFkwEwYHKoZIzj0", "MHYwEAYHKoZIzj0")
GUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-")
NOT_AN_IOC_IPV4 = {"0.0.0.0", "255.0.0.0", "255.255.0.0", "255.255.255.0", "255.255.255.255"}

IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
IPV6 = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
HOSTNAME = re.compile(
    r"(?<![\w.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{1,62})(?![\w-]|\.[\w-])"
)
BASE64 = re.compile(r"(?<![\w+/])([A-Za-z0-9+/]{100,}={0,2})(?![\w+/=])")
OBFUSCATED_BASE64 = re.compile(r"([\w+/\-{}%\\'\"]{100,}={0,2})")


@lru_cache(maxsize=1)
def _tlds():
    with open(os.path.join(HERE, "tlds.txt")) as f:
        return {line.strip().lower() for line in f if line.strip() and not line.startswith("#")} | EXTRA_TLDS


@lru_cache(maxsize=1)
def _exclusions():
    with open(os.path.join(HERE, "ioc_exclusions"), errors="ignore") as f:
        return {line.strip().lower() for line in f if line.strip()}


def _public_ipv4(value):
    # Network addresses (x.x.x.0) are almost always version numbers or OIDs
    # (1.0.0.0, 2.5.24.0) rather than hosts
    if value in NOT_AN_IOC_IPV4 or value.endswith(".0") or value.startswith("0."):
        return False
    address = ipaddress.ip_address(value)
    # RFC 1918, loopback and link-local only: ipaddress also calls documentation
    # ranges (198.51.100.0/24...) private, and those turn up in real reporting
    return not (any(address in net for net in RFC1918) or address.is_loopback or address.is_link_local or address.is_multicast)


def _version_number(line, start, end):
    """x.x.x.x inside a package name (Name_2.4.1.100_arm64) or after 'version'."""
    return line[start - 1:start] == "_" or line[end:end + 1] == "_" or "version" in line[max(0, start - 16):start].lower()


def _plausible_hostname(value, line, start):
    labels = value.lower().split(".")
    if labels[-1] not in _tlds() or len(labels) > 6 or labels[0].isdigit() and len(labels) == 2:
        return False
    if any(label != label.lower() and label != label.upper() for label in value.split(".")):
        return False  # CamelCase: .NET and PowerShell identifiers (IntPtr.Zero)
    before = line[max(0, start - 3):start]
    in_url = before.endswith("://") or before.endswith("@")
    tld = labels[-1]
    if not in_url and len(tld) > 3 and tld not in ABUSED_LONG_TLDS and tld not in EXTRA_TLDS:
        return False
    if not in_url and line[start - 1:start] in ("/", "\\"):
        return False  # a file in a path
    if not in_url and len(labels) == 2 and labels[-1] in FILE_EXTENSION_TLDS:
        return False  # update.sh, notes.md
    if len(labels) >= 3 and labels[0] in REVERSE_DNS_PREFIXES:
        return False  # com.apple.bg...
    return True


def _excluded(value):
    """In the exclusions list, or a subdomain of a domain that is."""
    value = value.lower()
    if value in _exclusions():
        return True
    labels = value.split(".")
    return any(".".join(labels[i:]) in _exclusions() for i in range(1, len(labels) - 1))


def _not_encoded_data(value):
    """File or URL paths (several separators, no padding or '+'), GUID paths, and
    public keys or certificates."""
    if value.count("/") >= 3 and ("+" not in value and "=" not in value or re.search(r"/[^/]*[._][^/]*/", value)):
        return True  # base64 never contains '.' or '_'; path segments do
    return bool(GUID.search(value)) or value.startswith(KEY_PREFIXES)


def extract_line_iocs(line):
    """Every IOC on a line, as (value, type) pairs in order of appearance.
    Types match the iocs.csv indicator_type column."""
    found = []
    for m in IPV4.finditer(line):
        if _public_ipv4(m.group(0)) and not _version_number(line, m.start(), m.end()):
            found.append((m.start(), m.group(0), "IPv4 address"))
    for m in IPV6.finditer(line):
        value = m.group(0)
        if len(value) > 7:
            try:
                address = ipaddress.IPv6Address(value)
            except ValueError:
                continue
            # As for IPv4: not loopback, link-local, multicast or unique local (fc00::/7)
            mapped = address.ipv4_mapped
            if not (address.is_loopback or address.is_unspecified or address.is_link_local or address.is_multicast
                    or address in UNIQUE_LOCAL or (mapped is not None and not _public_ipv4(str(mapped)))):
                found.append((m.start(), value, "IPv6 address"))
    for m in HOSTNAME.finditer(line):
        value = m.group(1)
        if not IPV4.fullmatch(value) and _plausible_hostname(value, line, m.start(1)):
            found.append((m.start(1), value, "domain"))
    seen_spans = []
    for m in BASE64.finditer(line):
        if any(c in m.group(1) for c in "+/=") and not _not_encoded_data(m.group(1)):
            found.append((m.start(1), m.group(1), "pure base64 encoded string"))
            seen_spans.append(m.span(1))
    for m in OBFUSCATED_BASE64.finditer(line):
        if any(a <= m.start(1) < b for a, b in seen_spans):
            continue
        value = m.group(1).strip("/+{}\\\"'%")
        if len(value) > 100 and any(c in value for c in "+/=") and not BASE64.fullmatch(value) and not _not_encoded_data(value):
            found.append((m.start(1), value, "obfuscated base64 encoded string"))
    result, seen = [], set()
    for _, value, kind in sorted(found):
        if value.lower() not in seen and not _excluded(value):
            seen.add(value.lower())
            result.append((value, kind))
    return result


def dns_lookups_enabled():
    """Whether Elrond may ask DNS about the IOCs it extracts: ROWANHOLT_ONLINE_LOOKUPS includes "dns".
    Off by default: each lookup tells whoever runs the domain's nameserver that someone is looking."""
    return "dns" in {n.strip() for n in os.environ.get("ROWANHOLT_ONLINE_LOOKUPS", "").lower().split(",")}


@lru_cache(maxsize=4096)
def _resolvable(value):
    """'resolvable' when DNS answers for a domain or IPv4 address, 'N/A' when it doesn't, and
    'not checked' when DNS lookups are off."""
    if not dns_lookups_enabled():
        return "not checked"
    try:
        out = subprocess.run(["host", "-W", "4", value], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    sinkholed = any(p in out for p in ("92.242.130.", "92.242.131.", "92.242.132."))
    answered = any(p in out for p in ("has address", "has IPv6 address", "is an alias for", "mail is handled by", "domain name pointer"))
    return "resolvable" if answered and not sinkholed else "N/A"


def compare_iocs(
    output_directory,
    verbosity,
    img,
    stage,
    vssimage,
    iocfiles,
    lineno,
    previous_state,
    watchlist_file=None,
):
    from utils.file_limits import safe_open

    watchlist = load_ioc_watchlist(watchlist_file)
    host = img.split("::")[0]
    csv_path = output_directory + host + "/analysis/iocs.csv"
    print("      Commencing IOC extraction for '{}'...\n".format(host))
    for index, iocfile in enumerate(iocfiles):
        path = iocfile.split(": ")[0]
        if not os.path.exists(path):
            continue
        current_progress = round(index / len(iocfiles), 1) * 100
        if current_progress != previous_state and str(current_progress).split(".")[0] != "100":
            print(
                "\n\t\033[1;96m------------------------------------------------------------\n\t {}% of IOC extraction completed for '{}'... \n\t------------------------------------------------------------\033[1;m\n".format(
                    str(current_progress).split(".")[0], host
                )
            )
            previous_state = current_progress
        hits = []
        try:
            with safe_open(path, "r") as reading_for_iocs:
                for lineno, line in enumerate(reading_for_iocs, 1):
                    if len(line) > 7 and ("." in line or ":" in line or "=" in line):
                        hits.extend((lineno, value, kind) for value, kind in extract_line_iocs(line))
        except (OSError, UnicodeDecodeError, ValueError):
            continue
        if not hits:
            continue
        filetimes = ",".join(
            str(datetime.fromtimestamp(t(path))) for t in (os.path.getctime, os.path.getatime, os.path.getmtime)
        )
        reported = set()
        with open(csv_path, "a") as ioccsv:
            for lineno, value, kind in hits:
                if kind in ("domain", "IPv4 address"):
                    resolve = _resolvable(value)
                else:
                    resolve = "-"
                ioccsv.write(
                    "{},{},{},{},{},{},{}\n".format(
                        filetimes,
                        path.replace(",", "%2C").strip(),
                        value,
                        kind,
                        lineno,
                        resolve,
                        "YES" if watchlist_match(value, watchlist) else "",
                    )
                )
                if value.lower() not in reported:
                    reported.add(value.lower())
                    entry, prnt = "{},{},{},IOC '{}' ({}) extracted from '{}'\n".format(
                        datetime.now().isoformat(), host, stage, value, kind, path
                    ), " -> {} -> potential IOC '{}' ({}) extracted from '{}' for '{}'".format(
                        datetime.now().isoformat().replace("T", " "), value, kind, path.split("/")[-1], host
                    )
                    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    print("      IOC extraction completed for {}.\n".format(vssimage))
