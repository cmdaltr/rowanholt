"""Online lookups: one IP, domain or file hash at a time, asked of VirusTotal when an analyst presses
the button. Off unless .env sets ROWANHOLT_ONLINE_LOOKUPS=virustotal and VIRUSTOTAL_API_KEY.

The value leaves the building, so: only the backend calls out, only for a value an analyst typed or
picked, never from Elrond or Smith (a smith-mcp token or Smith's agent header is refused), never a private
or reserved address or an internal-looking name, and each lookup is logged with who asked.
"""

import ipaddress
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Dict, Tuple

try:
    from .config import settings
except ImportError:
    from config import settings

logger = logging.getLogger(__name__)

PROVIDERS = ("virustotal",)
VT_API = "https://www.virustotal.com/api/v3"
VT_PATHS = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}
VT_GUI = {"ip": "ip-address", "domain": "domain", "hash": "file"}
TIMEOUT = 15
CACHE_SECONDS = 3600
CACHE_MAX = 1000

HASH = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
# Names that only mean something inside a network, and would tell a third party about it
INTERNAL_SUFFIXES = (".local", ".localdomain", ".lan", ".home", ".internal", ".intranet", ".corp",
                     ".private", ".home.arpa", ".test", ".example", ".invalid", ".localhost", ".arpa")


class LookupRefused(ValueError):
    """A value that isn't sent: not an IP, domain or hash, or one that shouldn't leave."""


class LookupFailed(RuntimeError):
    """The provider couldn't answer; `status` is the HTTP status to give the caller."""

    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


def provider() -> str:
    """The provider lookups go to, or "" when they're off (no provider, or no key for it)."""
    # A comma list: "dns" is Elrond's, for the IOCs it extracts (analysis/iocs.py)
    names = {n.strip() for n in settings.rowanholt_online_lookups.lower().split(",")}
    if "virustotal" in names and settings.virustotal_api_key:
        return "virustotal"
    return ""


def classify(value: str) -> Tuple[str, str]:
    """(kind, normalised value) for a value that may be sent, else LookupRefused."""
    value = value.strip().strip("[]").lower()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    if address is not None:
        if not address.is_global:
            raise LookupRefused("A private, reserved or local address isn't sent outside")
        return "ip", str(address)
    if HASH.match(value):
        return "hash", value
    value = value.rstrip(".")
    if DOMAIN.match(value):
        if value.endswith(INTERNAL_SUFFIXES):
            raise LookupRefused("An internal name isn't sent outside")
        return "domain", value
    raise LookupRefused("Only an IP address, a domain or an MD5, SHA-1 or SHA-256 hash can be looked up")


def _fetch(url: str, headers: Dict[str, str]) -> dict:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # nosec B310: a fixed https URL
        return json.load(response)


fetch: Callable[[str, Dict[str, str]], dict] = _fetch  # tests swap this

_cache: Dict[Tuple[str, str], Tuple[float, dict]] = {}
_cache_lock = threading.Lock()


def _virustotal(kind: str, value: str) -> dict:
    url = f"{VT_API}/{VT_PATHS[kind]}/{urllib.parse.quote(value, safe='')}"
    link = f"https://www.virustotal.com/gui/{VT_GUI[kind]}/{value}"
    try:
        data = fetch(url, {"x-apikey": settings.virustotal_api_key, "accept": "application/json"})
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"found": False, "link": link}
        if exc.code == 429:
            raise LookupFailed("VirusTotal's quota is used up for now: try again later", 429)
        if exc.code in (401, 403):
            raise LookupFailed("VirusTotal refused the API key", 502)
        raise LookupFailed(f"VirusTotal answered {exc.code}")
    except (OSError, ValueError) as exc:  # URLError, timeouts, a body that isn't JSON
        raise LookupFailed(f"Couldn't reach VirusTotal: {exc}")
    attributes = (data.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    when = attributes.get("last_analysis_date")
    return {
        "found": True,
        "link": link,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attributes.get("reputation"),
        "last_analysis": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(when)) if when else None,
        "tags": attributes.get("tags", [])[:20],
    }


def lookup(value: str, who: str) -> dict:
    """What the provider says about one value: cached for an hour, logged with who asked."""
    name = provider()
    if not name:
        raise LookupFailed("Online lookups are off", 404)
    kind, value = classify(value)
    key = (kind, value)
    with _cache_lock:
        hit = _cache.get(key)
        if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
            return {**hit[1], "cached": True}
    logger.info("Online lookup: %s asked %s about %s %s", who, name, kind, value)
    result = {"value": value, "kind": kind, "provider": name, **_virustotal(kind, value)}
    with _cache_lock:
        if len(_cache) >= CACHE_MAX:
            _cache.pop(next(iter(_cache)))
        _cache[key] = (time.monotonic(), result)
    return {**result, "cached": False}


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()

