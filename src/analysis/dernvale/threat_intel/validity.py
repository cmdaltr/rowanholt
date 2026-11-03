"""How long an indicator holds: kept beside the fixed 10-column schema, never in it.

STIX gives an indicator its own valid_until and confidence; every other source gets a default
lifetime by the kind of value it is (90 days for IPs and domains, as Archer uses; none for hashes,
tool names, commands and paths, which don't move to someone else). The backend stores these in
threat_intel_validity (one row per indicator id), and an expired indicator is left out of matching
until a refreshed import or an admin brings it back.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from dernvale.threat_intel.index import classify
from dernvale.threat_intel.schema import Indicator

DEFAULT_LIFETIME: Dict[str, timedelta] = {"ip": timedelta(days=90), "domain": timedelta(days=90)}


@dataclass(frozen=True)
class Validity:
    """valid_until None: no expiry. Times are naive UTC, as the database stores them."""

    valid_until: Optional[datetime] = None
    confidence: Optional[int] = None
    first_seen: Optional[datetime] = None

    def merge(self, other: "Validity") -> "Validity":
        """The same indicator from two STIX objects: the later expiry (none beats any), the higher confidence."""
        until = None if self.valid_until is None or other.valid_until is None else max(self.valid_until, other.valid_until)
        confidences = [c for c in (self.confidence, other.confidence) if c is not None]
        seen = [s for s in (self.first_seen, other.first_seen) if s is not None]
        return Validity(until, max(confidences) if confidences else None, min(seen) if seen else None)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def parse_time(value: object) -> Optional[datetime]:
    """A STIX timestamp (2026-01-01T00:00:00.000Z) or an ISO date as naive UTC; None if it isn't one."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip().replace("Z", "+00:00").replace("z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def default_validity(indicator: Indicator, now: Optional[datetime] = None) -> Validity:
    """The lifetime an indicator without its own gets from now, by the kind of value it is."""
    now = now or utcnow()
    lifetime = DEFAULT_LIFETIME.get(classify(indicator.evidential_element))
    return Validity(valid_until=now + lifetime if lifetime else None, first_seen=now)


def expired(valid_until: Optional[datetime], now: Optional[datetime] = None) -> bool:
    return valid_until is not None and valid_until <= (now or utcnow())
