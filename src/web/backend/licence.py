"""Which edition Rowanholt runs, from a licence signed with Rowanholt's private key.

    Free       the whole product, reports in Rowanholt's own style, no webhooks. Local mode (one
               analyst, no sign-in) is the Free edition and needs no licence; a team server allows
               up to FREE_SEATS accounts that can sign in
    Pro        the licence's seats, `report-branding` (one brand for the installation's reports) and
               `automation` (signed webhooks)
    Services   Pro, plus `brand-library` (a brand per client, chosen for each case) and the right to
               run Rowanholt for clients as a managed service, which the Elastic License 2.0 otherwise
               forbids (COMMERCIAL-LICENSE.md)

A solo analyst in local mode can install a Pro or Services licence for branding and webhooks; seats
only ever apply to a team server.

This follows the licence format shared by ostraka, Shikari and Rowanholt (docs/LICENSING_MODEL.md).
A licence is one line, `rowanholt-licence-1.<payload>.<signature>`: the payload is base64url of
canonical JSON (sorted keys, compact), and the signature is Ed25519 over the ASCII of everything
before the last dot, prefix included, so a licence for another product or format version can't be
passed off as this one. Only public keys ship, so a licence is checked offline and can't be forged
or edited. Each product has its own key; the private half stays with the licensor
(`scripts/admin/sign_licence.py`). Rotating it means adding the new public half to PUBLIC_KEYS.

What a licence grants is its edition's features (EDITION_FEATURES) plus any it names; "*" grants
every feature. A feature is checked with has() where it's used (when a report is built, when a
webhook is sent), never when it's configured, so a brand or webhook saved under one licence is kept
when the licence changes and only what happens next differs. managed-service is a right in the
terms, not a switch in the code.

Rowanholt keeps users in a JSON file, not a database, so the installed licence lives beside it
(licence.json next to USERS_FILE, or ROWANHOLT_LICENCE), with the admin's acceptance of the
commercial terms (a copy ships in legal/): the version, who and when.

When a licence runs out, its edition carries on for GRACE with a warning, then the server is Free
again. Nobody is deactivated: past the free limit, only adding someone (an account, a first SSO
sign-in, re-enabling) is refused. A case mustn't stall because a renewal was late.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

logger = logging.getLogger(__name__)

PRODUCT = "rowanholt"
FORMAT = f"{PRODUCT}-licence-1"
FREE_SEATS = 4
GRACE = timedelta(days=30)
TERMS = Path(__file__).parent / "legal" / "COMMERCIAL-LICENSE.md"
# Raw Ed25519 public keys, hex
PUBLIC_KEYS: Tuple[str, ...] = ("4a048df1b8382979b9fad6c665efd29c21df4528c65df35ccd62fa0ae2f47f6d",)


class Edition(str, Enum):
    FREE = "free"
    PRO = "pro"
    SERVICES = "services"


# Feature ids: short, kebab-case, stable. docs/LICENSING_MODEL.md says what each gates.
REPORT_BRANDING = "report-branding"  # one brand for the installation's case reports
BRAND_LIBRARY = "brand-library"  # a brand per client, chosen for each case
AUTOMATION = "automation"  # signed webhooks
MANAGED_SERVICE = "managed-service"  # a right in COMMERCIAL-LICENSE.md, not a switch in the code
FEATURES = (REPORT_BRANDING, BRAND_LIBRARY, AUTOMATION, MANAGED_SERVICE)
WILDCARD = "*"
EDITION_FEATURES: Dict[Edition, frozenset] = {
    Edition.FREE: frozenset(),
    Edition.PRO: frozenset({REPORT_BRANDING, AUTOMATION}),
    Edition.SERVICES: frozenset({REPORT_BRANDING, AUTOMATION, BRAND_LIBRARY, MANAGED_SERVICE}),
}


class LicenceProblem(ValueError):
    """A licence that can't be used, with a reason an admin can act on."""


@dataclass(frozen=True)
class Licence:
    licence_id: str
    licensee: str
    edition: Edition
    seats: Optional[int]  # None: unlimited
    issued: date
    expires: Optional[date]  # None: perpetual
    email: str = ""
    features: Tuple[str, ...] = ()  # beyond the edition's own
    not_before: Optional[date] = None
    product: str = PRODUCT


@dataclass(frozen=True)
class Standing:
    """What the server may do now."""

    edition: Edition
    seats: Optional[int]  # None: unlimited
    state: str  # "free" (no licence), "pending" (before not_before), "active", "grace", "lapsed"
    licence: Optional[Licence] = None
    features: frozenset = field(default_factory=frozenset)

    def has(self, feature: str) -> bool:
        return feature in self.features or WILDCARD in self.features


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def payload_of(licence: Licence) -> dict:
    """The signed fields. Optional ones are left out rather than sent empty."""
    out: dict = {
        "licence_id": licence.licence_id,
        "product": licence.product,
        "licensee": licence.licensee,
        "edition": licence.edition.value,
        "seats": licence.seats,
        "issued": licence.issued.isoformat(),
        "expires": licence.expires.isoformat() if licence.expires else None,
    }
    if licence.email:
        out["email"] = licence.email
    if licence.features:
        out["features"] = sorted(licence.features)
    if licence.not_before:
        out["not_before"] = licence.not_before.isoformat()
    return out


def sign(private_key: Ed25519PrivateKey, licence: Licence) -> str:
    """The licence as a line to send to the customer."""
    canonical = json.dumps(payload_of(licence), sort_keys=True, separators=(",", ":"))
    head = f"{licence.product}-licence-1.{_b64(canonical.encode())}"
    return f"{head}.{_b64(private_key.sign(head.encode()))}"


def _day(value: Optional[str]) -> Optional[date]:
    return date.fromisoformat(value) if value else None


def parse(text: str) -> Licence:
    """A licence, once its signature checks out against one of PUBLIC_KEYS. Raises LicenceProblem."""
    parts = text.strip().split(".")
    if len(parts) != 3 or not parts[0].endswith("-licence-1"):
        raise LicenceProblem("That isn't a Rowanholt licence. Paste the whole line you were sent.")
    if parts[0] != FORMAT:
        product = parts[0][: -len("-licence-1")]
        raise LicenceProblem(f"That's a licence for {product}, not Rowanholt.")
    head = f"{parts[0]}.{parts[1]}"
    try:
        signature = _unb64(parts[2])
        payload = json.loads(_unb64(parts[1]))
    except (binascii.Error, ValueError) as exc:
        raise LicenceProblem("That licence is damaged. Paste the whole line you were sent.") from exc
    for key in PUBLIC_KEYS:
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(signature, head.encode())
            break
        except InvalidSignature:
            continue
    else:
        raise LicenceProblem("That licence wasn't issued for Rowanholt, or has been altered.")
    try:
        licence = Licence(
            licence_id=str(payload["licence_id"]),
            product=str(payload["product"]),
            licensee=str(payload["licensee"]),
            email=str(payload.get("email", "")),
            edition=Edition(payload["edition"]),
            seats=None if payload["seats"] is None else int(payload["seats"]),
            features=tuple(str(f) for f in payload.get("features", [])),
            issued=date.fromisoformat(payload["issued"]),
            not_before=_day(payload.get("not_before")),
            expires=_day(payload["expires"]),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise LicenceProblem(
            "That licence is from a newer version of Rowanholt. Update, then try again."
        ) from exc
    if licence.product != PRODUCT:
        raise LicenceProblem(f"That's a licence for {licence.product}, not Rowanholt.")
    if licence.edition is Edition.FREE or (licence.seats is not None and licence.seats < 1):
        raise LicenceProblem("That licence grants nothing beyond the free edition.")
    return licence


def _midnight(day: date) -> datetime:
    return datetime.combine(day, datetime.min.time(), timezone.utc)


def standing(licence: Optional[Licence], now: Optional[datetime] = None) -> Standing:
    """The edition a licence (or none) gives at `now`. A licence runs from the start of its
    not_before day to the end of its expiry day."""
    free = Standing(Edition.FREE, FREE_SEATS, "free")
    if licence is None:
        return free
    now = now or datetime.now(timezone.utc)
    if licence.not_before and now < _midnight(licence.not_before):
        return Standing(Edition.FREE, FREE_SEATS, "pending", licence)
    granted = EDITION_FEATURES[licence.edition] | frozenset(licence.features)
    paid = Standing(licence.edition, licence.seats, "active", licence, granted)
    if licence.expires is None:
        return paid
    ends = _midnight(licence.expires + timedelta(days=1))
    if now < ends:
        return paid
    if now < ends + GRACE:
        return Standing(licence.edition, licence.seats, "grace", licence, granted)
    return Standing(Edition.FREE, FREE_SEATS, "lapsed", licence)


def grace_ends(licence: Licence) -> Optional[date]:
    return licence.expires + GRACE if licence.expires else None


# ── The installed licence: one JSON file beside users.json ───────────────────


def install_path() -> Path:
    """Read at each call, so a test (or ROWANHOLT_LICENCE set after import) takes effect."""
    explicit = os.environ.get("ROWANHOLT_LICENCE")
    if explicit:
        return Path(explicit)
    users = os.environ.get("USERS_FILE", "/app/data/users.json")
    return Path(users).parent / "licence.json"


# The file is read on most requests that add someone; the mtime keeps that to one read per change
_cache: dict = {"path": None, "mtime": None, "record": None}


def installed() -> Optional[dict]:
    """The installed record: {"licence", "terms_version", "accepted_by", "accepted_by_name",
    "accepted_at"}, or None. A damaged file counts as none, logged, rather than stopping the server."""
    path = install_path()
    try:
        mtime = path.stat().st_mtime_ns
    except FileNotFoundError:
        return None
    if _cache["path"] == path and _cache["mtime"] == mtime:
        return _cache["record"]
    try:
        record = json.loads(path.read_text())
        if not isinstance(record, dict) or not isinstance(record.get("licence"), str):
            raise ValueError("no licence line")
    except (OSError, ValueError) as exc:
        logger.error("Ignoring the installed licence at %s: %s", path, exc)
        record = None
    _cache.update(path=path, mtime=mtime, record=record)
    return record


def current(now: Optional[datetime] = None) -> Standing:
    """The server's standing from its installed licence. A stored licence that no longer verifies
    (say, after a key was withdrawn) counts as none."""
    record = installed()
    if record is None:
        return standing(None)
    try:
        return standing(parse(record["licence"]), now)
    except LicenceProblem:
        return standing(None)


@lru_cache(maxsize=None)
def terms() -> Tuple[str, str]:
    """The commercial terms an admin accepts: (version, text). The version is the one the text states."""
    text = TERMS.read_text()
    found = re.search(r"\*\*Version (\S+)\*\*", text)
    if not found:
        raise RuntimeError(f"{TERMS} doesn't state its version")
    return found[1], text


def record_install(text: str, *, accepted_by: Optional[str], accepted_by_name: str) -> dict:
    """Put a licence line (already parsed) in place of the current one, with who accepted which
    version of the terms. Written readable by the backend's user only, like users.json."""
    record = {
        "licence": text.strip(),
        "terms_version": terms()[0],
        "accepted_by": accepted_by,  # the account's id, or None from the server's command line
        "accepted_by_name": accepted_by_name,
        "accepted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    path = install_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(record, f, indent=2)
    os.replace(tmp, path)
    return record


def remove() -> bool:
    """Back to the free edition. True if there was a licence to remove."""
    try:
        install_path().unlink()
        return True
    except FileNotFoundError:
        return False


# ── Seats ────────────────────────────────────────────────────────────────────


def places_held(users: dict) -> int:
    """Accounts that can sign in. Rowanholt has no invitations to count."""
    return sum(1 for u in users.values() if u.get("is_active", True))


def seat_refusal(users: dict, server_mode: bool, now: Optional[datetime] = None) -> Optional[str]:
    """Why one more account can't be added, or None. Asked only when someone is added, never of
    the people already in, and never in local mode (one analyst, no licence)."""
    if not server_mode:
        return None
    st = current(now)
    if st.seats is None:
        return None
    held = places_held(users)
    if held < st.seats:
        return None
    edition = "the free edition" if st.edition is Edition.FREE else f"this {st.edition.value} licence"
    return (
        f"All {st.seats} places on {edition} are taken ({held} accounts can sign in). "
        "Disable an account to make room, or install a licence with more seats."
    )


# ── The security log ─────────────────────────────────────────────────────────

_storage = None


def configure(storage) -> None:
    """Give the licence the backend's JobStorage, for the audit log (main.py does)."""
    global _storage
    _storage = storage


def audit(action: str, actor: Optional[dict], ip: Optional[str] = None, resource_type: str = "licence",
          resource_id: Optional[str] = None, **details) -> None:
    """An install or removal (or a brand's change: branding.py) into the audit_logs table. The file
    is already written: a database that's down is logged loudly rather than undoing it."""
    if _storage is None:
        logger.warning("Licence %s not audited (no storage configured): %s", action, details)
        return
    try:
        from .storage import AuditLogModel
    except ImportError:
        from storage import AuditLogModel
    actor = actor or {}
    session = _storage.Session()
    try:
        session.add(AuditLogModel(
            id=str(uuid.uuid4()),
            user_id=actor.get("id"),
            username=actor.get("username") or "server",
            action=action,
            resource_type=resource_type,
            resource_id=resource_id or details.get("licence"),
            details=details,
            ip_address=ip,
            timestamp=datetime.utcnow(),
        ))
        session.commit()
    except Exception:  # noqa: BLE001 - the audit write must not hide the install's outcome
        session.rollback()
        logger.exception("Licence %s not audited: %s", action, details)
    finally:
        session.close()


def new_id() -> str:
    return f"lic_{uuid.uuid4().hex[:12]}"
