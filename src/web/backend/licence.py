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

The licence line, `rowanholt-licence-1.<payload>.<signature>`, its offline Ed25519 check, the
editions, their features and the 30 days' grace are the suite's shared format, read by
samarkand.licence (docs/LICENSING_MODEL.md). What's Rowanholt's own is here: its id and name, its
public keys (PUBLIC_KEYS; rotating the key means adding the new public half), its four free seats,
where the installed licence is kept and the seat rule. The private half stays with the licensor
(`scripts/admin/sign_licence.py`).

A feature is checked with has() where it's used (when a report is built, when a webhook is sent),
never when it's configured, so a brand or webhook saved under one licence is kept when the licence
changes and only what happens next differs. managed-service is a right in the terms, not a switch in
the code.

Rowanholt keeps users in a JSON file, not a database, so the installed licence lives beside it
(licence.json next to USERS_FILE, or ROWANHOLT_LICENCE), with the admin's acceptance of the
commercial terms (a copy ships in legal/): the version, who and when.

When a licence runs out, its edition carries on for GRACE with a warning, then the server is Free
again. Nobody is deactivated: past the free limit, only adding someone (an account, a first SSO
sign-in, re-enabling) is refused. A case mustn't stall because a renewal was late.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Tuple

from samarkand import licence as shared
from samarkand.licence import (  # noqa: F401 (re-exported: callers use licence.<name>)
    AUTOMATION,
    BRAND_LIBRARY,
    EDITION_FEATURES,
    FEATURES,
    GRACE,
    MANAGED_SERVICE,
    REPORT_BRANDING,
    WILDCARD,
    Edition,
    LicenceProblem,
    Standing,
    check_installable,
    grace_ends,
    head_of,
    line_of,
    payload_of,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

logger = logging.getLogger(__name__)

PRODUCT = "rowanholt"
NAME = "Rowanholt"
FORMAT = shared.format_of(PRODUCT)
FREE_SEATS = 4
TERMS = Path(__file__).parent / "legal" / "COMMERCIAL-LICENSE.md"
# Raw Ed25519 public keys, hex
PUBLIC_KEYS: Tuple[str, ...] = ("4a048df1b8382979b9fad6c665efd29c21df4528c65df35ccd62fa0ae2f47f6d",)


@dataclass(frozen=True)
class Licence(shared.Licence):
    """samarkand's licence, for Rowanholt unless it names another product."""

    product: str = PRODUCT


@lru_cache(maxsize=8)
def _rules_for(keys: Tuple[str, ...], free_seats: int) -> shared.Rules:
    return shared.Rules(PRODUCT, keys, free_seats, NAME)


def rules() -> shared.Rules:
    """Rowanholt's licence rules, bound to PUBLIC_KEYS and FREE_SEATS as they are at the call (a
    test trusts its own key by swapping PUBLIC_KEYS)."""
    return _rules_for(tuple(PUBLIC_KEYS), FREE_SEATS)


def sign(private_key: "Ed25519PrivateKey", licence: shared.Licence) -> str:
    """The licence as a line to send to the customer (the licensor's script and the tests sign)."""
    head = head_of(licence)
    return line_of(head, private_key.sign(head.encode()))


def parse(text: str) -> Licence:
    """A licence, once its signature checks out against one of PUBLIC_KEYS. Raises LicenceProblem."""
    read = rules().parse(text)
    return Licence(**{f.name: getattr(read, f.name) for f in fields(read)})


def standing(licence: Optional[shared.Licence], now: Optional[datetime] = None) -> Standing:
    """The edition a licence (or none) gives at `now`. A licence runs from the start of its
    not_before day to the end of its expiry day."""
    return rules().standing(licence, now)


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
