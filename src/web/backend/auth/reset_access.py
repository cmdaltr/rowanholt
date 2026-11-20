"""
Reset Access

For someone who has lost their password, their authenticator or their backup codes: a one-time link
(`<public URL>/reset-access#<token>`) to choose a new password and set up a new authenticator. The
same in Ostraka, Rowanholt and Shikari, on a team server and a local stack alike. An admin issues it,
from the server (`rowanholt server users reset-access`) or the API (`POST /api/auth/users/{id}/reset-access`),
or the person asks for one themselves (`POST /api/auth/forgot-password`), which is emailed when SMTP is
set up (mailer.py).

An admin's link ends every session the account has, revokes its API tokens and replaces any earlier
link. A self-service one does neither, since anyone can ask for it: it replaces an earlier self-service
link, never an admin's that's still open. Only the token's SHA-256 is kept, on the user's record
(`access_reset_hash`), with when it expires and who it came from (`access_reset_via`). The token is in
the link's fragment, so it never reaches a server's or proxy's logs.

Opening the link: `start` makes a new TOTP secret, kept on the record (Fernet-encrypted, as
mfa.py keeps a pending one) rather than trusted from the page, and opening it again shows the same
one; `complete` takes the new password and a code from the new authenticator. Only then does anything
change: the password, MFA on with the new secret (whatever ROWANHOLT_REQUIRE_MFA says: a reset always
ends with MFA), ten fresh backup codes in place of the old ones, every session ended and every API
token revoked, and the link used up. Until then the account's old password and authenticator stand,
so a link nobody opens takes nothing away. An expired link says so (410) for a day after it expired,
then reads as never valid.

An invitation (auth/invitations.py) is the same flow ending in a new account, and shares the pieces
here: the token and its hash, the link, the lifetime, the authenticator to set up and MFA turned on
with fresh backup codes.

Callers hold users.locked() from loading the users to saving them.
"""

import hashlib
import hmac
import secrets
import sys
from urllib.parse import urlsplit

try:
    from ..config import settings
    from . import mfa
    from .users import end_sessions, set_password
except ImportError:
    from auth import mfa
    from auth.users import end_sessions, set_password
    from config import settings

RESET_HOURS = 24  # a reset link's lifetime, and an invitation's
KEEP_EXPIRED_SECONDS = 24 * 3600  # how long an expired link still says it has expired (410)
PATH = "/reset-access"
SELF_SERVICE = "self-service"

INVALID = "This link isn't valid or has been used: ask an administrator for a new one"
EXPIRED = "This link has expired: ask an administrator for a new one, or ask for another from Forgot password"
_RESET = "Nobody sets another person's password: give them a reset link instead, "
RESET_INSTEAD = _RESET + "POST /api/auth/users/{id}/reset-access (or rowanholt server users reset-access <user>)"
NO_PUBLIC_URL = ("ROWANHOLT_PUBLIC_URL isn't set, so this link is for this machine: set it in .env to the "
                 "address people open, and the links will use it")


class ResetRefused(ValueError):
    """An account that can't be given a reset link, or a link that can't be used; the message says why,
    `status` is the API's answer (410 for an expired link), and `changed` says the record was cleared
    (pending choices dropped) and wants saving."""

    def __init__(self, message: str, status: int = 400, changed: bool = False):
        super().__init__(message)
        self.status = status
        self.changed = changed


def token_hash(token: str) -> str:
    """What's kept of a link's token: its SHA-256 (256 random bits need no slow hash)."""
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> tuple[str, float]:
    """A link's token, to pass on once, and when it expires (epoch seconds, RESET_HOURS on)."""
    return secrets.token_urlsafe(32), mfa._now() + RESET_HOURS * 60 * 60  # mfa's clock: the tests move it on


def local_origin() -> str:
    """Where the CLI's links point without ROWANHOLT_PUBLIC_URL: this machine's web app."""
    return "https://localhost" if settings.rowanholt_server_mode else "http://localhost:5687"


def request_origin(request) -> str:
    """The address a request came to, for links when ROWANHOLT_PUBLIC_URL isn't set: the browser's
    Origin (a dev server's proxy rewrites Host), else the proxy's X-Forwarded-Host and -Proto (uvicorn's
    --proxy-headers believes them only from the server's proxy), else the request's own."""
    origin = (request.headers.get("Origin") or "").strip()
    parts = urlsplit(origin)
    if parts.scheme in ("http", "https") and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host") or request.url.netloc
    scheme = request.headers.get("X-Forwarded-Proto") or request.url.scheme
    return f"{scheme}://{host}"


def link(path: str, token: str, origin: str | None = None) -> str:
    """The link at the public URL (else `origin`, else this machine), with the token in the fragment."""
    base = settings.rowanholt_public_url or origin or local_origin()
    return f"{base.rstrip('/')}{path}#{token}"


def warn_without_public_url() -> None:
    """Said on stderr each time the CLI prints a link while ROWANHOLT_PUBLIC_URL is unset."""
    if not settings.rowanholt_public_url:
        print(f"Warning: {NO_PUBLIC_URL}.", file=sys.stderr)


def enrolment(secret: str, username: str) -> dict:
    """An authenticator to set up: the secret as text, its otpauth:// URI and QR code."""
    uri = mfa.provisioning_uri(secret, username)
    return {"secret": secret, "otpauth_uri": uri, "qr_svg": mfa.qr_svg_data_uri(uri)}


def turn_on_mfa(record: dict, secret: str, step: int) -> list:
    """MFA on with a confirmed secret and ten new backup codes, returned to be shown once. Off first,
    so enable() makes new codes: a re-enrolment would keep the old ones, which may be what was lost."""
    mfa.disable(record)
    return mfa.enable(record, secret, step)


def _clear(record: dict) -> None:
    for field in ("access_reset_hash", "access_reset_expires", "access_reset_pending_secret", "access_reset_via"):
        record.pop(field, None)


def _revoke_tokens(record: dict, storage) -> int | None:
    """Revoke the account's API tokens: ending sessions (sessions_after) doesn't touch them, and a
    token made by whoever had the account mustn't outlast the reset. None when there's no storage."""
    return storage.revoke_user_tokens(record["id"]) if storage is not None else None


def _refusal(record: dict) -> str | None:
    if not record.get("is_active", True):
        return f"{record['username']} is disabled: enable them first"
    if not mfa.offered_to(record):
        return (f"{record['username']} signs in with single sign-on: there's no password to reset. "
                "Their identity provider handles recovery")
    return None


def _new_link(record: dict, via: str, origin: str | None) -> tuple[str, float]:
    token, expires = new_token()
    _clear(record)  # an earlier link stops working, and its authenticator with it
    record["access_reset_hash"] = token_hash(token)
    record["access_reset_expires"] = expires
    record["access_reset_via"] = via
    return link(PATH, token, origin), expires


def issue(record: dict, actor: dict | None, ip: str | None = None, storage=None, origin: str | None = None,
          via: str = "admin", **details) -> tuple[str, float]:
    """Give `record` a reset link: (the link, to pass on once; when it expires, epoch seconds).
    Ends its sessions now and revokes its API tokens. The caller saves the users."""
    refusal = _refusal(record)
    if refusal:
        raise ResetRefused(refusal)
    link_, expires = _new_link(record, via, origin)
    end_sessions(record)
    revoked = _revoke_tokens(record, storage)
    mfa.audit("access_reset_issued", actor, record, ip, storage=storage, via=via, tokens_revoked=revoked, **details)
    return link_, expires


def open_admin_link(record: dict) -> bool:
    """Whether the record has an admin's (or the CLI's) link that's still open, which a self-service
    request mustn't replace: the admin may be handing it over at this moment."""
    return bool(record.get("access_reset_hash") and record.get("access_reset_via") != SELF_SERVICE
                and float(record.get("access_reset_expires") or 0) >= mfa._now())


def issue_self_service(record: dict, ip: str | None = None, storage=None) -> str | None:
    """A link the person asked for (Forgot password), to email them, or None when this account gets
    none (disabled, single sign-on, an admin's link still open, or no ROWANHOLT_PUBLIC_URL). The link is
    always the public URL's, never the request's address: whoever asks chooses that, and the token would
    be emailed pointing at them. Sessions and tokens are left alone, since anyone can ask: completing
    the reset ends them. The caller saves the users."""
    if not settings.rowanholt_public_url or _refusal(record) or open_admin_link(record):
        return None
    link_, _ = _new_link(record, SELF_SERVICE, None)
    mfa.audit("access_reset_issued", None, record, ip, storage=storage, via=SELF_SERVICE, tokens_revoked=0)
    return link_


def find(users: dict, token: str) -> dict:
    """The user record a reset token is for; ResetRefused if it's unknown, used or expired (410, for a
    day after it expired). An expired link loses its pending authenticator, and a day on, the link
    itself: `changed` on the refusal says to save."""
    hashed = token_hash(token or "")
    record = next((u for u in users.values()
                   if hmac.compare_digest(u.get("access_reset_hash") or "", hashed)), None)
    if not token or record is None or _refusal(record):
        raise ResetRefused(INVALID, 404)
    expires = float(record.get("access_reset_expires") or 0)
    if expires < mfa._now():
        if expires < mfa._now() - KEEP_EXPIRED_SECONDS:
            _clear(record)
            raise ResetRefused(INVALID, 404, changed=True)
        changed = record.pop("access_reset_pending_secret", None) is not None
        raise ResetRefused(EXPIRED, 410, changed=changed)
    return record


def start(record: dict) -> dict:
    """The reset's new authenticator: the secret (kept on the record until `complete`), its otpauth://
    URI and QR code. Opening the page again (a reload, a second tab) shows the same one, so a phone that
    has already scanned it isn't left with a secret that's been replaced. The caller saves the users."""
    stored = record.get("access_reset_pending_secret")
    secret = (mfa.decrypt_secret(stored) if stored else None) or mfa.new_secret()
    record["access_reset_pending_secret"] = mfa.encrypt_secret(secret)
    return {"username": record["username"], **enrolment(secret, record["username"])}


def pending_step(record: dict, code: str) -> int | None:
    """The step a code from the reset's new authenticator is for, or None (no secret yet, or a wrong code)."""
    stored = record.get("access_reset_pending_secret")
    secret = mfa.decrypt_secret(stored) if stored else None
    if not secret:
        raise ResetRefused("Start again: open the link once more to set up the authenticator")
    return mfa.matching_step(secret, code)


def complete(record: dict, password: str, step: int, ip: str | None = None, storage=None) -> list:
    """Finish the reset once `pending_step` has accepted a code: the new password (ending every
    session), MFA with the new secret, fresh backup codes (returned, to be shown once), every API token
    revoked, and the link used up. The caller saves the users and signs the person in."""
    secret = mfa.decrypt_secret(record["access_reset_pending_secret"])
    via = record.get("access_reset_via") or "admin"
    set_password(record, password)
    codes = turn_on_mfa(record, secret, step)
    _clear(record)
    revoked = _revoke_tokens(record, storage)  # any made since the link was issued, by the old sign-in
    mfa.audit("access_reset_completed", record, record, ip, storage=storage, via=via, tokens_revoked=revoked)
    return codes
