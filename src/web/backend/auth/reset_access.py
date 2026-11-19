"""
Reset Access

For someone who has lost their password, their authenticator or their backup codes: a one-time link
(`<public URL>/reset-access#<token>`) to choose a new password and set up a new authenticator. The
same in Ostraka, Rowanholt and Shikari. An admin issues it, from the server (`rowanholt server users
reset-access`) or the API (`POST /api/auth/users/{id}/reset-access`).

Issuing ends every session the account has, revokes its API tokens and replaces any earlier link.
Only the token's SHA-256 is kept, on the user's record (`access_reset_hash`), with when it expires.
The token is in the link's fragment, so it never reaches a server's or proxy's logs.

Opening the link: `start` makes a new TOTP secret, kept on the record (Fernet-encrypted, as
mfa.py keeps a pending one) rather than trusted from the page; `complete` takes the new password
and a code from the new authenticator. Only then does anything change: the password, MFA on with
the new secret (whatever ROWANHOLT_REQUIRE_MFA says: a reset always ends with MFA), ten fresh
backup codes in place of the old ones, and the link used up. Until then the account's old
password and authenticator stand, so a link nobody opens takes nothing away.

An invitation (auth/invitations.py) is the same flow ending in a new account, and shares the pieces
here: the token and its hash, the link, the lifetime, the authenticator to set up and MFA turned on
with fresh backup codes.
"""

import hashlib
import hmac
import secrets
import time

try:
    from ..config import settings
    from . import mfa
    from .users import set_password
except ImportError:
    from auth import mfa
    from auth.users import set_password
    from config import settings

RESET_HOURS = 24  # a reset link's lifetime, and an invitation's
PATH = "/reset-access"

INVALID = "This link isn't valid or has been used: ask an administrator for a new one"
EXPIRED = "This link has expired: ask an administrator for a new one"
LOCAL = ("Reset access is for a team server: on your own machine, set a new password with "
         "rowanholt server users password <username>")
_RESET = "On a team server people choose their own passwords: give them a reset link instead, "
RESET_INSTEAD = _RESET + "POST /api/auth/users/{id}/reset-access (or rowanholt server users reset-access <user>)"
RESET_INSTEAD_CLI = _RESET + "rowanholt server users reset-access <user>"


class ResetRefused(ValueError):
    """An account that can't be given a reset link, or a link that can't be used; the message says why."""


def token_hash(token: str) -> str:
    """What's kept of a link's token: its SHA-256 (256 random bits need no slow hash)."""
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> tuple[str, float]:
    """A link's token, to pass on once, and when it expires (epoch seconds, RESET_HOURS on)."""
    return secrets.token_urlsafe(32), mfa._now() + RESET_HOURS * 60 * 60  # mfa's clock: the tests move it on


def link(path: str, token: str) -> str:
    """The link at the server's public URL, with the token in the fragment."""
    return f"{settings.rowanholt_public_url.rstrip('/')}{path}#{token}"


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
    for field in ("access_reset_hash", "access_reset_expires", "access_reset_pending_secret"):
        record.pop(field, None)


def _revoke_tokens(record: dict, storage) -> int | None:
    """Revoke the account's API tokens: ending sessions (sessions_after) doesn't touch them, and a
    token made by whoever had the account mustn't outlast the reset. None when there's no storage."""
    return storage.revoke_user_tokens(record["id"]) if storage is not None else None


def issue(record: dict, actor: dict | None, ip: str | None = None, storage=None,
          **details) -> tuple[str, float]:
    """Give `record` a reset link: (the link, to pass on once; when it expires, epoch seconds).
    Ends its sessions now and revokes its API tokens. The caller saves the users."""
    if not settings.rowanholt_server_mode:
        raise ResetRefused(LOCAL)
    if not record.get("is_active", True):
        raise ResetRefused(f"{record['username']} is disabled: enable them first")
    if not mfa.offered_to(record):
        raise ResetRefused(f"{record['username']} signs in with single sign-on: there's no password to reset. "
                           "Their identity provider handles recovery")
    token, expires = new_token()
    _clear(record)  # an earlier link stops working
    record["access_reset_hash"] = token_hash(token)
    record["access_reset_expires"] = expires
    record["sessions_after"] = round(time.time(), 3)
    revoked = _revoke_tokens(record, storage)
    mfa.audit("access_reset_issued", actor, record, ip, storage=storage, tokens_revoked=revoked, **details)
    return link(PATH, token), expires


def find(users: dict, token: str) -> dict:
    """The user record a reset token is for; ResetRefused if it's unknown, used or expired."""
    if not settings.rowanholt_server_mode:
        raise ResetRefused(LOCAL)
    hashed = token_hash(token or "")
    record = next((u for u in users.values()
                   if hmac.compare_digest(u.get("access_reset_hash") or "", hashed)), None)
    if not token or record is None or not record.get("is_active", True) or not mfa.offered_to(record):
        raise ResetRefused(INVALID)
    if float(record.get("access_reset_expires") or 0) < mfa._now():
        raise ResetRefused(EXPIRED)
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
    session), MFA with the new secret, fresh backup codes (returned, to be shown once), and the link
    used up. The caller saves the users and signs the person in."""
    secret = mfa.decrypt_secret(record["access_reset_pending_secret"])
    set_password(record, password)
    codes = turn_on_mfa(record, secret, step)
    _clear(record)
    revoked = _revoke_tokens(record, storage)  # any made since the link was issued, by the old sign-in
    mfa.audit("access_reset_completed", record, record, ip, storage=storage, tokens_revoked=revoked)
    return codes
