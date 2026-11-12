"""
Multi-factor authentication for password accounts: TOTP (RFC 6238) and backup codes.

What's kept, in the user's record in the user store (auth/users.py):
- `mfa_secret`: the TOTP secret, Fernet-encrypted with a key derived (HKDF) from the server's
  secret key; `mfa_pending_secret` the same for an enrolment not yet confirmed
- `mfa_last_step`: the last 30-second step a code was accepted for, so a code can't be used twice
- `mfa_backup_codes`: HMAC-SHA256 of each unused backup code, under another derived key

Single sign-on accounts get their second factor from the identity provider, and API tokens are
the non-interactive way in, so neither goes through this.

A password sign-in with MFA on gets a challenge rather than a session (`new_challenge`): signed
with its own derived key and prefixed `mfa_`, so it's neither a JWT nor an API token and nothing
but the sign-in's second step will take it.
"""

import base64
import hashlib
import hmac
import json
import logging
import secrets
import struct
import time
from functools import lru_cache
from typing import List, Optional, Tuple
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    from ..config import settings
except ImportError:
    from config import settings

logger = logging.getLogger(__name__)

ISSUER = "Rowanholt"
STEP_SECONDS = 30
DIGITS = 6
DRIFT_STEPS = 1  # the step before and after now: a phone's clock a little out, or a slow typist
BACKUP_CODES = 10
CHALLENGE_SECONDS = 300
BACKUP_CLAIM_SECONDS = 24 * 60 * 60
CHALLENGE_PREFIX = "mfa_"
# No 0/O, 1/I/L: a code read off paper is typed back right. 31 symbols, 10 of them: 49 bits
_BACKUP_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

# HKDF labels. Changing one makes what it protects unreadable (secrets) or unmatchable (codes,
# challenges in flight), so they carry a version rather than ever being edited.
_SECRET_LABEL = b"rowanholt mfa totp secret v1"
_BACKUP_LABEL = b"rowanholt mfa backup code v1"
_CHALLENGE_LABEL = b"rowanholt mfa sign-in challenge v1"


def _now() -> float:
    """The time codes and challenges are checked against (a seam for the tests' clock)."""
    return time.time()


class MfaError(ValueError):
    """A code or challenge that wasn't accepted; the message is for the person signing in."""


# ── keys ──────────────────────────────────────────────────────────────────────

@lru_cache(maxsize=8)
def _derive(label: bytes, secret_key: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label).derive(secret_key.encode())


def _key(label: bytes) -> bytes:
    # Keyed on the secret as it is now: tests (and a server whose SECRET_KEY was set) change it
    return _derive(label, settings.secret_key)


def encrypt_secret(secret: str) -> str:
    """The TOTP secret as it's stored."""
    return Fernet(base64.urlsafe_b64encode(_key(_SECRET_LABEL))).encrypt(secret.encode()).decode()


def decrypt_secret(stored: str) -> Optional[str]:
    """The TOTP secret, or None when it can't be read (the server's secret key has changed)."""
    try:
        return Fernet(base64.urlsafe_b64encode(_key(_SECRET_LABEL))).decrypt(stored.encode()).decode()
    except (InvalidToken, ValueError, TypeError):
        logger.error("A stored TOTP secret can't be decrypted: has SECRET_KEY changed?")
        return None


# ── TOTP (RFC 6238 over RFC 4226, HMAC-SHA1: what every authenticator app does) ─

def new_secret() -> str:
    """A random 160-bit secret, base32 without padding, as authenticator apps take it."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def code_at(secret: str, step: int) -> str:
    """The code for one 30-second step."""
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10 ** DIGITS).zfill(DIGITS)


def current_step(now: Optional[float] = None) -> int:
    return int((_now() if now is None else now) // STEP_SECONDS)


def matching_step(secret: str, code: str, last_step: int = -1, now: Optional[float] = None) -> Optional[int]:
    """The step `code` is for, within a step either side of now, or None. A step at or before
    `last_step` has been used already and doesn't match: that's what stops a replay."""
    code = "".join(ch for ch in code or "" if ch.isdigit())
    if len(code) != DIGITS:
        return None
    current = current_step(now)
    for step in range(current - DRIFT_STEPS, current + DRIFT_STEPS + 1):
        if step > last_step and hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def provisioning_uri(secret: str, username: str) -> str:
    """The otpauth:// URI an authenticator app reads from the QR code."""
    label = quote(f"{ISSUER}:{username}", safe="")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}")


def qr_svg_data_uri(uri: str) -> str:
    """The URI as a QR code, an SVG data URI the page shows as an <img>. Drawn here so the web
    app needs no QR library, and the secret never goes to a third-party QR service."""
    import segno  # only enrolment needs it

    return segno.make(uri, error="m").svg_data_uri(scale=5, border=2, dark="#000", light="#fff")


# ── backup codes ──────────────────────────────────────────────────────────────

def new_backup_codes(count: int = BACKUP_CODES) -> List[str]:
    """Fresh codes, as they're shown: XXXXX-XXXXX."""
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_BACKUP_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def normalise_backup_code(code: str) -> str:
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def hash_backup_code(code: str) -> str:
    """A keyed hash rather than bcrypt: a code is 49 random bits, not a password a person chose, so
    a slow hash adds nothing a key doesn't, and a sign-in checks up to ten of them."""
    return hmac.new(_key(_BACKUP_LABEL), normalise_backup_code(code).encode(), hashlib.sha256).hexdigest()


def looks_like_backup_code(code: str) -> bool:
    return len(normalise_backup_code(code)) == 10 and not normalise_backup_code(code).isdigit()


# ── the user's record ─────────────────────────────────────────────────────────

def is_enabled(record: dict) -> bool:
    return bool(record.get("mfa_enabled") and record.get("mfa_secret"))


def offered_to(record: dict) -> bool:
    """MFA here is for password accounts; single sign-on accounts have the identity provider's."""
    return bool(record.get("hashed_password")) and not record.get("oidc_subject")


def check_code(record: dict, code: str, allow_backup: bool = True) -> Tuple[bool, str]:
    """Check a second factor against the user's record, using it up if it's accepted.

    Returns (accepted, how): how is "totp" or "backup_code". The caller saves the record.
    """
    secret = decrypt_secret(record.get("mfa_secret") or "")
    if secret:
        step = matching_step(secret, code, int(record.get("mfa_last_step", -1)))
        if step is not None and _first_use(f"totp|{record['id']}|{step}"):
            record["mfa_last_step"] = step
            return True, "totp"
    if allow_backup and looks_like_backup_code(code):
        hashed = hash_backup_code(code)
        stored = list(record.get("mfa_backup_codes") or [])
        for index, candidate in enumerate(stored):
            if hmac.compare_digest(candidate, hashed):
                # Claimed as well as removed: two requests with one code both read the list before
                # either saves it. The key is the hash, never the code; a day outlasts any save
                if not _first_use(f"backup|{record['id']}|{hashed}", BACKUP_CLAIM_SECONDS):
                    return False, ""
                del stored[index]
                record["mfa_backup_codes"] = stored
                return True, "backup_code"
    return False, ""


def _first_use(key: str, seconds: int = (2 * DRIFT_STEPS + 2) * STEP_SECONDS) -> bool:
    """Whether this is the first time `key` is seen, across every backend process (Redis, else this
    one): two requests racing with one code both read the old mfa_last_step."""
    try:
        from .throttle import throttle
    except ImportError:
        from auth.throttle import throttle
    return throttle.first_use(key, seconds)


def enable(record: dict, secret: str, step: int) -> Optional[List[str]]:
    """Switch MFA on with a confirmed secret. Backup codes are made the first time (returned, to be
    shown once); a re-enrolment keeps the ones the user already has."""
    first = not is_enabled(record)
    record["mfa_enabled"] = True
    record["mfa_secret"] = encrypt_secret(secret)
    record["mfa_last_step"] = step
    record.pop("mfa_pending_secret", None)
    record.pop("mfa_pending_at", None)
    record["mfa_enabled_at"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    if first or not record.get("mfa_backup_codes"):
        return replace_backup_codes(record)
    return None


def replace_backup_codes(record: dict) -> List[str]:
    codes = new_backup_codes()
    record["mfa_backup_codes"] = [hash_backup_code(code) for code in codes]
    return codes


def disable(record: dict) -> None:
    for field in ("mfa_enabled", "mfa_secret", "mfa_pending_secret", "mfa_pending_at", "mfa_last_step",
                  "mfa_backup_codes", "mfa_enabled_at"):
        record.pop(field, None)


def status(record: dict) -> dict:
    """What the Account page shows; never the secret."""
    return {
        "enabled": is_enabled(record),
        "backup_codes_left": len(record.get("mfa_backup_codes") or []) if is_enabled(record) else 0,
        "backup_codes_total": BACKUP_CODES,
        "enabled_at": record.get("mfa_enabled_at") if is_enabled(record) else None,
    }


# ── the sign-in challenge ─────────────────────────────────────────────────────

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _password_tag(record: dict) -> str:
    # A password change while a challenge is out makes it stale
    return hashlib.sha256((record.get("hashed_password") or "").encode()).hexdigest()[:16]


def new_challenge(record: dict, now: Optional[float] = None) -> str:
    """A short-lived ticket that the password was right, for the sign-in's second step only."""
    body = json.dumps({"u": record["id"], "n": secrets.token_urlsafe(16), "p": _password_tag(record),
                       "e": int((_now() if now is None else now) + CHALLENGE_SECONDS)},
                      separators=(",", ":")).encode()
    signature = hmac.new(_key(_CHALLENGE_LABEL), body, hashlib.sha256).digest()
    return f"{CHALLENGE_PREFIX}{_b64(body)}.{_b64(signature)}"


def read_challenge(challenge: str, users: dict, now: Optional[float] = None) -> Tuple[dict, str]:
    """The user record a challenge is for and its nonce; MfaError if it's forged, expired or stale.
    Single use is the caller's: `spend_challenge` once the code is accepted."""
    try:
        if not challenge.startswith(CHALLENGE_PREFIX):
            raise ValueError
        body_text, signature_text = challenge[len(CHALLENGE_PREFIX):].split(".", 1)
        body = _unb64(body_text)
        expected = hmac.new(_key(_CHALLENGE_LABEL), body, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(signature_text)):
            raise ValueError
        claims = json.loads(body)
    except (ValueError, AttributeError, TypeError):
        raise MfaError("That sign-in isn't valid; start again")
    if claims.get("e", 0) < (_now() if now is None else now):
        raise MfaError("That sign-in has expired; start again")
    record = users.get(claims.get("u", ""))
    if not record or not record.get("is_active", True) or claims.get("p") != _password_tag(record):
        raise MfaError("That sign-in isn't valid; start again")
    return record, claims["n"]


def spend_challenge(nonce: str) -> bool:
    """Use a challenge up; False if it already was."""
    try:
        from .throttle import throttle
    except ImportError:
        from auth.throttle import throttle
    return throttle.first_use(f"challenge|{nonce}", CHALLENGE_SECONDS + 60)


# ── the security log ──────────────────────────────────────────────────────────

def audit(action: str, actor: Optional[dict], target: dict, ip: Optional[str] = None, storage=None,
          **details) -> None:
    """An MFA event in the audit_logs table (enabled, disabled, a backup code used, codes
    regenerated, a failed second factor, an admin's reset). A database that's down is logged
    rather than undoing what's been done."""
    try:
        from . import access
    except ImportError:
        from auth import access
    storage = storage or access._storage
    details = {"username": target.get("username"), **details}
    logger.info("MFA %s for %s by %s", action, target.get("username"), (actor or {}).get("username") or "server")
    if storage is None:
        logger.warning("MFA %s not audited (no storage configured): %s", action, details)
        return
    storage.audit(action, actor or {"username": "server"}, ip, resource_type="user",
                  resource_id=target.get("id"), **details)
