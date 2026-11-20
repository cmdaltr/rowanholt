"""
Invitations

How a team server's accounts are made: an admin invites an email with a role (`rowanholt server users
invite`, or `POST /api/auth/users/invitations`), and the one-time link it prints
(`<public URL>/accept-invite#<token>`) is where that person chooses a username, a password and an
authenticator. The account exists only once a code from the authenticator is confirmed, with MFA on
whatever ROWANHOLT_REQUIRE_MFA says. The same in Ostraka, Rowanholt and Shikari. Admins no longer set
anyone's first password on a server; a local stack, one analyst, has no invitations.

The flow is a reset of access (auth/reset_access.py) that ends in a new account, and shares its
pieces: the token (only its SHA-256 kept), the link with the token in its fragment, the lifetime
(RESET_HOURS), the authenticator to set up and MFA with ten new backup codes.

Pending invitations are kept in their own file beside the users (invitations.json, readable by the
backend's user only), not in users.json: everything that reads the users (licence places, the
directory, sign-in, single sign-on's matching, evidence folders named after accounts) would otherwise
have to learn to skip them. A new invitation for an email replaces an earlier one, and expired ones
are dropped when the file is written a day after they expired.

Opening the link again shows the same authenticator. Five wrong codes close the invitation (each is
audited), and the admin issues a new one. An invitation an admin made is refused at completion if that
admin has since been disabled or is no longer an admin; the server's own (the CLI, first-admin) have
no inviter to check. Callers hold users.locked() from loading the files to saving them.
"""

import hmac
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    from .. import licence
    from ..config import settings
    from . import mfa, reset_access
    from . import users as user_store
except ImportError:
    import licence
    from auth import mfa, reset_access
    from auth import users as user_store
    from config import settings

PATH = "/accept-invite"
ROLES = ("admin", "user")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
KEEP_EXPIRED_SECONDS = reset_access.KEEP_EXPIRED_SECONDS
MAX_WRONG_CODES = 5

INVALID = "This invitation isn't valid or has been used: ask an administrator for a new one"
EXPIRED = "This invitation has expired: ask an administrator for a new one"
LOCAL = "Invitations are for a team server: on your own machine, Rowanholt has one analyst"
_INVITE = "Accounts on a team server are made by invitation, so nobody else sets their password: "
INVITE_INSTEAD = _INVITE + "rowanholt server users invite <email> (or POST /api/auth/users/invitations)"
CLOSED = (f"That's {MAX_WRONG_CODES} wrong codes, so this invitation is closed: ask an administrator "
          "for a new one")
INVITER_GONE = ("Whoever invited you can no longer invite people to this server: ask an administrator "
                "for a new invitation")
ADMIN_EXISTS = ("This server already has an active admin, who invites everyone else "
                "(rowanholt server users invite). --force makes another admin's invitation anyway")


class InvitationRefused(ValueError):
    """An invitation that can't be made or used; the message says why, and `status` is the API's answer
    (402 no free place, 403 the inviter can no longer invite, 409 an account already, 410 expired)."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# ── the file ──────────────────────────────────────────────────────────────────

def _file() -> Path:
    # Beside the users, wherever USERS_FILE puts them (read each time: the tests move it)
    return Path(user_store.USERS_FILE).with_name("invitations.json")


def load() -> dict:
    """Pending invitations by ID, expired ones included (find() refuses those)."""
    try:
        return json.loads(_file().read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save(invitations: dict) -> None:
    """Write the invitations, readable by the backend's user only. Expired ones are dropped once they're
    a day past it: until then their link still says it's expired (410), not that it was never valid."""
    keep_after = mfa._now() - KEEP_EXPIRED_SECONDS
    live = {key: inv for key, inv in invitations.items() if float(inv.get("expires") or 0) >= keep_after}
    path = _file()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(live, f, indent=2)
    os.replace(tmp, path)


def public(invitation: dict) -> dict:
    """What the API lists of an invitation: never its hash or pending secret."""
    return {
        "id": invitation["id"],
        "email": invitation["email"],
        "role": invitation["role"],
        "full_name": invitation.get("full_name"),
        "invited_by": invitation.get("invited_by"),
        "created_at": invitation.get("created_at"),
        "expires_at": _iso(invitation["expires"]),
    }


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(float(epoch), timezone.utc).replace(tzinfo=None).isoformat()


def audit(action: str, actor: dict | None, invitation: dict, ip: str | None, storage=None, **details) -> None:
    mfa.audit(action, actor, {"id": invitation["id"], "username": invitation["email"]}, ip, storage=storage,
              email=invitation["email"], role=invitation["role"], **details)


# ── inviting ──────────────────────────────────────────────────────────────────

def create(users: dict, email: str, role: str = "user", full_name: str | None = None,
           actor: dict | None = None, ip: str | None = None, storage=None, first_admin: bool = False,
           origin: str | None = None, **details) -> tuple[dict, str]:
    """Invite `email` as `role`: (the invitation, as the API lists it; the link, to pass on once).
    Refused for an email that already has an account, and when the licence has no free place (pending
    invitations hold one each, licence.places_held).

    `first_admin` is a server's first admin (`rowanholt server users first-admin`), with nobody yet to
    invite anyone: an admin's invitation that needs no free place while no admin can sign in (there
    must always be a way back in), and only the newest such invitation works. The caller refuses it
    when an active admin exists, unless forced. `origin` is where the link points without
    ROWANHOLT_PUBLIC_URL (reset_access.link)."""
    with user_store.locked():
        return _create(users, email, role, full_name, actor, ip, storage, first_admin, origin, **details)


def _create(users: dict, email: str, role: str, full_name: str | None, actor: dict | None, ip: str | None,
            storage, first_admin: bool, origin: str | None, **details) -> tuple[dict, str]:
    if not settings.rowanholt_server_mode:
        raise InvitationRefused(LOCAL)
    email = (email or "").strip().lower()
    if not EMAIL.match(email):
        raise InvitationRefused("Give the email address of the person to invite")
    if role not in ROLES:
        raise InvitationRefused("Role must be admin or user")
    existing = user_store.find_user(users, email) or next(
        (u for u in users.values() if (u.get("email") or "").lower() == email), None)
    if existing:
        raise InvitationRefused(f"{email} already has an account ({existing['username']}): if they can't sign in, "
                                f"give them a reset link (rowanholt server users reset-access {existing['username']})",
                                409)
    if first_admin:
        role = "admin"
    # Replaced, so not counted: an earlier one for this email, and for a first admin any earlier first admin's
    earlier = {key for key, inv in load().items() if inv["email"] == email or (first_admin and inv.get("first_admin"))}
    refusal = None if first_admin and not user_store.active_admin(users) else licence.seat_refusal(
        users, settings.rowanholt_server_mode, excluding=earlier)
    if refusal:
        raise InvitationRefused(refusal, 402)
    token, expires = reset_access.new_token()
    invitation = {
        "id": str(uuid.uuid4()),
        "email": email,
        "role": role,
        "full_name": (full_name or "").strip() or None,
        "invited_by": (actor or {}).get("username") or "server",
        # An admin's account, checked again at completion (the CLI's actor has none: the server's own)
        **({"invited_by_id": actor["id"]} if (actor or {}).get("id") else {}),
        "created_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        "expires": expires,
        "token_hash": reset_access.token_hash(token),
        **({"first_admin": True} if first_admin else {}),
    }
    current = load()
    invitations = {key: inv for key, inv in current.items() if key not in earlier}  # replaces earlier ones
    invitations[invitation["id"]] = invitation
    save(invitations)
    for key in earlier & current.keys():
        audit("invitation_revoked", actor, current[key], ip, storage, reason="replaced", replaced_by=invitation["id"])
    audit("invitation_created", actor, invitation, ip, storage, **({"first_admin": True} if first_admin else {}),
          **details)
    return public(invitation), reset_access.link(PATH, token, origin)


def revoke(invitation_id: str, actor: dict | None = None, ip: str | None = None, storage=None,
           **details) -> dict | None:
    """Withdraw a pending invitation; None if there's no such invitation (or it's been used)."""
    with user_store.locked():
        invitations = load()
        invitation = invitations.pop(invitation_id, None)
        if invitation is None:
            return None
        save(invitations)
    audit("invitation_revoked", actor, invitation, ip, storage, **details)
    return public(invitation)


def pending() -> list:
    """The invitations not yet used or expired, newest first."""
    now = mfa._now()
    return sorted((public(inv) for inv in load().values() if float(inv.get("expires") or 0) >= now),
                  key=lambda inv: inv["created_at"], reverse=True)


# ── accepting ─────────────────────────────────────────────────────────────────

def find(token: str) -> tuple[dict, dict]:
    """(the invitations, the one a token is for); InvitationRefused if it's unknown, used or expired
    (410, until it's dropped a day later). An expired one loses its pending authenticator, saved here:
    the caller holds users.locked()."""
    if not settings.rowanholt_server_mode:
        raise InvitationRefused(LOCAL)
    invitations = load()
    hashed = reset_access.token_hash(token or "")
    invitation = next((inv for inv in invitations.values()
                       if hmac.compare_digest(inv.get("token_hash") or "", hashed)), None)
    if not token or invitation is None:
        raise InvitationRefused(INVALID)
    if float(invitation.get("expires") or 0) < mfa._now():
        if float(invitation["expires"]) < mfa._now() - KEEP_EXPIRED_SECONDS:
            raise InvitationRefused(INVALID)  # save() drops it
        if invitation.pop("pending_secret", None) is not None:
            save(invitations)
        raise InvitationRefused(EXPIRED, 410)
    return invitations, invitation


def suggested_username(users: dict, email: str) -> str:
    """A username from the email's local part, made to fit the pattern and not taken."""
    base = re.sub(r"[^A-Za-z0-9._-]", "", email.split("@", 1)[0])[:60] or "analyst"
    base = base if len(base) >= 2 else f"{base}1"
    name, n = base, 1
    while user_store.find_user(users, name):
        n += 1
        name = f"{base}{n}"
    return name


def preview(users: dict, invitation: dict) -> dict:
    """What the page shows before anything is chosen."""
    return {"email": invitation["email"], "role": invitation["role"], "full_name": invitation.get("full_name"),
            "username": suggested_username(users, invitation["email"]),
            "expires_in": int(float(invitation["expires"]) - mfa._now())}


def check_username(users: dict, invitations: dict, invitation: dict, username: str) -> str:
    """The username, if it's well formed and free. Sign-in finds an account by username or email, so a
    username can't be another account's email, nor the email another pending invitation is for."""
    username = (username or "").strip()
    if not user_store.USERNAME_PATTERN.match(username):
        raise InvitationRefused("Usernames are 2-64 letters, digits and . _ @ -")
    folded = username.lower()
    taken = {(u.get("username") or "").lower() for u in users.values()}
    taken |= {(u.get("email") or "").lower() for u in users.values()}
    taken |= {inv["email"] for key, inv in invitations.items() if key != invitation["id"]}
    if folded in taken:
        raise InvitationRefused(f"The username {username} is taken: choose another")
    return username


def start(users: dict, invitations: dict, invitation: dict, username: str) -> dict:
    """The authenticator to set up, labelled with the chosen username; its secret is kept on the
    invitation (encrypted) until `complete`. Starting again (a reload, a second tab, another username)
    shows the same one, so a phone that has already scanned it still works. The caller saves."""
    username = check_username(users, invitations, invitation, username)
    stored = invitation.get("pending_secret")
    secret = (mfa.decrypt_secret(stored) if stored else None) or mfa.new_secret()
    invitation["pending_secret"] = mfa.encrypt_secret(secret)
    invitations[invitation["id"]] = invitation
    return {"username": username, **reset_access.enrolment(secret, username)}


def pending_step(invitation: dict, code: str) -> int | None:
    """The step a code from the invitation's new authenticator is for, or None."""
    stored = invitation.get("pending_secret")
    secret = mfa.decrypt_secret(stored) if stored else None
    if not secret:
        raise InvitationRefused("Start again: set up the authenticator first")
    return mfa.matching_step(secret, code)


def wrong_code(invitations: dict, invitation: dict, ip: str | None = None, storage=None) -> bool:
    """A wrong code on the invitation's new authenticator, audited; at the fifth the invitation is
    closed (removed, its authenticator with it) and that's audited too. Whether it's closed. The caller
    saves the invitations."""
    invitation["wrong_codes"] = int(invitation.get("wrong_codes") or 0) + 1
    audit("invitation_wrong_code", None, invitation, ip, storage, attempt=invitation["wrong_codes"])
    if invitation["wrong_codes"] < MAX_WRONG_CODES:
        invitations[invitation["id"]] = invitation
        return False
    invitations.pop(invitation["id"], None)
    audit("invitation_closed", None, invitation, ip, storage, reason="wrong codes", wrong_codes=invitation["wrong_codes"])
    return True


def inviter_refusal(users: dict, invitation: dict) -> str | None:
    """Why an admin's invitation can't be completed: they've been disabled, removed or are no longer an
    admin (only admins invite). None for the server's own invitations and an inviter who still can."""
    inviter_id = invitation.get("invited_by_id")
    if inviter_id:
        inviter = users.get(inviter_id)
    elif invitation.get("invited_by") in (None, "server", "server-cli") or invitation.get("first_admin"):
        return None
    else:  # made before invited_by_id was kept
        inviter = user_store.find_user(users, invitation["invited_by"])
    if not inviter or not inviter.get("is_active", True) or inviter.get("role") != "admin":
        return INVITER_GONE
    return None


def complete(users: dict, invitations: dict, invitation: dict, username: str, full_name: str | None,
             password: str, step: int, ip: str | None = None, storage=None) -> tuple[dict, list]:
    """Make the account, once `pending_step` has accepted a code: (the new user record; its ten
    backup codes, to be shown once). The username, the email and a place are checked again, since
    any may have gone since the invitation was made. Saves both files: the invitation is used up."""
    refusal = inviter_refusal(users, invitation)
    if refusal:
        raise InvitationRefused(refusal, 403)
    username = check_username(users, invitations, invitation, username)
    if any(invitation["email"] in ((u.get("email") or "").lower(), (u.get("username") or "").lower())
           for u in users.values()):
        raise InvitationRefused(f"{invitation['email']} already has an account: sign in instead", 409)
    # A first admin's needs no place while nobody can administer the server (see create)
    refusal = None if invitation.get("first_admin") and not user_store.active_admin(users) else licence.seat_refusal(
        users, settings.rowanholt_server_mode, excluding={invitation["id"]})
    if refusal:
        raise InvitationRefused(refusal, 402)
    record = user_store.new_user(username, invitation["email"], role=invitation["role"], password=password,
                                 full_name=(full_name or "").strip() or invitation.get("full_name"),
                                 invited_by=invitation.get("invited_by"))
    codes = reset_access.turn_on_mfa(record, mfa.decrypt_secret(invitation["pending_secret"]), step)
    record["last_login"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    users[record["id"]] = record
    user_store.save_users(users)
    invitations.pop(invitation["id"], None)
    save(invitations)
    mfa.audit("account_created", record, record, ip, storage=storage, role=record["role"],
              invitation=invitation["id"], invited_by=invitation.get("invited_by"))
    return record, codes
