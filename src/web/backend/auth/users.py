"""
User Store

Users live in a JSON file (USERS_FILE) beside the backend's data, keyed by user ID.
Password users carry a bcrypt hash; single sign-on users carry their IdP subject instead.

The API and `rowanholt server users` (another process, in the same container) both write the users
and the invitations beside them, so anything that reads one of those files, decides, and writes it
back does so inside `locked()`: two completions of one link can't both pass the check.
"""

import ipaddress
import json
import logging
import os
import re
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

try:
    import fcntl
except ImportError:  # Windows: the backend runs in Linux containers, but the CLI's tests may not
    fcntl = None
    import msvcrt

try:
    from ..config import settings
    from .security import hash_password
except ImportError:
    from config import settings
    from auth.security import hash_password

logger = logging.getLogger(__name__)

USERS_FILE = os.environ.get("USERS_FILE", "/app/data/users.json")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._@-]{2,64}$")
DEFAULT_ADMIN = "admin"

NO_ACCOUNTS = ("This server has no accounts yet: make the first admin with "
               "rowanholt server users first-admin <email>, which prints a one-time link")


def ensure_data_dir() -> None:
    """Ensure the data directory exists."""
    data_dir = os.path.dirname(USERS_FILE)
    if data_dir and not os.path.exists(data_dir):
        os.makedirs(data_dir, exist_ok=True)


_held = threading.local()
_in_process = threading.RLock()


@contextmanager
def locked() -> Iterator[None]:
    """An exclusive lock on the user store and the invitations beside it, shared by every process that
    writes them (a lock file beside USERS_FILE). Re-entrant in one thread, so a caller already holding it
    can call code that takes it again."""
    if getattr(_held, "depth", 0):
        _held.depth += 1
        try:
            yield
        finally:
            _held.depth -= 1
        return
    with _in_process:
        ensure_data_dir()
        fd = os.open(f"{USERS_FILE}.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            _lock(fd)
            _held.depth = 1
            try:
                yield
            finally:
                _held.depth = 0
                _unlock(fd)
        finally:
            os.close(fd)


def _lock(fd: int) -> None:
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return
    os.lseek(fd, 0, os.SEEK_SET)
    while True:  # msvcrt gives up after ten seconds; keep waiting, as flock does
        try:
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            return
        except OSError:
            continue


def _unlock(fd: int) -> None:
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)
    else:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


def load_users() -> dict:
    """Load users from the JSON file."""
    ensure_data_dir()
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def save_users(users: dict) -> None:
    """Save users to the JSON file, readable by the backend's user only."""
    ensure_data_dir()
    tmp = f"{USERS_FILE}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(users, f, indent=2, default=str)
    os.replace(tmp, USERS_FILE)


def set_password(record: dict, password: str) -> None:
    """A new password, and an end to every session signed in before it: whoever had the old one
    (the reason for a reset, often) is signed out too. auth.access refuses tokens issued earlier."""
    record["hashed_password"] = hash_password(password)
    end_sessions(record)


def end_sessions(record: dict) -> None:
    """Every session signed in until now ends: auth.access refuses tokens issued before sessions_after."""
    record["sessions_after"] = round(time.time(), 3)


def deactivate(record: dict, actor: dict | None, ip: str | None = None, storage=None, **details) -> None:
    """Disable an account: its sessions end and its API tokens are revoked, so re-enabling it later
    doesn't bring either back. Audited. The caller saves the users."""
    try:
        from . import access, mfa
    except ImportError:
        from auth import access, mfa
    storage = storage if storage is not None else access._storage
    record["is_active"] = False
    end_sessions(record)
    revoked = storage.revoke_user_tokens(record["id"]) if storage is not None else None
    mfa.audit("account_deactivated", actor, record, ip, storage=storage, tokens_revoked=revoked, **details)


def new_user(username: str, email: str, role: str = "user", password: Optional[str] = None,
             full_name: Optional[str] = None, **extra) -> dict:
    """A user record; `password` None leaves it without one (single sign-on users)."""
    if not USERNAME_PATTERN.match(username):
        raise ValueError("Usernames are 2-64 letters, digits and . _ @ -")
    if role not in ("admin", "user"):
        raise ValueError("Role must be admin or user")
    return {
        "id": str(uuid.uuid4()),
        "email": email,
        "username": username,
        "hashed_password": hash_password(password) if password else "",
        "full_name": full_name,
        "role": role,
        "is_active": True,
        "created_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        "last_login": None,
        **extra,
    }


def loopback_only(bind: str) -> bool:
    """Whether the stack's ports are published on this machine only (ROWANHOLT_BIND)."""
    host = (bind or "").strip().strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def init_default_admin() -> dict:
    """The users, after making the default admin on a local stack whose store is empty.

    A local stack (an analyst's own machine, or the desktop app) seeds `admin` with the published
    password (settings.default_admin_password), and only while its ports are this machine's alone
    (ROWANHOLT_BIND on loopback): a known password mustn't be reachable from the network. A team
    server seeds nothing: its first admin comes from an invitation (`rowanholt server users
    first-admin <email>`, auth/invitations.py), and an old .env's ROWANHOLT_ADMIN_PASSWORD is ignored.
    """
    users = load_users()
    if users:
        return users
    with locked():
        return _seed_default_admin()


def _seed_default_admin() -> dict:
    users = load_users()  # again, under the lock: another process may have seeded it meanwhile
    if users:
        return users
    if settings.rowanholt_server_mode:
        if settings.rowanholt_admin_password:
            logger.warning("ROWANHOLT_ADMIN_PASSWORD is set but ignored: a server's first admin comes from "
                           "rowanholt server users first-admin <email>. Remove it from .env")
        return users
    if not loopback_only(settings.rowanholt_bind):
        logger.warning("No default admin made: Rowanholt is published beyond this machine (ROWANHOLT_BIND=%s), "
                       "where a known password would be anyone's. Run it as a team server (rowanholt server "
                       "init), whose first admin comes from rowanholt server users first-admin <email>",
                       settings.rowanholt_bind)
        return users
    admin = new_user(DEFAULT_ADMIN, settings.default_admin_email, role="admin",
                     password=settings.default_admin_password, full_name="Administrator")
    users[admin["id"]] = admin
    save_users(users)
    try:
        from . import mfa
    except ImportError:
        from auth import mfa
    mfa.audit("default_admin_seeded", None, admin, role="admin", bind=settings.rowanholt_bind)
    return users


def active_admin(users: dict) -> bool:
    """Whether any admin can sign in."""
    return any(u.get("role") == "admin" and u.get("is_active", True) for u in users.values())


def find_user(users: dict, name: str) -> Optional[dict]:
    """A user by username or email."""
    for user in users.values():
        if user["username"] == name or user["email"] == name:
            return user
    return None


def public(user: dict) -> dict:
    """The fields the API returns for a user."""
    return {
        "id": user["id"],
        "email": user.get("email", ""),
        "username": user["username"],
        "full_name": user.get("full_name"),
        "role": user["role"],
        "is_active": user.get("is_active", True),
        "auth": "sso" if user.get("oidc_subject") else "password",
        "mfa_enabled": bool(user.get("mfa_enabled") and user.get("mfa_secret")),
        "last_login": user.get("last_login"),
    }
