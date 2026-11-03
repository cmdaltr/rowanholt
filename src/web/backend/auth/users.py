"""
User Store

Users live in a JSON file (USERS_FILE) beside the backend's data, keyed by user ID.
Password users carry a bcrypt hash; single sign-on users carry their IdP subject instead.
"""

import json
import os
import re
import uuid
from datetime import datetime
from typing import Optional

try:
    from ..config import settings
    from .security import hash_password
except ImportError:
    from config import settings
    from auth.security import hash_password

USERS_FILE = os.environ.get("USERS_FILE", "/app/data/users.json")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._@-]{2,64}$")


class AdminPasswordMissing(RuntimeError):
    """Server mode with no users yet and no RIVENDELL_ADMIN_PASSWORD to create the first admin."""


def ensure_data_dir() -> None:
    """Ensure the data directory exists."""
    data_dir = os.path.dirname(USERS_FILE)
    if data_dir and not os.path.exists(data_dir):
        os.makedirs(data_dir, exist_ok=True)


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
        "created_at": datetime.utcnow().isoformat(),
        "last_login": None,
        **extra,
    }


def init_default_admin() -> dict:
    """Create the first admin if there are no users, and return the users.

    Locally that admin has the built-in password. A server takes it from
    RIVENDELL_ADMIN_PASSWORD and refuses to create one without it, since the
    built-in password is public.
    """
    users = load_users()
    if users:
        return users
    if settings.rivendell_server_mode:
        if not settings.rivendell_admin_password:
            raise AdminPasswordMissing("Set RIVENDELL_ADMIN_PASSWORD (rivendell server init does) to create the first admin")
        password = settings.rivendell_admin_password
    else:
        password = settings.default_admin_password
    admin = new_user("admin", settings.default_admin_email, role="admin", password=password, full_name="Administrator")
    users[admin["id"]] = admin
    save_users(users)
    return users


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
        "last_login": user.get("last_login"),
    }
