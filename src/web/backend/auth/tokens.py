"""
API Tokens

Long-lived, revocable tokens for scripts and Aulë's MCP server, in place of a sign-in's
24-hour JWT. A token is "rvt_" and 43 random characters; only its SHA-256 is stored
(the api_tokens table), so it's shown once, when it's made. It stops working when it's
revoked, when it expires (at most a year), or when its user is deactivated or removed.

A token's scope says what it may do:
- full: whatever its user may do, apart from making or revoking tokens and trading the
  token for a sign-in's session (so revoking a token is the end of it)
- aule-mcp: what Aulë's MCP server needs and no more: reading, and flagging leads and adding
  notes, recorded as "Aulë (for <user>)" whether or not the caller says it's Aulë. Admin areas
  are refused even when the user is an admin. "eru-mcp", its name before Aulë was Eru, is
  still taken wherever a scope is given or checked, and read as aule-mcp.
"""

import hashlib
import re
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional

PREFIX = "rvt_"
SCOPES = ("full", "aule-mcp")
AULE_SCOPE = "aule-mcp"
# Scopes from before a rename, still taken: tokens made before the migration that renamed them
# (alembic f2b7c9d4e816), and scripts that still ask for the old name
OLD_SCOPES = {"eru-mcp": AULE_SCOPE}
DEFAULT_DAYS = 90
MAX_DAYS = 365
# last_used_at is written at most this often per token, not on every request
TOUCH_EVERY = timedelta(minutes=1)

# The only writes an aule-mcp token may make: Aulë's flag_lead and add_note
AULE_WRITES = re.compile(r"^/api/jobs/[0-9a-fA-F-]{36}/case/(findings|notes)$")
# Aulë's questions are POSTs that only read the case: the MCP server's ask_offline, ask_aule,
# case_summary and suggestions
AULE_QUESTIONS = re.compile(r"^/api/ai/(offline/answer|cases/[^/]+/(query|summary|suggestions))$")
READ_METHODS = ("GET", "HEAD", "OPTIONS")
# Never through a token: making or revoking tokens, swapping one for a session, or anything that
# sets a password or makes an account (each would outlive the token, so revoking it wouldn't end
# the access)
SIGN_IN_ONLY = ("/api/auth/tokens", "/api/auth/session", "/api/auth/users", "/api/auth/change-password")


def scope_of(scope: Optional[str]) -> Optional[str]:
    """A scope by its current name: an old one (OLD_SCOPES) as the scope it became."""
    return OLD_SCOPES.get(scope, scope) if scope else scope


def is_api_token(token: Optional[str]) -> bool:
    return bool(token) and token.startswith(PREFIX)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token(user: dict, name: str, scope: str, days: int) -> tuple:
    """A new token for `user`: (the token, to show once; the record to store)."""
    token = PREFIX + secrets.token_urlsafe(32)
    now = datetime.now()
    record = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "username": user["username"],
        "name": name,
        "token_hash": hash_token(token),
        "prefix": token[:len(PREFIX) + 6],
        "scope": scope,
        "created_at": now,
        "expires_at": now + timedelta(days=days),
    }
    return token, record


def usable(record: Optional[dict], now: datetime) -> bool:
    return bool(record) and record["revoked_at"] is None and record["expires_at"] > now


def refusal(token: dict, method: str, path: str, admin_prefixes: tuple) -> Optional[str]:
    """Why a request made with this token is refused, or None if it's allowed."""
    if path.startswith(SIGN_IN_ONLY):
        return "Tokens are managed from a sign-in, not with a token"
    if scope_of(token["scope"]) != AULE_SCOPE:
        return None
    if path.startswith(admin_prefixes):
        return "An aule-mcp token can't use admin areas"
    if method in READ_METHODS or (method == "POST" and (AULE_WRITES.match(path) or AULE_QUESTIONS.match(path))):
        return None
    return "An aule-mcp token can only read, flag leads and add notes"
