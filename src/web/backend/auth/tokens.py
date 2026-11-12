"""
API Tokens

Long-lived, revocable tokens for scripts and Smith's MCP server, in place of a sign-in's
24-hour JWT. A token is "rvt_" and 43 random characters; only its SHA-256 is stored
(the api_tokens table), so it's shown once, when it's made. It stops working when it's
revoked, when it expires (at most a year), or when its user is deactivated or removed.

A token's scope says what it may do:
- full: whatever its user may do, apart from making or revoking tokens and trading the
  token for a sign-in's session (so revoking a token is the end of it)
- smith-mcp: what Smith's MCP server needs and no more: reading, and flagging leads and adding
  notes, recorded as "Smith (for <user>)" whether or not the caller says it's Smith. Admin areas
  are refused even when the user is an admin. Its names from before the analyst was renamed,
  "aule-mcp" (Aulë, until 12 November 2026) and "eru-mcp" (Eru, until 9 November 2026), are
  still taken wherever a scope is given or checked, and read as smith-mcp.
"""

import hashlib
import re
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional

PREFIX = "rvt_"
SCOPES = ("full", "smith-mcp")
SMITH_SCOPE = "smith-mcp"
# Scopes from before a rename, still taken: tokens made before the migrations that renamed them
# (alembic f2b7c9d4e816 and e8c3a1f5b927), and scripts and MCP hosts that still ask for the old name
OLD_SCOPES = {"aule-mcp": SMITH_SCOPE, "eru-mcp": SMITH_SCOPE}
DEFAULT_DAYS = 90
MAX_DAYS = 365
# last_used_at is written at most this often per token, not on every request
TOUCH_EVERY = timedelta(minutes=1)

# The only writes a smith-mcp token may make: Smith's flag_lead and add_note
SMITH_WRITES = re.compile(r"^/api/jobs/[0-9a-fA-F-]{36}/case/(findings|notes)$")
# Smith's questions are POSTs that only read the case: the MCP server's ask_offline, ask_smith,
# case_summary and suggestions
SMITH_QUESTIONS = re.compile(r"^/api/ai/(offline/answer|cases/[^/]+/(query|summary|suggestions))$")
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
    if scope_of(token["scope"]) != SMITH_SCOPE:
        return None
    if path.startswith(admin_prefixes):
        return "A smith-mcp token can't use admin areas"
    if method in READ_METHODS or (method == "POST" and (SMITH_WRITES.match(path) or SMITH_QUESTIONS.match(path))):
        return None
    return "A smith-mcp token can only read, flag leads and add notes"
