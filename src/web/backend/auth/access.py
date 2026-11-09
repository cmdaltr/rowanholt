"""
Access Control

Who is calling, and which jobs and cases they may see.

Local mode (the default) keeps the API as open as it has always been on an analyst's
own machine: a caller with no token acts as the local analyst, with admin rights.

Server mode (settings.rowanholt_server_mode) puts every /api route behind a signed-in
user, apart from PUBLIC_PATHS, so a route added later is covered without remembering
to protect it. Admin-only areas are listed in ADMIN_PREFIXES. A job is visible to its
owner, the users it's shared with, and admins; a job from before server mode has no
owner, so only admins see it until one shares it.
"""

import logging
import posixpath
import re
from datetime import datetime
from typing import Iterable, Optional
from urllib.parse import unquote

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.requests import HTTPConnection

try:
    from ..config import settings
    from .security import verify_token
    from .users import load_users, public
    from . import tokens
except ImportError:
    from config import settings
    from auth.security import verify_token
    from auth.users import load_users, public
    from auth import tokens

logger = logging.getLogger(__name__)

LOCAL_USER = {
    "id": "local",
    "email": "",
    "username": "local",
    "full_name": "Local analyst",
    "role": "admin",
    "is_active": True,
    "auth": "local",
    "last_login": None,
}

PUBLIC_PATHS = {
    "/api/health",
    "/api/auth/config",
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/oidc/login",
    "/api/auth/oidc/callback",
    "/api/auth/verify",
}
# An online lookup is a POST (it sends the value out) that every analyst may make
LOOKUP_PATH = "/api/threat-intel/lookup"
ADMIN_PREFIXES = ("/api/lab", "/api/anduril", "/api/aragorn", "/api/auth/users")
JOB_PATH = re.compile(r"^/api/jobs/([0-9a-fA-F-]{36})(?:/|$)")
CASE_PATH = re.compile(r"^/api/ai/cases/([^/]+)/")

_storage = None


def configure(storage) -> None:
    """Give the access checks the backend's JobStorage."""
    global _storage
    _storage = storage


def server_mode() -> bool:
    return settings.rowanholt_server_mode


def user_from_request(request: HTTPConnection) -> Optional[dict]:
    """The caller from the bearer token, else the session cookie (a stale or empty
    header mustn't hide a good cookie)."""
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        user = user_from_token(header[7:].strip())
        if user:
            return user
    return user_from_token(request.cookies.get("session_token"))


def user_from_token(token: Optional[str]) -> Optional[dict]:
    """The active user a token belongs to, as returned by the API. For an API token
    (auth/tokens.py) the user carries it as "token": its id, name and scope."""
    if not token:
        return None
    if tokens.is_api_token(token):
        return _user_from_api_token(token)
    payload = verify_token(token)
    if not payload:
        return None
    user = load_users().get(payload.get("sub", ""))
    if not user or not user.get("is_active", True):
        return None
    return public(user)


def _user_from_api_token(token: str) -> Optional[dict]:
    if _storage is None:
        return None
    now = datetime.now()
    record = _storage.token_by_hash(tokens.hash_token(token))
    if not tokens.usable(record, now):
        return None
    user = load_users().get(record["user_id"])
    if not user or not user.get("is_active", True):
        return None
    if not record["last_used_at"] or now - record["last_used_at"] > tokens.TOUCH_EVERY:
        try:
            _storage.touch_token(record["id"], now)
        except Exception as exc:  # a missed last-used time mustn't refuse the request
            logger.warning(f"Could not record token {record['prefix']}… as used: {exc}")
    return {**public(user), "token": {"id": record["id"], "name": record["name"], "scope": tokens.scope_of(record["scope"])}}


def token_scope(request: Request) -> Optional[str]:
    """The scope of the API token behind this request, or None for a sign-in or no token."""
    user = getattr(request.state, "user", None) or {}
    return tokens.scope_of((user.get("token") or {}).get("scope"))


def is_admin(user: dict) -> bool:
    return user.get("role") == "admin"


async def middleware(request: Request, call_next):
    """Resolve the caller for every request; in server mode, turn away the ones not allowed."""
    path = request.url.path
    user = user_from_request(request)
    request.state.user = user or (None if server_mode() else LOCAL_USER)

    if user and user.get("token") and path.startswith("/api"):
        reason = tokens.refusal(user["token"], request.method, path, ADMIN_PREFIXES)
        if reason:
            return JSONResponse({"detail": reason}, status_code=403)
    if server_mode() and path.startswith("/api") and path not in PUBLIC_PATHS and request.method != "OPTIONS":
        if not user:
            return JSONResponse({"detail": "Sign in required"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
        admin_only = path.startswith(ADMIN_PREFIXES) or (
            path.startswith(("/api/mordor", "/api/threat-intel")) and request.method != "GET"
            and path != LOOKUP_PATH)
        if admin_only and not is_admin(user):
            return JSONResponse({"detail": "Admin privileges required"}, status_code=403)
        match = JOB_PATH.match(path)
        if match and not can_access_job(user, match.group(1)):
            # 404 rather than 403, so job IDs can't be probed
            return JSONResponse({"detail": "Job not found"}, status_code=404)
        match = CASE_PATH.match(path)
        if match and not case_allowed(user, unquote(match.group(1))):
            return JSONResponse({"detail": "Case not found"}, status_code=404)
    return await call_next(request)


def websocket_user(websocket: HTTPConnection) -> Optional[dict]:
    """The caller of a websocket under /api, or None if refused. middleware() only sees HTTP
    requests, so a websocket route asks this itself (at the handshake and again while open):
    the same token, sign-in, admin-area and job checks, read as a GET. Browsers send cookies with a
    websocket to any site that opens one, so one from a page on another origin is refused
    (an origin check is the only CSRF defence a websocket has)."""
    origin = websocket.headers.get("origin")
    if origin and origin.rstrip("/") not in [o.rstrip("/") for o in settings.cors_origins]:
        return None
    path = websocket.url.path
    user = user_from_request(websocket)
    if user and user.get("token") and tokens.refusal(user["token"], "GET", path, ADMIN_PREFIXES):
        return None
    if not server_mode():
        return user or LOCAL_USER
    if not user:
        return None
    if path.startswith(ADMIN_PREFIXES) and not is_admin(user):
        return None  # as the middleware's admin areas (the lab's consoles are a websocket)
    match = JOB_PATH.match(path)
    if match and not can_access_job(user, match.group(1)):
        return None
    return user


def current_user(request: Request) -> dict:
    """FastAPI dependency: the caller (the local analyst when local)."""
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(status_code=401, detail="Sign in required")
    return user


def require_admin(request: Request) -> dict:
    """FastAPI dependency: the caller, who must be an admin."""
    user = current_user(request)
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


def allowed(user: dict, access: Optional[dict]) -> bool:
    """Whether `user` may see a job with this access record (owner, shared_with)."""
    if not server_mode() or is_admin(user):
        return True
    if not access:
        return False
    return access.get("owner_id") == user["id"] or user["username"] in (access.get("shared_with") or [])


def can_access_job(user: dict, job_id: str) -> bool:
    if not server_mode() or is_admin(user):
        return True
    if _storage is None:
        logger.error("Access checks used before configure(); refusing")
        return False
    return allowed(user, _storage.get_access(job_id))


def can_manage_job(user: dict, job_id: str) -> bool:
    """Owners and admins change who a job is shared with; the people it's shared with don't."""
    if not server_mode() or is_admin(user):
        return True
    access = _storage.get_access(job_id) if _storage else None
    return bool(access) and access.get("owner_id") == user["id"]


def visible_job_ids(user: dict) -> Optional[set]:
    """The job IDs `user` may see, or None for all of them."""
    if not server_mode() or is_admin(user):
        return None
    return {job_id for job_id, access in _storage.all_access().items() if allowed(user, access)}


def filter_job_ids(user: dict, job_ids: Iterable[str]) -> list:
    """The subset of `job_ids` `user` may see (bulk actions)."""
    return [job_id for job_id in job_ids if can_access_job(user, job_id)]


def visible_cases(user: dict) -> Optional[set]:
    """The case numbers `user` may see (through jobs they can see), or None for all.
    A case directory with no job behind it is for admins only."""
    visible = visible_job_ids(user)
    if visible is None:
        return None
    return {job.case_number for job in _storage.list_jobs(limit=100000, job_ids=visible)}


# The ATT&CK Navigator serves each case's layer as /assets/<case>.json (post/mitre/nav_config.py)
LAYER_PATH = re.compile(r"^/assets/([^/]+)\.json$")


def layer_allowed(user: dict, uri: str) -> bool:
    """Whether `user` may fetch this Navigator URI. A case's layer follows the case; the
    Navigator's own assets (ATT&CK itself, its config) are for anyone signed in."""
    # Normalised as the Navigator's nginx will (//, /./, ..), so another spelling of a case's
    # layer can't skip the check
    # (not urlsplit: it reads //assets/... as a host)
    path = unquote((uri or "/").split("?", 1)[0].split("#", 1)[0])
    match = LAYER_PATH.match(posixpath.normpath("/" + path.lstrip("/")))
    if not match:
        return True
    cases = visible_cases(user)
    if cases is None or match.group(1) in cases:
        return True
    # Not one of theirs: refuse it if it's anyone's case, and admins-only if it's a layer
    # with no job behind it (an Elrond run from the command line)
    case = match.group(1)
    if any(job.case_number == case for job in _storage.list_jobs(limit=100000)):
        return False
    return not (settings.output_dir / case).is_dir()


def case_allowed(user: dict, case_id: str) -> bool:
    cases = visible_cases(user)
    return cases is None or case_id in cases
